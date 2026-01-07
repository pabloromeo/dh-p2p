use log::{debug, info, warn};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::{mpsc, oneshot, watch},
};

use crate::buffer::JitterBuffer;
use crate::config::DropPolicy;
use crate::fdlog::log_fd_snapshot;
use crate::shutdown::ShutdownReason;
use crate::transport::ptcp::{PTCPBody, PTCPEvent, PTCPPayload, PTCPSession, PTCP};

fn log_fd_state(
    label: &str,
    channels: &Arc<Mutex<HashMap<u32, ClientChannel>>>,
    conn_channels: &Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
) {
    let (chan_len, conn_len) = {
        let chans = channels.lock().unwrap();
        let conns = conn_channels.lock().unwrap();
        (chans.len(), conns.len())
    };
    log_fd_snapshot(label, chan_len, conn_len);
}

#[derive(Clone)]
pub struct ClientChannel {
    buffer: Arc<tokio::sync::Mutex<VecDeque<Vec<u8>>>>,
    not_empty: Arc<tokio::sync::Notify>,
    space_available: Arc<tokio::sync::Notify>,
    /// Flag to mark the channel as closed, preventing further pushes
    closed: Arc<AtomicBool>,
}

impl ClientChannel {
    pub fn new() -> Self {
        ClientChannel {
            buffer: Arc::new(tokio::sync::Mutex::new(VecDeque::new())),
            not_empty: Arc::new(tokio::sync::Notify::new()),
            space_available: Arc::new(tokio::sync::Notify::new()),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Mark the channel as closed, preventing further pushes
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Wake up any blocked push() calls so they can see the closed flag
        self.space_available.notify_waiters();
    }

    /// Check if the channel is closed
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub async fn push(
        &self,
        data: Vec<u8>,
        capacity: usize,
        drop_policy: DropPolicy,
        realm: u32,
        health: &HealthCounters,
    ) {
        // Check if channel is closed before pushing
        if self.is_closed() {
            debug!("Realm {:08x}: push skipped - channel closed", realm);
            return;
        }

        loop {
            // Re-check closed flag on each iteration (for Block policy waits)
            if self.is_closed() {
                debug!("Realm {:08x}: push aborted - channel closed during wait", realm);
                return;
            }

            let mut buf = self.buffer.lock().await;
            if buf.len() < capacity {
                buf.push_back(data);
                self.not_empty.notify_one();
                return;
            }

            match drop_policy {
                DropPolicy::Block => {
                    // Release lock and wait for space to be available
                    // Use a timeout to prevent indefinite blocking if consumer dies
                    drop(buf);
                    const BLOCK_TIMEOUT_SECS: u64 = 5;
                    match tokio::time::timeout(
                        Duration::from_secs(BLOCK_TIMEOUT_SECS),
                        self.space_available.notified(),
                    )
                    .await
                    {
                        Ok(()) => {
                            // Got notification, retry push in next loop iteration
                            // The notification might be because channel was closed
                        }
                        Err(_) => {
                            warn!(
                                "Realm {:08x}: push blocked for {}s, dropping frame to prevent deadlock",
                                realm, BLOCK_TIMEOUT_SECS
                            );
                            health.drops_newest.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    }
                }
                DropPolicy::DropNewest => {
                    warn!(
                        "Realm {:08x} dropping newest frame due to full buffer (DropNewest)",
                        realm
                    );
                    health.drops_newest.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                DropPolicy::DropOldestKeepLatest => {
                    if let Some(_dropped) = buf.pop_front() {
                        warn!(
                            "Realm {:08x} dropped oldest frame to keep latest (DropOldestKeepLatest)",
                            realm
                        );
                        health.drops_oldest.fetch_add(1, Ordering::Relaxed);
                    }
                    buf.push_back(data);
                    self.not_empty.notify_one();
                    return;
                }
            }
        }
    }

    pub async fn recv(&self, shutdown: &mut watch::Receiver<ShutdownReason>) -> Option<Vec<u8>> {
        loop {
            {
                let mut buf = self.buffer.lock().await;
                if let Some(data) = buf.pop_front() {
                    // Notify potential producers waiting for space
                    self.space_available.notify_one();
                    return Some(data);
                }
                // If buffer is empty and channel is closed, no more data will arrive
                if self.is_closed() {
                    return None;
                }
            }

            tokio::select! {
                _ = self.not_empty.notified() => { /* retry loop */ }
                _ = shutdown.changed() => return None,
            }
        }
    }
}

/**
 * Read data from the channel and write it back to the client
 */
pub async fn process_writer(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    channel: ClientChannel,
    mut shutdown: watch::Receiver<ShutdownReason>,
) {
    loop {
        let data = match channel.recv(&mut shutdown).await {
            Some(d) => d,
            None => break,
        };

        if writer.write_all(&data).await.is_err() {
            warn!("Writer: Socket closed by peer.");
            break;
        }
    }
}

/**
 * Read data from the client and send it to the channel
 */
pub async fn process_reader(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    realm_id: u32,
    peer: SocketAddr,
    dh_tx: mpsc::Sender<PTCPEvent>,
    mut shutdown: watch::Receiver<ShutdownReason>,
) {
    let mut buf = [0u8; 4096];
    info!(
        "Reader started for realm {:08x} (client {})",
        realm_id, peer
    );
    let mut stop_reason = "shutdown";

    loop {
        let n = tokio::select! {
            res = reader.read(&mut buf) => {
                match res {
                    Ok(n) => {
                        if n == 0 {
                            warn!(
                                "Reader: socket closed by peer {} (realm {:08x})",
                                peer, realm_id
                            );
                            stop_reason = "peer_closed";
                            let _ = dh_tx.send(PTCPEvent::Disconnect(realm_id)).await;
                            break;
                        }
                        n
                    }
                    Err(e) => {
                        warn!(
                            "Reader error from {} (realm {:08x}): {}",
                            peer, realm_id, e
                        );
                        stop_reason = "read_error";
                        let _ = dh_tx.send(PTCPEvent::Disconnect(realm_id)).await;
                        break;
                    }
                }
            }
            _ = shutdown.changed() => {
                stop_reason = "shutdown_signal";
                break
            },
        };

        if dh_tx
            .send(PTCPEvent::Data(realm_id, buf[0..n].to_vec()))
            .await
            .is_err()
        {
            break;
        }
    }
    info!(
        "Reader stopped for realm {:08x} (client {}, reason={})",
        realm_id, peer, stop_reason
    );
}

/**
 * Read data from client and send it to devices
 */
pub async fn dh_writer(
    session: Arc<Mutex<PTCPSession>>,
    socket: Arc<UdpSocket>,
    mut dh_rx: mpsc::Receiver<PTCPEvent>,
    remote_port: u32,
    mut shutdown: watch::Receiver<ShutdownReason>,
    shutdown_tx: Arc<watch::Sender<ShutdownReason>>,
    channels: Arc<Mutex<HashMap<u32, ClientChannel>>>,
    conn_channels: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
    health: Arc<HealthCounters>,
) {
    loop {
        let ev = tokio::select! {
            ev = dh_rx.recv() => ev,
            _ = shutdown.changed() => None,
        };

        let Some(ev) = ev else { break };

        match ev {
            PTCPEvent::Heartbeat => {
                let p = session.lock().unwrap().send(PTCPBody::Heartbeat);
                if let Err(e) = socket.ptcp_request(p).await {
                    log::error!("PTCP heartbeat send error: {}", e);
                    if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        let _ = shutdown_tx.send(ShutdownReason::Restart);
                        break;
                    }
                }
            }
            PTCPEvent::Connect(realm) => {
                let p = session
                    .lock()
                    .unwrap()
                    .send(PTCPBody::Bind(realm, remote_port));
                info!(
                    "Realm {:08x}: sending PTCP bind (remote_port={})",
                    realm, remote_port
                );
                if let Err(e) = socket.ptcp_request(p).await {
                    log::error!(
                        "PTCP bind send error for realm {:08x}: {}",
                        realm,
                        e
                    );
                    if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        let _ = shutdown_tx.send(ShutdownReason::Restart);
                        break;
                    }
                }
            }
            PTCPEvent::Disconnect(realm) => {
                let p = session
                    .lock()
                    .unwrap()
                    .send(PTCPBody::Status(realm, "DISC".to_string()));
                if let Err(e) = socket.ptcp_request(p).await {
                    log::error!(
                        "PTCP disconnect send error for realm {:08x}: {}",
                        realm,
                        e
                    );
                    if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        let _ = shutdown_tx.send(ShutdownReason::Restart);
                        break;
                    }
                }
                // Close the channel BEFORE removing from map to prevent race condition
                // where dh_reader continues pushing to a channel that's being removed
                let removed_chan = {
                    let mut chans = channels.lock().unwrap();
                    if let Some(channel) = chans.get(&realm) {
                        channel.close();
                    }
                    chans.remove(&realm).is_some()
                };
                let removed_conn = conn_channels.lock().unwrap().remove(&realm).is_some();
                let remaining = channels.lock().unwrap().len();
                info!(
                    "Realm {:08x} client disconnect cleanup: channel_removed={}, conn_removed={}, remaining_realms={}",
                    realm, removed_chan, removed_conn, remaining
                );
                log_fd_state("dh_writer disconnect", &channels, &conn_channels);
            }
            PTCPEvent::Data(realm, data) => {
                health.bytes_to_device.fetch_add(data.len() as u64, Ordering::Relaxed);
                health.packets_to_device.fetch_add(1, Ordering::Relaxed);
                let p = session
                    .lock()
                    .unwrap()
                    .send(PTCPBody::Payload(PTCPPayload { realm, data }));
                if let Err(e) = socket.ptcp_request(p).await {
                    log::error!(
                        "PTCP payload send error for realm {:08x}: {}",
                        realm,
                        e
                    );
                    if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        let _ = shutdown_tx.send(ShutdownReason::Restart);
                        break;
                    }
                }
            }
        }
    }
}

/// Send packets to their respective client channels
async fn send_to_clients(
    packets: Vec<(u32, Vec<u8>)>,
    channels: &Arc<Mutex<HashMap<u32, ClientChannel>>>,
    drop_policy: DropPolicy,
    capacity: usize,
    health: &Arc<HealthCounters>,
) {
    for (realm, data) in packets {
        let tx = {
            let chans = channels.lock().unwrap();
            chans.get(&realm).cloned()
        };
        if let Some(tx) = tx {
            tx.push(data, capacity, drop_policy.clone(), realm, health)
                .await;
        }
    }
}

fn update_max(atomic: &AtomicU64, value: u64) {
    let mut current = atomic.load(Ordering::Relaxed);
    while value > current {
        match atomic.compare_exchange(
            current,
            value,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(v) => current = v,
        }
    }
}

#[derive(Default)]
pub struct HealthCounters {
    pub bytes_from_device: AtomicU64,
    pub bytes_to_device: AtomicU64,
    pub packets_from_device: AtomicU64,
    pub packets_to_device: AtomicU64,
    pub drops_newest: AtomicU64,
    pub drops_oldest: AtomicU64,
    pub jitter_enabled: AtomicBool,
    pub jitter_in_packets: AtomicU64,
    pub jitter_in_bytes: AtomicU64,
    pub jitter_out_packets: AtomicU64,
    pub jitter_out_bytes: AtomicU64,
    pub jitter_late_drops: AtomicU64,
    pub jitter_max_depth: AtomicU64,
}

/**
 * Read data from devices and send it to clients
 */
pub async fn dh_reader(
    session: Arc<Mutex<PTCPSession>>,
    socket: Arc<UdpSocket>,
    channels: Arc<Mutex<HashMap<u32, ClientChannel>>>,
    conn_channels: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
    mut shutdown: watch::Receiver<ShutdownReason>,
    shutdown_tx: Arc<watch::Sender<ShutdownReason>>,
    last_activity: Arc<Mutex<std::time::Instant>>,
    drop_policy: DropPolicy,
    buffer_ms: u64,
    channel_capacity: usize,
    health: Arc<HealthCounters>,
    heartbeat_ok: Option<Arc<AtomicBool>>,
) {
    // Create jitter buffer if enabled
    let mut jitter_buffer = if buffer_ms > 0 {
        let jb = JitterBuffer::new(Duration::from_millis(buffer_ms));
        health.jitter_enabled.store(true, Ordering::Relaxed);
        Some(jb)
    } else {
        None
    };
    let mut last_late_dropped: u64 = 0;

    // Create a tick interval for the buffer (runs every 10ms)
    let mut tick_interval = tokio::time::interval(Duration::from_millis(10));
    tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // Handle incoming packets
            result = socket.ptcp_read() => {
                let packet = match result {
                    Ok(p) => p,
                    Err(e) => {
                        // Handle read errors
                        if e.is_fatal() {
                            warn!("PTCP fatal read error: {}, triggering restart", e);
                            let _ = shutdown_tx.send(ShutdownReason::Restart);
                            break;
                        }
                        // Non-fatal errors (malformed packets) - log and continue
                        // Don't update session state for malformed packets
                        debug!("PTCP non-fatal read error: {}, continuing", e);
                        continue;
                    }
                };

                let seq = packet.sent;
                let packet = session.lock().unwrap().recv(packet);
                {
                    let mut last = last_activity.lock().unwrap();
                    *last = std::time::Instant::now();
                }
                if let Some(flag) = &heartbeat_ok {
                    flag.store(true, Ordering::Relaxed);
                }

                // Handle empty packets
                if let PTCPBody::Empty = packet.body {
                    continue;
                }

                // Send ACK
                let p = session.lock().unwrap().send(PTCPBody::Empty);
                if let Err(e) = socket.ptcp_request(p).await {
                    log::error!("PTCP ack send error: {}", e);
                    if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        let _ = shutdown_tx.send(ShutdownReason::Restart);
                        break;
                    }
                }

                match packet.body {
                    PTCPBody::Status(realm, status) => {
                        if status == "CONN" {
                            info!("Realm {:08x} streaming ready; notifying waiter", realm);
                            if let Some(sender) = conn_channels.lock().unwrap().remove(&realm) {
                                let _ = sender.send(true);
                            } else {
                                warn!("Realm {:08x} ready but no waiter found", realm);
                            }
                            log_fd_state("dh_reader conn ready", &channels, &conn_channels);
                        } else if status == "DISC" || status.starts_with("DISC") {
                            // Close channel before removing to prevent race condition
                            let removed = {
                                let mut chans = channels.lock().unwrap();
                                if let Some(channel) = chans.get(&realm) {
                                    channel.close();
                                }
                                chans.remove(&realm)
                            };
                            if removed.is_some() {
                                warn!(
                                    "Realm {:08x} device sent DISC; removing client channel",
                                    realm
                                );
                                log_fd_state("dh_reader device disc", &channels, &conn_channels);
                            } else {
                                debug!("Realm {:08x} device sent DISC (already removed)", realm);
                            }
                        } else {
                            info!("Realm {:08x} status: {}", realm, status);
                        }
                    }
                    PTCPBody::Payload(payload) => {
                        let payload_len = payload.data.len() as u64;
                        if jitter_buffer.is_some() {
                            health
                                .jitter_in_packets
                                .fetch_add(1, Ordering::Relaxed);
                            health.jitter_in_bytes.fetch_add(payload_len, Ordering::Relaxed);
                        }
                        health.bytes_from_device.fetch_add(
                            payload.data.len() as u64,
                            Ordering::Relaxed,
                        );
                        health.packets_from_device.fetch_add(1, Ordering::Relaxed);
                        if let Some(ref mut buffer) = jitter_buffer {
                            // Insert and get ready packets
                            let ready = buffer.insert(seq, payload.realm, payload.data);
                            let late_now = buffer.late_dropped();
                            let late_delta = late_now.saturating_sub(last_late_dropped);
                            if late_delta > 0 {
                                health
                                    .jitter_late_drops
                                    .fetch_add(late_delta, Ordering::Relaxed);
                                last_late_dropped = late_now;
                            }
                            let depth = buffer.buffered_len() as u64;
                            update_max(&health.jitter_max_depth, depth);
                            if !ready.is_empty() {
                                let ready_bytes: u64 =
                                    ready.iter().map(|(_, d)| d.len() as u64).sum();
                                health
                                    .jitter_out_packets
                                    .fetch_add(ready.len() as u64, Ordering::Relaxed);
                                health
                                    .jitter_out_bytes
                                    .fetch_add(ready_bytes, Ordering::Relaxed);
                                send_to_clients(
                                    ready,
                                    &channels,
                                    drop_policy.clone(),
                                    channel_capacity,
                                    &health,
                                )
                                .await;
                            }
                        } else {
                            // No buffering - send directly
                            let packets = vec![(payload.realm, payload.data)];
                            send_to_clients(
                                packets,
                                &channels,
                                drop_policy.clone(),
                                channel_capacity,
                                &health,
                            )
                            .await;
                        }
                    }
                    _ => {}
                }
            }

            // Periodic tick to flush the buffer
            _ = tick_interval.tick(), if jitter_buffer.is_some() => {
                if let Some(ref mut buffer) = jitter_buffer {
                    let ready = buffer.tick();
                    if !ready.is_empty() {
                        let ready_bytes: u64 =
                            ready.iter().map(|(_, d)| d.len() as u64).sum();
                        health
                            .jitter_out_packets
                            .fetch_add(ready.len() as u64, Ordering::Relaxed);
                        health
                            .jitter_out_bytes
                            .fetch_add(ready_bytes, Ordering::Relaxed);
                        send_to_clients(
                            ready,
                            &channels,
                            drop_policy.clone(),
                            channel_capacity,
                            &health,
                        )
                        .await;
                    }
                }
            }

            // Shutdown
            _ = shutdown.changed() => {
                if let Some(ref mut buffer) = jitter_buffer {
                    let remaining = buffer.flush_all();
                    let remaining_bytes: u64 =
                        remaining.iter().map(|(_, d)| d.len() as u64).sum();
                    health
                        .jitter_out_packets
                        .fetch_add(remaining.len() as u64, Ordering::Relaxed);
                    health
                        .jitter_out_bytes
                        .fetch_add(remaining_bytes, Ordering::Relaxed);
                    send_to_clients(
                        remaining,
                        &channels,
                        drop_policy.clone(),
                        channel_capacity,
                        &health,
                    )
                    .await;
                    buffer.log_stats();
                }
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::watch;

    #[tokio::test]
    async fn drop_policy_drop_newest_drops_when_full() {
        let channels = Arc::new(Mutex::new(HashMap::new()));
        let channel = ClientChannel::new();
        channels.lock().unwrap().insert(1, channel.clone());
        let health = Arc::new(HealthCounters::default());

        // Fill the channel
        send_to_clients(
            vec![(1, b"a".to_vec())],
            &channels,
            DropPolicy::DropNewest,
            1,
            &health,
        )
        .await;
        // Second send should drop
        send_to_clients(
            vec![(1, b"b".to_vec())],
            &channels,
            DropPolicy::DropNewest,
            1,
            &health,
        )
        .await;

        let (shutdown_tx, mut shutdown_rx) = watch::channel::<ShutdownReason>(ShutdownReason::Stop);
        let first = channel.recv(&mut shutdown_rx).await.unwrap();
        assert_eq!(first, b"a");
        // Trigger shutdown so the second recv unblocks and returns None
        let _ = shutdown_tx.send(ShutdownReason::Restart);
        assert!(matches!(channel.recv(&mut shutdown_rx).await, None));
    }

    #[tokio::test]
    async fn drop_policy_drop_oldest_keep_latest_keeps_newest() {
        let channel = ClientChannel::new();
        let health = Arc::new(HealthCounters::default());

        channel
            .push(
                b"a".to_vec(),
                1,
                DropPolicy::DropOldestKeepLatest,
                1,
                &health,
            )
            .await;
        channel
            .push(
                b"b".to_vec(),
                1,
                DropPolicy::DropOldestKeepLatest,
                1,
                &health,
            )
            .await;

        let (shutdown_tx, mut shutdown_rx) = watch::channel::<ShutdownReason>(ShutdownReason::Stop);
        let first = channel.recv(&mut shutdown_rx).await.unwrap();
        assert_eq!(first, b"b");
        let _ = shutdown_tx.send(ShutdownReason::Restart);
    }

    #[tokio::test]
    async fn drop_policy_block_waits_until_space_available() {
        let channel = ClientChannel::new();
        let health = Arc::new(HealthCounters::default());

        channel
            .push(b"a".to_vec(), 1, DropPolicy::Block, 1, &health)
            .await;

        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let channel_block = channel.clone();
        let health_block = health.clone();
        tokio::spawn(async move {
            channel_block
                .push(b"b".to_vec(), 1, DropPolicy::Block, 1, &*health_block)
                .await;
            let _ = done_tx.send(());
        });

        // Should not complete while buffer is full
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut done_rx)
                .await
                .is_err()
        );

        let (shutdown_tx, mut shutdown_rx) =
            watch::channel::<ShutdownReason>(ShutdownReason::Stop);
        let first = channel.recv(&mut shutdown_rx).await.unwrap();
        assert_eq!(first, b"a");

        // Now the second push can complete
        tokio::time::timeout(Duration::from_millis(200), &mut done_rx)
            .await
            .expect("push should complete after space frees")
            .expect("push task join failed");

        let second = channel.recv(&mut shutdown_rx).await.unwrap();
        assert_eq!(second, b"b");
        let _ = shutdown_tx.send(ShutdownReason::Restart);
    }

    #[tokio::test]
    async fn channel_close_prevents_push() {
        let channel = ClientChannel::new();
        let health = Arc::new(HealthCounters::default());

        // Push initial data
        channel
            .push(b"a".to_vec(), 10, DropPolicy::DropNewest, 1, &health)
            .await;
        
        // Close the channel
        channel.close();
        assert!(channel.is_closed());

        // Push after close should be silently ignored
        channel
            .push(b"b".to_vec(), 10, DropPolicy::DropNewest, 1, &health)
            .await;

        let (_, mut shutdown_rx) = watch::channel::<ShutdownReason>(ShutdownReason::Stop);
        // Should only receive the first message
        let first = channel.recv(&mut shutdown_rx).await.unwrap();
        assert_eq!(first, b"a");
        // Channel is closed and buffer is empty, recv should return None
        assert!(channel.recv(&mut shutdown_rx).await.is_none());
    }

    #[tokio::test]
    async fn channel_close_unblocks_blocked_push() {
        let channel = ClientChannel::new();
        let health = Arc::new(HealthCounters::default());

        // Fill the buffer to capacity=1
        channel
            .push(b"a".to_vec(), 1, DropPolicy::Block, 1, &health)
            .await;

        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let channel_block = channel.clone();
        let health_block = health.clone();
        tokio::spawn(async move {
            channel_block
                .push(b"b".to_vec(), 1, DropPolicy::Block, 1, &*health_block)
                .await;
            let _ = done_tx.send(());
        });

        // Wait a bit for the push to block
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify push is blocked
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut done_rx)
                .await
                .is_err()
        );

        // Close the channel - should unblock the push
        channel.close();

        // Now the push should complete (aborted due to closed channel)
        tokio::time::timeout(Duration::from_millis(200), &mut done_rx)
            .await
            .expect("push should complete after close")
            .expect("push task join failed");
    }

    #[tokio::test]
    async fn channel_close_recv_returns_none_when_empty() {
        let channel = ClientChannel::new();
        let (_, mut shutdown_rx) = watch::channel::<ShutdownReason>(ShutdownReason::Stop);

        // Close the channel immediately (no data pushed)
        channel.close();

        // recv should return None immediately since buffer is empty and closed
        let result = channel.recv(&mut shutdown_rx).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn channel_close_drains_existing_data() {
        let channel = ClientChannel::new();
        let health = Arc::new(HealthCounters::default());
        let (_, mut shutdown_rx) = watch::channel::<ShutdownReason>(ShutdownReason::Stop);

        // Push some data
        channel
            .push(b"a".to_vec(), 10, DropPolicy::DropNewest, 1, &health)
            .await;
        channel
            .push(b"b".to_vec(), 10, DropPolicy::DropNewest, 1, &health)
            .await;

        // Close the channel
        channel.close();

        // Should still be able to drain existing data
        let first = channel.recv(&mut shutdown_rx).await.unwrap();
        assert_eq!(first, b"a");
        let second = channel.recv(&mut shutdown_rx).await.unwrap();
        assert_eq!(second, b"b");
        // Now buffer is empty and closed, should return None
        assert!(channel.recv(&mut shutdown_rx).await.is_none());
    }
}
