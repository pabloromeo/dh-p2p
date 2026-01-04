use clap::Parser;
use log::{debug, info, warn};
use rand::Rng;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
#[cfg(unix)]
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use tokio::{
    net::{TcpListener, UdpSocket},
    signal,
    sync::{mpsc, oneshot, watch},
};

use crate::{
    dh::p2p_handshake,
    fdlog::log_fd_snapshot,
    process::{dh_reader, dh_writer, process_reader, process_writer},
    ptcp::PTCPEvent,
    shutdown::ShutdownReason,
};

mod buffer;
mod dh;
mod fdlog;
mod process;
mod ptcp;
mod shutdown;

const HEARTBEAT_INTERVAL_SECS: u64 = 5;
const HEARTBEAT_MISSED_LIMIT: u64 = 2;
const HEARTBEAT_TIMEOUT_SECS: u64 = HEARTBEAT_INTERVAL_SECS * HEARTBEAT_MISSED_LIMIT + 2; // small grace
const RESTART_BACKOFF_INITIAL_SECS: u64 = 1;
const RESTART_BACKOFF_MAX_SECS: u64 = 30;
const RESTART_BACKOFF_JITTER_MS: u64 = 500;
const HANDSHAKE_TIMEOUT_SECS: u64 = 15;

#[derive(Parser)]
#[command(about = "A PoC implementation of TCP tunneling over Dahua P2P protocol.", long_about = None)]
struct Cli {
    /// Bind address, port and remote port. Default: 127.0.0.1:1554:554
    #[arg(short, long, value_name = "[bind_address:]port:remote_port")]
    port: Option<String>,
    /// Relay mode (experimental)
    #[arg(short, long)]
    relay: bool,
    /// Jitter buffer duration in milliseconds (0 to disable). Default: 0
    #[arg(short = 'b', long, value_name = "ms", default_value = "0")]
    buffer_ms: u64,
    /// Increase verbosity (-v for debug, -vv for trace)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Serial number of the camera
    serial: String,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    // Initialize logger based on verbosity level
    let log_level = match args.verbose {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    env_logger::Builder::new()
        .filter_level(log_level)
        .format_target(false)
        .format_timestamp_secs()
        .init();

    debug!("Log level set to {:?}", log_level);

    let serial = args.serial;
    let port = args.port.unwrap_or("127.0.0.1:1554:554".to_string());

    let parts: Vec<&str> = port.split(':').collect();
    let (bind_address, bind_port, remote_port): (&str, u16, u16) = match parts.len() {
        2 => (
            "127.0.0.1",
            parts[0].parse().unwrap(),
            parts[1].parse().unwrap(),
        ),
        3 => (
            parts[0],
            parts[1].parse().unwrap(),
            parts[2].parse().unwrap(),
        ),
        _ => panic!("Invalid port specification"),
    };

    let mut iteration: u64 = 0;
    let mut backoff_secs: u64 = RESTART_BACKOFF_INITIAL_SECS;
    loop {
        iteration += 1;
        info!("Starting server iteration {}", iteration);
        let reason = run_server_once(
            bind_address.to_string(),
            bind_port,
            remote_port,
            serial.clone(),
            args.relay,
            args.buffer_ms,
        )
        .await;

        match reason {
            ShutdownReason::Stop => {
                info!("Shutdown reason: Stop (iteration {})", iteration);
                break;
            }
            ShutdownReason::Restart => {
                warn!(
                    "Shutdown reason: Restart requested, re-handshaking... (iteration {}), backoff {}s",
                    iteration, backoff_secs
                );
                let jitter_ms = rand::thread_rng().gen_range(0..=RESTART_BACKOFF_JITTER_MS);
                let sleep_dur =
                    Duration::from_secs(backoff_secs) + Duration::from_millis(jitter_ms);
                tokio::time::sleep(sleep_dur).await;
                backoff_secs = (backoff_secs.saturating_mul(2)).min(RESTART_BACKOFF_MAX_SECS);
            }
        }
    }
}

async fn run_server_once(
    bind_address: String,
    bind_port: u16,
    remote_port: u16,
    serial: String,
    relay: bool,
    buffer_ms: u64,
) -> ShutdownReason {
    // Bind the listener to the address
    let listener = TcpListener::bind(format!("{}:{}", bind_address, bind_port))
        .await
        .unwrap();

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to bind UDP socket: {}", e);
            return ShutdownReason::Restart;
        }
    };

    let handshake = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        p2p_handshake(socket, serial, relay),
    )
    .await;

    let (socket, session) = match handshake {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => {
            warn!("P2P handshake failed: {}", e);
            return ShutdownReason::Restart;
        }
        Err(_) => {
            warn!(
                "P2P handshake timed out after {}s",
                HANDSHAKE_TIMEOUT_SECS
            );
            return ShutdownReason::Restart;
        }
    };

    let (dh_tx, dh_rx) = mpsc::channel::<PTCPEvent>(128);
    let (shutdown_tx, shutdown_rx) = watch::channel::<ShutdownReason>(ShutdownReason::Stop);
    let shutdown_tx = Arc::new(shutdown_tx);
    let session = Arc::new(Mutex::new(session));
    let last_activity = Arc::new(Mutex::new(Instant::now()));

    let channels = Arc::new(Mutex::new(HashMap::<u32, mpsc::Sender<Vec<u8>>>::new()));
    let conn_channels = Arc::new(Mutex::new(HashMap::<u32, oneshot::Sender<bool>>::new()));

    info!("PTCP session established");

    /*
     * Clone the handles
     */

    let reader = Arc::new(socket);
    let writer = reader.clone();

    let session2 = session.clone();
    let channels2 = channels.clone();
    let conn_channels2 = conn_channels.clone();

    let shutdown_notify = shutdown_tx.clone();
    let shutdown_handle = tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        let _ = shutdown_notify.send(ShutdownReason::Stop);
    });

    // Periodic FD and channel usage logging
    let mut fd_monitor_shutdown = shutdown_rx.clone();
    let fd_monitor_channels = channels2.clone();
    let fd_monitor_conn_channels = conn_channels2.clone();
    let fd_monitor_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let (chan_len, conn_len) = {
                        let chans = fd_monitor_channels.lock().unwrap();
                        let conns = fd_monitor_conn_channels.lock().unwrap();
                        (chans.len(), conns.len())
                    };
                    log_fd_snapshot("periodic", chan_len, conn_len);
                }
                _ = fd_monitor_shutdown.changed() => {
                    let (chan_len, conn_len) = {
                        let chans = fd_monitor_channels.lock().unwrap();
                        let conns = fd_monitor_conn_channels.lock().unwrap();
                        (chans.len(), conns.len())
                    };
                    log_fd_snapshot("shutdown", chan_len, conn_len);
                    break;
                }
            }
        }
    });

    let mut hb_shutdown = shutdown_rx.clone();
    let hb_tx = dh_tx.clone();
    let heartbeat_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(HEARTBEAT_INTERVAL_SECS)) => {
                    if hb_tx.send(PTCPEvent::Heartbeat).await.is_err() {
                        break;
                    }
                }
                _ = hb_shutdown.changed() => {
                    break;
                }
            }
        }
    });

    let writer_shutdown = shutdown_rx.clone();
    let writer_channels = Arc::clone(&channels2);
    let writer_conn_channels = Arc::clone(&conn_channels2);
    let shutdown_tx_writer = shutdown_tx.clone();
    let writer_handle = tokio::spawn(async move {
        dh_writer(
            session,
            writer,
            dh_rx,
            remote_port.into(),
            writer_shutdown,
            shutdown_tx_writer,
            writer_channels,
            writer_conn_channels,
        )
        .await;
    });

    let reader_shutdown = shutdown_rx.clone();
    let shutdown_tx_reader = shutdown_tx.clone();
    let last_activity_reader = last_activity.clone();
    let reader_handle = tokio::spawn(async move {
        dh_reader(
            session2,
            reader,
            channels,
            conn_channels,
            reader_shutdown,
            shutdown_tx_reader,
            last_activity_reader,
            buffer_ms,
        )
        .await;
    });

    // Watchdog for heartbeat / inactivity
    let mut watchdog_shutdown = shutdown_rx.clone();
    let shutdown_tx_watchdog = shutdown_tx.clone();
    let last_activity_watchdog = last_activity.clone();
    let watchdog_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let last = *last_activity_watchdog.lock().unwrap();
                    let timeout = Duration::from_secs(HEARTBEAT_TIMEOUT_SECS);
                    if last.elapsed() >= timeout {
                        warn!("No PTCP activity for {:?}, requesting restart", timeout);
                        let _ = shutdown_tx_watchdog.send(ShutdownReason::Restart);
                        break;
                    }
                }
                _ = watchdog_shutdown.changed() => break,
            }
        }
    });

    info!("Ready to connect!");
    if remote_port == 554 {
        info!(
            "RTSP URL: rtsp://127.0.0.1{}/cam/realmonitor?channel=1&subtype=0",
            if bind_port != 554 {
                format!(":{}", bind_port)
            } else {
                String::new()
            }
        );
    }

    let mut shutdown_accept = shutdown_rx.clone();
    let shutdown_reason;
    loop {
        // The second item contains the IP and port of the new connection.
        let accept = tokio::select! {
            res = listener.accept() => res,
            _ = shutdown_accept.changed() => {
                info!("Shutdown requested, stopping listener");
                break;
            }
        };

        let (client, addr) = match accept {
            Ok(pair) => pair,
            Err(e) => {
                info!("Listener stopped: {}", e);
                break;
            }
        };
        info!("Accepted connection from {} (new client)", addr);

        // Create a channel for the client
        let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
        let (conn_tx, conn_rx) = oneshot::channel::<bool>();
        let dh_tx = dh_tx.clone();
        let mut shutdown_conn = shutdown_rx.clone();

        let realm_id = rand::random::<u32>();
        info!(
            "Client {} assigned realm {:08x}; enqueuing PTCP Connect",
            addr, realm_id
        );

        // Store the channel in the map
        channels2.lock().unwrap().insert(realm_id, tx);
        conn_channels2.lock().unwrap().insert(realm_id, conn_tx);
        {
            let chans = channels2.lock().unwrap();
            let conns = conn_channels2.lock().unwrap();
            log_fd_snapshot("after accept", chans.len(), conns.len());
        }

        if dh_tx.send(PTCPEvent::Connect(realm_id)).await.is_err() {
            warn!("Failed to enqueue connect event for realm {:08x}", realm_id);
            continue;
        }

        info!(
            "Waiting for realm {:08x} to become ready (client {})",
            realm_id, addr
        );
        tokio::select! {
            res = conn_rx => {
                if res.is_err() {
                    warn!("Realm {:08x} connection handshake failed", realm_id);
                    continue;
                }
                info!(
                    "Realm {:08x} ready; starting reader/writer tasks for client {}",
                    realm_id, addr
                );
            }
            _ = shutdown_conn.changed() => {
                info!(
                    "Shutdown before realm {:08x} became ready (client {})",
                    realm_id, addr
                );
                // Remove partially registered realm before continuing
                channels2.lock().unwrap().remove(&realm_id);
                conn_channels2.lock().unwrap().remove(&realm_id);
                continue;
            }
        }

        let (reader, writer) = client.into_split();

        tokio::spawn({
            let shutdown_rx = shutdown_rx.clone();
            let peer = addr;
            async move {
                process_reader(reader, realm_id, peer, dh_tx, shutdown_rx).await;
            }
        });

        tokio::spawn({
            let shutdown_rx = shutdown_rx.clone();
            async move {
                process_writer(writer, rx, shutdown_rx).await;
            }
        });
    }

    // If we exited the accept loop without observing the latest reason, read it now.
    shutdown_reason = *shutdown_rx.borrow();

    info!("Sending PTCP disconnect to active realms");
    let realms: Vec<u32> = channels2.lock().unwrap().keys().copied().collect();
    for realm in realms {
        if dh_tx.send(PTCPEvent::Disconnect(realm)).await.is_err() {
            warn!("Failed to enqueue disconnect for realm {:08x}", realm);
        }
    }

    channels2.lock().unwrap().clear();
    conn_channels2.lock().unwrap().clear();
    drop(dh_tx);

    let _ = heartbeat_handle.await;
    let _ = writer_handle.await;
    let _ = reader_handle.await;
    let _ = fd_monitor_handle.await;
    let _ = watchdog_handle.await;

    if shutdown_reason == ShutdownReason::Restart {
        shutdown_handle.abort();
    } else {
        let _ = shutdown_handle.await;
    }

    info!("run_server_once completed with reason {:?}", shutdown_reason);
    shutdown_reason
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term_stream =
            unix_signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
        tokio::select! {
            _ = signal::ctrl_c() => info!("Received Ctrl+C"),
            _ = term_stream.recv() => info!("Received SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        info!("Received Ctrl+C");
    }
}
