use clap::Parser;
use log::{debug, info, warn};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use axum::{extract::State, http::StatusCode, routing::get, serve, Router};
#[cfg(unix)]
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use tokio::{
    net::{TcpListener, UdpSocket},
    signal,
    sync::{mpsc, oneshot, watch},
};

use crate::{
    config::{Config, DropPolicy},
    fdlog::log_fd_snapshot,
    metrics::{InMemoryMetrics, MetricsHandle},
    process::{
        dh_reader, dh_writer, process_reader, process_writer, ClientChannel, HealthCounters,
    },
    shutdown::ShutdownReason,
    transport::{handshake::p2p_handshake, ptcp::PTCPEvent},
};

mod buffer;
mod config;
mod fdlog;
mod metrics;
mod process;
mod shutdown;
mod supervisor;
mod transport;

#[derive(Clone, Default)]
struct ProbeState {
    handshake_ready: Arc<AtomicBool>,
    heartbeat_ok: Arc<AtomicBool>,
}

impl ProbeState {
    fn is_ready(&self) -> bool {
        self.handshake_ready.load(Ordering::Relaxed) && self.heartbeat_ok.load(Ordering::Relaxed)
    }
}

async fn live_handler() -> StatusCode {
    StatusCode::OK
}

async fn ready_handler(State(state): State<ProbeState>) -> StatusCode {
    if state.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

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
    /// Drop policy for slow clients: block|drop_newest|keep_latest
    #[arg(long, value_name = "policy", default_value = "block")]
    drop_policy: String,
    /// Health log interval in seconds
    #[arg(long, value_name = "secs", default_value = "60")]
    health_interval_secs: u64,
    /// Enable HTTP probe server (/livez, /readyz)
    #[arg(long, default_value_t = false)]
    enable_probe: bool,
    /// HTTP probe listen port
    #[arg(long, value_name = "port", default_value = "8080")]
    probe_port: u16,
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
    let mut config = Config::default();
    config.jitter_buffer_ms = args.buffer_ms;
    config.health_interval_secs = args.health_interval_secs;
    config.enable_probe = args.enable_probe;
    config.probe_port = args.probe_port;
    config.drop_policy = match args.drop_policy.as_str() {
        "block" => DropPolicy::Block,
        "drop_newest" => DropPolicy::DropNewest,
        "keep_latest" => DropPolicy::DropOldestKeepLatest,
        other => panic!("Invalid drop_policy: {}", other),
    };
    let config = Arc::new(config);
    let metrics: MetricsHandle = Arc::new(InMemoryMetrics::default());

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

    supervisor::run_loop(
        bind_address.to_string(),
        bind_port,
        remote_port,
        serial,
        args.relay,
        args.buffer_ms,
        config.clone(),
        metrics.clone(),
        |bind_address,
         bind_port,
         remote_port,
         serial,
         relay,
         buffer_ms,
         config,
         metrics,
         shutdown_tx,
         shutdown_rx| async move {
            run_server_once(
                bind_address,
                bind_port,
                remote_port,
                serial,
                relay,
                buffer_ms,
                config,
                metrics,
                shutdown_tx,
                shutdown_rx,
            )
            .await
        },
    )
    .await;
}

async fn run_server_once(
    bind_address: String,
    bind_port: u16,
    remote_port: u16,
    serial: String,
    relay: bool,
    buffer_ms: u64,
    config: Arc<Config>,
    metrics: MetricsHandle,
    shutdown_tx_external: Arc<watch::Sender<ShutdownReason>>,
    shutdown_rx_external: watch::Receiver<ShutdownReason>,
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
        Duration::from_secs(config.handshake_timeout_secs),
        p2p_handshake(socket, serial.clone(), relay),
    )
    .await;

    let (socket, session) = match handshake {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => {
            warn!("P2P handshake failed: {}", e);
            metrics.inc_counter("handshake_fail");
            return ShutdownReason::Restart;
        }
        Err(_) => {
            warn!(
                "P2P handshake timed out after {}s",
                config.handshake_timeout_secs
            );
            metrics.inc_counter("handshake_timeout");
            return ShutdownReason::Restart;
        }
    };

    let (dh_tx, dh_rx) = mpsc::channel::<PTCPEvent>(config.channel_capacity);
    let shutdown_tx = shutdown_tx_external.clone();
    let shutdown_rx = shutdown_rx_external;
    let session = Arc::new(Mutex::new(session));
    let last_activity = Arc::new(Mutex::new(Instant::now()));
    let health = Arc::new(HealthCounters::default());
    let probe_state = ProbeState::default();
    let probe_state_opt = if config.enable_probe {
        Some(probe_state.clone())
    } else {
        None
    };

    let channels = Arc::new(Mutex::new(HashMap::<u32, ClientChannel>::new()));
    let conn_channels = Arc::new(Mutex::new(HashMap::<u32, oneshot::Sender<bool>>::new()));

    info!(
        "PTCP session established (serial={}, relay={}, remote_port={})",
        serial, relay, remote_port
    );
    if let Some(state) = probe_state_opt.as_ref() {
        state.handshake_ready.store(true, Ordering::Relaxed);
        state.heartbeat_ok.store(true, Ordering::Relaxed);
    }
    metrics.inc_counter("handshake_success");

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
    let hb_config = config.clone();
    let heartbeat_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(hb_config.heartbeat_interval_secs)) => {
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
    let health_writer = health.clone();
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
            health_writer,
        )
        .await;
    });

    let reader_shutdown = shutdown_rx.clone();
    let shutdown_tx_reader = shutdown_tx.clone();
    let last_activity_reader = last_activity.clone();
    let drop_policy = config.drop_policy.clone();
    let channel_capacity = config.channel_capacity;
    let health_reader = health.clone();
    let heartbeat_ok_flag = if config.enable_probe {
        Some(probe_state.heartbeat_ok.clone())
    } else {
        None
    };
    let reader_handle = tokio::spawn(async move {
        dh_reader(
            session2,
            reader,
            channels,
            conn_channels,
            reader_shutdown,
            shutdown_tx_reader,
            last_activity_reader,
            drop_policy,
            buffer_ms,
            channel_capacity,
            health_reader,
            heartbeat_ok_flag,
        )
        .await;
    });

    // Watchdog for heartbeat / inactivity
    let mut watchdog_shutdown = shutdown_rx.clone();
    let shutdown_tx_watchdog = shutdown_tx.clone();
    let last_activity_watchdog = last_activity.clone();
    let watchdog_config = config.clone();
    let heartbeat_flag = if config.enable_probe {
        Some(probe_state.heartbeat_ok.clone())
    } else {
        None
    };
    let watchdog_handle = tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(watchdog_config.heartbeat_interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let last = *last_activity_watchdog.lock().unwrap();
                    let timeout = Duration::from_secs(
                        watchdog_config.heartbeat_interval_secs * watchdog_config.heartbeat_missed_limit
                            + watchdog_config.heartbeat_timeout_grace_secs,
                    );
                    if last.elapsed() >= timeout {
                        warn!("No PTCP activity for {:?}, requesting restart", timeout);
                        if let Some(flag) = &heartbeat_flag {
                            flag.store(false, Ordering::Relaxed);
                        }
                        let _ = shutdown_tx_watchdog.send(ShutdownReason::Restart);
                        break;
                    }
                }
                _ = watchdog_shutdown.changed() => break,
            }
        }
    });

    // Periodic health snapshot (info-level)
    let mut health_shutdown = shutdown_rx.clone();
    let health_channels = channels2.clone();
    let health_conn_channels = conn_channels2.clone();
    let health_counters = health.clone();
    let health_interval_secs = config.health_interval_secs;
    let health_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(health_interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let realms = health_channels.lock().unwrap().len();
                    let waiters = health_conn_channels.lock().unwrap().len();
                    let bytes_in = health_counters.bytes_from_device.swap(0, Ordering::Relaxed);
                    let bytes_out = health_counters.bytes_to_device.swap(0, Ordering::Relaxed);
                    let pkts_in = health_counters.packets_from_device.swap(0, Ordering::Relaxed);
                    let pkts_out = health_counters.packets_to_device.swap(0, Ordering::Relaxed);
                    let drops_newest = health_counters.drops_newest.swap(0, Ordering::Relaxed);
                    let drops_oldest = health_counters.drops_oldest.swap(0, Ordering::Relaxed);
                    let interval = health_interval_secs as u64;
                    let in_bps = bytes_in / interval;
                    let out_bps = bytes_out / interval;
                    let jitter_in_pkts = health_counters
                        .jitter_in_packets
                        .swap(0, Ordering::Relaxed);
                    let jitter_out_pkts = health_counters
                        .jitter_out_packets
                        .swap(0, Ordering::Relaxed);
                    let jitter_in_bytes =
                        health_counters.jitter_in_bytes.swap(0, Ordering::Relaxed);
                    let jitter_out_bytes =
                        health_counters.jitter_out_bytes.swap(0, Ordering::Relaxed);
                    let jitter_late_drops =
                        health_counters.jitter_late_drops.swap(0, Ordering::Relaxed);
                    let jitter_max_depth =
                        health_counters.jitter_max_depth.swap(0, Ordering::Relaxed);
                    info!(
                        "Health realms={} waiters={} bytes_in={} bytes_out={} in_Bps={} out_Bps={} pkts_in={} pkts_out={} drops_newest={} drops_oldest={} jitter_on={} jitter_in_pkts={} jitter_out_pkts={} jitter_in_bytes={} jitter_out_bytes={} jitter_late_drops={} jitter_max_depth={}",
                        realms,
                        waiters,
                        bytes_in,
                        bytes_out,
                        in_bps,
                        out_bps,
                        pkts_in,
                        pkts_out,
                        drops_newest,
                        drops_oldest,
                        health_counters.jitter_enabled.load(Ordering::Relaxed),
                        jitter_in_pkts,
                        jitter_out_pkts,
                        jitter_in_bytes,
                        jitter_out_bytes,
                        jitter_late_drops,
                        jitter_max_depth,
                    );
                }
                _ = health_shutdown.changed() => break,
            }
        }
    });

    // Probe server
    let probe_handle = if config.enable_probe {
        let probe_state_server = probe_state.clone();
        let mut probe_shutdown = shutdown_rx.clone();
        let addr: SocketAddr = format!("0.0.0.0:{}", config.probe_port)
            .parse()
            .expect("invalid probe port");
        info!("HTTP probe enabled on port {}", config.probe_port);
        Some(tokio::spawn(async move {
            let app = Router::new()
                .route("/livez", get(live_handler))
                .route("/readyz", get(ready_handler))
                .with_state(probe_state_server);
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .expect("failed to bind probe port");
            let serve_fut = serve(listener, app);
            let _ = serve_fut
                .with_graceful_shutdown(async move {
                    let _ = probe_shutdown.changed().await;
                })
                .await;
        }))
    } else {
        None
    };

    info!(
        "Ready to accept TCP clients on {}:{} (remote_port={}, buffer_ms={}, drop_policy={:?})",
        bind_address, bind_port, remote_port, buffer_ms, config.drop_policy
    );
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
        let client_connected_at = Instant::now();
        info!("Accepted TCP client {}", addr);
        metrics.inc_counter("client_accept");

        // Create a channel for the client
        let channel = ClientChannel::new();
        let (conn_tx, conn_rx) = oneshot::channel::<bool>();
        let dh_tx = dh_tx.clone();
        let _shutdown_conn = shutdown_rx.clone();

        let realm_id = rand::random::<u32>();
        info!(
            "Client {} assigned realm {:08x}; enqueuing PTCP Connect",
            addr, realm_id
        );

        // Store the channel in the map
        channels2.lock().unwrap().insert(realm_id, channel.clone());
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
        let ready = tokio::time::timeout(
            Duration::from_secs(config.realm_ready_timeout_secs),
            conn_rx,
        )
        .await;
        match ready {
            Ok(res) => {
                if res.is_err() {
                    warn!(
                        "Realm {:08x} connection handshake failed after {}ms (client {})",
                        realm_id,
                        client_connected_at.elapsed().as_millis(),
                        addr
                    );
                    metrics.inc_counter("realm_ready_failed");
                    channels2.lock().unwrap().remove(&realm_id);
                    conn_channels2.lock().unwrap().remove(&realm_id);
                    continue;
                }
                info!(
                    "Realm {:08x} ready after {}ms; starting reader/writer tasks for client {}",
                    realm_id,
                    client_connected_at.elapsed().as_millis(),
                    addr
                );
                metrics.inc_counter("realm_ready");
            }
            Err(_) => {
                warn!(
                    "Realm {:08x} ready wait timed out after {}s (client {}, elapsed_ms={})",
                    realm_id,
                    config.realm_ready_timeout_secs,
                    addr,
                    client_connected_at.elapsed().as_millis()
                );
                metrics.inc_counter("realm_ready_timeout");
                channels2.lock().unwrap().remove(&realm_id);
                conn_channels2.lock().unwrap().remove(&realm_id);
                continue;
            }
        }

        let (reader, writer) = client.into_split();

        tokio::spawn({
            let shutdown_rx = shutdown_rx.clone();
            let peer = addr;
            let dh_tx = dh_tx.clone();
            async move {
                process_reader(reader, realm_id, peer, dh_tx, shutdown_rx).await;
            }
        });

        tokio::spawn({
            let shutdown_rx = shutdown_rx.clone();
            let channel = channel.clone();
            async move {
                process_writer(writer, channel, shutdown_rx).await;
            }
        });
    }

    // If we exited the accept loop without observing the latest reason, read it now.
    shutdown_reason = *shutdown_rx.borrow();

    let realm_count = channels2.lock().unwrap().len();
    info!("Sending PTCP disconnect to {} active realms", realm_count);
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
    let _ = health_handle.await;
    if let Some(state) = probe_state_opt.as_ref() {
        state.handshake_ready.store(false, Ordering::Relaxed);
        state.heartbeat_ok.store(false, Ordering::Relaxed);
    }
    if let Some(handle) = probe_handle {
        let _ = handle.await;
    }

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
