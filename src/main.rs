use axum::{extract::State, http::StatusCode, routing::get, serve, Router};
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
#[cfg(unix)]
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use tokio::{
    net::{TcpListener, UdpSocket},
    signal,
    sync::{mpsc, oneshot, watch},
};

use crate::{
    accept::{
        allocate_unique_realm_id, schedule_client_setup, AcceptDeps, AcceptLimits, AcceptPipeline,
    },
    config::{Config, DropPolicy},
    fdlog::log_fd_snapshot,
    metrics::{InMemoryMetrics, MetricsHandle},
    process::{dh_reader, dh_writer, ClientChannel, HealthCounters, ResetBurstTracker},
    shutdown::ShutdownReason,
    transport::{handshake::p2p_handshake, ptcp::PTCPEvent},
};

const REALM_ID_ALLOCATION_MAX_ATTEMPTS: usize = 64;

mod accept;
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

fn spawn_probe_server(
    config: &Config,
    probe_state: ProbeState,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enable_probe {
        return None;
    }

    let addr: SocketAddr = format!("0.0.0.0:{}", config.probe_port)
        .parse()
        .expect("invalid probe port");
    info!("HTTP probe enabled on port {}", config.probe_port);

    Some(tokio::spawn(async move {
        let app = Router::new()
            .route("/livez", get(live_handler))
            .route("/readyz", get(ready_handler))
            .with_state(probe_state);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("failed to bind probe port");
        let _ = serve(listener, app).await;
    }))
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
    /// Jitter buffer duration in milliseconds (0 to disable)
    #[arg(short = 'b', long, value_name = "ms", default_value = "0")]
    buffer_ms: u64,
    /// Drop policy for slow clients: block|drop_newest|keep_latest
    #[arg(
        short = 'd',
        long = "drop-policy",
        value_name = "policy",
        default_value = "block"
    )]
    drop_policy: String,
    /// Health log interval in seconds (0 disables health logging)
    #[arg(
        short = 'H',
        long = "health-interval-secs",
        value_name = "secs",
        default_value = "60"
    )]
    health_interval_secs: u64,
    /// PTCP heartbeat send interval in seconds
    #[arg(
        long = "heartbeat-interval-secs",
        value_name = "secs",
        default_value = "2"
    )]
    heartbeat_interval_secs: u64,
    /// Consecutive heartbeat intervals without inbound PTCP activity before restart
    #[arg(
        long = "heartbeat-missed-limit",
        value_name = "count",
        default_value = "10"
    )]
    heartbeat_missed_limit: u64,
    /// Extra grace period before restarting an inactive PTCP session
    #[arg(
        long = "heartbeat-timeout-grace-secs",
        value_name = "secs",
        default_value = "10"
    )]
    heartbeat_timeout_grace_secs: u64,
    /// Enable HTTP probe server (/livez, /readyz)
    #[arg(short = 'e', long = "enable-probe", default_value_t = false)]
    enable_probe: bool,
    /// HTTP probe listen port
    #[arg(
        short = 'P',
        long = "probe-port",
        value_name = "port",
        default_value = "8080"
    )]
    probe_port: u16,
    /// Max concurrent pending realm setup waits
    #[arg(
        long = "max-pending-realm-setups",
        value_name = "count",
        default_value = "128"
    )]
    max_pending_realm_setups: usize,
    /// Warn only when reset-by-peer bursts exceed this count per minute (0 disables escalation)
    #[arg(
        long = "reset-burst-warn-threshold-per-minute",
        value_name = "count",
        default_value = "20"
    )]
    reset_burst_warn_threshold_per_minute: u64,
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
    config.heartbeat_interval_secs = args.heartbeat_interval_secs.max(1);
    config.heartbeat_missed_limit = args.heartbeat_missed_limit.max(1);
    config.heartbeat_timeout_grace_secs = args.heartbeat_timeout_grace_secs;
    config.enable_probe = args.enable_probe;
    config.probe_port = args.probe_port;
    config.max_pending_realm_setups = args.max_pending_realm_setups.max(1);
    config.reset_burst_warn_threshold_per_minute = args.reset_burst_warn_threshold_per_minute;
    config.drop_policy = match args.drop_policy.as_str() {
        "block" => DropPolicy::Block,
        "drop_newest" => DropPolicy::DropNewest,
        "keep_latest" => DropPolicy::DropOldestKeepLatest,
        other => panic!("Invalid drop_policy: {}", other),
    };
    let config = Arc::new(config);
    let metrics: MetricsHandle = Arc::new(InMemoryMetrics::default());
    let probe_state = ProbeState::default();
    let probe_handle = spawn_probe_server(&config, probe_state.clone());

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
         shutdown_rx| {
            let probe_state = probe_state.clone();
            async move {
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
                    probe_state,
                )
                .await
            }
        },
    )
    .await;

    if let Some(handle) = probe_handle {
        handle.abort();
    }
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
    probe_state: ProbeState,
) -> ShutdownReason {
    probe_state.handshake_ready.store(false, Ordering::Relaxed);
    probe_state.heartbeat_ok.store(false, Ordering::Relaxed);

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

    let (socket, session, relay_lease) = match handshake {
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
    let reset_tracker = Arc::new(ResetBurstTracker::new(
        Duration::from_secs(60),
        config.reset_burst_warn_threshold_per_minute,
    ));

    let channels = Arc::new(Mutex::new(HashMap::<u32, ClientChannel>::new()));
    let conn_channels = Arc::new(Mutex::new(HashMap::<u32, oneshot::Sender<bool>>::new()));

    info!(
        "PTCP session established (serial={}, relay={}, remote_port={})",
        serial, relay, remote_port
    );
    probe_state.handshake_ready.store(true, Ordering::Relaxed);
    probe_state.heartbeat_ok.store(true, Ordering::Relaxed);
    metrics.inc_counter("handshake_success");

    /*
     * Clone the handles
     */

    let reader = Arc::new(socket);
    let writer = reader.clone();
    let relay_release_socket = reader.clone();

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
    let heartbeat_ok_flag = Some(probe_state.heartbeat_ok.clone());
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
    let heartbeat_flag = Some(probe_state.heartbeat_ok.clone());
    let watchdog_handle = tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(watchdog_config.heartbeat_interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let last = *last_activity_watchdog.lock().unwrap();
                    let timeout = Duration::from_secs(watchdog_config.ptcp_inactivity_timeout_secs());
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
    let health_handle = if health_interval_secs == 0 {
        info!("Health logging disabled (interval set to 0)");
        None
    } else {
        Some(tokio::spawn(async move {
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
                        let tcp_peer_disconnects =
                            health_counters.tcp_peer_disconnects.swap(0, Ordering::Relaxed);
                        let tcp_peer_resets =
                            health_counters.tcp_peer_resets.swap(0, Ordering::Relaxed);
                        let tcp_peer_reset_bursts =
                            health_counters.tcp_peer_reset_bursts.swap(0, Ordering::Relaxed);
                        info!(
                            "Health realms={} waiters={} bytes_in={} bytes_out={} in_Bps={} out_Bps={} pkts_in={} pkts_out={} drops_newest={} drops_oldest={} jitter_on={} jitter_in_pkts={} jitter_out_pkts={} jitter_in_bytes={} jitter_out_bytes={} jitter_late_drops={} jitter_max_depth={} tcp_peer_disconnects={} tcp_peer_resets={} tcp_peer_reset_bursts={}",
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
                            tcp_peer_disconnects,
                            tcp_peer_resets,
                            tcp_peer_reset_bursts,
                        );
                    }
                    _ = health_shutdown.changed() => break,
                }
            }
        }))
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
    info!("dh-p2p is ready to receive client connections");

    let mut shutdown_accept = shutdown_rx.clone();
    let accept_pipeline = AcceptPipeline::new(
        AcceptDeps::new(
            config.clone(),
            metrics.clone(),
            dh_tx.clone(),
            health.clone(),
            reset_tracker.clone(),
            channels2.clone(),
            conn_channels2.clone(),
            shutdown_rx.clone(),
        ),
        AcceptLimits::new(config.max_pending_realm_setups),
    );
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
        let Some(realm_id) = allocate_unique_realm_id(
            &channels2,
            &conn_channels2,
            REALM_ID_ALLOCATION_MAX_ATTEMPTS,
        ) else {
            warn!(
                "Dropping client {}: failed to allocate unique realm id after {} attempts",
                addr, REALM_ID_ALLOCATION_MAX_ATTEMPTS
            );
            metrics.inc_counter("realm_id_allocation_failed");
            continue;
        };
        schedule_client_setup(client, addr, realm_id, &accept_pipeline);
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

    drop(accept_pipeline);
    channels2.lock().unwrap().clear();
    conn_channels2.lock().unwrap().clear();
    drop(dh_tx);

    let _ = heartbeat_handle.await;
    let _ = writer_handle.await;
    let _ = reader_handle.await;
    let _ = fd_monitor_handle.await;
    let _ = watchdog_handle.await;
    if let Some(handle) = health_handle {
        let _ = handle.await;
    }
    probe_state.handshake_ready.store(false, Ordering::Relaxed);
    probe_state.heartbeat_ok.store(false, Ordering::Relaxed);

    if let Some(lease) = relay_lease {
        if relay {
            lease.release_with_socket(&relay_release_socket).await;
        } else {
            lease.release().await;
        }
    }

    if shutdown_reason == ShutdownReason::Restart {
        shutdown_handle.abort();
    } else {
        let _ = shutdown_handle.await;
    }

    info!(
        "run_server_once completed with reason {:?}",
        shutdown_reason
    );
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
