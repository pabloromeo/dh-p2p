use log::{info, warn};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot, watch, Semaphore},
};

use crate::{
    config::Config,
    fdlog::log_fd_snapshot,
    metrics::MetricsHandle,
    process::{process_reader, process_writer, ClientChannel, HealthCounters, ResetBurstTracker},
    shutdown::ShutdownReason,
    transport::ptcp::PTCPEvent,
};

#[derive(Clone)]
pub(crate) struct AcceptDeps {
    config: Arc<Config>,
    metrics: MetricsHandle,
    dh_tx: mpsc::Sender<PTCPEvent>,
    health: Arc<HealthCounters>,
    reset_tracker: Arc<ResetBurstTracker>,
    channels: Arc<Mutex<HashMap<u32, ClientChannel>>>,
    conn_channels: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
    shutdown_rx: watch::Receiver<ShutdownReason>,
}

impl AcceptDeps {
    pub(crate) fn new(
        config: Arc<Config>,
        metrics: MetricsHandle,
        dh_tx: mpsc::Sender<PTCPEvent>,
        health: Arc<HealthCounters>,
        reset_tracker: Arc<ResetBurstTracker>,
        channels: Arc<Mutex<HashMap<u32, ClientChannel>>>,
        conn_channels: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
        shutdown_rx: watch::Receiver<ShutdownReason>,
    ) -> Self {
        Self {
            config,
            metrics,
            dh_tx,
            health,
            reset_tracker,
            channels,
            conn_channels,
            shutdown_rx,
        }
    }
}

#[derive(Clone)]
pub(crate) struct AcceptLimits {
    pending_setups: Arc<Semaphore>,
}

impl AcceptLimits {
    pub(crate) fn new(max_pending_realm_setups: usize) -> Self {
        Self {
            pending_setups: Arc::new(Semaphore::new(max_pending_realm_setups.max(1))),
        }
    }
}

#[derive(Clone)]
pub(crate) struct AcceptPipeline {
    pub(crate) deps: AcceptDeps,
    pub(crate) limits: AcceptLimits,
}

impl AcceptPipeline {
    pub(crate) fn new(deps: AcceptDeps, limits: AcceptLimits) -> Self {
        Self { deps, limits }
    }
}

async fn handle_accepted_client(
    client: TcpStream,
    addr: SocketAddr,
    realm_id: u32,
    deps: AcceptDeps,
) {
    let client_connected_at = Instant::now();
    info!("Accepted TCP client {}", addr);
    deps.metrics.inc_counter("client_accept");

    // Create a channel for the client.
    let channel = ClientChannel::new();
    let (conn_tx, conn_rx) = oneshot::channel::<bool>();

    info!(
        "Client {} assigned realm {:08x}; enqueuing PTCP Connect",
        addr, realm_id
    );

    // Store the channel in the map before connect request.
    deps.channels
        .lock()
        .unwrap()
        .insert(realm_id, channel.clone());
    deps.conn_channels.lock().unwrap().insert(realm_id, conn_tx);
    {
        let chans = deps.channels.lock().unwrap();
        let conns = deps.conn_channels.lock().unwrap();
        log_fd_snapshot("after accept", chans.len(), conns.len());
    }

    if deps.dh_tx.send(PTCPEvent::Connect(realm_id)).await.is_err() {
        warn!("Failed to enqueue connect event for realm {:08x}", realm_id);
        deps.channels.lock().unwrap().remove(&realm_id);
        deps.conn_channels.lock().unwrap().remove(&realm_id);
        return;
    }

    info!(
        "Waiting for realm {:08x} to become ready (client {})",
        realm_id, addr
    );
    let ready = tokio::time::timeout(
        Duration::from_secs(deps.config.realm_ready_timeout_secs),
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
                deps.metrics.inc_counter("realm_ready_failed");
                deps.channels.lock().unwrap().remove(&realm_id);
                deps.conn_channels.lock().unwrap().remove(&realm_id);
                return;
            }
            info!(
                "Realm {:08x} ready after {}ms; starting reader/writer tasks for client {}",
                realm_id,
                client_connected_at.elapsed().as_millis(),
                addr
            );
            deps.metrics.inc_counter("realm_ready");
        }
        Err(_) => {
            warn!(
                "Realm {:08x} ready wait timed out after {}s (client {}, elapsed_ms={})",
                realm_id,
                deps.config.realm_ready_timeout_secs,
                addr,
                client_connected_at.elapsed().as_millis()
            );
            deps.metrics.inc_counter("realm_ready_timeout");
            deps.channels.lock().unwrap().remove(&realm_id);
            deps.conn_channels.lock().unwrap().remove(&realm_id);
            return;
        }
    }

    let (reader, writer) = client.into_split();
    tokio::spawn({
        let shutdown_rx = deps.shutdown_rx.clone();
        let peer = addr;
        let dh_tx = deps.dh_tx.clone();
        let channels = deps.channels.clone();
        let health = deps.health.clone();
        let reset_tracker = deps.reset_tracker.clone();
        async move {
            process_reader(
                reader,
                realm_id,
                peer,
                dh_tx,
                channels,
                health,
                reset_tracker,
                shutdown_rx,
            )
            .await;
        }
    });

    tokio::spawn({
        let channel = channel.clone();
        let channels = deps.channels.clone();
        let health = deps.health.clone();
        let reset_tracker = deps.reset_tracker.clone();
        let shutdown_rx = deps.shutdown_rx.clone();
        let peer = addr;
        async move {
            process_writer(
                writer,
                channel,
                realm_id,
                peer,
                channels,
                health,
                reset_tracker,
                shutdown_rx,
            )
            .await;
        }
    });
}

pub(crate) fn schedule_client_setup(
    client: TcpStream,
    addr: SocketAddr,
    realm_id: u32,
    pipeline: &AcceptPipeline,
) {
    let permit = match pipeline.limits.pending_setups.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            warn!(
                "Dropping client {} (realm {:08x}): too many pending realm setups",
                addr, realm_id
            );
            pipeline.deps.metrics.inc_counter("realm_setup_rejected");
            return;
        }
    };

    let deps = pipeline.deps.clone();
    tokio::spawn(async move {
        let _permit = permit;
        handle_accepted_client(client, addr, realm_id, deps).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::InMemoryMetrics;
    use tokio::net::TcpListener;

    fn make_test_pipeline(
        cfg: Arc<Config>,
        metrics: MetricsHandle,
        dh_tx: mpsc::Sender<PTCPEvent>,
        health: Arc<HealthCounters>,
        reset_tracker: Arc<ResetBurstTracker>,
        channels: Arc<Mutex<HashMap<u32, ClientChannel>>>,
        conn_channels: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
        shutdown_rx: watch::Receiver<ShutdownReason>,
    ) -> AcceptPipeline {
        let deps = AcceptDeps::new(
            cfg.clone(),
            metrics,
            dh_tx,
            health,
            reset_tracker,
            channels,
            conn_channels,
            shutdown_rx,
        );
        let limits = AcceptLimits::new(cfg.max_pending_realm_setups);
        AcceptPipeline::new(deps, limits)
    }

    async fn make_accepted_client() -> (TcpStream, SocketAddr, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connector = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (accepted, peer_addr) = listener.accept().await.unwrap();
        let client_side = connector.await.unwrap();
        (accepted, peer_addr, client_side)
    }

    #[tokio::test]
    async fn client_setup_scheduling_is_not_serialized_by_ready_wait() {
        let mut cfg = Config::default();
        cfg.realm_ready_timeout_secs = 1;
        cfg.max_pending_realm_setups = 8;
        let cfg = Arc::new(cfg);
        let metrics: MetricsHandle = Arc::new(InMemoryMetrics::default());
        let health = Arc::new(HealthCounters::default());
        let reset_tracker = Arc::new(ResetBurstTracker::new(Duration::from_secs(60), 20));
        let (dh_tx, mut dh_rx) = mpsc::channel::<PTCPEvent>(8);
        let channels = Arc::new(Mutex::new(HashMap::<u32, ClientChannel>::new()));
        let conn_channels = Arc::new(Mutex::new(HashMap::<u32, oneshot::Sender<bool>>::new()));
        let (_shutdown_tx, shutdown_rx) = watch::channel(ShutdownReason::Stop);
        let pipeline = make_test_pipeline(
            cfg.clone(),
            metrics.clone(),
            dh_tx.clone(),
            health,
            reset_tracker,
            channels,
            conn_channels,
            shutdown_rx,
        );

        let (accepted1, addr1, hold1) = make_accepted_client().await;
        let (accepted2, addr2, hold2) = make_accepted_client().await;
        let _hold_streams = (hold1, hold2);

        let started = Instant::now();
        schedule_client_setup(accepted1, addr1, 0x1111_1111, &pipeline);
        schedule_client_setup(accepted2, addr2, 0x2222_2222, &pipeline);

        let evt1 = tokio::time::timeout(Duration::from_millis(100), dh_rx.recv())
            .await
            .unwrap();
        let evt2 = tokio::time::timeout(Duration::from_millis(100), dh_rx.recv())
            .await
            .unwrap();

        assert!(matches!(evt1, Some(PTCPEvent::Connect(_))));
        assert!(matches!(evt2, Some(PTCPEvent::Connect(_))));
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "second setup was delayed by first realm-ready wait"
        );
    }

    #[tokio::test]
    async fn pending_realm_setup_limit_rejects_excess_clients() {
        let mut cfg = Config::default();
        cfg.realm_ready_timeout_secs = 1;
        cfg.max_pending_realm_setups = 1;
        let cfg = Arc::new(cfg);
        let metrics: MetricsHandle = Arc::new(InMemoryMetrics::default());
        let health = Arc::new(HealthCounters::default());
        let reset_tracker = Arc::new(ResetBurstTracker::new(Duration::from_secs(60), 20));
        let (dh_tx, mut dh_rx) = mpsc::channel::<PTCPEvent>(8);
        let channels = Arc::new(Mutex::new(HashMap::<u32, ClientChannel>::new()));
        let conn_channels = Arc::new(Mutex::new(HashMap::<u32, oneshot::Sender<bool>>::new()));
        let (_shutdown_tx, shutdown_rx) = watch::channel(ShutdownReason::Stop);
        let pipeline = make_test_pipeline(
            cfg.clone(),
            metrics.clone(),
            dh_tx.clone(),
            health,
            reset_tracker,
            channels,
            conn_channels,
            shutdown_rx,
        );

        let (accepted1, addr1, hold1) = make_accepted_client().await;
        let (accepted2, addr2, hold2) = make_accepted_client().await;
        let _hold_streams = (hold1, hold2);

        schedule_client_setup(accepted1, addr1, 0x3333_3333, &pipeline);
        schedule_client_setup(accepted2, addr2, 0x4444_4444, &pipeline);

        let evt1 = tokio::time::timeout(Duration::from_millis(100), dh_rx.recv())
            .await
            .unwrap();
        assert!(matches!(evt1, Some(PTCPEvent::Connect(0x3333_3333))));
        let evt2 = tokio::time::timeout(Duration::from_millis(100), dh_rx.recv()).await;
        assert!(
            evt2.is_err(),
            "second client should be rejected while pending limit is full"
        );
    }
}
