use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{info, warn};
use rand::Rng;
use tokio::sync::watch;

use crate::config::Config;
use crate::shutdown::ShutdownReason;

pub async fn run_loop<F, Fut>(
    bind_address: String,
    bind_port: u16,
    remote_port: u16,
    serial: String,
    relay: bool,
    buffer_ms: u64,
    config: Arc<Config>,
    metrics: crate::metrics::MetricsHandle,
    mut run_once: F,
) where
    F: FnMut(
        String,
        u16,
        u16,
        String,
        bool,
        u64,
        Arc<Config>,
        crate::metrics::MetricsHandle,
        Arc<watch::Sender<ShutdownReason>>,
        watch::Receiver<ShutdownReason>,
    ) -> Fut,
    Fut: std::future::Future<Output = ShutdownReason>,
{
    let mut iteration: u64 = 0;
    let mut backoff_secs: u64 = config.restart_backoff_initial_secs;

    loop {
        iteration += 1;
        info!("Starting server iteration {}", iteration);
        let iteration_started = Instant::now();

        let (shutdown_tx, shutdown_rx) = watch::channel::<ShutdownReason>(ShutdownReason::Stop);
        let shutdown_tx = Arc::new(shutdown_tx);

        let reason = run_once(
            bind_address.clone(),
            bind_port,
            remote_port,
            serial.clone(),
            relay,
            buffer_ms,
            config.clone(),
            metrics.clone(),
            shutdown_tx.clone(),
            shutdown_rx.clone(),
        )
        .await;
        let iteration_duration = iteration_started.elapsed();

        match reason {
            ShutdownReason::Stop => {
                info!("Shutdown reason: Stop (iteration {})", iteration);
                break;
            }
            restart_reason if restart_reason.is_restart() => {
                if iteration_duration
                    >= Duration::from_secs(config.restart_backoff_reset_after_secs)
                    && backoff_secs != config.restart_backoff_initial_secs
                {
                    info!(
                        "Resetting restart backoff to {}s after healthy run of {}s",
                        config.restart_backoff_initial_secs,
                        iteration_duration.as_secs()
                    );
                    backoff_secs = config.restart_backoff_initial_secs;
                }
                warn!(
                    "Shutdown reason: {:?}, re-handshaking... (iteration {}), backoff {}s",
                    restart_reason, iteration, backoff_secs
                );
                metrics.inc_counter("restart");
                let jitter_ms = rand::thread_rng().gen_range(0..=config.restart_backoff_jitter_ms);
                let sleep_dur =
                    Duration::from_secs(backoff_secs) + Duration::from_millis(jitter_ms);
                tokio::time::sleep(sleep_dur).await;
                backoff_secs =
                    (backoff_secs.saturating_mul(2)).min(config.restart_backoff_max_secs);
            }
            other => {
                warn!(
                    "Unexpected shutdown reason {:?}; stopping supervisor",
                    other
                );
                break;
            }
        }
    }
}
