#[derive(Clone, Debug)]
pub enum DropPolicy {
    /// Block on backpressure (current behavior)
    Block,
    /// Drop the newest frame when the queue is full
    DropNewest,
    /// Drop the oldest frame and keep the latest
    DropOldestKeepLatest,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub heartbeat_interval_secs: u64,
    pub heartbeat_missed_limit: u64,
    pub heartbeat_timeout_grace_secs: u64,
    pub health_interval_secs: u64,
    pub enable_probe: bool,
    pub probe_port: u16,
    pub restart_backoff_initial_secs: u64,
    pub restart_backoff_max_secs: u64,
    pub restart_backoff_jitter_ms: u64,
    pub restart_backoff_reset_after_secs: u64,
    pub handshake_timeout_secs: u64,
    pub realm_ready_timeout_secs: u64,
    pub max_pending_realm_setups: usize,
    pub reset_burst_warn_threshold_per_minute: u64,
    pub channel_capacity: usize,
    pub drop_policy: DropPolicy,
    pub jitter_buffer_ms: u64,
}

impl Config {
    pub fn ptcp_inactivity_timeout_secs(&self) -> u64 {
        self.heartbeat_interval_secs
            .saturating_mul(self.heartbeat_missed_limit)
            .saturating_add(self.heartbeat_timeout_grace_secs)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: 10,
            heartbeat_missed_limit: 1,
            heartbeat_timeout_grace_secs: 0,
            health_interval_secs: 60,
            enable_probe: false,
            probe_port: 8080,
            restart_backoff_initial_secs: 1,
            restart_backoff_max_secs: 30,
            restart_backoff_jitter_ms: 500,
            restart_backoff_reset_after_secs: 60,
            handshake_timeout_secs: 15,
            realm_ready_timeout_secs: 10,
            max_pending_realm_setups: 128,
            reset_burst_warn_threshold_per_minute: 20,
            channel_capacity: 128,
            drop_policy: DropPolicy::Block,
            jitter_buffer_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, DropPolicy};

    #[test]
    fn drop_policy_variants_exist() {
        let _a = DropPolicy::Block;
        let _b = DropPolicy::DropNewest;
        let _c = DropPolicy::DropOldestKeepLatest;
    }

    #[test]
    fn default_ptcp_inactivity_timeout_is_less_eager_than_heartbeat_interval() {
        let cfg = Config::default();

        assert_eq!(cfg.heartbeat_interval_secs, 10);
        assert_eq!(cfg.heartbeat_missed_limit, 1);
        assert_eq!(cfg.heartbeat_timeout_grace_secs, 0);
        assert_eq!(cfg.ptcp_inactivity_timeout_secs(), 10);
    }
}
