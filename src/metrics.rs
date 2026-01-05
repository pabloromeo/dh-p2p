use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub trait Metrics: Send + Sync {
    fn inc_counter(&self, _name: &str) {}
}

pub type MetricsHandle = Arc<dyn Metrics>;

#[derive(Default)]
pub struct InMemoryMetrics {
    counters: Mutex<HashMap<String, u64>>,
}

impl Metrics for InMemoryMetrics {
    fn inc_counter(&self, name: &str) {
        let mut map = self.counters.lock().unwrap();
        *map.entry(name.to_string()).or_insert(0) += 1;
    }
}

