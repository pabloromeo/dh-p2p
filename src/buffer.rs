use log::{debug, info, warn};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Simple jitter buffer that holds packets for a short time to allow reordering.
/// 
/// Packets are sorted by their sequence number (`sent` field).
/// After `max_delay`, packets are released in order regardless of gaps.
pub struct JitterBuffer {
    /// Buffered packets: seq -> (realm, data, received_time)
    buffer: BTreeMap<u32, (u32, Vec<u8>, Instant)>,
    /// Sequence of last released packet (to detect late arrivals)
    last_released_seq: Option<u32>,
    /// How long to hold packets before releasing
    max_delay: Duration,
    /// Stats
    packets_in: u64,
    packets_out: u64,
    late_dropped: u64,
}

impl JitterBuffer {
    pub fn new(max_delay: Duration) -> Self {
        info!("JitterBuffer: max_delay={}ms", max_delay.as_millis());
        JitterBuffer {
            buffer: BTreeMap::new(),
            last_released_seq: None,
            max_delay,
            packets_in: 0,
            packets_out: 0,
            late_dropped: 0,
        }
    }

    /// Insert a packet and return any packets ready for release.
    pub fn insert(&mut self, seq: u32, realm: u32, data: Vec<u8>) -> Vec<(u32, Vec<u8>)> {
        self.packets_in += 1;
        let now = Instant::now();

        // Check if this is a late packet (already released a higher seq)
        if let Some(last) = self.last_released_seq {
            if seq <= last {
                warn!("JitterBuffer: dropping late packet seq={} (last released={})", seq, last);
                self.late_dropped += 1;
                return vec![];
            }
        }

        // Check for duplicate
        if self.buffer.contains_key(&seq) {
            debug!("JitterBuffer: dropping duplicate seq={}", seq);
            return vec![];
        }

        // Buffer the packet
        self.buffer.insert(seq, (realm, data, now));

        // Release any packets that have waited long enough
        self.flush(now)
    }

    /// Release packets that have waited long enough.
    fn flush(&mut self, now: Instant) -> Vec<(u32, Vec<u8>)> {
        let mut result = Vec::new();

        // Release all packets that have been buffered for >= max_delay
        // We must release in order (lowest seq first), which BTreeMap guarantees
        loop {
            // Peek at the first (lowest seq) packet
            let first_entry = self.buffer.iter().next();
            let should_release = match first_entry {
                Some((_, &(_, _, received_at))) => {
                    now.duration_since(received_at) >= self.max_delay
                }
                None => false,
            };

            if should_release {
                let (&seq, _) = self.buffer.iter().next().unwrap();
                let (realm, data, _) = self.buffer.remove(&seq).unwrap();
                self.last_released_seq = Some(seq);
                self.packets_out += 1;
                result.push((realm, data));
            } else {
                break;
            }
        }

        result
    }

    /// Call periodically to release packets that have waited long enough.
    pub fn tick(&mut self) -> Vec<(u32, Vec<u8>)> {
        self.flush(Instant::now())
    }

    /// Flush all remaining packets (e.g., on shutdown).
    pub fn flush_all(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut result = Vec::new();
        let keys: Vec<u32> = self.buffer.keys().cloned().collect();
        for seq in keys {
            if let Some((realm, data, _)) = self.buffer.remove(&seq) {
                result.push((realm, data));
                self.packets_out += 1;
            }
        }
        result
    }

    /// Print stats
    pub fn log_stats(&self) {
        info!(
            "JitterBuffer stats: in={}, out={}, dropped={}, buffered={}",
            self.packets_in,
            self.packets_out,
            self.late_dropped,
            self.buffer.len()
        );
    }
}
