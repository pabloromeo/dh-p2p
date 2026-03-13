use log::{debug, info, warn};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Compare sequence numbers handling u32 wraparound.
/// Returns true if `a` is "after" `b` in sequence space.
/// Works correctly when sequences are within 2^31 of each other.
#[inline]
fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Returns true if `a` is "before or equal to" `b` in sequence space.
#[inline]
fn seq_before_or_eq(a: u32, b: u32) -> bool {
    !seq_after(a, b)
}

/// Returns true if `a` is strictly "before" `b` in sequence space.
#[inline]
fn seq_before(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) > 0
}

/// Simple jitter buffer that holds packets for a short time to allow reordering.
///
/// Packets are sorted by their sequence number (`sent` field).
/// After `max_delay`, packets are released in order regardless of gaps.
///
/// This implementation handles u32 sequence number wraparound by:
/// 1. Tracking a base sequence number (minimum seq in buffer)
/// 2. Storing normalized (relative) sequence numbers in the BTreeMap
/// 3. Using wraparound-aware comparisons for late packet detection
/// 4. Rebasing when the buffer becomes empty or when we see an earlier seq
pub struct JitterBuffer {
    /// The base sequence number - used for normalization
    /// This is the minimum seq currently in the buffer (or last released)
    base_seq: Option<u32>,
    /// Buffered packets: normalized_seq -> (realm, original_seq, data, received_time)
    /// The key is (seq - base_seq), which gives correct ordering
    buffer: BTreeMap<u32, (u32, u32, Vec<u8>, Instant)>,
    /// Sequence of last released packet (original, not normalized)
    last_released_seq: Option<u32>,
    /// How long to hold packets before releasing
    max_delay: Duration,
    /// Stats
    packets_in: u64,
    packets_out: u64,
    late_dropped: u64,
    /// Count of detected wraparounds (for debugging)
    wraparound_count: u64,
    /// Suppresses repeated wraparound logs/counts while still in the same crossing window.
    wraparound_crossing_active: bool,
}

impl JitterBuffer {
    pub fn new(max_delay: Duration) -> Self {
        info!("JitterBuffer: max_delay={}ms", max_delay.as_millis());
        JitterBuffer {
            base_seq: None,
            buffer: BTreeMap::new(),
            last_released_seq: None,
            max_delay,
            packets_in: 0,
            packets_out: 0,
            late_dropped: 0,
            wraparound_count: 0,
            wraparound_crossing_active: false,
        }
    }

    /// Normalize a sequence number relative to the base.
    /// This converts absolute sequence numbers to offsets from base_seq,
    /// which gives correct ordering in BTreeMap.
    #[inline]
    fn normalize(&self, seq: u32) -> u32 {
        match self.base_seq {
            Some(base) => seq.wrapping_sub(base),
            None => 0,
        }
    }

    /// Rebuild the BTreeMap with a new base sequence.
    /// Called when we need to change the base (e.g., when we see an earlier seq).
    fn rebase(&mut self, new_base: u32) {
        if self.buffer.is_empty() {
            self.base_seq = Some(new_base);
            return;
        }

        let old_base = self.base_seq.unwrap_or(0);

        // Collect all entries
        let entries: Vec<(u32, u32, Vec<u8>, Instant)> = self
            .buffer
            .values()
            .map(|(realm, original_seq, data, time)| (*realm, *original_seq, data.clone(), *time))
            .collect();

        // Clear and reinsert with new normalized keys
        self.buffer.clear();
        for (realm, original_seq, data, time) in entries {
            let new_normalized = original_seq.wrapping_sub(new_base);
            self.buffer
                .insert(new_normalized, (realm, original_seq, data, time));
        }

        self.base_seq = Some(new_base);
        debug!(
            "JitterBuffer: rebased from {} to {} ({} packets)",
            old_base,
            new_base,
            self.buffer.len()
        );
    }

    /// Insert a packet and return any packets ready for release.
    pub fn insert(&mut self, seq: u32, realm: u32, data: Vec<u8>) -> Vec<(u32, Vec<u8>)> {
        self.packets_in += 1;
        let now = Instant::now();

        // Check if this is a late packet (already released a packet that's "after" this one)
        if let Some(last) = self.last_released_seq {
            // Use wraparound-aware comparison
            if seq_before_or_eq(seq, last) {
                // Log with extra detail when near wraparound boundary
                if seq < 1_000_000 && last > u32::MAX - 1_000_000 {
                    warn!(
                        "JitterBuffer: dropping late packet seq={} (last released={}) - WRAPAROUND BOUNDARY",
                        seq, last
                    );
                } else {
                    warn!(
                        "JitterBuffer: dropping late packet seq={} (last released={})",
                        seq, last
                    );
                }
                self.late_dropped += 1;
                return vec![];
            }

            // Detect and log wraparound once per actual crossing window.
            let wraparound_crossing = seq < last && seq_after(seq, last);
            if wraparound_crossing {
                if !self.wraparound_crossing_active {
                    self.wraparound_count += 1;
                    info!(
                        "JitterBuffer: sequence wraparound detected! seq={} last={} (wraparound #{})",
                        seq, last, self.wraparound_count
                    );
                    self.wraparound_crossing_active = true;
                }
            } else {
                self.wraparound_crossing_active = false;
            }
        }

        // Initialize or update base_seq
        match self.base_seq {
            None => {
                // First packet - set base
                self.base_seq = Some(seq);
                debug!("JitterBuffer: initialized base_seq={}", seq);
            }
            Some(base) => {
                // If this seq is BEFORE our current base (in wraparound-aware terms),
                // we need to rebase
                if seq_before(seq, base) {
                    self.rebase(seq);
                }
            }
        }

        // Normalize the sequence for BTreeMap storage
        let normalized_seq = self.normalize(seq);

        // Check for duplicate (using normalized key)
        if self.buffer.contains_key(&normalized_seq) {
            debug!(
                "JitterBuffer: dropping duplicate seq={} (normalized={})",
                seq, normalized_seq
            );
            return vec![];
        }

        // Buffer the packet with both normalized key and original seq
        self.buffer.insert(normalized_seq, (realm, seq, data, now));

        // Release any packets that have waited long enough
        self.flush(now)
    }

    /// Release packets that have waited long enough.
    fn flush(&mut self, now: Instant) -> Vec<(u32, Vec<u8>)> {
        let mut result = Vec::new();

        // Release all packets that have been buffered for >= max_delay
        // BTreeMap iterates in normalized order, which is correct
        loop {
            // Peek at the first (lowest normalized seq) packet
            let first_entry = self.buffer.iter().next();
            let should_release = match first_entry {
                Some((_, &(_, _, _, received_at))) => {
                    now.duration_since(received_at) >= self.max_delay
                }
                None => false,
            };

            if should_release {
                let (&normalized_seq, _) = self.buffer.iter().next().unwrap();
                let (realm, original_seq, data, _) = self.buffer.remove(&normalized_seq).unwrap();
                self.last_released_seq = Some(original_seq);
                self.packets_out += 1;
                result.push((realm, data));

                // If buffer is now empty, reset base for next batch
                if self.buffer.is_empty() {
                    self.base_seq = None;
                } else {
                    // Update base to the new minimum (first remaining entry)
                    if let Some((&_, &(_, new_base_seq, _, _))) = self.buffer.iter().next() {
                        if self.base_seq != Some(new_base_seq) {
                            self.rebase(new_base_seq);
                        }
                    }
                }
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
        // Collect keys in order (normalized order = correct sequence order)
        let keys: Vec<u32> = self.buffer.keys().cloned().collect();
        for normalized_seq in keys {
            if let Some((realm, _original_seq, data, _)) = self.buffer.remove(&normalized_seq) {
                result.push((realm, data));
                self.packets_out += 1;
            }
        }
        self.base_seq = None;
        result
    }

    /// Print stats
    pub fn log_stats(&self) {
        info!(
            "JitterBuffer stats: in={}, out={}, dropped={}, buffered={}, wraparounds={}",
            self.packets_in,
            self.packets_out,
            self.late_dropped,
            self.buffer.len(),
            self.wraparound_count
        );
    }

    pub fn late_dropped(&self) -> u64 {
        self.late_dropped
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seq_after_normal() {
        // Normal cases (no wraparound)
        assert!(seq_after(10, 5));
        assert!(seq_after(100, 99));
        assert!(!seq_after(5, 10));
        assert!(!seq_after(5, 5)); // equal is not "after"
    }

    #[test]
    fn test_seq_after_wraparound() {
        // Wraparound cases
        // 0 is after u32::MAX (just wrapped)
        assert!(seq_after(0, u32::MAX));
        assert!(seq_after(1, u32::MAX));
        assert!(seq_after(100, u32::MAX - 50));

        // u32::MAX is before 0
        assert!(!seq_after(u32::MAX, 0));
        assert!(!seq_after(u32::MAX - 50, 100));
    }

    #[test]
    fn test_seq_before() {
        // Normal cases
        assert!(seq_before(5, 10));
        assert!(seq_before(99, 100));
        assert!(!seq_before(10, 5));
        assert!(!seq_before(5, 5)); // equal is not "before"

        // Wraparound cases
        assert!(seq_before(u32::MAX, 0)); // MAX is before 0 after wrap
        assert!(seq_before(u32::MAX - 50, 100));
        assert!(!seq_before(0, u32::MAX));
    }

    #[test]
    fn test_seq_after_large_gap() {
        // Large gaps (close to 2^31) - edge cases
        let half = i32::MAX as u32; // 2^31 - 1

        // Just under half the space - still "after"
        assert!(seq_after(half, 0));

        // At exactly half + 1, it wraps to "before"
        assert!(!seq_after(half + 2, 0));
    }

    #[test]
    fn test_jitter_buffer_normal_order() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0));

        // Insert in order
        let r1 = jb.insert(100, 1, vec![1]);
        let r2 = jb.insert(101, 1, vec![2]);
        let r3 = jb.insert(102, 1, vec![3]);

        // With 0ms delay, all should be released immediately
        assert_eq!(r1.len(), 1);
        assert_eq!(r2.len(), 1);
        assert_eq!(r3.len(), 1);
        assert_eq!(r1[0].1, vec![1]);
        assert_eq!(r2[0].1, vec![2]);
        assert_eq!(r3[0].1, vec![3]);
    }

    #[test]
    fn test_jitter_buffer_out_of_order() {
        let mut jb = JitterBuffer::new(Duration::from_millis(100));

        // Insert out of order
        let r1 = jb.insert(102, 1, vec![3]);
        assert!(r1.is_empty()); // Not released yet (buffer delay)

        let r2 = jb.insert(100, 1, vec![1]);
        assert!(r2.is_empty());

        let r3 = jb.insert(101, 1, vec![2]);
        assert!(r3.is_empty());

        // All 3 are buffered
        assert_eq!(jb.buffered_len(), 3);

        // Flush all - should come out in order
        let all = jb.flush_all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].1, vec![1]); // seq 100
        assert_eq!(all[1].1, vec![2]); // seq 101
        assert_eq!(all[2].1, vec![3]); // seq 102
    }

    #[test]
    fn test_jitter_buffer_late_packet() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0));

        // Insert and release seq 100
        let _ = jb.insert(100, 1, vec![1]);

        // Try to insert seq 99 (late)
        let result = jb.insert(99, 1, vec![0]);
        assert!(result.is_empty());
        assert_eq!(jb.late_dropped(), 1);

        // Try to insert seq 100 again (duplicate of released)
        let result = jb.insert(100, 1, vec![1]);
        assert!(result.is_empty());
        assert_eq!(jb.late_dropped(), 2);
    }

    #[test]
    fn test_jitter_buffer_wraparound() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0));

        // Start near u32::MAX
        let _ = jb.insert(u32::MAX - 2, 1, vec![1]);
        let _ = jb.insert(u32::MAX - 1, 1, vec![2]);
        let _ = jb.insert(u32::MAX, 1, vec![3]);

        // Now wraparound to 0, 1, 2
        let r0 = jb.insert(0, 1, vec![4]);
        assert_eq!(r0.len(), 1);
        assert_eq!(r0[0].1, vec![4]);

        let r1 = jb.insert(1, 1, vec![5]);
        assert_eq!(r1.len(), 1);

        let r2 = jb.insert(2, 1, vec![6]);
        assert_eq!(r2.len(), 1);

        // No late drops - wraparound was handled correctly
        assert_eq!(jb.late_dropped(), 0);
        assert_eq!(jb.wraparound_count, 1);
    }

    #[test]
    fn test_jitter_buffer_wraparound_with_reorder() {
        let mut jb = JitterBuffer::new(Duration::from_millis(100));

        // Start near u32::MAX
        let _ = jb.insert(u32::MAX - 1, 1, vec![1]);
        let _ = jb.insert(u32::MAX, 1, vec![2]);

        // Packets arrive out of order across the wrap boundary
        let _ = jb.insert(1, 1, vec![4]); // Post-wrap, out of order
        let _ = jb.insert(0, 1, vec![3]); // Post-wrap, should come before 1

        // Flush all - should be in correct order despite wraparound
        let all = jb.flush_all();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].1, vec![1]); // u32::MAX - 1
        assert_eq!(all[1].1, vec![2]); // u32::MAX
        assert_eq!(all[2].1, vec![3]); // 0 (post-wrap)
        assert_eq!(all[3].1, vec![4]); // 1 (post-wrap)
    }

    #[test]
    fn test_jitter_buffer_late_after_wraparound() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0));

        // Release packets up to and including seq 5 (after wraparound)
        let _ = jb.insert(u32::MAX, 1, vec![1]);
        let _ = jb.insert(0, 1, vec![2]);
        let _ = jb.insert(5, 1, vec![3]);

        // Now try to insert a "late" packet that's actually from before the wrap
        // u32::MAX - 10 looks like a big number but it's "before" 5 in sequence space
        let result = jb.insert(u32::MAX - 10, 1, vec![0]);
        assert!(result.is_empty());
        assert_eq!(jb.late_dropped(), 1);

        // Also try inserting seq 3, which is between 0 and 5 but already past last_released
        let result = jb.insert(3, 1, vec![0]);
        assert!(result.is_empty());
        assert_eq!(jb.late_dropped(), 2);
    }

    #[test]
    fn test_jitter_buffer_duplicate() {
        let mut jb = JitterBuffer::new(Duration::from_millis(100));

        // Insert packet
        let _ = jb.insert(100, 1, vec![1]);
        assert_eq!(jb.buffered_len(), 1);

        // Try to insert duplicate (same seq, still buffered)
        let result = jb.insert(100, 1, vec![2]);
        assert!(result.is_empty());
        assert_eq!(jb.buffered_len(), 1); // Still just 1 packet
    }

    #[test]
    fn test_jitter_buffer_rebase_on_earlier_seq() {
        let mut jb = JitterBuffer::new(Duration::from_millis(100));

        // Insert seq 1000 first
        let _ = jb.insert(1000, 1, vec![1]);
        assert_eq!(jb.base_seq, Some(1000));

        // Now insert seq 990 (earlier) - should trigger rebase
        let _ = jb.insert(990, 1, vec![2]);
        assert_eq!(jb.base_seq, Some(990));

        // Insert seq 995 (in between)
        let _ = jb.insert(995, 1, vec![3]);

        // Flush all - should be in order: 990, 995, 1000
        let all = jb.flush_all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].1, vec![2]); // seq 990
        assert_eq!(all[1].1, vec![3]); // seq 995
        assert_eq!(all[2].1, vec![1]); // seq 1000
    }

    #[test]
    fn test_jitter_buffer_multiple_realms() {
        let mut jb = JitterBuffer::new(Duration::from_millis(100));

        // Insert packets from different realms with same seq numbers
        // (seq is global, but we track realm for routing)
        let _ = jb.insert(100, 1, vec![1]); // realm 1
        let _ = jb.insert(101, 2, vec![2]); // realm 2
        let _ = jb.insert(102, 1, vec![3]); // realm 1

        let all = jb.flush_all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0], (1, vec![1])); // realm 1, seq 100
        assert_eq!(all[1], (2, vec![2])); // realm 2, seq 101
        assert_eq!(all[2], (1, vec![3])); // realm 1, seq 102
    }

    #[test]
    fn test_jitter_buffer_wraparound_normalization_order() {
        // This test verifies that packets spanning the u32 wraparound
        // are correctly ordered in the BTreeMap using normalized keys.
        let mut jb = JitterBuffer::new(Duration::from_millis(100));

        // Start with base near u32::MAX
        let base = u32::MAX - 5;
        let _ = jb.insert(base, 1, vec![1]);           // normalized = 0
        let _ = jb.insert(base + 3, 1, vec![2]);       // normalized = 3
        let _ = jb.insert(u32::MAX, 1, vec![3]);       // normalized = 5

        // Now add packets after wraparound
        let _ = jb.insert(0, 1, vec![4]);              // normalized = 6 (wrapping_sub)
        let _ = jb.insert(5, 1, vec![5]);              // normalized = 11

        // Verify order is correct: base, base+3, MAX, 0, 5
        let all = jb.flush_all();
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].1, vec![1]); // base (seq u32::MAX - 5)
        assert_eq!(all[1].1, vec![2]); // base + 3
        assert_eq!(all[2].1, vec![3]); // u32::MAX
        assert_eq!(all[3].1, vec![4]); // 0 (post-wrap)
        assert_eq!(all[4].1, vec![5]); // 5 (post-wrap)
    }

    #[test]
    fn test_jitter_buffer_wraparound_out_of_order_across_boundary() {
        // Packets arrive out of order, spanning the wraparound boundary
        let mut jb = JitterBuffer::new(Duration::from_millis(100));

        // Packets arrive in this order: 0, MAX-1, MAX, 2, 1
        let _ = jb.insert(0, 1, vec![4]);              // First packet, becomes base
        let _ = jb.insert(u32::MAX - 1, 1, vec![2]);   // Before base in sequence space!
        let _ = jb.insert(u32::MAX, 1, vec![3]);       // Also before base
        let _ = jb.insert(2, 1, vec![6]);              // After base
        let _ = jb.insert(1, 1, vec![5]);              // After base, out of order

        // Should be ordered: MAX-1, MAX, 0, 1, 2
        let all = jb.flush_all();
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].1, vec![2]); // u32::MAX - 1
        assert_eq!(all[1].1, vec![3]); // u32::MAX
        assert_eq!(all[2].1, vec![4]); // 0
        assert_eq!(all[3].1, vec![5]); // 1
        assert_eq!(all[4].1, vec![6]); // 2
    }

    #[test]
    fn test_jitter_buffer_wraparound_count_once_per_crossing_window() {
        let mut jb = JitterBuffer::new(Duration::from_millis(100));

        // Simulate that we already released a packet near the u32 boundary.
        jb.last_released_seq = Some(u32::MAX - 1);

        // Multiple post-wrap packets arrive while last_released_seq is still pre-wrap.
        let _ = jb.insert(0, 1, vec![1]);
        let _ = jb.insert(1, 1, vec![2]);
        let _ = jb.insert(2, 1, vec![3]);

        // Should count/log wraparound once for this crossing window.
        assert_eq!(jb.wraparound_count, 1);
    }
}
