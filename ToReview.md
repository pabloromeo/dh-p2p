# Stability Issues Analysis - dh-p2p

This document tracks identified stability issues that cause streams to fail after several hours of operation.

## Observed Symptoms

- Streams work initially but fail after a few hours of running 4 cameras
- go2rtc reports errors: "undefined error", "EOF", or timeouts
- Log messages show sequence numbers near the u32 wraparound limit:
  ```
  JitterBuffer: dropping late packet seq=4767083 (last released=4294966241)
  ```

---

## Understanding the u32 Wraparound Problem (Systemic Issue)

The PTCP protocol uses several `u32` counters that increment continuously. After ~4 billion increments, they wrap from `4,294,967,295` back to `0`. This is a **systemic problem** affecting multiple fields.

### PTCPSession State (`src/transport/ptcp.rs:235-241`):
```rust
pub struct PTCPSession {
    sent: u32,   // Cumulative bytes sent - WRAPS after ~4GB transferred
    recv: u32,   // Cumulative bytes received - WRAPS after ~4GB received
    count: u32,  // Message count - WRAPS after ~4B messages
    id: u32,     // Local message ID - WRAPS after ~4B packets
    rmid: u32,   // Remote message ID (echoed from device)
}
```

### Time to Wraparound Estimates:

| Field | Increment Rate | Time to Wrap |
|-------|---------------|--------------|
| `sent` | ~2 MB/s (4 cameras) | **~35 minutes** |
| `recv` | ~2 MB/s (4 cameras) | **~35 minutes** |
| `count` | ~100 msg/s | ~497 days |
| `id` | ~100 msg/s | ~497 days |

**The `sent`/`recv` fields are the immediate problem** - they wrap within an hour!

### Analysis of Each Field:

| Field | Used For | Wraparound Impact | Risk |
|-------|----------|-------------------|------|
| `sent` | Sequence in JitterBuffer, protocol ACKs | JitterBuffer breaks completely | 🔴 CRITICAL |
| `recv` | ACK to device | Device may reject our ACKs | 🟠 HIGH |
| `count`→`pid` | Packet ID calculation | Unknown device behavior | 🟠 MEDIUM |
| `id`→`lmid` | Message ID | Device tracks this | 🟡 LOW |
| `rmid` | Echo of device's lmid | Just passthrough | 🟢 NONE |

### The `pid` Calculation Problem (line 259):
```rust
let pid = 0x0000FFFF - self.count;
```
- When `count = 0`: `pid = 65535`
- When `count = 65535`: `pid = 0`
- When `count = 65536`: `pid = 0x0000FFFF - 65536 = 0xFFFFFFFF` (wraps to huge number!)

This is a potential protocol violation after 65536 messages.

---

## 🔴 Critical Issue 1: Sequence Number Wraparound in Jitter Buffer

**Status**: ✅ FIXED

**Location**: `src/buffer.rs`

**Problem**: 
The sequence number (`sent` field) is a `u32` that increments continuously. When it wraps from `4,294,967,295` back to `0`, the comparison `seq <= last` incorrectly identifies ALL new packets as "late".

**Evidence from logs**:
```
JitterBuffer: dropping late packet seq=4767083 (last released=4294966241)
```

**Fix Applied**:
Implemented wraparound-aware comparison functions:

```rust
/// Compare sequence numbers handling u32 wraparound.
/// Returns true if `a` is "after" `b` in sequence space.
fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

fn seq_before_or_eq(a: u32, b: u32) -> bool {
    !seq_after(a, b)
}
```

The late packet check now uses `seq_before_or_eq(seq, last)` which correctly handles wraparound.

**Tests Added**:
- `test_seq_after_normal` - normal sequence comparison
- `test_seq_after_wraparound` - wraparound cases (0 after MAX, etc.)
- `test_seq_before` - before comparison
- `test_jitter_buffer_wraparound` - buffer handles wrap correctly
- `test_jitter_buffer_late_after_wraparound` - late detection after wrap
- `test_jitter_buffer_wraparound_with_reorder` - reordering across wrap boundary

All 13 buffer tests pass.

---

## 🔴 Critical Issue 2: PTCPSession Sequence Corruption on UDP Errors

**Status**: ✅ FIXED

**Location**: `src/transport/ptcp.rs` and `src/process.rs`

**Problem**:
When UDP recv failed, `ptcp_read` returned a fake packet with `sent: 0`. When `session.recv()` processed this, it corrupted `self.recv = 0`, breaking all subsequent protocol communication.

**Fix Applied**:

1. Created `PTCPReadError` enum to distinguish IO errors from malformed packets:
```rust
pub enum PTCPReadError {
    Io(io::Error),
    Malformed(String),
}

impl PTCPReadError {
    pub fn is_fatal(&self) -> bool {
        match self {
            PTCPReadError::Io(e) => {
                e.kind() == io::ErrorKind::ConnectionRefused
                    || e.kind() == io::ErrorKind::ConnectionReset
                    || e.kind() == io::ErrorKind::NotConnected
            }
            PTCPReadError::Malformed(_) => false, // Non-fatal
        }
    }
}
```

2. Changed `ptcp_read` to return `Result<PTCPPacket, PTCPReadError>`

3. Updated `dh_reader` to handle errors properly:
```rust
let packet = match result {
    Ok(p) => p,
    Err(e) => {
        if e.is_fatal() {
            warn!("PTCP fatal read error: {}, triggering restart", e);
            let _ = shutdown_tx.send(ShutdownReason::Restart);
            break;
        }
        // Non-fatal errors - log and continue without corrupting session
        debug!("PTCP non-fatal read error: {}, continuing", e);
        continue;
    }
};
```

4. Updated `handshake.rs` to propagate errors using `?` operator

**Key improvements**:
- Fatal errors (connection refused/reset) trigger automatic restart
- Malformed packets are logged but don't corrupt session state
- Session state is only updated for valid packets

---

## 🔴 Critical Issue 3: BTreeMap Ordering Breaks on Sequence Wraparound

**Status**: ✅ FIXED

**Location**: `src/buffer.rs`

**Problem**:
`BTreeMap` orders keys by their natural `Ord` implementation. For `u32`, this is simple numeric ordering. When sequence numbers wrap around, packets with low sequence numbers (post-wrap) would sort BEFORE packets with high sequence numbers (pre-wrap).

**Fix Applied** (Option B - Relative Sequences):
The JitterBuffer now:
1. Tracks a `base_seq` (the minimum sequence currently in the buffer)
2. Stores **normalized** sequence numbers as BTreeMap keys: `key = seq.wrapping_sub(base_seq)`
3. Rebases when a packet arrives with a sequence earlier than current base
4. Stores original sequence alongside normalized key for proper tracking

```rust
pub struct JitterBuffer {
    base_seq: Option<u32>,
    // Key is normalized (relative), value includes original seq
    buffer: BTreeMap<u32, (u32, u32, Vec<u8>, Instant)>,
    // ...
}

fn normalize(&self, seq: u32) -> u32 {
    match self.base_seq {
        Some(base) => seq.wrapping_sub(base),
        None => 0,
    }
}
```

**Tests Added**:
- `test_jitter_buffer_out_of_order` - verifies correct ordering when packets arrive out of order
- `test_jitter_buffer_wraparound_with_reorder` - reordering across the wrap boundary
- `test_jitter_buffer_rebase_on_earlier_seq` - rebasing when earlier packet arrives

All tests pass.

---

## 🟠 High-Risk Issue 4: No Timeout on UDP recv

**Status**: ✅ FIXED

**Location**: `src/transport/ptcp.rs`

**Problem**:
The `recv` call blocked indefinitely. If the network path became black-holed, this would block forever.

**Fix Applied**:
Added 30-second timeout to UDP recv:

```rust
const RECV_TIMEOUT_SECS: u64 = 30;
let recv_result = tokio::time::timeout(
    Duration::from_secs(RECV_TIMEOUT_SECS),
    self.recv(&mut buf),
).await;

let n = match recv_result {
    Ok(Ok(n)) => n,
    Ok(Err(e)) => return Err(PTCPReadError::Io(e)),
    Err(_) => {
        log::warn!("PTCP recv timeout after {}s", RECV_TIMEOUT_SECS);
        return Err(PTCPReadError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("UDP recv timeout after {}s", RECV_TIMEOUT_SECS),
        )));
    }
};
```

Also updated `is_fatal()` to treat `TimedOut` as fatal, triggering automatic restart.

---

## 🟠 High-Risk Issue 5: Potential Deadlock with DropPolicy::Block

**Status**: ✅ FIXED

**Location**: `src/process.rs`

**Problem**:
If the consumer (`process_writer`) exited without notifying `space_available`, the producer would block forever, freezing ALL camera streams.

**Fix Applied**:
Added 5-second timeout to the blocking wait:

```rust
DropPolicy::Block => {
    drop(buf);
    const BLOCK_TIMEOUT_SECS: u64 = 5;
    match tokio::time::timeout(
        Duration::from_secs(BLOCK_TIMEOUT_SECS),
        self.space_available.notified(),
    ).await {
        Ok(()) => { /* retry push */ }
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
```

After 5 seconds of blocking, the frame is dropped and counted as `drops_newest` in health metrics. This prevents a single slow/dead client from blocking all streams.

---

## 🟡 Medium Issue 6: Channel Cleanup Race Condition

**Status**: ✅ FIXED

**Location**: `src/process.rs` (disconnect handling) and `src/main.rs` (channel maps)

**Problem**:
When a client disconnects:
1. `process_reader` sends `PTCPEvent::Disconnect(realm_id)` to `dh_tx`
2. `dh_writer` receives it and removes the channel from the map

But if `dh_writer` is slow or blocked:
- `dh_reader` may still try to push data to the stale channel
- Memory is held until eventually cleaned up
- Potential for orphaned entries

**Fix Applied**:
Added a `closed` flag (`Arc<AtomicBool>`) to `ClientChannel`:

1. **New fields/methods in `ClientChannel`**:
   - `closed: Arc<AtomicBool>` - Flag to mark channel as closed
   - `close()` method - Sets the flag and wakes up blocked pushers
   - `is_closed()` method - Checks the flag

2. **`push()` now checks closed flag**:
   - At the start of `push()`, if closed, returns immediately
   - Re-checks on each loop iteration (for Block policy)
   - Prevents wasted work pushing to dead channels

3. **`recv()` returns None when closed and empty**:
   - If buffer is empty and channel is closed, returns `None` immediately
   - Allows clean shutdown of process_writer

4. **Disconnect handling closes channel before removal**:
   - In `dh_writer`: `PTCPEvent::Disconnect` handler now calls `channel.close()` before removing from map
   - In `dh_reader`: Device-initiated DISC also closes channel before removal

**Unit Tests Added** (4 new tests):
- `channel_close_prevents_push` - Verifies push is ignored after close
- `channel_close_unblocks_blocked_push` - Verifies blocked push is unblocked by close
- `channel_close_recv_returns_none_when_empty` - Verifies recv returns None when closed+empty
- `channel_close_drains_existing_data` - Verifies existing data can still be drained after close

**Result**: All 29 tests pass, release build successful

---

## 🟡 Medium Issue 7: No Retransmission for Lost UDP Packets

**Status**: ⏭️ SKIPPED (Not Needed)

**Location**: General PTCP protocol handling

**Problem**:
PTCP runs over UDP but implements no retransmission. If a heartbeat or ACK is lost, the device may think connection is dead.

**Decision**: Not implementing - the existing watchdog and restart mechanism handles connection failures adequately. Retransmission would add significant complexity for minimal benefit in typical network conditions.

---

## Testing Plan

### Confirming Wraparound Issue

1. **Calculate time to wrap**:
   - Monitor `sent` values in debug logs
   - Calculate bytes/second rate
   - Predict when wrap will occur

2. **Force early wraparound** (for testing):
   - Modify `PTCPSession::new()` to initialize `sent` near `u32::MAX`:
     ```rust
     PTCPSession {
         sent: u32::MAX - 1000000,  // Start near wrap point
         // ...
     }
     ```

3. **Add wraparound detection logging**:
   ```rust
   if seq < 1000 && last > u32::MAX - 1000 {
       warn!("WRAPAROUND DETECTED: seq={} last={}", seq, last);
   }
   ```

### Monitoring Commands

```bash
# Run with maximum verbosity
./dh-p2p -vv YOUR_SERIAL 2>&1 | tee debug.log

# Watch for late drops
tail -f debug.log | grep -E "(late packet|WRAPAROUND|recv error)"

# Monitor jitter stats in health logs
tail -f debug.log | grep "Health "
```

---

## 🟠 High-Risk Issue 8: pid Calculation Overflow

**Status**: ✅ FIXED

**Location**: `src/transport/ptcp.rs`

**Problem**:
After 65536 messages, the `pid` calculation `0x0000FFFF - self.count` would underflow to `0xFFFFFFFF`.

**Fix Applied**:
Used modular arithmetic to keep pid in 16-bit range:

```rust
let pid = match body {
    PTCPBody::Sync => 0x0002FFFF,
    _ => 0x0000FFFF - (self.count & 0xFFFF),  // Wrap every 65536 messages
};
```

**Tests Added**:
- `test_pid_calculation_normal` - basic pid countdown
- `test_pid_calculation_at_boundary` - verifies wrap at 65536
- `test_pid_calculation_large_count` - verifies correct behavior with count > 65536
- `test_pid_sync_special_case` - Sync uses special pid value
- `test_pid_empty_doesnt_increment_count` - Empty packets don't affect count
- `test_session_sent_recv_tracking` - sent/recv byte tracking

All 6 PTCP tests pass.

---

## Priority Order for Fixes

### Phase 1: Critical (Must Fix)
1. ~~**🔴 Sequence wraparound in JitterBuffer comparison**~~ - ✅ FIXED
2. ~~**🔴 BTreeMap ordering on wraparound**~~ - ✅ FIXED  
3. ~~**🔴 PTCP recv error handling**~~ - ✅ FIXED

### Phase 2: High Priority
4. ~~**🟠 pid calculation overflow**~~ - ✅ FIXED
5. ~~**🟠 UDP recv timeout**~~ - ✅ FIXED
6. ~~**🟠 Block policy deadlock**~~ - ✅ FIXED

### Phase 3: Medium Priority
7. **🟡 Channel cleanup race** - Memory/resource management
8. **🟡 recv field wraparound** - May cause device to reject ACKs

### Phase 4: Nice to Have
9. **🟡 Retransmission** - Complex to implement, may not be needed

---

## Comprehensive Fix Strategy

### Approach A: Wraparound-Aware Comparisons (Minimal Change)

Add a helper function for sequence comparison that handles wraparound:

```rust
/// Compare sequence numbers handling u32 wraparound.
/// Returns true if `a` is "after" `b` in sequence space.
/// Works correctly when sequences are within 2^31 of each other.
fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Returns true if `a` is "before or equal to" `b` in sequence space.
fn seq_before_or_eq(a: u32, b: u32) -> bool {
    !seq_after(a, b)
}
```

**Pros**: Minimal code changes, well-understood technique (used in TCP)
**Cons**: Doesn't fix BTreeMap ordering

### Approach B: Relative Sequence Numbers (More Robust)

Track a "base" sequence and store relative offsets:

```rust
pub struct JitterBuffer {
    base_seq: Option<u32>,  // First sequence we saw
    buffer: BTreeMap<u32, ...>,  // Store (seq - base_seq) as key
    last_released_offset: u32,
}

impl JitterBuffer {
    fn normalize(&self, seq: u32) -> u32 {
        match self.base_seq {
            Some(base) => seq.wrapping_sub(base),
            None => 0,
        }
    }
}
```

**Pros**: BTreeMap ordering works correctly, clean design
**Cons**: More code changes, need to reset base periodically

### Approach C: Use i64 Instead of u32 (Simplest)

Convert all sequence numbers to i64 internally and never worry about wrap:

```rust
pub struct JitterBuffer {
    buffer: BTreeMap<i64, ...>,
    last_released_seq: Option<i64>,
    seq_offset: i64,  // Added when we detect wrap
}
```

**Pros**: No wraparound issues at all (would take millions of years to wrap i64)
**Cons**: Need to detect wraps and adjust offset

### Recommended Approach: Hybrid

1. **For JitterBuffer**: Use Approach B (relative sequences) - most robust
2. **For PTCPSession**: Keep u32 with Rust's natural wrapping arithmetic
3. **For pid calculation**: Fix the underflow with modular arithmetic
4. **Add extensive logging**: Detect and log when sequences approach wrap

---

## Quick Test to Verify Wraparound is the Issue

Modify `PTCPSession::new()` to start near the wrap point:

```rust
pub fn new() -> PTCPSession {
    PTCPSession {
        sent: u32::MAX - 10_000_000,  // Start ~10MB before wrap
        recv: 0,
        count: 0,
        id: 0,
        rmid: 0,
    }
}
```

This will force wraparound to occur within minutes instead of hours, confirming the theory.

---

## Change Log

| Date | Issue | Status | Notes |
|------|-------|--------|-------|
| (initial) | All issues | Identified | Initial analysis |
| (initial) | Systemic u32 wrap | Documented | Full analysis of all u32 fields |
| 2026-01-06 | Issue #1: JitterBuffer seq comparison | ✅ FIXED | Added `seq_after()`/`seq_before_or_eq()` wraparound-aware comparisons |
| 2026-01-06 | Issue #3: BTreeMap ordering | ✅ FIXED | Implemented relative sequence normalization with rebasing |
| 2026-01-06 | Unit tests | Added | 15 tests for buffer module, all passing |
| 2026-01-06 | Issue #2: PTCP recv error handling | ✅ FIXED | Created `PTCPReadError`, proper error propagation, fatal vs non-fatal handling |
| 2026-01-06 | Issue #8: pid calculation overflow | ✅ FIXED | Added modular arithmetic `& 0xFFFF` to keep pid in 16-bit range |
| 2026-01-06 | Issue #4: UDP recv timeout | ✅ FIXED | Added 30s timeout to prevent indefinite blocking |
| 2026-01-06 | Issue #5: Block policy deadlock | ✅ FIXED | Added 5s timeout to prevent deadlock when consumer dies |
| 2026-01-06 | PTCP tests | Added | 6 tests for PTCPSession, total 25 tests all passing |
| 2026-01-06 | Issue #6: Channel cleanup race | ✅ FIXED | Added `closed` flag to ClientChannel, prevents push after close, unblocks blocked pushers |
| 2026-01-06 | Issue #7: Retransmission | ⏭️ SKIPPED | Not needed - existing watchdog handles connection failures |
| 2026-01-06 | Channel tests | Added | 4 tests for close behavior, total 29 tests all passing |


