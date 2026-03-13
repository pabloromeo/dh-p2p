# Pending Stability Recommendations

This document tracks the pending stability improvements for the current `dh-p2p` implementation, based on behavior observed with Frigate and current logs.

## 0) Working mode and test-first rule (must follow for every issue)

**Policy**  
We will not implement fixes right away. For each issue in this document, we must first create tests that reproduce the bug and fail.

**Required workflow for each item**
1. Reproduce the issue with a unit/integration test.
2. Confirm the new test fails before any production code changes.
3. Implement the fix.
4. Re-run the full test suite and ensure:
   - the new test passes,
   - related existing tests still pass,
   - no regression is introduced.
5. Only then consider the issue solved.

**Test quality requirements**
- Tests should be deterministic and minimal (focus on one behavior).
- Prefer unit tests first; use integration tests when concurrency/timing paths are involved.
- Include an explanatory test name that states expected behavior.

---

## 1) Prevent global head-of-line blocking in device->client forwarding (highest priority) - COMPLETED

**Problem**  
One slow TCP client can block the global PTCP reader loop, delaying packets for all realms.

**Why it happens**  
`dh_reader` calls `send_to_clients`, which awaits `ClientChannel::push(...)` per packet. With `DropPolicy::Block`, push can wait up to 5 seconds when a queue is full.

**Recommendations**
- Decouple per-realm forwarding from the single PTCP reader loop.
- Ensure per-realm backpressure does not block other realms.
- Keep `keep_latest` semantics for live video streams.

**Success criteria**
- A slow/disconnected client no longer causes bursts of disconnects in unrelated realms.
- Reader loop latency remains stable under mixed fast/slow clients.

**Completion notes (2026-03-12)**
- Implemented per-realm forwarding isolation in `src/process.rs` so one blocked realm no longer stalls forwarding for other realms.
- Added explicit forwarder lifecycle handling (cleanup on close, stale forwarder replacement on realm reuse).
- Added bounded per-realm queue behavior with drop accounting/logging when full.
- Added regression and integration coverage for direct and jitter-buffer paths, including reconnect and cleanup races.

---

## 2) Make TCP accept path non-serial (high priority) - COMPLETED

**Problem**  
New client accepts are effectively serialized behind realm readiness handshakes (~2.2s each in current logs).

**Why it happens**  
After `listener.accept()`, the code waits for `conn_rx` (`realm ready`) before proceeding to the next accept iteration.

**Recommendations**
- Move realm setup + ready-wait into a spawned task per accepted client.
- Keep the main accept loop immediately available for the next incoming client.
- Add guardrails for maximum concurrent pending realm setups.

**Success criteria**
- Accept cadence is independent of realm bind/ready timing.
- No stepwise client connection delays under bursty reconnect behavior.

**Completion notes (2026-03-12)**
- Extracted accept-path scheduling/setup into dedicated `src/accept.rs` module (`AcceptDeps`, `AcceptLimits`, `AcceptPipeline`) to keep orchestration in `src/main.rs` minimal.
- Changed accept handling to schedule per-client setup work in spawned tasks so the main listener loop immediately returns to `listener.accept()`.
- Added a bounded pending-setup guardrail using a semaphore (`max_pending_realm_setups`) and rejection metric/log when saturated.
- Added regression tests proving setup scheduling is no longer serialized by realm-ready waits and that excess pending setups are rejected deterministically.
- Re-ran full test suite (`cargo test`) with all tests passing.

---

## 3) Keep runtime policy optimized for live streams (high operational priority) - COMPLETED

**Current**
- `--drop-policy keep_latest` (good)
- `-b 500` jitter buffer (likely too high for real-time RTSP consumers)

**Recommendations**
- Test `-b 0` first to establish baseline stability.
- Then test `-b 50` to `-b 100` if reordering compensation is still needed.
- Keep `--drop-policy keep_latest` for Frigate/ffmpeg live consumption.

**Success criteria**
- Lower reconnect/reset frequency from Frigate.
- Better end-to-end latency and fewer queue pressure events.

**Completion notes (2026-03-13)**
- Runtime tuning was completed in the production cluster environment.
- Live-stream policy kept on `--drop-policy keep_latest` with operational jitter buffer tuning validated in-cluster.

---

## 4) Reduce jitter wraparound log noise and correct wrap accounting (medium priority) - COMPLETED

**Problem**  
`JitterBuffer` wraparound detection logs can spam many lines per second and overcount wraps.

**Why it happens**  
Near `u32` boundary, multiple packets satisfy current wrap condition while `last_released_seq` remains high.

**Recommendations**
- Detect and log wraparound once per actual boundary crossing.
- Track wrap state or last wrap marker to avoid repeated info logs.
- Downgrade repetitive wrap logs to `debug` if necessary.

**Success criteria**
- Wraparound logs become sparse and meaningful.
- `wraparound_count` reflects actual wrap events rather than packet bursts.

**Completion notes (2026-03-13)**
- Updated `JitterBuffer` wraparound detection to count/log once per crossing window using explicit crossing state reset logic.
- Kept wraparound logs at current level (no downgrade to `debug`) while reducing repeated noise.
- Added regression coverage to ensure multiple post-wrap packets in the same crossing window increment `wraparound_count` only once.

---

## 5) Reclassify and enrich reset-by-peer logs (medium priority) - COMPLETED

**Problem**  
`Connection reset by peer (os error 104)` is noisy and may be interpreted as server failure.

**Interpretation**
- This usually means Frigate/ffmpeg closed the socket (often reacting to upstream stall/timing issues).

**Recommendations**
- Log `ECONNRESET` as expected client disconnect unless rate exceeds threshold.
- Add contextual counters (per minute resets, active realms, queue stats) to make it actionable.
- Trigger warning escalation only when reset bursts exceed configured limits.

**Success criteria**
- Logs distinguish normal client churn from real instability.
- Easier correlation between reset bursts and upstream pressure events.

**Completion notes (2026-03-13)**
- Added reset burst tracking (`resets_last_min`) with warning escalation only when bursts exceed a configurable threshold (`--reset-burst-warn-threshold-per-minute`).
- Reclassified TCP `ECONNRESET`/`BrokenPipe`/`ConnectionAborted` handling as expected client disconnect at info level by default, with warning-level logs only on burst escalation.
- Enriched reset logs with actionable context (`active_realms`, `drops_newest`, `drops_oldest`, `jitter_late_drops`) and added periodic health counters for `tcp_peer_disconnects`, `tcp_peer_resets`, and `tcp_peer_reset_bursts`.
- Added regression tests for the burst tracker window/threshold behavior and validated with full `cargo test`.

---

## 6) Harden handshake/parser path by removing panic/unwrap/assert on network data (medium priority)

**Problem**  
Handshake and protocol parse paths still use panic-prone operations (`unwrap/assert/panic`) on external data.

**Risk**
- A malformed/partial response can terminate process unexpectedly.

**Recommendations**
- Replace panic paths with `Result` propagation and graceful restart decisions.
- Validate lengths/fields before indexing into byte slices.
- Treat malformed data as non-fatal where possible and continue/retry.

**Success criteria**
- No process crash from malformed packet/response inputs.
- Errors are logged with context and handled via restart/recovery paths.

---

## 7) Add realm ID collision protection (low-medium priority)

**Problem**  
Realm IDs are random `u32` and inserted directly; collision can overwrite an existing realm mapping.

**Recommendations**
- Retry realm ID generation until unused (bounded attempts).
- Optionally maintain monotonic or hybrid ID strategy to reduce collision chance.

**Success criteria**
- No accidental channel replacement due to realm ID collision.

---

## 8) Improve observability for real root-cause analysis (high operational priority)

**Recommendations**
- Temporarily set `--health-interval-secs 15` during investigation.
- Add queue depth metrics per realm (current, max, drops by reason).
- Add timing metrics: accept->realm-ready, packet forwarding delay, reader loop tick duration.
- Export/reset counters in periodic snapshots for easier trend reading.

**Success criteria**
- Can correlate Frigate reconnect waves with measurable internal pressure.
- Clear signal on whether bottleneck is accept path, forwarding backpressure, or network quality.

---

## 9) Run controlled soak tests after each change (high priority for validation)

**Recommendations**
- Build a repeatable test profile:
  - N concurrent Frigate/ffmpeg consumers
  - fixed run time (e.g., 1-4 hours)
  - baseline + one change at a time
- Compare:
  - reset/disconnect rate
  - realm churn
  - drop counters
  - latency behavior

**Success criteria**
- Each merged change shows measurable improvement against baseline.
- No regressions in long-running behavior.

---

## 10) Suggested execution order

1. For the selected issue, write a reproducing test first and confirm it fails.  
2. Keep `--drop-policy keep_latest`; reduce jitter buffer (`-b 0`, then `50-100`) and measure.  
3. Implement non-serial accept path.  
4. Implement non-blocking per-realm forwarding isolation.  
5. Improve reset/wrap logging semantics and counters.  
6. Harden panic-prone handshake/parser paths.  
7. Add realm ID collision handling.  
8. Re-run soak tests and compare against baseline metrics.

---

## 11) Completion tracker

**Tracking rule (automatic update policy)**  
When an item is fully completed (test-first reproduction, fix, and regression checks green), immediately:
1. Mark the item heading with `- COMPLETED`.
2. Add/update completion notes under that item with date and scope.
3. Update the checklist below by switching `[ ]` to `[x]`.

**Checklist**
- [x] 1) Prevent global head-of-line blocking in device->client forwarding
- [x] 2) Make TCP accept path non-serial
- [x] 3) Keep runtime policy optimized for live streams
- [x] 4) Reduce jitter wraparound log noise and correct wrap accounting
- [x] 5) Reclassify and enrich reset-by-peer logs
- [ ] 6) Harden handshake/parser path by removing panic/unwrap/assert on network data
- [ ] 7) Add realm ID collision protection
- [ ] 8) Improve observability for real root-cause analysis
- [ ] 9) Run controlled soak tests after each change

