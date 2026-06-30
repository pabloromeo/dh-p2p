# Dahua P2P Reverse Engineering Notes

This file is a living notebook for the Dahua P2P / relay protocol work. It captures confirmed findings, likely interpretations, and open questions so each reverse-engineering pass can build on the last one without relying on chat history.

## Sources

- Confirmed: EasyViewer Pro Android APK was downloaded and inspected under `/tmp/easyviewer-analysis`.
- Confirmed: `libEasy4IpComponent-arm64.so` contains the useful protocol implementation, including Dahua `Tou` symbols for request generation, relay state handling, WSSE helpers, PTCP, and device-password authentication.
- Confirmed: Useful native symbols include:
  - `Dahua::Tou::CP2PSDKChannelClient::generateRequest`
  - `Dahua::Tou::GenerateRequest`
  - `Dahua::Tou::GenerateContent`
  - `Dahua::Tou::phttp_generate`
  - `Dahua::Tou::CP2PLinkThroughRelay::packetP2PChannelRequest`
  - `Dahua::Tou::CP2PLinkThroughRelay::packetRelayChannelRequest`
  - `Dahua::Tou::CDevicePasswordAuth::*`
- Confirmed: a PCAPdroid capture from EasyViewer Pro was inspected on 2026-06-30. It validates several static findings and corrects a few assumptions called out below.

## SDK Request Model

Confirmed: the SDK request object layout is approximately:

```text
offset  field
0x00    CSeq / sequence number
0x08    path or request target string
0x10    device id / host-related string
0x18    username / auth-related string
0x20    std::map<string, string> body fields
```

Confirmed: `CP2PSDKChannelClient::generateRequest` builds an internal `HttpReqPars`, calls `GenerateRequest`, then serializes it with `phttp_generate`.

Confirmed: the wire format is HTTP-like over UDP/TCP, not plain XML. Request formatting includes these strings:

```text
%s %s HTTP/1.1\r\n
Host: %s\r\n
X-HSPV: %s\r\n
Date: %s\r\n
X-Version: %s\r\n
x-pcs-request-id: %s\r\n
X-ToUType: %s\r\n
CSeq: %d\r\n
Authorization: WSSE profile="UsernameToken"\r\n
X-WSSE: UsernameToken Username="%s", PasswordDigest="%s", Nonce="%s", Created="%s"\r\n
Content-Type: %s\r\n
Content-Length: %d\r\n
```

Confirmed: observed method strings include `DHGET`, `NFGET`, `GET`, and `NFPOST`.

Confirmed from PCAPdroid: EasyViewer Pro used `NFGET` and `NFPOST` for the captured setup flow.

Implementation status:

- Implemented: Rust emits `NFGET` and `NFPOST` by default to match the PCAPdroid capture.

Confirmed from PCAPdroid: EasyViewer Pro requests include additional headers not currently emitted by Rust:

```text
X-Version: 6.7.11
X-TSVersion: TS_1.1.4
x-pcs-request-id: ...
X-ToUType: Client/Dmss_Android
```

Implementation status:

- Implemented: Rust emits `X-Version`, `X-TSVersion`, `x-pcs-request-id`, and `X-ToUType` headers with captured SDK-style values by default.

## XML Body Serialization

Confirmed: `GenerateContent(map, string)` serializes request bodies from a `std::map<string, string>`.

Confirmed: if the map contains the special key `body`, the SDK uses that value directly as the body content.

Confirmed: otherwise the SDK serializes the sorted map as:

```xml
<body><Key>Value</Key><OtherKey>OtherValue</OtherKey></body>
```

Likely: because `std::map` is ordered, SDK-generated XML fields are sorted by key, not insertion order. The server probably does not care, but matching SDK output is low-cost.

Open: escaping behavior for XML special characters was not fully audited. Current known values are simple addresses, identifiers, numbers, and auth strings.

## Relay Setup Endpoints

### Bootstrap

Confirmed endpoints:

```text
/online/p2psrv
/online/relay
```

Current Rust behavior in `src/transport/handshake.rs` already requests these endpoints and extracts `body/Address`.

### P2P Channel

Confirmed SDK endpoint:

```text
/device/{serial}/p2p-channel
```

Confirmed SDK body keys from `CP2PMessageParser::addr2MsgRelay`:

```text
Identify
PubAddr
```

Confirmed from PCAPdroid: EasyViewer Pro's captured `p2p-channel` request did not include `PubAddr`; it included `LocalAddr` and auth-related fields. The `p2p-channel` response did include `PubAddr`.

Captured `p2p-channel` request body keys:

```text
CreateDate
DevAuth
Identify
IpEncrpt
LocalAddr
NatValueT
Nonce
TransType
UserName
version
```

Confirmed value formats:

- `Identify`: 8-byte client identifier formatted as lowercase hex bytes separated by spaces.
- `PubAddr`: local/public candidate address formatted as `ip:port`.

Likely: SDK may also understand response keys such as `PubAddr`, `LocalAddr`, and `PortMapAddr`; `msg2Addr` checks multiple candidate address keys.

Current Rust body:

```xml
<body><Identify>...</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>127.0.0.1:{port}</LocalAddr><version>5.0.0</version></body>
```

Implementation status:

- Local experiment: request `PubAddr` was removed to better match the PCAPdroid request.
- Local experiment: `CreateDate`, `Nonce`, `NatValueT=268435455`, `TransType=1`, and `version=6.7.11` were added.
- Open: `UserName` and `DevAuth` remain absent until the auth algorithm is reconstructed.
- Result: failed local runtime validation when bundled with the other PCAP-matching changes. Reverted locally to the previous working request shape: `Identify`, `IpEncrpt`, `LocalAddr`, `PubAddr`, and `version=5.0.0`.

Protocol delta:

- Local experiment: align the non-auth fields with the captured request.
- Open: captured EasyViewer Pro request uses `UserName` and `DevAuth`; Rust does not.

### Relay Agent Allocation

Confirmed SDK endpoint:

```text
/relay/agent
```

Confirmed SDK body:

```xml
<body><Dev>{serial}</Dev></body>
```

Current Rust behavior sends `/relay/agent` with no body.

Protocol delta:

- Implemented: send `Dev={serial}` in the `/relay/agent` request.

### Relay Start

Confirmed SDK endpoint:

```text
/relay/start/{token}
```

Confirmed SDK body keys:

```text
Client
Dev
```

Confirmed value formats:

- `Client`: static analysis suggested the relay socket local address, but PCAPdroid captured `:0`.
- `Dev`: camera/device serial.

Current Rust body:

```xml
<body><Client>:0</Client></body>
```

Protocol delta:

- Implemented: send `Client=:0` and `Dev={serial}` by default to match the PCAPdroid capture.

### Relay Channel

Confirmed SDK endpoint:

```text
/device/{serial}/relay-channel
```

Confirmed SDK body keys:

```text
agentAddr
Nonce
CreateDate
DevAuth
```

Confirmed optional SDK body keys when configured:

```text
UserName
RandSalt
```

Confirmed value formats:

- `agentAddr`: relay agent address returned by `/relay/agent`.
- `Nonce`: random integer string.
- `CreateDate`: adjusted Unix timestamp string. The SDK maintains a server time offset after auth failures.
- `UserName`: camera/device username, if present.
- `RandSalt`: random salt, if present.
- `DevAuth`: encrypted device-password authentication value.
- `TransType`: captured as `1` in PCAPdroid for relay and P2P channel requests.

Current Rust body:

```xml
<body><agentAddr>{agent}</agentAddr></body>
```

Protocol delta:

- Implemented: add `Nonce`, `CreateDate`, and `TransType=1` by default even before implementing credential-backed auth.
- Auth-dependent candidate: add `UserName`, `RandSalt`, and `DevAuth` only when camera credentials are configured or when protocol compatibility requires it.

## PCAPdroid Capture Findings

Confirmed capture: `/mnt/c/dev/_temp/PCAPdroid_30_Jun_12_03_20.pcap`, recorded from EasyViewer Pro on 2026-06-30.

Confirmed high-level flow:

```text
NFGET  /online/stun
NFGET  /p2p/stun/probe
NFGET  /online/p2psrv/{serial}
NFGET  /probe/device/{serial}
NFGET  /info/device/{serial}
NFGET  /online/relay
NFPOST /device/{serial}/local-channel
NFPOST /device/{serial}/tcprelay-channel
NFPOST /device/{serial}/p2p-channel
NFPOST /relay/agent
NFPOST /relay/start/{token}
NFPOST /device/{serial}/relay-channel
POST   /tcprelay/client-bind
```

Confirmed: EasyViewer Pro appears to attempt multiple connection strategies in parallel: local broadcast, TCP relay, P2P channel, and UDP relay channel.

Confirmed captured request body keys:

```text
/relay/agent:
  Dev

/relay/start/{token}:
  Client
  Dev

/device/{serial}/p2p-channel:
  CreateDate
  DevAuth
  Identify
  IpEncrpt
  LocalAddr
  NatValueT
  Nonce
  TransType
  UserName
  version

/device/{serial}/relay-channel:
  CreateDate
  DevAuth
  Nonce
  TransType
  UserName
  agentAddr

/device/{serial}/local-channel:
  CreateDate
  DevAuth
  Nonce
  UserName

/device/{serial}/tcprelay-channel:
  CreateDate
  DevAuth
  Nonce
  UserName
```

Confirmed captured values and formats:

- `/relay/start/{token}` sent `Client=:0`.
- `TransType` was `1` in captured P2P/relay-channel requests.
- `version` was `6.7.11`.
- `NatValueT` was `268435455`.
- `LocalAddr` contained comma-separated encoded/private address candidates and the local UDP port.
- `CreateDate` was a Unix timestamp-like integer adjusted relative to local/server time.

Open: determine which of `DevAuth`, `TransType`, `NatValueT`, and method/header differences are required for long-term stability versus only needed for broader compatibility.

## Accepted Local Protocol Parity

The following PCAP-derived behaviors have been promoted from local experiment flags to default behavior after successful local runtime testing:

- `NFGET` and `NFPOST` methods.
- SDK-style headers: `X-Version`, `X-TSVersion`, `x-pcs-request-id`, and `X-ToUType`.
- `/relay/start/{token}` body uses `Client=:0` and `Dev={serial}`.
- `/device/{serial}/relay-channel` includes `CreateDate`, `Nonce`, `TransType=1`, and `agentAddr`.

## Relay Candidate Startup Reliability

Confirmed from local logs: some `/online/relay` responses return a relay server that never answers `/relay/agent`. Before the fast-timeout change, that dead candidate consumed the full outer 15 second handshake timeout before the process retried and discovered a different relay.

Implemented local behavior:

- `/relay/agent` connect/send/read has a 2 second per-step timeout.
- `/relay/start/{token}` connect/send/read has a 2 second per-step timeout.
- On timeout, the existing outer server loop restarts the handshake and can discover a different relay candidate.

Open: if this proves useful, consider retrying relay discovery inside one `p2p_handshake` call instead of relying on the outer restart/backoff loop.

## Device Auth Findings

Confirmed: `DevAuth` is not the same as the HTTP WSSE header. It is generated by `Dahua::Tou::CDevicePasswordAuth`.

Confirmed: the SDK uses this intermediate MD5 seed format:

```text
{username}:Login to {rand_salt}:{password}
```

Confirmed: the native format string is:

```text
%s:Login to %s:%s
```

Confirmed: `getDevicePwdMd5` calls `calcMd5(..., uppercase=true)`, so the MD5 output is uppercase hexadecimal.

Confirmed by the public `khoanguyen-3fc/dh-p2p` implementation:

```text
key = uppercase_md5("{username}:Login to {rand_salt}:{password}")
DevAuth = base64(hmac_sha256(key, "{nonce}{create_date}{payload}"))
```

Local experiment result:

- Failed local runtime validation. Adding `UserName`, `RandSalt`, `Nonce`, `CreateDate`, `DevAuth`, and encrypted `LocalAddr` caused `/device/{serial}/p2p-channel` to receive no device-channel response and the handshake timed out before relay-channel setup.
- Rolled back locally; do not re-enable without an exact EasyViewer Pro request-body capture or a native test vector for this device.

Confirmed AES-related constants found in the native library:

```text
PROXY_AES_DEVAUTH_IV  = "2z52*lk9o6HRyJrf"
PROXY_AES_DEVINFO_IV  = "MydvJw*Iw1w&i^kk"
PROXY_AES_DEVINFO_KEY = "kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf"
```

Open: confirm whether this default `RandSalt` is universal enough for EasyViewer Pro, or whether we need to fetch `/info/device/{serial}` before channel requests.

Open: determine whether unauthenticated cameras can ignore missing `DevAuth` forever, or whether relay leases eventually require authenticated renewal.

## Relay State Machine And Timing

Confirmed: relay response handlers treat status codes specially:

- `100`: continue / wait for final response.
- `200`: success.
- `401`: auth failure path; server time can be parsed and used to update local offset.
- Other errors: transition to failure states.

Confirmed constants observed in native global data:

```text
auth retry limit: 3
short wait:       500 ms
long wait:        10 seconds
```

Likely: the SDK does not immediately abandon the relay flow on the first auth-related response. It retries after updating server time offset.

Current Rust behavior has a fixed retry loop for relay channel confirmation and a `500ms` wait, but does not implement server-time offset updates or auth retries.

### Native Relay Retry State Machine

Confirmed from `CP2PLinkThroughRelay::heartbeat`, its decoded state jump table, and handlers such as `onChannelInit`, `onWaitRelayConfig`, `onGetRelaySuccess`, `onWaitAgentConfig`, `onGetAgentSuccess`, `onWaitStartInfo`, `onResponseRelayStart`, and `onBindSuccess`.

The SDK does not perform relay setup as one blocking sequence. It runs a heartbeat-driven state machine:

```text
0   onChannelInit       -> send /online/relay
1   onWaitRelayConfig   -> wait for /online/relay response
2   onGetRelaySuccess   -> send /relay/agent
5   onWaitAgentConfig   -> wait for /relay/agent response
6   onGetAgentSuccess   -> send /relay/start/{token}
16  onWaitStartInfo     -> wait for /relay/start response
17  onBindSuccess       -> send p2p-channel or relay-channel bind request
20  ICE/start wait path
22  success notification path
3/4/7/8/19/23/24 terminal/error paths
```

The request wait windows use a small retry/backoff value stored at object offset `0x14d0`:

- First request wait is `500ms`.
- If a stage times out and resends, the next window doubles.
- Successful responses reset this value back to `0`.

The wait handlers also compare the current heartbeat time against the relay object's start timestamp plus `10,000ms`. That acts as the overall cap for the early relay setup flow; once exceeded, the SDK moves to a terminal/error state instead of continuing to wait forever.

Per-stage retry behavior:

- `/online/relay`: `onChannelInit` sends the request and moves to `onWaitRelayConfig`. If the short deadline expires, it returns to state `0` and sends `/online/relay` again. If the 10s cap is crossed, it goes to a failure state.
- `/relay/agent`: after `/online/relay` succeeds, `onGetRelaySuccess` sends `/relay/agent` and moves to `onWaitAgentConfig`. Short timeout returns to state `2`, resending `/relay/agent`. The 10s cap goes to failure.
- `/relay/start/{token}`: after `/relay/agent` succeeds, `onGetAgentSuccess` sends `/relay/start/{token}` to the agent and moves to `onWaitStartInfo`. Short timeout returns to state `6`, resending `/relay/start`. The 10s cap goes to failure.
- Bind/channel request: after `/relay/start` succeeds, `onBindSuccess` sends either a P2P channel request or a relay-channel request, depending on internal SDK flags/state. This stage also enforces the 10s cap before reporting failure.

`401` responses are special:

- `onRelayResponse` increments an auth failure counter for response code `401`.
- The counter limit is `3`.
- While the counter is not exhausted, the SDK retries the current relevant stage rather than immediately failing.
- When the counter exceeds the limit, the state machine transitions to an error state.

Current implementation delta: `src/transport/handshake.rs` now implements the SDK-derived retry timing for relay setup without fully rewriting the Rust handshake into a heartbeat state machine. `/online/relay`, `/relay/agent`, `/relay/start/{token}`, and relay-channel confirmation use a `500ms` initial wait, doubling wait windows, a `10s` per-stage cap, and up to `3` retries for `401` responses. This keeps the existing linear Rust flow but matches the SDK's observed retry/backoff behavior much more closely.

### Native Relay Shutdown

Confirmed from `CP2PLinkThroughRelay::sendRelayUnbind` and `CP2PLinkThroughRelay::onResponseUnbind`.

The SDK releases a relay allocation with:

```text
/relay/unbind/{token}
```

Important details:

- The endpoint string in native global data is `/relay/unbind/`.
- The SDK appends the relay token to that endpoint.
- The request is sent to the original relay server address returned by `/online/relay`, not to the allocated relay agent returned by `/relay/agent`.
- The SDK sends this as an asynchronous request through `CP2PSDKChannelClient::sendRequest`; `onResponseUnbind` only logs the response code and returns success.

Current implementation status: `src/transport/handshake.rs` now stores the original relay server address in `RelayLease` and sends `/relay/unbind/{token}` to that relay server during best-effort shutdown. Previous local behavior sent `/relay/stop/{token}` to the relay agent, which does not match the native SDK and may explain stale relay allocations after local restarts.

Runtime observation: after rapid Ctrl-C/restart cycles, `/relay/unbind/{token}` returns `200 OK`, but the next relay-channel confirmation may require additional retry attempts. Waiting roughly 10 seconds before starting the app again allowed one run to connect on the first relay-channel attempt, but later tests showed that a post-unbind sleep does not fix the accumulating retry pattern. The local implementation no longer sleeps after unbind; the remaining issue is likely a missing protocol-level teardown step before relay release.

Implementation correction: relay-mode shutdown now sends `/relay/unbind/{token}` from the existing relay/PTCP UDP socket instead of creating a new UDP socket. This preserves the same local source port and NAT mapping used for `/relay/agent`, `/relay/start`, relay-channel confirmation, and PTCP. The native SDK appears to send teardown through its existing channel client object, so a successful `200 OK` from a new source port may not be enough to clear the device/agent-side relay channel state promptly.

Follow-up observation: rapid restarts can show an accumulating number of missed relay-channel confirmations. A local experiment changed relay-channel setup to send only one `/device/{serial}/relay-channel` request per relay allocation and then fail fast. Result: worse local startup behavior; the app repeatedly failed to connect and supervisor backoff grew. Reverted to in-stage relay-channel retries, which at least allows later confirmations to connect.

Shutdown investigation update: native proxy/PTCP teardown has explicit per-stream control messages (`sendPause`, `sendAck`, and state ACKs), while relay unbind is issued from the relay lifecycle path rather than the relay object's destructor. In the Rust implementation, the data-plane writer was able to exit as soon as the shutdown watch changed, before `main.rs` enqueued best-effort `DISC` frames for active realms. That did not explain idle restarts with zero active realms, but it was a real mismatch for shutdowns while VLC/RTSP clients are active. The writer now drains `PTCPEvent` messages until the channel closes so queued `DISC` frames are sent before relay release.

Runtime correction: one local tree still initialized relay-channel confirmation with the generic setup wait (`500ms`), causing duplicate `/device/{serial}/relay-channel` requests when the agent confirmation arrived slightly after 500ms. The relay-channel stage now starts at `2s` and backs off within the 10s cap. This does not solve the rapid-restart accumulation, but it avoids the worse behavior caused by failing every relay allocation after a single missed confirmation.

Rejected hypothesis: using one connected UDP socket while switching between the main server and relay agent might drop cross-peer packets at the OS level. A local experiment disconnected the UDP socket after sending `/device/{serial}/relay-channel` and waited for the confirmation without peer filtering. Result: worse; relay-channel confirmation timed out completely. Reverted to the connected-agent receive path.

## Current Implementation Deltas

These are the main known differences between the SDK and `src/transport/handshake.rs`.

### Low-Risk Candidates

- Implemented: send `<Dev>{serial}</Dev>` on `/relay/agent`.
- Implemented: send `<Dev>{serial}</Dev>` on `/relay/start/{token}`.
- Implemented: match captured `/relay/start` by sending `<Client>:0</Client>`.
- Local experiment: remove request `PubAddr`; PCAPdroid captured `PubAddr` in the response but not the request.
- Implemented: add `Nonce` and `CreateDate` for `/device/{serial}/relay-channel`.
- Implemented: log sanitized outgoing body key names for relay setup requests, mirroring the existing response `body_keys` logging.

### Medium-Risk Candidates

- Local experiment: match captured `/relay/start` by sending `<Client>:0</Client>`.
- Local experiment: remove request `PubAddr` unless further testing shows it helps.
- Partially implemented: add captured non-auth-ish constants. `TransType=1` is enabled for relay-channel; `NatValueT` and captured `version=6.7.11` remain unimplemented for p2p-channel.
- Implemented: switch DHGET/DHPOST to NFGET/NFPOST.
- Implemented: add captured SDK headers (`X-Version`, `X-TSVersion`, `x-pcs-request-id`, `X-ToUType`).
- Implemented locally: match SDK retry limits for relay setup (`3` auth retries, `500ms` initial wait with backoff, `10s` per-stage cap).
- Add server-time-offset tracking based on `401` responses.

### Auth-Dependent Candidates

- Add optional camera credentials to config or environment.
- Implement `UserName` and `DevAuth`.
- Determine whether `RandSalt` is only used in other SDK paths; the PCAPdroid channel requests used `UserName` and `DevAuth` but did not show `RandSalt`.
- Add test vectors from either a controlled SDK run or a small native harness.

## Suggested Iterations

### Iteration 1: Non-Auth Relay Body Parity

Goal: match SDK request bodies where credentials are not required.

Status: implemented in `src/transport/handshake.rs`; needs live runtime validation.

Tasks:

- Done: update `/relay/agent` to include `Dev`.
- Done: update `/relay/start/{token}` to include real `Client` and `Dev`.
- Done: add `Nonce` and `CreateDate` to `/relay-channel`.
- Done: add focused tests for body generation helpers.
- Run locally long enough to cross the previous 30-minute instability window.

Expected outcome: fewer unexplained relay lease or agent-side oddities without adding credential handling.

### Iteration 2: P2P Candidate Address Parity

Goal: align `p2p-channel` candidate fields with SDK behavior.

Tasks:

- Add `PubAddr`.
- Decide whether to keep or remove `LocalAddr`, `IpEncrpt`, and `version`.
- Compare server responses and body keys before and after the change.

Expected outcome: clearer understanding of whether current direct/relay fallback behavior depends on non-SDK fields.

### Iteration 3: DevAuth Reconstruction

Goal: implement authenticated relay-channel requests correctly.

Tasks:

- Finish static mapping of `CDevicePasswordAuth::calcDevPwdAuth`.
- Reconstruct exact AES/OFB key, IV, plaintext, and output encoding.
- Produce deterministic test vectors with fake credentials if possible.
- Add optional credential configuration without logging secrets.

Expected outcome: support devices/accounts that return `401` during relay setup.

### Iteration 4: Dynamic Validation

Goal: validate static findings against real SDK traffic.

Tasks:

- Capture EasyViewer Pro traffic from an Android device or emulator.
- Compare request bodies and headers against this implementation.
- Confirm retry timing and server-time offset behavior.
- Update this file with packet-derived evidence.

Expected outcome: reduce uncertainty around fields that are hard to prove statically.

## Operational Notes

- Do not commit serial numbers, passwords, relay tokens, or captured auth material.
- Prefer sanitized logs: body key names, response codes, token lengths, and address presence are useful; raw credentials and auth blobs are not.
- Update this file after each reverse-engineering pass, especially when a finding moves from `Likely` or `Open` to `Confirmed`.
