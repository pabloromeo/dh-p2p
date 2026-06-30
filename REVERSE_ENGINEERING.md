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
- Open: Findings from static analysis should still be validated against a live EasyViewer Pro packet capture when possible.

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

Confirmed: observed method strings include `DHGET`, `NFGET`, `GET`, and `NFPOST`. The Rust implementation currently uses the Dahua HTTP-like format through `dh_request`; exact method selection should be compared before changing it.

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

Confirmed value formats:

- `Identify`: 8-byte client identifier formatted as lowercase hex bytes separated by spaces.
- `PubAddr`: local/public candidate address formatted as `ip:port`.

Likely: SDK may also understand response keys such as `PubAddr`, `LocalAddr`, and `PortMapAddr`; `msg2Addr` checks multiple candidate address keys.

Current Rust body:

```xml
<body><Identify>...</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>127.0.0.1:{port}</LocalAddr><version>5.0.0</version></body>
```

Implementation status:

- Implemented: `PubAddr={socket.local_addr()}` was added while preserving the existing `IpEncrpt`, `LocalAddr`, and `version` fields for compatibility.

Protocol delta:

- Implemented: add SDK-like `PubAddr={socket.local_addr()}` instead of relying only on hard-coded `127.0.0.1`.
- Open: whether keeping `IpEncrpt`, `LocalAddr`, and `version` helps compatibility or diverges from SDK enough to hurt relay stability.

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

- `Client`: the relay socket's local address formatted as `ip:port`.
- `Dev`: camera/device serial.

Current Rust body:

```xml
<body><Client>:0</Client></body>
```

Implementation status:

- Implemented: send `Client={socket.local_addr()}` and `Dev={serial}`.

Protocol delta:

- Implemented: send the actual socket local address and include `Dev={serial}`.
- Open: if the local address is `0.0.0.0:{port}` after binding, decide whether to send that, discover the route-local IP, or preserve SDK behavior as closely as the OS exposes it.

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

Current Rust body:

```xml
<body><agentAddr>{agent}</agentAddr></body>
```

Implementation status:

- Implemented: add `Nonce` and `CreateDate` to the unauthenticated relay-channel request body.
- Open: `UserName`, `RandSalt`, and `DevAuth` remain unimplemented until the auth path is fully reconstructed.

Protocol delta:

- Implemented: add `Nonce` and `CreateDate` even before implementing credential-backed auth.
- Auth-dependent candidate: add `UserName`, `RandSalt`, and `DevAuth` only when camera credentials are configured.

## Device Auth Findings

Confirmed: `DevAuth` is not the same as the HTTP WSSE header. It is generated by `Dahua::Tou::CDevicePasswordAuth`.

Confirmed: the SDK uses this intermediate MD5 seed format:

```text
{username}:Login to {password}:{rand_salt}
```

Confirmed: the native format string is:

```text
%s:Login to %s:%s
```

Confirmed: `getDevicePwdMd5` calls `calcMd5(..., uppercase=true)`, so the MD5 output is uppercase hexadecimal.

Likely auth flow:

```text
pwd_md5 = uppercase_md5("{username}:Login to {password}:{rand_salt}")
DevAuth = aes_ofb_encrypt_or_derived_auth(pwd_md5, nonce, create_date, constants)
```

Confirmed AES-related constants found in the native library:

```text
PROXY_AES_DEVAUTH_IV  = "2z52*lk9o6HRyJrf"
PROXY_AES_DEVINFO_IV  = "MydvJw*Iw1w&i^kk"
PROXY_AES_DEVINFO_KEY = "kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf"
```

Open: exact `DevAuth` plaintext, key derivation, and AES/OFB output encoding need final reconstruction and test vectors before implementation.

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

## Current Implementation Deltas

These are the main known differences between the SDK and `src/transport/handshake.rs`.

### Low-Risk Candidates

- Implemented: send `<Dev>{serial}</Dev>` on `/relay/agent`.
- Implemented: send real `<Client>{local_ip}:{local_port}</Client>` and `<Dev>{serial}</Dev>` on `/relay/start/{token}`.
- Implemented: add SDK-like `PubAddr` for `/device/{serial}/p2p-channel`.
- Implemented: add `Nonce` and `CreateDate` for `/device/{serial}/relay-channel`.
- Implemented: log sanitized outgoing body key names for relay setup requests, mirroring the existing response `body_keys` logging.

### Medium-Risk Candidates

- Replace the current `LocalAddr=127.0.0.1:{port}` P2P channel body with SDK-like `PubAddr`.
- Match SDK retry limits exactly for relay-channel setup (`3` auth retries, `500ms` short wait, `10s` longer wait).
- Add server-time-offset tracking based on `401` responses.

### Auth-Dependent Candidates

- Add optional camera credentials to config or environment.
- Implement `RandSalt`, `UserName`, and `DevAuth`.
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
