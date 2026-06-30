# RTSP Streaming with Dahua P2P Protocol Implementation

This is a proof of concept implementation of RTSP over Dahua P2P protocol. It works with Dahua and derived cameras / NVRs.

## Motivation

The Dahua P2P protocol is utilized for remote access to Dahua devices. It is commonly used by Dahua apps such as [gDMSS Lite](https://play.google.com/store/apps/details?id=com.mm.android.direct.gdmssphoneLite) on Android or [SmartPSS](https://dahuawiki.com/SmartPSS), [KBiVMS](https://kbvisiongroup.com/support/download-center.html) on Windows.

In my specific scenario, I have a KBVision CCTV system. Although I can access the cameras using the KBiVMS client, I primarily use non-Windows platforms. Therefore, I wanted to explore alternative options for streaming the video using an RTSP client, which is more widely supported. As a result, I decided to experiment with reimplementing the Dahua P2P protocol.

## Files

- Rust implementation:
  - `src/*.rs` - Rust source files
  - `Cargo.toml` - Rust dependencies
- Python implementation:
  - `main.py` - Main script
  - `helpers.py` - Helper functions
  - `requirements.txt` - Python dependencies
- Others:
  - `dh-p2p.lua` - Wireshark dissector for Dahua P2P protocol

## Rust implementation

Rust implementation utilizing async programming and message passing pattern, making it more efficient and flexible.

### Building and running locally

See `BUILDING.md` for the canonical local workflow. In particular, build release binaries with:

```bash
CARGO_TARGET_DIR=target cargo build --release
```

`run.sh` executes `./target/release/dh-p2p`, so using an alternate Cargo target directory can leave `run.sh` running a stale binary.

### Rust usage

```text
A PoC implementation of TCP tunneling over Dahua P2P protocol.

Usage: dh-p2p [OPTIONS] <SERIAL>

Arguments:
  <SERIAL>  Serial number of the camera

Options:
  -p, --port <[bind_address:]port:remote_port>
          Bind address, port and remote port. Default: 127.0.0.1:1554:554
  -r, --relay
          Relay mode (experimental)
  -b, --buffer-ms <ms>
          Jitter buffer duration in milliseconds (0 to disable). Default: 0
  -d, --drop-policy <policy>
          Drop policy for slow clients: block|drop_newest|keep_latest (default: block)
  -H, --health-interval-secs <secs>
          Interval for periodic health logs (default: 60)
      --heartbeat-interval-secs <secs>
          PTCP heartbeat send interval in seconds (default: 10)
      --heartbeat-missed-limit <count>
          Consecutive heartbeat intervals without inbound PTCP activity before restart (default: 1)
      --heartbeat-timeout-grace-secs <secs>
          Extra grace period before restarting an inactive PTCP session (default: 0)
  -e, --enable-probe
          Enable HTTP probe server for liveness/readiness (/livez, /readyz)
  -P, --probe-port <port>
          HTTP probe listen port (default: 8080)
  -v, --verbose...
          Increase verbosity (-v for debug, -vv for trace)
  -h, --help
          Print help
```

### HTTP probes

When `--enable-probe` is set, an internal HTTP server exposes:
- `/livez`: always 200 OK while the process runs.
- `/readyz`: 200 OK only after PTCP handshake succeeds and heartbeat/activity is healthy; otherwise 503.

Configure probe port with `--probe-port` (default 8080). Intended for Kubernetes liveness/readiness probes.

### PTCP heartbeat and inactivity watchdog

The Rust proxy sends PTCP heartbeats every `--heartbeat-interval-secs` and restarts the PTCP session if no inbound PTCP activity is observed for:

```text
heartbeat_interval_secs * heartbeat_missed_limit + heartbeat_timeout_grace_secs
```

The default is `10 * 1 + 0 = 10` seconds. The 10-second heartbeat cadence matches the native SDK's PTCP keepalive interval, while the shorter watchdog reduces video loss during silent relay stalls. If an active PTCP heartbeat, bind, payload, or ACK send returns `ECONNREFUSED`, the proxy requests an immediate restart instead of waiting for the watchdog. For Kubernetes deployments, keep these values explicit in the manifest so watchdog behavior is obvious during operations.

### Jitter Buffer

Since the Dahua P2P protocol uses UDP, packets may arrive out of order. The optional jitter buffer (`-b`) helps smooth out video streaming by:

- Buffering incoming packets for the specified duration (in milliseconds)
- Releasing them in the correct sequence order
- Dropping late packets that arrive after the buffer window

**Usage:**
```bash
# No buffering (default, direct passthrough)
./dh-p2p YOUR_SERIAL

# 100ms buffer - good for most networks
./dh-p2p YOUR_SERIAL -b 100

# 200ms buffer - for higher latency/jitter networks
./dh-p2p YOUR_SERIAL -b 200
```

**Tradeoffs:**
- Longer buffer = better reordering, but adds latency to all packets
- Shorter buffer = lower latency, but smaller reordering window
- For typical video streaming, 50-200ms is usually sufficient

### Graceful shutdown

The Rust server handles `SIGTERM`/`SIGINT` (Ctrl+C). On shutdown it:
- Stops accepting new TCP clients and lets heartbeat/IO tasks exit via a shared shutdown signal.
- Sends a PTCP `DISC` status to every active realm before closing channels so devices can tear down cleanly.

This makes it friendlier for containers/orchestrators (e.g., Kubernetes rolling updates) by reducing dropped connections during termination.

### Logging

The application supports configurable log levels via the `-v` flag:

| Flag | Level | Description |
|------|-------|-------------|
| (none) | INFO | User-facing messages only (session status, connections) |
| `-v` | DEBUG | Protocol flow (requests, responses, packet types) |
| `-vv` | TRACE | Full wire-level details (raw bytes, packet dumps) |

You can also use the `RUST_LOG` environment variable for fine-grained control:

```bash
RUST_LOG=trace ./dh-p2p YOUR_SERIAL
```

## Python implementation

The Python implementation of DH-P2P is a simple and straightforward approach. It is used for drafting and testing purposes due to its quick and easy-to-write nature. Additionally, the implementation is more linear and follows a top-down execution flow, making it easier to understand. Python, being a popular programming language, further contributes to its accessibility and familiarity among developers.

### Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
python main.py [CAMERA_SERIAL]

# Stream (e.g. with ffplay) rtsp://[username]:[password]@127.0.0.1/cam/realmonitor?channel=1&subtype=0
ffplay -rtsp_transport tcp -i "rtsp://[username]:[password]@127.0.0.1/cam/realmonitor?channel=1&subtype=0"
```

### Python usage

To use the script with a device that requires authentication when creating a channel, use the `-t 1` option.

When running in `--debug` mode or when the `--type` > 0, the `USERNAME` and `PASSWORD` arguments are mandatory. Additionally, make sure that `ffplay` is in the system path when debug mode is enabled.

```text
usage: main.py [-h] [-u USERNAME] [-p PASSWORD] [-d] serial

positional arguments:
  serial                Serial number of the camera

options:
  -h, --help            show this help message and exit
  -d, --debug           Enable debug mode
  -t TYPE, --type TYPE  Type of the camera
  -u USERNAME, --username USERNAME
                        Username of the camera
  -p PASSWORD, --password PASSWORD
                        Password of the camer
```

### Limitations

- Single threaded, so only one client can connect at a time
- Polling based, so it's inefficient and inflexible
- Not fully implemented (e.g. only simplex keep-alive, no mulpile connections, etc.)
- Work better with `ffplay` and `-rtsp_transport tcp` option
- Still unstable, can crash at any time

## Protocol description

For reverse engineering the protocol, I used [Wireshark](https://www.wireshark.org/) and [KBiVMS V2.02.0](https://kbvisiongroup.com/support/download-center.html) as a client on Windows. Using `dh-p2p.lua` dissector, you can see the protocol in Wireshark easier.

For RTSP client, either [VLC](https://www.videolan.org/vlc/) or [ffplay](https://ffmpeg.org/ffplay.html) can be used for easier control of the signals.

### Overview

```mermaid
graph LR
  App[[This script]]
  Service[Easy4IPCloud]
  Device[Camera/NVR]
  App -- 1 --> Service
  Service -- 2 --> Device
  App <-. 3 .-> Device
```

The Dahua P2P protocol initiates with a P2P handshake. This process involves locating the device using its Serial Number (SN) via a third-party service, Easy4IPCloud:

1. The script queries the service to retrieve the device's status and IP address.
2. The service then communicates with the device to prepare it for connection.
3. Finally, the script establishes a connection with the device.

```mermaid
graph LR
  Device[Camera/NVR]
  App[[This script]]
  Client1[RTSP Client 1]
  Client2[RTSP Client 2]
  Clientn[RTSP Client n]
  Client1 -- TCP --> App
  Client2 -- TCP --> App
  Clientn -- TCP --> App
  App <-. UDP\nPTCP protocol .-> Device
```

Following the P2P handshake, the script begins to listen for RTSP connections on port 554. Upon a client's connection, the script initiates a new realm within the PTCP protocol. Essentially, this script serves as a tunnel between the client and the device, facilitating communication through PTCP encapsulation.

### P2P handshake

```mermaid
sequenceDiagram
  participant A as This script
  participant B as Easy4IPCloud
  participant C1 as P2P Server
  participant C2 as Relay Server
  participant C3 as Agent Server
  participant D as Camera/NVR

  A->>B: /probe/p2psrv
  B-->>A: ;
  A->>B: /online/p2psrv/{SN}
  B-->>A: p2psrv info

  A->>C1: /probe/device/{SN}
  C1-->>A: ;

  A->>C1: /info/device/{SN}
  C1-->>A: [randsalt]

  A->>B: /online/relay
  B-->>A: relay info

  A->>B: /device/{SN}/p2p-channel (*)

  par
    A->>C2: /relay/agent
    C2-->>A: agent info + token
    A->>C3: /relay/start/{token}
    C3-->>A: ;
  end

  B-->>A: device info

  A->>B: /device/{SN}/relay-channel + agent info

  C3-->>A: Server Nat Info!
  A->>C3: PTCP SYN
  A->>C3: PTCP request sign
  C3-->>A: PTCP sign

  A->>D: PTCP handshake (*)
```

_Note_: Both connections marked with `(*)` and all subsequent connections to the device must use the same UDP local port.

### PTCP protocol

PTCP (PhonyTCP) is a proprietary protocol developed by Dahua. It serves the purpose of encapsulating TCP packets within UDP packets, enabling the creation of a tunnel between a client and a device behind a NAT.

Please note that official documentation for PTCP is not available. The information provided here is based on reverse engineering.

### PTCP packet header

The PTCP packet header is a fixed 24-byte structure, as outlined below:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             magic                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             sent                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             recv                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             pid                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             lmid                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             rmid                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `magic`: A constant value, `PTCP`.
- `sent` and `recv`: Track the number of bytes sent and received, respectively.
- `pid`: The Packet ID.
- `lmid`: The Local ID.
- `rmid`: The Local ID of previously received packet.

### PTCP packet body

The packet body varies in size (0, 4, 12 bytes or more) based on the packet type. Its structure is as follows:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      type       |                     len                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             realm                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             padding                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `type`: Specifies the packet type.
- `len`: The length of the `data` field.
- `realm`: The Realm ID of the connection.
- `padding`: Padding bytes, always set to 0.
- `data`: The packet data.

Packet types:

- Special:
  - Empty body
  - `0x00`: SYN, the body is always 4 bytes `0x00030100`.
- Realm:
  - `0x10`: TCP data, where `len` is the length of the TCP data.
  - `0x11`: Binding port request.
  - `0x12`: Connection status, where the data is either `CONN` or `DISC`.
- Common (with `realm` set to 0):
  - `0x13`: Heartbeat, where `len` is always 0.
  - `0x17`
  - `0x18`
  - `0x19`: Authentication.
  - `0x1a`: Server response after `0x19`.
  - `0x1b`: Client response after `0x1a`.

## Acknowledgments

This project has been inspired and influenced by the following projects and people:

- [mcw0/PoC](https://github.com/mcw0/PoC): The foundational structure for the handshake and the PTCP protocol.
- [@p2p-sys](https://github.com/p2p-sys): The idea of inverting the STUN protocol.
