// Moved from ptcp.rs
use async_trait::async_trait;
use log::trace;
use std::cmp;
use std::io;
use std::time::Duration;
use tokio::net::UdpSocket;

pub enum PTCPEvent {
    Heartbeat,
    Connect(u32),
    Disconnect(u32),
    Data(u32, Vec<u8>),
}

pub struct PTCPPayload {
    pub realm: u32,
    pub data: Vec<u8>,
}

pub enum PTCPBody {
    Sync,
    Command(Vec<u8>),
    Payload(PTCPPayload),
    Bind(u32, u32),
    Status(u32, String),
    Heartbeat,
    Empty,
}

pub struct PTCPPacket {
    pub sent: u32,
    recv: u32,
    pid: u32,
    lmid: u32,
    rmid: u32,
    pub body: PTCPBody,
}

impl PTCPPayload {
    fn parse(data: &[u8]) -> Result<PTCPPayload, PTCPReadError> {
        if data.len() < 12 {
            return Err(PTCPReadError::Malformed(format!(
                "invalid payload: expected at least 12 bytes, got {}",
                data.len()
            )));
        }
        if data[0] != 0x10 {
            return Err(PTCPReadError::Malformed(format!(
                "invalid payload header: expected 0x10, got 0x{:02x}",
                data[0]
            )));
        }

        let header = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let length = header & 0xFFFF;
        let realm = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let padding = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data = data[12..].to_vec();

        if padding != 0 {
            return Err(PTCPReadError::Malformed(format!(
                "invalid payload padding: expected 0, got {}",
                padding
            )));
        }
        if length != data.len() as u32 {
            return Err(PTCPReadError::Malformed(format!(
                "invalid payload length: header says {}, body is {}",
                length,
                data.len()
            )));
        }

        Ok(PTCPPayload { realm, data })
    }

    fn serialize(&self) -> Vec<u8> {
        let length = self.data.len() as u32;
        let header = 0x10000000 | length;
        let header = header.to_be_bytes();
        let realm = self.realm.to_be_bytes();
        let padding = 0u32.to_be_bytes();

        [
            header.to_vec(),
            realm.to_vec(),
            padding.to_vec(),
            self.data.clone(),
        ]
        .concat()
    }
}

impl std::fmt::Debug for PTCPPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "length: {}, realm: 0x{:08x}, data: [{}{}]",
            self.data.len(),
            self.realm,
            self.data[0..cmp::min(self.data.len(), 16)]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" "),
            if self.data.len() > 16 { " ..." } else { "" },
        )
    }
}

impl std::fmt::Debug for PTCPBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PTCPBody::Sync => write!(f, "Sync"),
            PTCPBody::Command(data) => write!(
                f,
                "Command([{}])",
                data.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            PTCPBody::Payload(payload) => write!(f, "{:?}", payload),
            PTCPBody::Bind(realm, port) => {
                write!(f, "Bind {{ realm: 0x{:08x}, port: {} }}", realm, port)
            }
            PTCPBody::Status(realm, status) => {
                write!(f, "Status {{ realm: 0x{:08x}, status: {} }}", realm, status)
            }
            PTCPBody::Heartbeat => write!(f, "Heartbeat"),
            PTCPBody::Empty => write!(f, "Empty"),
        }
    }
}

impl std::fmt::Debug for PTCPPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PTCPPacket {{ sent: {}, recv: {}, pid: 0x{:08x}, lmid: 0x{:08x}, rmid: 0x{:08x}, body: {:?} }}",
            self.sent, self.recv, self.pid, self.lmid, self.rmid, self.body
        )
    }
}

impl PTCPBody {
    fn parse_status_body(data: &[u8]) -> Option<(u32, String)> {
        // Status frames are expected to use the fixed 12-byte header:
        // 0x12 00 00 00 <realm:u32> 00 00 00 00 <ascii status>
        if data.len() < 13 || data[1..4] != [0x00, 0x00, 0x00] || data[8..12] != [0, 0, 0, 0] {
            return None;
        }

        let realm = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        // Device statuses we've observed and act on are CONN and DISC*.
        // Other 0x12-prefixed payloads should be treated as opaque commands.
        let raw_status = data[12..].split(|b| *b == 0).next().unwrap_or(&[]).to_vec();
        if raw_status.is_empty() {
            return None;
        }
        if !(raw_status.starts_with(b"CONN") || raw_status.starts_with(b"DISC")) {
            return None;
        }

        let status = String::from_utf8_lossy(&raw_status).trim().to_string();
        if status.is_empty() {
            return None;
        }

        Some((realm, status))
    }

    fn parse(data: &[u8]) -> Result<PTCPBody, PTCPReadError> {
        if data.len() == 0 {
            return Ok(PTCPBody::Empty);
        }

        if data.len() < 4 {
            return Err(PTCPReadError::Malformed(format!(
                "invalid body: expected at least 4 bytes, got {}",
                data.len()
            )));
        }

        match data[0] {
            0x00 => Ok(PTCPBody::Sync),
            0x10 => Ok(PTCPBody::Payload(PTCPPayload::parse(data)?)),
            0x11 => {
                if data.len() < 16 {
                    return Err(PTCPReadError::Malformed(format!(
                        "invalid bind body: expected at least 16 bytes, got {}",
                        data.len()
                    )));
                }
                Ok(PTCPBody::Bind(
                    u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
                    u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
                ))
            }
            0x12 => {
                if data.len() < 12 {
                    return Err(PTCPReadError::Malformed(format!(
                        "invalid status body: expected at least 12 bytes, got {}",
                        data.len()
                    )));
                }
                if let Some((realm, status)) = Self::parse_status_body(data) {
                    Ok(PTCPBody::Status(realm, status))
                } else {
                    Ok(PTCPBody::Command(data.to_vec()))
                }
            }
            0x13 => Ok(PTCPBody::Heartbeat),
            _ => Ok(PTCPBody::Command(data.to_vec())),
        }
    }

    fn serialize(&self) -> Vec<u8> {
        match self {
            PTCPBody::Sync => b"\x00\x03\x01\x00".to_vec(),
            PTCPBody::Command(data) => data.to_vec(),
            PTCPBody::Payload(payload) => payload.serialize(),
            PTCPBody::Bind(realm, port) => [
                b"\x11\x00\x00\x00".to_vec(),
                realm.to_be_bytes().to_vec(),
                b"\x00\x00\x00\x00".to_vec(),
                port.to_be_bytes().to_vec(),
                b"\x7f\x00\x00\x01".to_vec(),
            ]
            .concat(),
            PTCPBody::Status(realm, status) => [
                b"\x12\x00\x00\x00".to_vec(),
                realm.to_be_bytes().to_vec(),
                b"\x00\x00\x00\x00".to_vec(),
                status.as_bytes().to_vec(),
            ]
            .concat(),
            PTCPBody::Heartbeat => b"\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            PTCPBody::Empty => Vec::new(),
        }
    }

    fn len(&self) -> usize {
        match self {
            PTCPBody::Sync => 4,
            PTCPBody::Command(data) => data.len(),
            PTCPBody::Payload(payload) => payload.data.len() + 12,
            PTCPBody::Bind(_, _) => 20,
            PTCPBody::Status(_, status) => status.len() + 12,
            PTCPBody::Heartbeat => 12,
            PTCPBody::Empty => 0,
        }
    }
}

impl PTCPPacket {
    fn parse(data: &[u8]) -> Result<PTCPPacket, PTCPReadError> {
        if data.len() < 24 {
            return Err(PTCPReadError::Malformed(format!(
                "invalid packet: expected at least 24 bytes, got {}",
                data.len()
            )));
        }

        let magic = &data[0..4];

        if magic != b"PTCP" {
            return Err(PTCPReadError::Malformed(format!(
                "invalid packet magic: expected PTCP, got {:02x?}",
                magic
            )));
        }

        let sent = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let recv = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let pid = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let lmid = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let rmid = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let body = PTCPBody::parse(&data[24..])?;

        Ok(PTCPPacket {
            sent,
            recv,
            pid,
            lmid,
            rmid,
            body,
        })
    }

    fn serialize(&self) -> Vec<u8> {
        [
            b"PTCP".to_vec(),
            self.sent.to_be_bytes().to_vec(),
            self.recv.to_be_bytes().to_vec(),
            self.pid.to_be_bytes().to_vec(),
            self.lmid.to_be_bytes().to_vec(),
            self.rmid.to_be_bytes().to_vec(),
            self.body.serialize(),
        ]
        .concat()
    }

    fn try_print_data(&self) {
        if let PTCPBody::Payload(p) = &self.body {
            if p.data.len() > 4 && p.data.iter().all(|b| *b < 0x80) {
                trace!("{}", String::from_utf8_lossy(&p.data));
            }
        }
    }
}

pub struct PTCPSession {
    sent: u32,
    recv: u32,
    count: u32,
    id: u32,
    rmid: u32,
}

impl PTCPSession {
    pub fn new() -> PTCPSession {
        PTCPSession {
            sent: 0,
            recv: 0,
            count: 0,
            id: 0,
            rmid: 0,
        }
    }

    pub fn send(&mut self, body: PTCPBody) -> PTCPPacket {
        let sent = self.sent;
        let recv = self.recv;
        // pid counts down from 0xFFFF, wrapping around every 65536 messages
        // Use modular arithmetic to prevent underflow when count > 0xFFFF
        let pid = match body {
            PTCPBody::Sync => 0x0002FFFF,
            _ => 0x0000FFFF - (self.count & 0xFFFF),
        };
        let lmid = self.id;
        let rmid = self.rmid;

        self.sent += body.len() as u32;

        self.id += 1;
        self.count += match body {
            PTCPBody::Sync => 0,
            PTCPBody::Empty => 0,
            _ => 1,
        };

        PTCPPacket {
            sent,
            recv,
            pid,
            lmid,
            rmid,
            body,
        }
    }

    pub fn recv(&mut self, packet: PTCPPacket) -> PTCPPacket {
        self.recv = packet.sent + packet.body.len() as u32;
        self.rmid = packet.lmid;

        packet
    }
}

/// Error type for PTCP read operations
#[derive(Debug)]
pub enum PTCPReadError {
    /// IO error from the underlying socket
    Io(io::Error),
    /// Received a malformed packet (undersized, invalid magic, etc.)
    /// Contains the error description
    Malformed(String),
}

impl std::fmt::Display for PTCPReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PTCPReadError::Io(e) => write!(f, "IO error: {}", e),
            PTCPReadError::Malformed(msg) => write!(f, "Malformed packet: {}", msg),
        }
    }
}

impl std::error::Error for PTCPReadError {}

impl From<io::Error> for PTCPReadError {
    fn from(e: io::Error) -> Self {
        PTCPReadError::Io(e)
    }
}

impl From<PTCPReadError> for io::Error {
    fn from(e: PTCPReadError) -> Self {
        match e {
            PTCPReadError::Io(io_err) => io_err,
            PTCPReadError::Malformed(msg) => io::Error::new(io::ErrorKind::InvalidData, msg),
        }
    }
}

impl PTCPReadError {
    /// Returns true if this error is fatal and should trigger a restart
    pub fn is_fatal(&self) -> bool {
        match self {
            PTCPReadError::Io(e) => {
                // These errors indicate the connection is dead or unusable
                // Note: TimedOut is NOT fatal - it just means no data arrived in the timeout
                // period. The watchdog will handle genuine connection death.
                //
                // UDP ECONNREFUSED usually means an ICMP error was reported for a prior send.
                // The Dahua SDK appears to tolerate those transient reports and let channel
                // inactivity decide whether the session is actually dead.
                e.kind() == io::ErrorKind::ConnectionReset
                    || e.kind() == io::ErrorKind::NotConnected
            }
            // Malformed packets are not fatal - could be transient network corruption
            PTCPReadError::Malformed(_) => false,
        }
    }
}

#[async_trait]
pub trait PTCP {
    async fn ptcp_request(&self, packet: PTCPPacket) -> io::Result<()>;
    /// Read a PTCP packet from the socket.
    /// Returns Ok(packet) on success, Err on IO error or malformed packet.
    async fn ptcp_read(&self) -> Result<PTCPPacket, PTCPReadError>;
}

#[async_trait]
impl PTCP for UdpSocket {
    async fn ptcp_request(&self, packet: PTCPPacket) -> io::Result<()> {
        if let Ok(peer) = self.peer_addr() {
            trace!(">>> {} {:?}", peer, packet.body);
        } else {
            trace!(">>> <unconnected> {:?}", packet.body);
        }
        trace!("{:?}", packet);
        packet.try_print_data();
        trace!("---");

        let packet = packet.serialize();
        self.send(&packet).await.map(|_| ())
    }

    async fn ptcp_read(&self) -> Result<PTCPPacket, PTCPReadError> {
        if let Ok(peer) = self.peer_addr() {
            trace!("### {}", peer);
        } else {
            trace!("### <unconnected>");
        }

        // Larger buffer for video frames
        let mut buf = [0u8; 65535];

        // Timeout on recv to prevent indefinite blocking if kernel/network stack is stuck
        // This is just a backstop - the watchdog handles genuine connection death
        const RECV_TIMEOUT_SECS: u64 = 60;
        let recv_result =
            tokio::time::timeout(Duration::from_secs(RECV_TIMEOUT_SECS), self.recv(&mut buf)).await;

        let n = match recv_result {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                log::error!("PTCP recv error: {}", e);
                return Err(PTCPReadError::Io(e));
            }
            Err(_) => {
                // This is not fatal - device may just have nothing to send
                // The watchdog will handle genuine connection death
                log::debug!("PTCP recv timeout after {}s, retrying", RECV_TIMEOUT_SECS);
                return Err(PTCPReadError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("UDP recv timeout after {}s", RECV_TIMEOUT_SECS),
                )));
            }
        };

        if n < 24 {
            let msg = format!("undersized packet ({} bytes)", n);
            log::warn!("PTCP: {}", msg);
            return Err(PTCPReadError::Malformed(msg));
        }

        if &buf[0..4] != b"PTCP" {
            let msg = "invalid magic in packet".to_string();
            log::warn!("PTCP: {}", msg);
            return Err(PTCPReadError::Malformed(msg));
        }

        let packet = PTCPPacket::parse(&buf[0..n])?;
        if let Ok(peer) = self.peer_addr() {
            trace!("<<< {} {:?}", peer, packet.body);
        } else {
            trace!("<<< <unconnected> {:?}", packet.body);
        }
        trace!("{:?}", packet);
        packet.try_print_data();
        trace!("---");

        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::panic;

    #[test]
    fn test_pid_calculation_normal() {
        let mut session = PTCPSession::new();

        // First message: count=0, pid = 0xFFFF - 0 = 65535
        let packet = session.send(PTCPBody::Heartbeat);
        assert_eq!(packet.pid, 0x0000FFFF);

        // Second message: count=1, pid = 0xFFFF - 1 = 65534
        let packet = session.send(PTCPBody::Heartbeat);
        assert_eq!(packet.pid, 0x0000FFFE);
    }

    #[test]
    fn test_pid_calculation_at_boundary() {
        let mut session = PTCPSession::new();
        // Manually set count to 65534 (just before wrap boundary)
        session.count = 65534;

        // count=65534, pid = 0xFFFF - 65534 = 1
        let packet = session.send(PTCPBody::Heartbeat);
        assert_eq!(packet.pid, 1);

        // count=65535, pid = 0xFFFF - 65535 = 0
        let packet = session.send(PTCPBody::Heartbeat);
        assert_eq!(packet.pid, 0);

        // count=65536, pid = 0xFFFF - (65536 & 0xFFFF) = 0xFFFF - 0 = 65535
        // This would have been 0xFFFFFFFF without the fix!
        let packet = session.send(PTCPBody::Heartbeat);
        assert_eq!(packet.pid, 0x0000FFFF);

        // count=65537, pid = 0xFFFF - (65537 & 0xFFFF) = 0xFFFF - 1 = 65534
        let packet = session.send(PTCPBody::Heartbeat);
        assert_eq!(packet.pid, 0x0000FFFE);
    }

    #[test]
    fn test_pid_calculation_large_count() {
        let mut session = PTCPSession::new();
        // Set count to a very large value (multiple wraparounds)
        session.count = 200000; // = 3 * 65536 + 3392

        // pid = 0xFFFF - (200000 & 0xFFFF) = 0xFFFF - 3392 = 62143
        let packet = session.send(PTCPBody::Heartbeat);
        assert_eq!(packet.pid, 0x0000FFFF - 3392);
        assert!(packet.pid <= 0xFFFF, "pid should be in 16-bit range");
    }

    #[test]
    fn test_pid_sync_special_case() {
        let mut session = PTCPSession::new();

        // Sync packets have a special pid value
        let packet = session.send(PTCPBody::Sync);
        assert_eq!(packet.pid, 0x0002FFFF);

        // Sync doesn't increment count
        assert_eq!(session.count, 0);
    }

    #[test]
    fn test_pid_empty_doesnt_increment_count() {
        let mut session = PTCPSession::new();

        // Send a regular message first
        session.send(PTCPBody::Heartbeat);
        assert_eq!(session.count, 1);

        // Empty packets don't increment count
        session.send(PTCPBody::Empty);
        assert_eq!(session.count, 1);

        session.send(PTCPBody::Empty);
        assert_eq!(session.count, 1);

        // But regular messages do
        session.send(PTCPBody::Heartbeat);
        assert_eq!(session.count, 2);
    }

    #[test]
    fn test_session_sent_recv_tracking() {
        let mut session = PTCPSession::new();

        // Heartbeat body is 12 bytes
        let packet = session.send(PTCPBody::Heartbeat);
        assert_eq!(packet.sent, 0); // First packet starts at 0
        assert_eq!(session.sent, 12); // After sending, sent = 12

        let packet = session.send(PTCPBody::Heartbeat);
        assert_eq!(packet.sent, 12); // Second packet starts at 12
        assert_eq!(session.sent, 24); // After sending, sent = 24
    }

    #[test]
    fn parse_rejects_undersized_packet() {
        let data = vec![0u8; 10];
        assert!(matches!(
            PTCPPacket::parse(&data),
            Err(PTCPReadError::Malformed(_))
        ));
    }

    #[test]
    fn parse_rejects_invalid_magic() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(b"XXXX");
        assert!(matches!(
            PTCPPacket::parse(&data),
            Err(PTCPReadError::Malformed(_))
        ));
    }

    #[test]
    fn parse_rejects_undersized_bind_body() {
        let mut data = Vec::new();
        data.extend_from_slice(b"PTCP");
        data.extend_from_slice(&0u32.to_be_bytes()); // sent
        data.extend_from_slice(&0u32.to_be_bytes()); // recv
        data.extend_from_slice(&0u32.to_be_bytes()); // pid
        data.extend_from_slice(&0u32.to_be_bytes()); // lmid
        data.extend_from_slice(&0u32.to_be_bytes()); // rmid
        data.extend_from_slice(&[0x11, 0x00, 0x00, 0x00]); // bind tag, too short
        assert!(matches!(
            PTCPPacket::parse(&data),
            Err(PTCPReadError::Malformed(_))
        ));
    }

    #[test]
    fn parse_rejects_invalid_payload_length() {
        let payload = [
            0x10, 0x00, 0x00, 0x05, // header says length 5
            0x00, 0x00, 0x00, 0x01, // realm
            0x00, 0x00, 0x00, 0x00, // padding
            0xaa, 0xbb, // actual payload is 2 bytes
        ];
        assert!(matches!(
            PTCPPayload::parse(&payload),
            Err(PTCPReadError::Malformed(_))
        ));
    }

    #[test]
    fn parse_rejects_invalid_payload_header_byte() {
        let payload = [
            0x11, 0x00, 0x00, 0x02, // invalid header type for payload parser
            0x00, 0x00, 0x00, 0x01, // realm
            0x00, 0x00, 0x00, 0x00, // padding
            0xaa, 0xbb,
        ];
        assert!(matches!(
            PTCPPayload::parse(&payload),
            Err(PTCPReadError::Malformed(_))
        ));
    }

    #[test]
    fn parse_rejects_non_zero_payload_padding() {
        let payload = [
            0x10, 0x00, 0x00, 0x02, // header says length 2
            0x00, 0x00, 0x00, 0x01, // realm
            0x00, 0x00, 0x00, 0x01, // invalid padding
            0xaa, 0xbb,
        ];
        assert!(matches!(
            PTCPPayload::parse(&payload),
            Err(PTCPReadError::Malformed(_))
        ));
    }

    #[test]
    fn parse_rejects_undersized_status_body() {
        let mut data = Vec::new();
        data.extend_from_slice(b"PTCP");
        data.extend_from_slice(&0u32.to_be_bytes()); // sent
        data.extend_from_slice(&0u32.to_be_bytes()); // recv
        data.extend_from_slice(&0u32.to_be_bytes()); // pid
        data.extend_from_slice(&0u32.to_be_bytes()); // lmid
        data.extend_from_slice(&0u32.to_be_bytes()); // rmid
        data.extend_from_slice(&[
            0x12, 0x00, 0x00, 0x00, // status tag
            0x00, 0x00, 0x00, 0x01, // realm
        ]); // only 8 body bytes; status requires at least 12
        assert!(matches!(
            PTCPPacket::parse(&data),
            Err(PTCPReadError::Malformed(_))
        ));
    }

    #[test]
    fn parse_status_accepts_conn_with_trailing_nul() {
        let body = [
            0x12, 0x00, 0x00, 0x00, // status tag
            0x12, 0x34, 0x56, 0x78, // realm
            0x00, 0x00, 0x00, 0x00, // reserved
            b'C', b'O', b'N', b'N', 0x00,
        ];

        let parsed = PTCPBody::parse(&body).expect("status should parse");
        match parsed {
            PTCPBody::Status(realm, status) => {
                assert_eq!(realm, 0x12345678);
                assert_eq!(status, "CONN");
            }
            _ => panic!("expected status body"),
        }
    }

    #[test]
    fn parse_status_like_unknown_payload_falls_back_to_command() {
        let body = [
            0x12, 0x00, 0x0b, 0x34, // 0x12-prefixed payload that is not status
            0x00, 0x00, 0x00, 0x00, // realm-like bytes
            0x00, 0x00, 0x00, 0x00, // reserved-like bytes
            b'+', b'8', b'K',
        ];

        let parsed = PTCPBody::parse(&body).expect("payload should parse");
        match parsed {
            PTCPBody::Command(data) => assert_eq!(data, body),
            _ => panic!("expected command fallback"),
        }
    }

    #[test]
    fn parse_random_inputs_do_not_panic() {
        let mut rng = StdRng::seed_from_u64(0x5EED_1234);
        for _ in 0..2500 {
            let len = rng.gen_range(0..512);
            let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let result = panic::catch_unwind(|| {
                let _ = PTCPPacket::parse(&data);
                let _ = PTCPBody::parse(&data);
                let _ = PTCPPayload::parse(&data);
            });
            assert!(result.is_ok(), "parse panicked for len {}", len);
        }
    }
}
