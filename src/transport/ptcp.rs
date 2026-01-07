// Moved from ptcp.rs
use async_trait::async_trait;
use log::{debug, trace};
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
    fn parse(data: &[u8]) -> PTCPPayload {
        assert!(data.len() >= 12, "Invalid payload");
        assert_eq!(data[0], 0x10, "Invalid header");

        let header = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let length = header & 0xFFFF;
        let realm = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let padding = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data = data[12..].to_vec();

        assert_eq!(padding, 0, "Invalid padding");
        assert_eq!(length, data.len() as u32, "Invalid length");

        PTCPPayload { realm, data }
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
    fn parse(data: &[u8]) -> PTCPBody {
        if data.len() == 0 {
            return PTCPBody::Empty;
        }

        assert!(data.len() >= 4, "Invalid body");

        match data[0] {
            0x00 => PTCPBody::Sync,
            0x10 => PTCPBody::Payload(PTCPPayload::parse(data)),
            0x11 => PTCPBody::Bind(
                u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
                u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            ),
            0x12 => {
                let realm = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let status = String::from_utf8_lossy(&data[12..]).to_string();
                PTCPBody::Status(realm, status)
            }
            0x13 => PTCPBody::Heartbeat,
            _ => PTCPBody::Command(data.to_vec()),
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
    fn parse(data: &[u8]) -> PTCPPacket {
        assert!(data.len() >= 24, "Invalid packet");

        let magic = &data[0..4];

        assert_eq!(magic, b"PTCP", "Invalid magic");

        let sent = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let recv = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let pid = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let lmid = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let rmid = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let body = PTCPBody::parse(&data[24..]);

        PTCPPacket {
            sent,
            recv,
            pid,
            lmid,
            rmid,
            body,
        }
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
                e.kind() == io::ErrorKind::ConnectionRefused
                    || e.kind() == io::ErrorKind::ConnectionReset
                    || e.kind() == io::ErrorKind::NotConnected
                    || e.kind() == io::ErrorKind::TimedOut
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
        debug!(">>> {} {:?}", self.peer_addr().unwrap(), packet.body);
        trace!("{:?}", packet);
        packet.try_print_data();
        trace!("---");

        let packet = packet.serialize();
        self.send(&packet).await.map(|_| ()).map_err(|e| {
            log::error!("PTCP send error: {}", e);
            e
        })
    }

    async fn ptcp_read(&self) -> Result<PTCPPacket, PTCPReadError> {
        trace!("### {}", self.peer_addr().unwrap());

        // Larger buffer for video frames
        let mut buf = [0u8; 65535];

        // Timeout on recv to prevent indefinite blocking if network path is black-holed
        const RECV_TIMEOUT_SECS: u64 = 30;
        let recv_result = tokio::time::timeout(
            Duration::from_secs(RECV_TIMEOUT_SECS),
            self.recv(&mut buf),
        )
        .await;

        let n = match recv_result {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                log::error!("PTCP recv error: {}", e);
                return Err(PTCPReadError::Io(e));
            }
            Err(_) => {
                log::warn!("PTCP recv timeout after {}s", RECV_TIMEOUT_SECS);
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

        let packet = PTCPPacket::parse(&buf[0..n]);
        debug!("<<< {} {:?}", self.peer_addr().unwrap(), packet.body);
        trace!("{:?}", packet);
        packet.try_print_data();
        trace!("---");

        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

