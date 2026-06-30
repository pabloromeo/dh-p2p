use async_trait::async_trait;
use base64::Engine;
use log::{debug, error, info, trace, warn};
use sha1::Digest;
use std::{
    collections::{BTreeMap, HashMap},
    io,
    net::SocketAddrV4,
    time::Instant,
};
use tokio::{net::UdpSocket, time};
use xml::reader::{EventReader, XmlEvent};

use super::ptcp::{PTCPBody, PTCPPacket, PTCPSession, PTCP};

static MAIN_SERVER: &str = "www.easy4ipcloud.com:8800";
const RELAY_STOP_TIMEOUT: time::Duration = time::Duration::from_secs(2);

static USERNAME: &str = "cba1b29e32cb17aa46b8ff9e73c7f40b";
static USERKEY: &str = "996103384cdf19179e19243e959bbf8b";

#[derive(Clone, Debug)]
pub struct RelayLease {
    token: String,
    agent: String,
}

impl RelayLease {
    pub async fn release(self) {
        if let Err(e) = release_relay_session(&self.token, &self.agent).await {
            warn!(
                "Failed to release relay session (agent={}, token_len={}): {}",
                self.agent,
                self.token.len(),
                e
            );
        } else {
            info!("Released relay session for agent {}", self.agent);
        }
    }
}

fn ip_to_bytes(ip: &str) -> io::Result<Vec<u8>> {
    let addr: SocketAddrV4 = ip.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid address '{}': {}", ip, e),
        )
    })?;
    let ip = addr.ip().octets();
    let port = addr.port();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&port.to_be_bytes());
    bytes.extend_from_slice(&ip);

    Ok(bytes.iter().map(|b| !b).collect())
}

fn response_body_field<'a>(res: &'a DHResponse, key: &str) -> io::Result<&'a str> {
    let body = res.body.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing response body while reading key '{}'", key),
        )
    })?;
    body.get(key).map(String::as_str).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing response field '{}'", key),
        )
    })
}

fn invalid_data(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn peer_addr_display(socket: &UdpSocket) -> String {
    socket
        .peer_addr()
        .map(|p| p.to_string())
        .unwrap_or_else(|_| "<unconnected>".to_string())
}

fn body_keys(res: &DHResponse) -> String {
    let Some(body) = &res.body else {
        return "<none>".to_string();
    };

    let mut keys = body.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    keys.join(",")
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn xml_body(fields: &[(&str, String)]) -> String {
    let mut sorted = BTreeMap::new();
    for (key, value) in fields {
        sorted.insert(*key, value.as_str());
    }

    let mut body = String::from("<body>");
    for (key, value) in sorted {
        body.push('<');
        body.push_str(key);
        body.push('>');
        body.push_str(&xml_escape(value));
        body.push_str("</");
        body.push_str(key);
        body.push('>');
    }
    body.push_str("</body>");
    body
}

fn format_client_id(cid: &[u8; 8]) -> String {
    cid.iter()
        .map(|b| format!("{:x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn socket_addr_body_value(socket: &UdpSocket) -> io::Result<String> {
    Ok(socket.local_addr()?.to_string())
}

fn relay_channel_nonce() -> String {
    rand::random::<u32>().to_string()
}

fn relay_channel_create_date() -> String {
    chrono::Utc::now().timestamp().to_string()
}

fn trace_peer(prefix: &str, socket: &UdpSocket) {
    trace!("{} {}", prefix, peer_addr_display(socket));
}

fn command_tail<'a>(body: &'a PTCPBody, min_len: usize, ctx: &str) -> io::Result<&'a [u8]> {
    match body {
        PTCPBody::Command(c) if c.len() >= min_len => Ok(&c[min_len..]),
        PTCPBody::Command(_) => Err(invalid_data(format!(
            "{} response too short; expected at least {} bytes",
            ctx, min_len
        ))),
        _ => Err(invalid_data(format!("invalid response type for {}", ctx))),
    }
}

fn parse_header_line(line: &str) -> io::Result<(String, String)> {
    let (key, value) = line
        .split_once(':')
        .ok_or_else(|| invalid_data(format!("malformed header line: '{}'", line)))?;
    let key = key.trim();
    let value = value.trim();
    if key.is_empty() {
        return Err(invalid_data(format!(
            "malformed header line with empty key: '{}'",
            line
        )));
    }
    Ok((key.to_string(), value.to_string()))
}

fn split_response_sections(res: &str) -> Option<(&str, &str)> {
    res.split_once("\r\n\r\n")
        .or_else(|| res.split_once("\n\n"))
}

async fn read_non_empty_packet(
    socket: &UdpSocket,
    session: &mut PTCPSession,
) -> io::Result<PTCPPacket> {
    let mut res = session.recv(socket.ptcp_read().await?);
    while let PTCPBody::Empty = res.body {
        res = session.recv(socket.ptcp_read().await?);
    }
    Ok(res)
}

async fn discover_bootstrap(
    socket: &UdpSocket,
    serial: &str,
    cseq: &mut u32,
) -> io::Result<(String, String)> {
    socket.dh_request("/probe/p2psrv", None, cseq).await?;
    socket.dh_read().await?;

    socket
        .dh_request(format!("/online/p2psrv/{}", serial).as_ref(), None, cseq)
        .await?;
    let p2psrv_res = socket.dh_read().await?;
    let p2psrv = response_body_field(&p2psrv_res, "body/US")?.to_string();
    info!(
        "P2P bootstrap resolved server for serial {}: p2psrv={} (code={}, status={}, body_keys={})",
        serial,
        p2psrv,
        p2psrv_res.code,
        p2psrv_res.status,
        body_keys(&p2psrv_res)
    );

    socket.dh_request("/online/relay", None, cseq).await?;
    let relay_res = socket.dh_read().await?;
    let relay = response_body_field(&relay_res, "body/Address")?.to_string();
    info!(
        "P2P bootstrap resolved relay for serial {}: relay={} (code={}, status={}, body_keys={})",
        serial,
        relay,
        relay_res.code,
        relay_res.status,
        body_keys(&relay_res)
    );

    Ok((p2psrv, relay))
}

async fn probe_device(socket2: &UdpSocket, serial: &str, cseq: &mut u32) -> io::Result<()> {
    socket2
        .dh_request(format!("/probe/device/{}", serial).as_ref(), None, cseq)
        .await?;
    socket2.dh_read().await?;
    Ok(())
}

async fn request_p2p_channel(
    socket: &UdpSocket,
    serial: &str,
    cid: &[u8; 8],
    cseq: &mut u32,
) -> io::Result<()> {
    let local_addr = socket_addr_body_value(socket)?;
    let body = xml_body(&[
        ("Identify", format_client_id(cid)),
        ("IpEncrpt", "true".to_string()),
        (
            "LocalAddr",
            format!("127.0.0.1:{}", socket.local_addr()?.port()),
        ),
        ("PubAddr", local_addr),
        ("version", "5.0.0".to_string()),
    ]);
    debug!("P2P channel request body_keys=Identify,IpEncrpt,LocalAddr,PubAddr,version");
    socket
        .dh_request(
            format!("/device/{}/p2p-channel", serial).as_ref(),
            Some(body.as_ref()),
            cseq,
        )
        .await
}

async fn setup_relay_agent(
    socket2: &UdpSocket,
    relay: &str,
    serial: &str,
    cseq: &mut u32,
) -> io::Result<(String, String)> {
    socket2.connect(relay).await?;
    debug!("Requesting relay agent...");
    let agent_body = xml_body(&[("Dev", serial.to_string())]);
    debug!("Relay agent request body_keys=Dev");
    socket2
        .dh_request("/relay/agent", Some(agent_body.as_ref()), cseq)
        .await?;
    let data = socket2.dh_read().await?;
    let token = response_body_field(&data, "body/Token")?.to_string();
    let agent = response_body_field(&data, "body/Agent")?.to_string();
    info!(
        "Relay agent allocated: relay={}, agent={}, token_len={}, code={}, status={}, body_keys={}",
        relay,
        agent,
        token.len(),
        data.code,
        data.status,
        body_keys(&data)
    );

    socket2.connect(&agent).await?;
    debug!(
        "Starting relay via agent {} (token_len={}, local_addr={})",
        agent,
        token.len(),
        socket2
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string())
    );
    let start_body = xml_body(&[
        ("Client", socket_addr_body_value(socket2)?),
        ("Dev", serial.to_string()),
    ]);
    debug!("Relay start request body_keys=Client,Dev");
    socket2
        .dh_request(
            format!("/relay/start/{}", token).as_ref(),
            Some(start_body.as_ref()),
            cseq,
        )
        .await?;
    let start_res = socket2.dh_read().await?;
    info!(
        "Relay started: agent={}, token_len={}, code={}, status={}, body_keys={}",
        agent,
        token.len(),
        start_res.code,
        start_res.status,
        body_keys(&start_res)
    );
    Ok((token, agent))
}

async fn wait_device_channel_response(socket: &UdpSocket) -> io::Result<DHResponse> {
    debug!("Waiting for device channel response...");
    let mut res = socket.dh_read_raw().await?;
    if res.code == 100 {
        debug!("Got 100 Continue, waiting for final response...");
        res = socket.dh_read_raw().await?;
    }
    if res.code >= 400 {
        if res.code == 403 {
            error!("Device requires authentication when creating P2P channel.");
            error!("Authentication is not supported at this time.");
        }
        return Err(io::Error::new(io::ErrorKind::Other, res.status));
    }
    debug!("Got device info (code {})", res.code);
    Ok(res)
}

async fn establish_relay_channel(
    socket2: &UdpSocket,
    serial: &str,
    agent: &str,
    cseq: &mut u32,
) -> io::Result<()> {
    let max_retries = 5;
    let mut attempt = 0;
    loop {
        attempt += 1;
        debug!(
            "Setting up relay channel (attempt {}/{})...",
            attempt, max_retries
        );

        socket2.connect(MAIN_SERVER).await?;
        let relay_channel_body = xml_body(&[
            ("CreateDate", relay_channel_create_date()),
            ("Nonce", relay_channel_nonce()),
            ("agentAddr", agent.to_string()),
        ]);
        debug!("Relay channel request body_keys=CreateDate,Nonce,agentAddr");
        socket2
            .dh_request(
                format!("/device/{}/relay-channel", serial).as_ref(),
                Some(relay_channel_body.as_ref()),
                cseq,
            )
            .await?;

        socket2.connect(agent).await?;
        debug!(
            "Waiting for relay channel confirmation from agent {} (attempt {}/{})",
            agent, attempt, max_retries
        );

        match time::timeout(time::Duration::from_millis(500), socket2.dh_read()).await {
            Ok(Ok(res)) => {
                info!(
                    "Relay channel ready for serial {} via agent {} (attempt {}/{}, code={}, status={}, body_keys={})",
                    serial,
                    agent,
                    attempt,
                    max_retries,
                    res.code,
                    res.status,
                    body_keys(&res)
                );
                return Ok(());
            }
            Ok(Err(e)) => {
                warn!(
                    "Relay channel setup response was invalid (attempt {}): {}",
                    attempt, e
                );
                if attempt >= max_retries {
                    return Err(e);
                }
            }
            Err(_) => {
                warn!(
                    "Timed out waiting for relay channel confirmation (attempt {})",
                    attempt
                );
                if attempt >= max_retries {
                    error!(
                        "Failed to confirm relay channel after {} attempts",
                        max_retries
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Relay channel confirmation timed out",
                    ));
                }
            }
        }
    }
}

async fn release_relay_session(token: &str, agent: &str) -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let mut cseq = 0;
    time::timeout(RELAY_STOP_TIMEOUT, socket.connect(agent))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out connecting to relay agent",
            )
        })??;
    time::timeout(
        RELAY_STOP_TIMEOUT,
        socket.dh_request(format!("/relay/stop/{}", token).as_ref(), None, &mut cseq),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timed out sending /relay/stop"))??;
    // Best-effort cleanup: some relay agents may not acknowledge stop,
    // and UDP replies can be dropped. A missing response should not fail shutdown.
    match time::timeout(RELAY_STOP_TIMEOUT, socket.dh_read()).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            warn!(
                "relay stop returned error response, continuing anyway: {}",
                e
            );
        }
        Err(_) => {
            debug!("relay stop returned no response before timeout; continuing");
        }
    }
    Ok(())
}

async fn negotiate_relay_sign(
    socket2: &UdpSocket,
    session: &mut PTCPSession,
) -> io::Result<Vec<u8>> {
    socket2
        .ptcp_request(session.send(PTCPBody::Command(
            b"\x17\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
        )))
        .await?;
    let res = read_non_empty_packet(socket2, session).await?;
    let sign = command_tail(&res.body, 12, "relay sign")?.to_vec();
    trace!(
        "Sign: {}",
        sign.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
    );
    Ok(sign)
}

async fn perform_direct_handshake(
    socket: &UdpSocket,
    device: &str,
    device_laddr: &str,
    cid: &[u8; 8],
    sign: &[u8],
) -> io::Result<PTCPSession> {
    let cookie: [u8; 4] = rand::random();
    let trans_id: [u8; 12] = rand::random();
    let cid: Vec<u8> = cid.iter().map(|b| !b).collect();

    trace_peer(">>>", socket);
    let data = [
        b"\xff\xfe\xff\xe7".to_vec(),
        cookie.to_vec(),
        trans_id.to_vec(),
        b"\x7f\xd5\xff\xf7".to_vec(),
        cid.clone(),
        b"\xff\xfb\xff\xf7\xff\xfe".to_vec(),
        ip_to_bytes(device)?,
    ]
    .concat();
    trace!(
        "Raw [{}]",
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    );
    socket.send(&data).await?;
    trace!("---");

    trace_peer("<<<", socket);
    let mut buf = [0u8; 4096];
    let result = time::timeout(time::Duration::from_secs(5), socket.recv(&mut buf)).await;
    if result.is_err() {
        warn!("Timeout occurred while waiting for a response from the device.");
        warn!("If the issue persists, you may need to use relay mode (--relay) with this device.");
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Device response timeout",
        ));
    }
    let n = match result {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e),
        Err(_) => unreachable!("timeout handled above"),
    };
    if n < 20 {
        return Err(invalid_data(format!(
            "device response too short: expected at least 20 bytes, got {}",
            n
        )));
    }
    trace!(
        "Raw [{}]",
        buf[0..n]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    );
    trace!("---");

    let rtrans_id = &buf[8..20];
    trace_peer(">>>", socket);
    let data = [
        b"\xfe\xfe\xff\xe7".to_vec(),
        cookie.to_vec(),
        rtrans_id.to_vec(),
        b"\x7f\xd6\xff\xf7".to_vec(),
        cid.clone(),
        b"\xff\xfb\xff\xf7\xff\xfe".to_vec(),
        ip_to_bytes(device_laddr)?,
    ]
    .concat();
    trace!(
        "Raw [{}]",
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    );
    socket.send(&data).await?;
    trace!("---");

    for _ in 0..5 {
        trace_peer("<<<", socket);
        let n = socket.recv(&mut buf).await?;
        trace!(
            "Raw [{}]",
            buf[0..n]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ")
        );
        trace!("---");
    }

    let mut session = PTCPSession::new();
    socket.ptcp_request(session.send(PTCPBody::Sync)).await?;
    let mut res = session.recv(socket.ptcp_read().await?);
    if !matches!(res.body, PTCPBody::Sync) {
        return Err(invalid_data("invalid direct sync response body"));
    }

    socket
        .ptcp_request(
            session.send(PTCPBody::Command(
                [
                    b"\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
                    sign.to_vec(),
                ]
                .concat(),
            )),
        )
        .await?;

    res = read_non_empty_packet(socket, &mut session).await?;
    match res.body {
        PTCPBody::Command(ref c) => {
            if c.first().copied() != Some(0x1A) {
                return Err(invalid_data("unexpected direct sign response command"));
            }
        }
        _ => return Err(invalid_data("invalid direct sign response body")),
    }

    socket
        .ptcp_request(session.send(PTCPBody::Command(
            b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
        )))
        .await?;
    res = session.recv(socket.ptcp_read().await?);
    if !matches!(res.body, PTCPBody::Empty) {
        return Err(invalid_data("invalid final direct handshake response body"));
    }

    Ok(session)
}

pub async fn p2p_handshake(
    socket: UdpSocket,
    serial: String,
    relay_mode: bool,
) -> io::Result<(UdpSocket, PTCPSession, Option<RelayLease>)> {
    let mut cseq = 0;
    let start = Instant::now();

    info!(
        "Connecting to P2P service (serial={}, relay={})...",
        serial, relay_mode
    );
    socket.connect(MAIN_SERVER).await?;
    let (p2psrv, relay) = discover_bootstrap(&socket, &serial, &mut cseq).await?;

    info!("Probing device {}...", serial);
    let socket2 = UdpSocket::bind("0.0.0.0:0").await?;
    socket2.connect(&p2psrv).await?;
    probe_device(&socket2, &serial, &mut cseq).await?;

    let cid: [u8; 8] = rand::random();
    request_p2p_channel(&socket, &serial, &cid, &mut cseq).await?;

    info!("Setting up relay connection...");
    let (token, agent) = setup_relay_agent(&socket2, &relay, &serial, &mut cseq).await?;
    let relay_lease = Some(RelayLease {
        token,
        agent: agent.clone(),
    });
    let res = wait_device_channel_response(&socket).await?;

    let device_laddr = response_body_field(&res, "body/LocalAddr")?;
    let device = response_body_field(&res, "body/PubAddr")?;

    socket.connect(device).await?;
    establish_relay_channel(&socket2, &serial, &agent, &mut cseq).await?;
    info!("Relay channel established; starting PTCP handshake");

    info!(
        "Initiating PTCP session (serial={}, relay={})...",
        serial, relay_mode
    );
    let mut session = PTCPSession::new();

    socket2.ptcp_request(session.send(PTCPBody::Sync)).await?;
    session.recv(socket2.ptcp_read().await?);

    if relay_mode {
        info!("Relay mode enabled");
        return Ok((socket2, session, relay_lease));
    }

    let sign = negotiate_relay_sign(&socket2, &mut session).await?;

    info!(
        "Establishing direct P2P connection (serial={}, relay={})...",
        serial, relay_mode
    );
    let session = perform_direct_handshake(&socket, device, device_laddr, &cid, &sign).await?;

    info!(
        "P2P handshake complete (serial={}, relay={}, elapsed_ms={})",
        serial,
        relay_mode,
        start.elapsed().as_millis()
    );
    Ok((socket, session, relay_lease))
}

#[derive(Debug)]
#[allow(dead_code)]
struct DHResponse {
    version: String,
    code: u16,
    status: String,
    headers: HashMap<String, String>,
    body: Option<HashMap<String, String>>,
}

impl DHResponse {
    fn parse_body(body: &str) -> io::Result<HashMap<String, String>> {
        let mut parser = EventReader::from_str(body);
        let mut stack = Vec::new();
        let mut tree = HashMap::new();

        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    stack.push(name.local_name);
                }
                Ok(XmlEvent::EndElement { .. }) => {
                    if stack.pop().is_none() {
                        return Err(invalid_data("malformed xml: unexpected closing tag"));
                    }
                }
                Ok(XmlEvent::Characters(s)) => {
                    let key = stack.as_slice().join("/");
                    // Repeated XML paths overwrite previous values. This matches
                    // the expected DH payload shape and preserves prior behavior.
                    tree.insert(key, s);
                }
                Ok(XmlEvent::EndDocument) => {
                    break;
                }
                Err(e) => {
                    return Err(invalid_data(format!("xml parse error: {}", e)));
                }
                _ => {}
            }
        }

        Ok(tree)
    }

    fn parse_response(res: &str) -> io::Result<DHResponse> {
        let (head, body) = split_response_sections(res)
            .ok_or_else(|| invalid_data("malformed response: missing header/body separator"))?;

        let mut head_parts = head.lines().map(|line| line.trim_end_matches('\r'));
        let status_line_raw = head_parts
            .next()
            .ok_or_else(|| invalid_data("malformed response: missing status line"))?;
        let mut status_line = status_line_raw.split_whitespace();
        let version = status_line
            .next()
            .ok_or_else(|| invalid_data("malformed response: missing version"))?
            .to_string();
        let code = status_line
            .next()
            .ok_or_else(|| invalid_data("malformed response: missing status code"))?
            .parse::<u16>()
            .map_err(|e| invalid_data(format!("invalid status code: {}", e)))?;
        let status = status_line.collect::<Vec<_>>().join(" ");
        let status = if status.is_empty() {
            "UNKNOWN".to_string()
        } else {
            status
        };

        let mut headers = HashMap::new();
        for line in head_parts {
            let (key, value) = parse_header_line(line)?;
            headers.insert(key, value);
        }

        let body = match body.trim().len() {
            0 => None,
            _ => Some(DHResponse::parse_body(body)?),
        };

        Ok(DHResponse {
            version,
            code,
            status,
            headers,
            body,
        })
    }
}

#[async_trait]
trait DHP2P {
    async fn dh_request(&self, path: &str, body: Option<&str>, seq: &mut u32) -> io::Result<()>;
    async fn dh_read_raw(&self) -> io::Result<DHResponse>;

    async fn dh_read(&self) -> io::Result<DHResponse> {
        let res = self.dh_read_raw().await?;

        if res.code < 300 {
            Ok(res)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("error response: {} ({})", res.status, res.code),
            ))
        }
    }
}

#[async_trait]
impl DHP2P for UdpSocket {
    async fn dh_request(&self, path: &str, body: Option<&str>, seq: &mut u32) -> io::Result<()> {
        let method = match body {
            Some(_) => "DHPOST",
            None => "DHGET",
        };

        let body = match body {
            Some(s) => s,
            None => "",
        };

        let nonce = rand::random::<u32>();
        let currdate = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let pwd = format!("{}{}DHP2P:{}:{}", nonce, currdate, USERNAME, USERKEY);

        let mut hasher = sha1::Sha1::new();
        hasher.update(pwd);
        let hash_digest = hasher.finalize();
        let digest = base64::engine::general_purpose::STANDARD.encode(&hash_digest);

        *seq += 1;

        let req = format!("\
            {} {} HTTP/1.1\r\n\
            CSeq: {}\r\n\
            Authorization: WSSE profile=\"UsernameToken\"\r\n\
            X-WSSE: UsernameToken Username=\"{}\", PasswordDigest=\"{}\", Nonce=\"{}\", Created=\"{}\"\r\n\r\n{}",
            method, path, seq, USERNAME, digest, nonce, currdate, body,
        );

        debug!(">>> {} {}", peer_addr_display(self), path);
        trace!("{}", req);
        trace!("---");

        self.send(req.as_bytes()).await.map(|_| ())
    }

    async fn dh_read_raw(&self) -> io::Result<DHResponse> {
        trace!("### {}", peer_addr_display(self));

        let mut buf = [0u8; 4096];
        let n = self.recv(&mut buf).await?;
        let res = String::from_utf8_lossy(&buf[0..n]);

        trace!("<<< {}", peer_addr_display(self));
        trace!("{}", res);
        trace!("---");

        let res = DHResponse::parse_response(&res)?;
        debug!(
            "<<< {} {} {}",
            peer_addr_display(self),
            res.code,
            res.status
        );

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::{command_tail, format_client_id, parse_header_line, xml_body, DHResponse};
    use crate::transport::ptcp::PTCPBody;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::panic;

    #[test]
    fn parse_response_rejects_missing_separator() {
        let raw = "HTTP/1.1 200 OK\r\nCSeq: 1\r\n";
        assert!(DHResponse::parse_response(raw).is_err());
    }

    #[test]
    fn parse_response_rejects_malformed_status_code() {
        let raw = "HTTP/1.1 abc OK\r\nCSeq: 1\r\n\r\n";
        assert!(DHResponse::parse_response(raw).is_err());
    }

    #[test]
    fn parse_response_rejects_malformed_xml_body() {
        let raw = "HTTP/1.1 200 OK\r\nCSeq: 1\r\n\r\n<body><Token>abc</Token>";
        assert!(DHResponse::parse_response(raw).is_err());
    }

    #[test]
    fn parse_response_accepts_header_without_space_after_colon() {
        let raw = "HTTP/1.1 200 OK\r\nCSeq:1\r\nServer:device\r\n\r\n";
        let res = DHResponse::parse_response(raw).expect("response should parse");
        assert_eq!(res.headers.get("CSeq").map(String::as_str), Some("1"));
        assert_eq!(
            res.headers.get("Server").map(String::as_str),
            Some("device")
        );
    }

    #[test]
    fn parse_header_line_accepts_common_variants() {
        let cases = [
            ("CSeq: 1", "CSeq", "1"),
            ("CSeq:1", "CSeq", "1"),
            ("  CSeq  :  1  ", "CSeq", "1"),
            ("X-Empty: ", "X-Empty", ""),
            ("X-Tab:\t42", "X-Tab", "42"),
        ];
        for (line, exp_key, exp_val) in cases {
            let (key, value) = parse_header_line(line).expect("header line should parse");
            assert_eq!(key, exp_key);
            assert_eq!(value, exp_val);
        }
    }

    #[test]
    fn parse_header_line_rejects_malformed_variants() {
        for line in ["CSeq 1", ": value", "", "   :1"] {
            assert!(parse_header_line(line).is_err());
        }
    }

    #[test]
    fn xml_body_sorts_fields_and_escapes_values() {
        let body = xml_body(&[
            ("Dev", "CAM&1".to_string()),
            ("Client", "192.0.2.10:1234".to_string()),
            ("Note", "<quoted>\"value\"".to_string()),
        ]);

        assert_eq!(
            body,
            "<body><Client>192.0.2.10:1234</Client><Dev>CAM&amp;1</Dev><Note>&lt;quoted&gt;&quot;value&quot;</Note></body>"
        );
    }

    #[test]
    fn format_client_id_matches_sdk_style_hex_bytes() {
        let cid = [0x00, 0x01, 0x0a, 0x10, 0xab, 0xcd, 0xef, 0xff];
        assert_eq!(format_client_id(&cid), "0 1 a 10 ab cd ef ff");
    }

    #[test]
    fn command_tail_rejects_short_command_payload() {
        let body = PTCPBody::Command(vec![0x10, 0x20]);
        assert!(command_tail(&body, 12, "relay sign").is_err());
    }

    #[test]
    fn command_tail_rejects_non_command_body() {
        let body = PTCPBody::Sync;
        assert!(command_tail(&body, 12, "relay sign").is_err());
    }

    #[test]
    fn parse_response_accepts_lf_only_separator() {
        let raw = "HTTP/1.1 200 OK\nCSeq:1\nServer:device\n\n";
        let res = DHResponse::parse_response(raw).expect("lf-only response should parse");
        assert_eq!(res.headers.get("CSeq").map(String::as_str), Some("1"));
        assert_eq!(
            res.headers.get("Server").map(String::as_str),
            Some("device")
        );
    }

    #[test]
    fn parse_response_random_inputs_do_not_panic() {
        let mut rng = StdRng::seed_from_u64(0xD0A1_CE55);
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-: \r\n\t";
        for _ in 0..1500 {
            let len = rng.gen_range(0..256);
            let s: String = (0..len)
                .map(|_| {
                    let idx = rng.gen_range(0..alphabet.len());
                    alphabet[idx] as char
                })
                .collect();
            let result = panic::catch_unwind(|| DHResponse::parse_response(&s));
            assert!(result.is_ok(), "parse_response panicked for input: {:?}", s);
        }
    }
}
