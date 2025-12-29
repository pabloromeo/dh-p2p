use log::{info, warn};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::{mpsc, oneshot, watch},
};

use crate::ptcp::{PTCPBody, PTCPEvent, PTCPPayload, PTCPSession, PTCP};

/**
 * Read data from the channel and write it back to the client
 */
pub async fn process_writer(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::Receiver<Vec<u8>>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            data = rx.recv() => {
                match data {
                    Some(data) => {
                        if writer.write_all(&data).await.is_err() {
                            warn!("Writer: Socket closed by peer.");
                            break;
                        }
                    }
                    None => break,
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

/**
 * Read data from the client and send it to the channel
 */
pub async fn process_reader(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    realm_id: u32,
    dh_tx: mpsc::Sender<PTCPEvent>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut buf = [0u8; 4096];

    loop {
        let n = tokio::select! {
            res = reader.read(&mut buf) => {
                match res {
                    Ok(n) => {
                        if n == 0 {
                            warn!("Reader: Socket closed by peer.");
                            let _ = dh_tx.send(PTCPEvent::Disconnect(realm_id)).await;
                            break;
                        }

                        n
                    }
                    Err(e) => {
                        warn!("Reader: {}", e);
                        let _ = dh_tx.send(PTCPEvent::Disconnect(realm_id)).await;
                        break;
                    }
                }
            }
            _ = shutdown.changed() => break,
        };

        if dh_tx
            .send(PTCPEvent::Data(realm_id, buf[0..n].to_vec()))
            .await
            .is_err()
        {
            break;
        }
    }
}

/**
* Read data from client and send it to devices
*/
pub async fn dh_writer(
    session: Arc<Mutex<PTCPSession>>,
    socket: Arc<UdpSocket>,
    mut dh_rx: mpsc::Receiver<PTCPEvent>,
    remote_port: u32,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let ev = tokio::select! {
            ev = dh_rx.recv() => ev,
            _ = shutdown.changed() => None,
        };

        let Some(ev) = ev else { break };

        match ev {
            PTCPEvent::Heartbeat => {
                let p = session.lock().unwrap().send(PTCPBody::Heartbeat);
                socket.ptcp_request(p).await;
            }
            PTCPEvent::Connect(realm) => {
                let p = session
                    .lock()
                    .unwrap()
                    .send(PTCPBody::Bind(realm, remote_port));
                socket.ptcp_request(p).await;
            }
            PTCPEvent::Disconnect(realm) => {
                let p = session
                    .lock()
                    .unwrap()
                    .send(PTCPBody::Status(realm, "DISC".to_string()));
                socket.ptcp_request(p).await;
            }
            PTCPEvent::Data(realm, data) => {
                let p = session
                    .lock()
                    .unwrap()
                    .send(PTCPBody::Payload(PTCPPayload { realm, data }));
                socket.ptcp_request(p).await;
            }
        }
    }
}

/**
 * Read data from devices and send it to clients
 */
pub async fn dh_reader(
    session: Arc<Mutex<PTCPSession>>,
    socket: Arc<UdpSocket>,
    channels: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    conn_channels: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let packet = tokio::select! {
            packet = socket.ptcp_read() => packet,
            _ = shutdown.changed() => break,
        };
        let packet = session.lock().unwrap().recv(packet);

        if let PTCPBody::Empty = packet.body {
            continue;
        }

        let p = session.lock().unwrap().send(PTCPBody::Empty);
        socket.ptcp_request(p).await;

        match packet.body {
            PTCPBody::Status(realm, status) => {
                if status == "CONN" {
                    info!("Realm {:08x} streaming ready", realm);
                    conn_channels
                        .lock()
                        .unwrap()
                        .remove(&realm)
                        .unwrap()
                        .send(true)
                        .unwrap();
                }
            }
            PTCPBody::Payload(p) => {
                let tx = channels.lock().unwrap().get(&p.realm).unwrap().clone();

                if tx.send(p.data).await.is_err() {
                    warn!("Realm {:08x} unavailable", p.realm);
                }
            }
            _ => {}
        }
    }
}
