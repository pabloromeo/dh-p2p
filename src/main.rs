use clap::Parser;
use log::{debug, info, warn};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
#[cfg(unix)]
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use tokio::{
    net::{TcpListener, UdpSocket},
    signal,
    sync::{mpsc, oneshot, watch},
};

use crate::{
    dh::p2p_handshake,
    process::{dh_reader, dh_writer, process_reader, process_writer},
    ptcp::PTCPEvent,
};

mod buffer;
mod dh;
mod process;
mod ptcp;

#[derive(Parser)]
#[command(about = "A PoC implementation of TCP tunneling over Dahua P2P protocol.", long_about = None)]
struct Cli {
    /// Bind address, port and remote port. Default: 127.0.0.1:1554:554
    #[arg(short, long, value_name = "[bind_address:]port:remote_port")]
    port: Option<String>,
    /// Relay mode (experimental)
    #[arg(short, long)]
    relay: bool,
    /// Jitter buffer duration in milliseconds (0 to disable). Default: 0
    #[arg(short = 'b', long, value_name = "ms", default_value = "0")]
    buffer_ms: u64,
    /// Increase verbosity (-v for debug, -vv for trace)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Serial number of the camera
    serial: String,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    // Initialize logger based on verbosity level
    let log_level = match args.verbose {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    env_logger::Builder::new()
        .filter_level(log_level)
        .format_target(false)
        .format_timestamp_secs()
        .init();

    debug!("Log level set to {:?}", log_level);

    let serial = args.serial;
    let port = args.port.unwrap_or("127.0.0.1:1554:554".to_string());

    let parts: Vec<&str> = port.split(':').collect();
    let (bind_address, bind_port, remote_port): (&str, u16, u16) = match parts.len() {
        2 => (
            "127.0.0.1",
            parts[0].parse().unwrap(),
            parts[1].parse().unwrap(),
        ),
        3 => (
            parts[0],
            parts[1].parse().unwrap(),
            parts[2].parse().unwrap(),
        ),
        _ => panic!("Invalid port specification"),
    };

    // Bind the listener to the address
    let listener = TcpListener::bind(format!("{}:{}", bind_address, bind_port))
        .await
        .unwrap();

    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();

    let (socket, session) = p2p_handshake(socket, serial, args.relay).await;

    let (dh_tx, dh_rx) = mpsc::channel::<PTCPEvent>(128);
    let (shutdown_tx, shutdown_rx) = watch::channel::<bool>(false);
    let session = Arc::new(Mutex::new(session));

    let channels = Arc::new(Mutex::new(HashMap::<u32, mpsc::Sender<Vec<u8>>>::new()));
    let conn_channels = Arc::new(Mutex::new(HashMap::<u32, oneshot::Sender<bool>>::new()));

    info!("PTCP session established");

    /*
     * Clone the handles
     */

    let reader = Arc::new(socket);
    let writer = reader.clone();

    let session2 = session.clone();
    let channels2 = channels.clone();
    let conn_channels2 = conn_channels.clone();

    let shutdown_notify = shutdown_tx;
    let shutdown_handle = tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        let _ = shutdown_notify.send(true);
    });

    let mut hb_shutdown = shutdown_rx.clone();
    let hb_tx = dh_tx.clone();
    let heartbeat_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {
                    if hb_tx.send(PTCPEvent::Heartbeat).await.is_err() {
                        break;
                    }
                }
                _ = hb_shutdown.changed() => {
                    break;
                }
            }
        }
    });

    let writer_shutdown = shutdown_rx.clone();
    let writer_channels = Arc::clone(&channels2);
    let writer_conn_channels = Arc::clone(&conn_channels2);
    let writer_handle = tokio::spawn(async move {
        dh_writer(
            session,
            writer,
            dh_rx,
            remote_port.into(),
            writer_shutdown,
            writer_channels,
            writer_conn_channels,
        )
        .await;
    });

    let reader_shutdown = shutdown_rx.clone();
    let buffer_ms = args.buffer_ms;
    let reader_handle = tokio::spawn(async move {
        dh_reader(session2, reader, channels, conn_channels, reader_shutdown, buffer_ms).await;
    });

    info!("Ready to connect!");
    if remote_port == 554 {
        info!(
            "RTSP URL: rtsp://127.0.0.1{}/cam/realmonitor?channel=1&subtype=0",
            if bind_port != 554 {
                format!(":{}", bind_port)
            } else {
                String::new()
            }
        );
    }

    let mut shutdown_accept = shutdown_rx.clone();
    loop {
        // The second item contains the IP and port of the new connection.
        let accept = tokio::select! {
            res = listener.accept() => res,
            _ = shutdown_accept.changed() => {
                info!("Shutdown requested, stopping listener");
                break;
            }
        };

        let (client, addr) = match accept {
            Ok(pair) => pair,
            Err(e) => {
                info!("Listener stopped: {}", e);
                break;
            }
        };
        info!("Accepted connection from {}", addr);

        // Create a channel for the client
        let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
        let (conn_tx, conn_rx) = oneshot::channel::<bool>();
        let dh_tx = dh_tx.clone();
        let mut shutdown_conn = shutdown_rx.clone();

        let realm_id = rand::random::<u32>();

        // Store the channel in the map
        channels2.lock().unwrap().insert(realm_id, tx);
        conn_channels2.lock().unwrap().insert(realm_id, conn_tx);

        if dh_tx.send(PTCPEvent::Connect(realm_id)).await.is_err() {
            warn!("Failed to enqueue connect event for realm {:08x}", realm_id);
            continue;
        }

        tokio::select! {
            res = conn_rx => {
                if res.is_err() {
                    warn!("Realm {:08x} connection handshake failed", realm_id);
                    continue;
                }
            }
            _ = shutdown_conn.changed() => {
                info!("Shutdown before realm {:08x} became ready", realm_id);
                continue;
            }
        }

        let (reader, writer) = client.into_split();

        tokio::spawn({
            let shutdown_rx = shutdown_rx.clone();
            async move {
                process_reader(reader, realm_id, dh_tx, shutdown_rx).await;
            }
        });

        tokio::spawn({
            let shutdown_rx = shutdown_rx.clone();
            async move {
                process_writer(writer, rx, shutdown_rx).await;
            }
        });
    }

    info!("Sending PTCP disconnect to active realms");
    let realms: Vec<u32> = channels2.lock().unwrap().keys().copied().collect();
    for realm in realms {
        if dh_tx.send(PTCPEvent::Disconnect(realm)).await.is_err() {
            warn!("Failed to enqueue disconnect for realm {:08x}", realm);
        }
    }

    channels2.lock().unwrap().clear();
    conn_channels2.lock().unwrap().clear();
    drop(dh_tx);

    let _ = heartbeat_handle.await;
    let _ = writer_handle.await;
    let _ = reader_handle.await;
    let _ = shutdown_handle.await;
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term_stream =
            unix_signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
        tokio::select! {
            _ = signal::ctrl_c() => info!("Received Ctrl+C"),
            _ = term_stream.recv() => info!("Received SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        info!("Received Ctrl+C");
    }
}
