use log::info;
use std::io;

#[cfg(target_os = "linux")]
fn fd_count() -> io::Result<usize> {
    Ok(std::fs::read_dir("/proc/self/fd")?.count())
}

#[cfg(not(target_os = "linux"))]
fn fd_count() -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "fd count not supported on this OS",
    ))
}

/// Log a snapshot of open file descriptors along with channel counts.
pub fn log_fd_snapshot(label: &str, channels_len: usize, conn_channels_len: usize) {
    match fd_count() {
        Ok(count) => info!(
            "FD usage [{}]: open_fds={}, channels={}, conn_channels={}",
            label, count, channels_len, conn_channels_len
        ),
        Err(e) => info!(
            "FD usage [{}]: open_fds=unavailable ({}), channels={}, conn_channels={}",
            label, e, channels_len, conn_channels_len
        ),
    }
}

