#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownReason {
    Stop,
    Restart,
    RestartWatchdog,
    RestartPtcpSendRefused,
    RestartPtcpReadFatal,
}

impl ShutdownReason {
    pub fn is_restart(self) -> bool {
        matches!(
            self,
            ShutdownReason::Restart
                | ShutdownReason::RestartWatchdog
                | ShutdownReason::RestartPtcpSendRefused
                | ShutdownReason::RestartPtcpReadFatal
        )
    }

    pub fn is_ptcp_send_refused(self) -> bool {
        matches!(self, ShutdownReason::RestartPtcpSendRefused)
    }
}
