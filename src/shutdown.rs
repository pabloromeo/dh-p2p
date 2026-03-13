#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownReason {
    Stop,
    Restart,
}
