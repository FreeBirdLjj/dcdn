#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("invalid proxy url: {0}")]
    InvalidUrl(String),
    #[error("proxy connect failed: status {code}: {body}")]
    ConnectFailed { code: u16, body: String },
    #[error("socks error: {0}")]
    Socks(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("tls error: {0}")]
    Tls(String),
}
