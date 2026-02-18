use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum AppError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("API error {code}: {message}")]
    Api { code: i64, message: String },

    #[error("SRP error: {0}")]
    Srp(String),

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("2FA required")]
    TwoFactorRequired,

    #[error("Not logged in -- run `tunmux <provider> login <username>` first")]
    NotLoggedIn,

    #[error("Session expired -- run `tunmux <provider> login <username>` again")]
    SessionExpired,

    #[error("No suitable server found")]
    NoServerFound,

    #[error("WireGuard error: {0}")]
    WireGuard(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("AirVPN API error: {0}")]
    AirVpnApi(String),

    #[error("AirVPN crypto error: {0}")]
    AirVpnCrypto(String),

    #[error("XML parse error: {0}")]
    Xml(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, AppError>;
