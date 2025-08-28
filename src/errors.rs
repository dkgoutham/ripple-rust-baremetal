use thiserror::Error;

pub type Result<T> = std::result::Result<T, XrplError>;

#[derive(Error, Debug)]
pub enum XrplError {
    #[error("WebSocket error: {0}")]
    WebSocket(Box<tungstenite::Error>),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Base58 decode error: {0}")]
    Base58Decode(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Invalid seed: {0}")]
    InvalidSeed(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Transaction error: {0}")]
    Transaction(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}

// Custom From implementation for boxed tungstenite errors
impl From<tungstenite::Error> for XrplError {
    fn from(err: tungstenite::Error) -> Self {
        XrplError::WebSocket(Box::new(err))
    }
}
