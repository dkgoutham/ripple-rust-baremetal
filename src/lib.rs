pub mod client;
pub mod crypto;
pub mod encoding;
pub mod errors;
pub mod transactions;
pub mod websocket;

// Re-export main types
pub use client::XrplClient;
pub use crypto::{Wallet, derive_keypair_from_seed, generate_seed};
pub use errors::{Result, XrplError};

/// Parameters for offline transaction signing
#[derive(Debug, Clone)]
pub struct OfflineSigningParams {
    pub user1_secret: String,
    pub user2_address: String,
    pub issuer_address: String,
    pub currency_code: String,
    pub amount: String,
    pub sequence: u32,
    pub fee: u64,
    pub last_ledger_sequence: u32,
}

// Part 1: Token Transfer Functions
pub async fn send_token(
    _user1_secret: &str,
    _user2_address: &str,
    _issuer_address: &str,
    _currency_code: &str,
    _amount: &str,
) -> Result<String> {
    todo!("Will implement after foundation is ready")
}

pub async fn verify_token_transfer(
    _tx_hash: &str,
    _expected_sender: &str,
    _expected_receiver: &str,
    _expected_amount: &str,
    _expected_currency: &str,
    _expected_issuer: &str,
) -> Result<bool> {
    todo!("Will implement in Phase 2")
}

// Part 2: Offline Signing Functions
pub async fn sign_transfer_offline(params: OfflineSigningParams) -> Result<String> {
    let _ = params;
    todo!("Will implement in Phase 2")
}

pub async fn submit_signed_blob(_signed_blob: &str) -> Result<String> {
    todo!("Will implement in Phase 2")
}
