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

// Part 1: Token Transfer Functions
pub async fn send_token(
    user1_secret: &str,
    user2_address: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
) -> Result<String> {
    todo!("Will implement after foundation is ready")
}

pub async fn verify_token_transfer(
    tx_hash: &str,
    expected_sender: &str,
    expected_receiver: &str,
    expected_amount: &str,
    expected_currency: &str,
    expected_issuer: &str,
) -> Result<bool> {
    todo!("later")
}

// Part 2: Offline Signing Functions
pub async fn sign_transfer_offline(
    user1_secret: &str,
    user2_address: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
    sequence: u32,
    fee: u64,
    last_ledger_sequence: u32,
) -> Result<String> {
    todo!("later")
}

pub async fn submit_signed_blob(signed_blob: &str) -> Result<String> {
    todo!("later")
}
