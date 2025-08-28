use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// XRPL account address
pub type Address = String;

/// Transaction hash
pub type Hash = String;

/// XRP amount in drops
pub type XrpDrops = u64;

/// Sequence number for transactions
pub type Sequence = u32;

/// Ledger index
pub type LedgerIndex = u32;

/// Generic XRPL JSON-RPC request
#[derive(Debug, Serialize)]
pub struct XrplRequest {
    pub id: u32,
    pub command: String,
    #[serde(flatten)]
    pub params: HashMap<String, serde_json::Value>,
}

/// Generic XRPL JSON-RPC response
#[derive(Debug, Deserialize)]
pub struct XrplResponse {
    pub id: u32,
    pub status: String,
    #[serde(rename = "type")]
    pub response_type: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub error_message: Option<String>,
}

/// Account info response
#[derive(Debug, Deserialize)]
pub struct AccountInfo {
    #[serde(rename = "Account")]
    pub account: Address,
    #[serde(rename = "Balance")]
    pub balance: String,
    #[serde(rename = "Sequence")]
    pub sequence: Sequence,
    #[serde(rename = "OwnerCount")]
    pub owner_count: u32,
    #[serde(rename = "Flags")]
    pub flags: u32,
}

/// Payment transaction structure
#[derive(Debug, Serialize)]
pub struct PaymentTransaction {
    #[serde(rename = "TransactionType")]
    pub transaction_type: String,
    #[serde(rename = "Account")]
    pub account: Address,
    #[serde(rename = "Destination")]
    pub destination: Address,
    #[serde(rename = "Amount")]
    pub amount: String,
    #[serde(rename = "Fee")]
    pub fee: String,
    #[serde(rename = "Sequence")]
    pub sequence: Sequence,
    #[serde(rename = "SigningPubKey")]
    pub signing_pub_key: String,
    #[serde(rename = "TxnSignature")]
    pub txn_signature: Option<String>,
}

/// Submit transaction response
#[derive(Debug, Deserialize)]
pub struct SubmitResponse {
    pub engine_result: String,
    pub engine_result_code: i32,
    pub engine_result_message: String,
    pub tx_blob: Option<String>,
    pub tx_json: Option<serde_json::Value>,
}

/// Transaction lookup response
#[derive(Debug, Deserialize)]
pub struct TransactionResponse {
    #[serde(rename = "Account")]
    pub account: Address,
    #[serde(rename = "Destination")]
    pub destination: Address,
    #[serde(rename = "Amount")]
    pub amount: String,
    #[serde(rename = "TransactionType")]
    pub transaction_type: String,
    #[serde(rename = "hash")]
    pub hash: Hash,
    #[serde(rename = "ledger_index")]
    pub ledger_index: LedgerIndex,
    pub validated: bool,
}

/// Constants
pub const XRP_DROPS_PER_XRP: u64 = 1_000_000;
pub const TESTNET_WEBSOCKET_URL: &str = "wss://s.altnet.rippletest.net:51233";
pub const MINIMUM_FEE_DROPS: u64 = 12;
