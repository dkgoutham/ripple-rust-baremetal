use crate::errors::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// Transaction types
pub const PAYMENT: u16 = 0;
pub const TRUST_SET: u16 = 20;

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentTransaction {
    #[serde(rename = "TransactionType")]
    pub transaction_type: String,
    #[serde(rename = "Account")]
    pub account: String,
    #[serde(rename = "Destination")]
    pub destination: String,
    #[serde(rename = "Amount")]
    pub amount: Value,
    #[serde(rename = "Fee")]
    pub fee: String,
    #[serde(rename = "Sequence")]
    pub sequence: u32,
    #[serde(rename = "LastLedgerSequence")]
    pub last_ledger_sequence: Option<u32>,
    #[serde(rename = "SigningPubKey")]
    pub signing_pub_key: Option<String>,
    #[serde(rename = "TxnSignature")]
    pub txn_signature: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustSetTransaction {
    #[serde(rename = "TransactionType")]
    pub transaction_type: String,
    #[serde(rename = "Account")]
    pub account: String,
    #[serde(rename = "LimitAmount")]
    pub limit_amount: Value,
    #[serde(rename = "Fee")]
    pub fee: String,
    #[serde(rename = "Sequence")]
    pub sequence: u32,
    #[serde(rename = "LastLedgerSequence")]
    pub last_ledger_sequence: Option<u32>,
    #[serde(rename = "SigningPubKey")]
    pub signing_pub_key: Option<String>,
    #[serde(rename = "TxnSignature")]
    pub txn_signature: Option<String>,
}

impl PaymentTransaction {
    pub fn new_xrp_payment(
        account: String,
        destination: String,
        amount_drops: u64,
        fee: u64,
        sequence: u32,
    ) -> Self {
        Self {
            transaction_type: "Payment".to_string(),
            account,
            destination,
            amount: json!(amount_drops.to_string()),
            fee: fee.to_string(),
            sequence,
            last_ledger_sequence: None,
            signing_pub_key: None,
            txn_signature: None,
        }
    }

    pub fn new_token_payment(
        account: String,
        destination: String,
        amount: String,
        currency: String,
        issuer: String,
        fee: u64,
        sequence: u32,
    ) -> Self {
        Self {
            transaction_type: "Payment".to_string(),
            account,
            destination,
            amount: json!({
                "value": amount,
                "currency": currency,
                "issuer": issuer
            }),
            fee: fee.to_string(),
            sequence,
            last_ledger_sequence: None,
            signing_pub_key: None,
            txn_signature: None,
        }
    }
}

impl TrustSetTransaction {
    pub fn new(
        account: String,
        limit_amount: String,
        currency: String,
        issuer: String,
        fee: u64,
        sequence: u32,
    ) -> Self {
        Self {
            transaction_type: "TrustSet".to_string(),
            account,
            limit_amount: json!({
                "value": limit_amount,
                "currency": currency,
                "issuer": issuer
            }),
            fee: fee.to_string(),
            sequence,
            last_ledger_sequence: None,
            signing_pub_key: None,
            txn_signature: None,
        }
    }
}

/// Simple transaction serialization for signing (placeholder)
/// This will be expanded with proper XRPL binary format later
pub fn serialize_for_signing(_tx_json: &Value) -> Result<String> {
    // For now, return a placeholder - we'll implement proper binary serialization later
    // This is just to make Phase 1 compilable
    Ok("PLACEHOLDER_FOR_BINARY_SERIALIZATION".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_creation() {
        let payment = PaymentTransaction::new_xrp_payment(
            "rSender123".to_string(),
            "rReceiver456".to_string(),
            1000000, // 1 XRP in drops
            12,      // Fee in drops
            1,       // Sequence
        );

        assert_eq!(payment.transaction_type, "Payment");
        assert_eq!(payment.amount, json!("1000000"));
    }

    #[test]
    fn test_token_payment_creation() {
        let payment = PaymentTransaction::new_token_payment(
            "rSender123".to_string(),
            "rReceiver456".to_string(),
            "100".to_string(),
            "USD".to_string(),
            "rIssuer789".to_string(),
            12,
            1,
        );

        assert_eq!(payment.transaction_type, "Payment");
        assert!(payment.amount.is_object());
    }

    #[test]
    fn test_trustset_creation() {
        let trustset = TrustSetTransaction::new(
            "rAccount123".to_string(),
            "1000".to_string(),
            "USD".to_string(),
            "rIssuer789".to_string(),
            12,
            1,
        );

        assert_eq!(trustset.transaction_type, "TrustSet");
        assert!(trustset.limit_amount.is_object());
    }
}
