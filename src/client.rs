use crate::errors::{Result, XrplError};
use crate::transactions::{PaymentTransaction, TrustSetTransaction};
use crate::websocket::WebSocketClient;
use serde_json::Value;

pub struct XrplClient {
    ws_client: WebSocketClient,
}

impl XrplClient {
    pub fn new(ws_client: WebSocketClient) -> Self {
        Self { ws_client }
    }

    pub fn testnet() -> Self {
        Self::new(WebSocketClient::testnet())
    }

    pub fn mainnet() -> Self {
        Self::new(WebSocketClient::mainnet())
    }

    /// Get account information
    pub async fn get_account_info(&self, address: &str) -> Result<Value> {
        self.ws_client.account_info(address).await
    }

    /// Get current ledger sequence
    pub async fn get_current_ledger_sequence(&self) -> Result<u32> {
        let response = self.ws_client.ledger_current().await?;

        if let Some(result) = response.get("result")
            && let Some(ledger_index) = result.get("ledger_current_index")
        {
            return Ok(ledger_index.as_u64().unwrap_or(0) as u32);
        }

        Err(XrplError::Network(
            "Failed to get current ledger sequence".to_string(),
        ))
    }

    /// Get account sequence number
    pub async fn get_account_sequence(&self, address: &str) -> Result<u32> {
        let response = self.get_account_info(address).await?;

        if let Some(result) = response.get("result")
            && let Some(account_data) = result.get("account_data")
            && let Some(sequence) = account_data.get("Sequence")
        {
            return Ok(sequence.as_u64().unwrap_or(0) as u32);
        }

        Err(XrplError::Network(
            "Failed to get account sequence".to_string(),
        ))
    }

    /// Get base fee from network
    pub async fn get_base_fee(&self) -> Result<u64> {
        let response = self.ws_client.fee().await?;

        if let Some(result) = response.get("result")
            && let Some(drops) = result.get("drops")
            && let Some(base_fee) = drops.get("base_fee")
        {
            return Ok(base_fee.as_str().unwrap_or("12").parse().unwrap_or(12));
        }

        Ok(12)
    }

    /// Submit a transaction
    pub async fn submit_transaction(&self, tx_blob: &str) -> Result<Value> {
        self.ws_client.submit(tx_blob).await
    }

    /// Get transaction details
    pub async fn get_transaction(&self, tx_hash: &str) -> Result<Value> {
        self.ws_client.tx(tx_hash).await
    }

    /// Auto-fill transaction fields (sequence, fee, last_ledger_sequence)
    pub async fn autofill_payment(&self, payment: &mut PaymentTransaction) -> Result<()> {
        // Get sequence if not set
        if payment.sequence == 0 {
            payment.sequence = self.get_account_sequence(&payment.account).await?;
        }

        // Set fee if not set (fee is already set in constructor, but this shows the pattern)
        if payment.fee == "0" {
            let base_fee = self.get_base_fee().await?;
            payment.fee = base_fee.to_string();
        }

        // Set last ledger sequence for expiration (current + 10 ledgers ~= 50 seconds)
        if payment.last_ledger_sequence.is_none() {
            let current_ledger = self.get_current_ledger_sequence().await?;
            payment.last_ledger_sequence = Some(current_ledger + 10);
        }

        Ok(())
    }

    /// Auto-fill trustset transaction fields
    pub async fn autofill_trustset(&self, trustset: &mut TrustSetTransaction) -> Result<()> {
        // Get sequence if not set
        if trustset.sequence == 0 {
            trustset.sequence = self.get_account_sequence(&trustset.account).await?;
        }

        // Set fee if not set
        if trustset.fee == "0" {
            let base_fee = self.get_base_fee().await?;
            trustset.fee = base_fee.to_string();
        }

        // Set last ledger sequence for expiration
        if trustset.last_ledger_sequence.is_none() {
            let current_ledger = self.get_current_ledger_sequence().await?;
            trustset.last_ledger_sequence = Some(current_ledger + 10);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let _client = XrplClient::testnet();
    }

    #[tokio::test]
    async fn test_get_current_ledger() {
        let client = XrplClient::testnet();
        let ledger_seq = client.get_current_ledger_sequence().await.unwrap();

        assert!(ledger_seq > 0);
    }

    #[tokio::test]
    async fn test_get_base_fee() {
        let client = XrplClient::testnet();
        let fee = client.get_base_fee().await.unwrap();

        assert!(fee >= 10);
    }
}
