use crate::errors::{Result, XrplError};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio_tungstenite::{connect_async, tungstenite::Message};

pub struct WebSocketClient {
    url: String,
    request_id: AtomicU64,
}

impl WebSocketClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            request_id: AtomicU64::new(1),
        }
    }

    pub fn testnet() -> Self {
        Self::new("wss://s.altnet.rippletest.net:51233")
    }

    pub fn mainnet() -> Self {
        Self::new("wss://s1.ripple.com:443")
    }

    /// Send a request and wait for response
    pub async fn request(&self, command: &str, params: Value) -> Result<Value> {
        let (ws_stream, _) = connect_async(&self.url).await?;
        let (mut write, mut read) = ws_stream.split();

        let request_id = self.request_id.fetch_add(1, Ordering::SeqCst);

        let mut request = json!({
            "id": request_id,
            "command": command
        });

        // Merge params into request
        if let Value::Object(params_map) = params {
            if let Value::Object(request_map) = &mut request {
                for (key, value) in params_map {
                    request_map.insert(key, value);
                }
            }
        }

        // Send request
        let request_str = serde_json::to_string(&request)?;
        write.send(Message::Text(request_str)).await?;

        // Wait for response
        while let Some(msg) = read.next().await {
            let msg = msg?;
            if let Message::Text(text) = msg {
                let response: Value = serde_json::from_str(&text)?;

                // Check if this is our response
                if let Some(id) = response.get("id") {
                    if id == &json!(request_id) {
                        return Ok(response);
                    }
                }
            }
        }

        Err(XrplError::Network("No response received".to_string()))
    }

    /// Get account info
    pub async fn account_info(&self, account: &str) -> Result<Value> {
        self.request(
            "account_info",
            json!({
                "account": account,
                "strict": true,
                "ledger_index": "current",
                "queue": true
            }),
        )
        .await
    }

    /// Get server info
    pub async fn server_info(&self) -> Result<Value> {
        self.request("server_info", json!({})).await
    }

    /// Submit a transaction
    pub async fn submit(&self, tx_blob: &str) -> Result<Value> {
        self.request(
            "submit",
            json!({
                "tx_blob": tx_blob
            }),
        )
        .await
    }

    /// Get transaction info
    pub async fn tx(&self, transaction: &str) -> Result<Value> {
        self.request(
            "tx",
            json!({
                "transaction": transaction,
                "binary": false
            }),
        )
        .await
    }

    /// Get fee info
    pub async fn fee(&self) -> Result<Value> {
        self.request("fee", json!({})).await
    }

    /// Get current ledger
    pub async fn ledger_current(&self) -> Result<Value> {
        self.request("ledger_current", json!({})).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_info() {
        let client = WebSocketClient::testnet();
        let response = client.server_info().await.unwrap();

        assert!(response.get("status").is_some());
        assert_eq!(response["status"], "success");
    }

    #[tokio::test]
    async fn test_fee_info() {
        let client = WebSocketClient::testnet();
        let response = client.fee().await.unwrap();

        assert!(response.get("status").is_some());
        assert_eq!(response["status"], "success");
        assert!(response.get("result").is_some());
    }
}
