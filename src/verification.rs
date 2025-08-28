use crate::{Address, Result, XrpDrops, XrplError, XrplWebSocketClient}; 

/// Verify XRP payment transaction
pub async fn verify_xrp_payment(
    client: &mut XrplWebSocketClient,
    tx_hash: &str,
    expected_from: &Address,
    expected_to: &Address,
    expected_amount: XrpDrops,
) -> Result<bool> {
    println!("Verifying transaction: {}", tx_hash);

    // Look up the transaction
    let tx = client.get_transaction(tx_hash).await?;

    println!("   Transaction found in ledger: {}", tx.ledger_index);
    println!("   Validated: {}", tx.validated);

    // Verify transaction details
    let mut verification_passed = true;

    // Check transaction type
    if tx.transaction_type != "Payment" {
        println!(
            "Wrong transaction type: {} (expected Payment)",
            tx.transaction_type
        );
        verification_passed = false;
    }

    // Check sender
    if tx.account != *expected_from {
        println!(
            "Wrong sender: {} (expected {})",
            tx.account, expected_from
        );
        verification_passed = false;
    }

    // Check recipient
    if tx.destination != *expected_to {
        println!(
            "Wrong recipient: {} (expected {})",
            tx.destination, expected_to
        );
        verification_passed = false;
    }

    // Check amount
    let tx_amount: XrpDrops = tx
        .amount
        .parse()
        .map_err(|_| XrplError::transaction("Invalid amount in transaction"))?;

    if tx_amount != expected_amount {
        println!(
            "Wrong amount: {} drops (expected {} drops)",
            tx_amount, expected_amount
        );
        verification_passed = false;
    }

    // Check if transaction is validated
    if !tx.validated {
        println!("Transaction not yet validated");
        verification_passed = false;
    }

    if verification_passed {
        println!("Transaction verification passed!");
        println!("   Type: Payment");
        println!("   From: {}", tx.account);
        println!("   To: {}", tx.destination);
        println!("   Amount: {} drops", tx_amount);
        println!("   Validated: {}", tx.validated);
    }

    Ok(verification_passed)
}

/// Get account balance
pub async fn get_account_balance(
    client: &mut XrplWebSocketClient,
    address: &Address,
) -> Result<XrpDrops> {
    let account_info = client.get_account_info(address).await?;
    let balance: XrpDrops = account_info
        .balance
        .parse()
        .map_err(|_| XrplError::transaction("Invalid balance format"))?;

    Ok(balance)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_logic() {
        // For now, just a placeholder
        assert!(true);
    }
}
