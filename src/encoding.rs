use crate::errors::{Result, XrplError};
use sha2::{Digest, Sha256};

const CLASSIC_ADDRESS_PREFIX: [u8; 1] = [0x00];
// SECP256K1 seeds
const FAMILY_SEED_PREFIX: [u8; 1] = [0x21];
// ED25519 seeds
const ED25519_SEED_PREFIX: [u8; 3] = [0x01, 0xE1, 0x4B];

/// Encode a classic XRPL address from account ID
pub fn encode_classic_address(account_id: &[u8]) -> Result<String> {
    if account_id.len() != 20 {
        return Err(XrplError::InvalidAddress(
            "Account ID must be 20 bytes".to_string(),
        ));
    }

    let mut payload = Vec::new();
    payload.extend_from_slice(&CLASSIC_ADDRESS_PREFIX);
    payload.extend_from_slice(account_id);

    let result = bs58::encode(payload)
        .with_alphabet(&bs58::Alphabet::RIPPLE)
        .with_check()
        .into_string();

    Ok(result)
}

/// Decode a classic XRPL address to account ID
pub fn decode_classic_address(address: &str) -> Result<Vec<u8>> {
    let decoded = bs58::decode(address)
        .with_alphabet(&bs58::Alphabet::RIPPLE)
        .with_check(None)
        .into_vec()
        .map_err(|e| XrplError::Base58Decode(format!("Failed to decode address: {:?}", e)))?;

    if decoded.len() < 1 {
        return Err(XrplError::InvalidAddress(
            "Decoded data too short".to_string(),
        ));
    }

    if decoded[0] != CLASSIC_ADDRESS_PREFIX[0] {
        return Err(XrplError::InvalidAddress(format!(
            "Invalid address prefix: expected {}, got {}",
            CLASSIC_ADDRESS_PREFIX[0], decoded[0]
        )));
    }

    let account_id = &decoded[1..];

    if account_id.len() != 20 {
        return Err(XrplError::InvalidAddress(format!(
            "Invalid account ID length: expected 20, got {}",
            account_id.len()
        )));
    }

    Ok(account_id.to_vec())
}

/// Encode a seed for XRPL
pub fn encode_seed(seed_bytes: &[u8]) -> Result<String> {
    if seed_bytes.len() != 16 {
        return Err(XrplError::InvalidSeed("Seed must be 16 bytes".to_string()));
    }

    // For ED25519 seeds, use the ED25519 prefix
    let mut payload = Vec::new();
    payload.extend_from_slice(&ED25519_SEED_PREFIX);
    payload.extend_from_slice(seed_bytes);

    let result = bs58::encode(payload)
        .with_alphabet(&bs58::Alphabet::RIPPLE)
        .with_check()
        .into_string();

    Ok(result)
}

/// Decode a seed from base58 format
pub fn decode_seed(seed_str: &str) -> Result<Vec<u8>> {
    let decoded = bs58::decode(seed_str)
        .with_alphabet(&bs58::Alphabet::RIPPLE)
        .with_check(None)
        .into_vec()
        .map_err(|e| XrplError::Base58Decode(format!("Failed to decode seed: {:?}", e)))?;

    // Try ED25519 prefix first
    if decoded.len() >= ED25519_SEED_PREFIX.len()
        && &decoded[..ED25519_SEED_PREFIX.len()] == &ED25519_SEED_PREFIX
    {
        let seed_bytes = &decoded[ED25519_SEED_PREFIX.len()..];

        if seed_bytes.len() != 16 {
            return Err(XrplError::InvalidSeed(format!(
                "Invalid ED25519 seed length: expected 16, got {}",
                seed_bytes.len()
            )));
        }

        return Ok(seed_bytes.to_vec());
    }

    // Try SECP256K1 prefix
    if decoded.len() >= FAMILY_SEED_PREFIX.len()
        && &decoded[..FAMILY_SEED_PREFIX.len()] == &FAMILY_SEED_PREFIX
    {
        let seed_bytes = &decoded[FAMILY_SEED_PREFIX.len()..];

        if seed_bytes.len() != 16 {
            return Err(XrplError::InvalidSeed(format!(
                "Invalid SECP256K1 seed length: expected 16, got {}",
                seed_bytes.len()
            )));
        }

        return Ok(seed_bytes.to_vec());
    }

    Err(XrplError::InvalidSeed(format!(
        "Invalid seed prefix. Expected ED25519 {:?} or SECP256K1 {:?}",
        ED25519_SEED_PREFIX, FAMILY_SEED_PREFIX
    )))
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(hex_str)?)
}

/// Convert bytes to hex string (uppercase)
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_encoding_decoding() {
        // Test with a known XRPL address
        let test_address = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";

        let account_id = decode_classic_address(test_address).unwrap();
        let re_encoded = encode_classic_address(&account_id).unwrap();

        assert_eq!(test_address, re_encoded);
    }

    #[test]
    fn test_seed_encoding_decoding() {
        let seed_bytes = [1u8; 16]; // Test seed
        let encoded = encode_seed(&seed_bytes).unwrap();
        let decoded = decode_seed(&encoded).unwrap();

        assert_eq!(seed_bytes.to_vec(), decoded);
    }
}
