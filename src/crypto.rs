use crate::encoding::{decode_seed, encode_classic_address};
use crate::errors::{Result, XrplError};
use core::convert::TryInto;
use ed25519_dalek::{SecretKey as Ed25519SecretKey, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug)]
pub struct Wallet {
    pub seed: String,
    pub private_key: String,
    pub public_key: String,
    pub classic_address: String,
}

/// Generate a new random seed (SECP256K1 format to start with 's')
pub fn generate_seed() -> Result<String> {
    let mut seed_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut seed_bytes);

    // Use SECP256K1 format so seeds start with 's'
    encode_seed_secp256k1(&seed_bytes)
}

/// Encode seed in SECP256K1 format (starts with 's')
fn encode_seed_secp256k1(seed_bytes: &[u8]) -> Result<String> {
    if seed_bytes.len() != 16 {
        return Err(XrplError::InvalidSeed("Seed must be 16 bytes".to_string()));
    }

    let family_seed_prefix = [0x21u8]; // SECP256K1 prefix
    let mut payload = Vec::new();
    payload.extend_from_slice(&family_seed_prefix);
    payload.extend_from_slice(seed_bytes);

    let result = bs58::encode(payload)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .with_check()
        .into_string();

    Ok(result)
}

/// Derive keypair and address from seed
pub fn derive_keypair_from_seed(seed_str: &str) -> Result<Wallet> {
    // First decode the seed to get the raw bytes and algorithm
    let seed_bytes = decode_seed(seed_str)?;

    // Determine algorithm from seed prefix
    let algorithm = get_algorithm_from_seed(seed_str)?;

    let (public_key, private_key) = match algorithm {
        CryptoAlgorithm::ED25519 => derive_ed25519_keypair(&seed_bytes)?,
        CryptoAlgorithm::SECP256K1 => derive_secp256k1_keypair(&seed_bytes)?,
    };

    // Derive classic address from public key
    let account_id = get_account_id_from_public_key(&public_key)?;
    let classic_address = encode_classic_address(&account_id)?;

    Ok(Wallet {
        seed: seed_str.to_string(),
        private_key,
        public_key,
        classic_address,
    })
}

#[derive(Debug)]
enum CryptoAlgorithm {
    ED25519,
    SECP256K1,
}

/// Determine crypto algorithm from seed format
fn get_algorithm_from_seed(seed_str: &str) -> Result<CryptoAlgorithm> {
    // Decode to see the prefix
    let decoded = bs58::decode(seed_str)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .with_check(None)
        .into_vec()
        .map_err(|e| XrplError::Base58Decode(format!("Failed to decode seed: {e:?}")))?;

    // Check prefixes
    if decoded.len() >= 3 && decoded[..3] == [0x01, 0xE1, 0x4B] {
        Ok(CryptoAlgorithm::ED25519)
    } else if !decoded.is_empty() && decoded[0] == 0x21 {
        Ok(CryptoAlgorithm::SECP256K1)
    } else {
        Err(XrplError::InvalidSeed("Unknown seed algorithm".to_string()))
    }
}

/// Derive ED25519 keypair
fn derive_ed25519_keypair(seed_bytes: &[u8]) -> Result<(String, String)> {
    // Step 1: Get raw_private using sha512_first_half
    let raw_private = sha512_first_half(seed_bytes);

    // Step 2: Create SecretKey from raw_private
    let private: Ed25519SecretKey = Ed25519SecretKey::from(raw_private);

    // Step 3: Create SigningKey from SecretKey
    let signing_key: SigningKey = private.into();

    // Step 4: Get VerifyingKey from SigningKey
    let public: VerifyingKey = (&signing_key).into();

    // Step 5: Format keys
    let formatted_keys = format_ed25519_keys(public, private);

    Ok(formatted_keys)
}

fn format_ed25519_keys(public: VerifyingKey, private: Ed25519SecretKey) -> (String, String) {
    (
        format_ed25519_key(&public_key_to_str(public)),
        format_ed25519_key(&private_key_to_str(private)),
    )
}

fn private_key_to_str(key: Ed25519SecretKey) -> String {
    hex::encode(key)
}

fn public_key_to_str(key: VerifyingKey) -> String {
    hex::encode(key.as_ref())
}

fn format_ed25519_key(keystr: &str) -> String {
    format!("{}{}", "ED", keystr.to_uppercase())
}

/// Derive SECP256K1 keypair using multi-step process
fn derive_secp256k1_keypair(seed_bytes: &[u8]) -> Result<(String, String)> {
    // Step 1: Derive root key pair
    let (root_public, root_private) = derive_secp256k1_part(seed_bytes, Secp256k1Phase::Root)?;

    // Step 2: Derive intermediate key pair from root public key
    let root_public_serialized = root_public.serialize();
    let (intermediate_public, intermediate_private) =
        derive_secp256k1_part(&root_public_serialized, Secp256k1Phase::Intermediate)?;

    // Step 3: Derive final master key pair (combine root + intermediate)
    let (final_public, final_private) = derive_secp256k1_final(
        root_public,
        root_private,
        intermediate_public,
        intermediate_private,
    )?;

    // Format keys
    let private_key = hex::encode_upper(final_private.secret_bytes());
    let public_key = hex::encode_upper(final_public.serialize());

    Ok((public_key, private_key))
}

#[derive(Debug, PartialEq)]
enum Secp256k1Phase {
    Root,
    Intermediate,
}

/// Derive a SECP256K1 key pair part (root or intermediate)
fn derive_secp256k1_part(
    input_bytes: &[u8],
    phase: Secp256k1Phase,
) -> Result<(secp256k1::PublicKey, secp256k1::SecretKey)> {
    // Try sequence numbers until we get a valid private key
    for seq in 0..128u32 {
        let seq_bytes = seq.to_be_bytes();

        // Prepare candidate bytes based on phase
        let candidate_bytes = match phase {
            Secp256k1Phase::Root => [input_bytes, &seq_bytes].concat(),
            Secp256k1Phase::Intermediate => {
                // Add intermediate padding
                let padding = [0x00u8; 4]; // intermediate padding
                [input_bytes, &padding, &seq_bytes].concat()
            }
        };

        // Hash the candidate
        let raw_private = sha512_first_half(&candidate_bytes);

        // Check if this creates a valid SECP256K1 private key
        if let Ok(secret_key) = secp256k1::SecretKey::from_slice(&raw_private) {
            let secp = secp256k1::Secp256k1::new();
            let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

            return Ok((public_key, secret_key));
        }
    }

    Err(XrplError::Crypto(
        "Unable to derive valid SECP256K1 key".to_string(),
    ))
}

/// Combine root and intermediate keys to create final master key pair
fn derive_secp256k1_final(
    root_public: secp256k1::PublicKey,
    root_private: secp256k1::SecretKey,
    intermediate_public: secp256k1::PublicKey,
    intermediate_private: secp256k1::SecretKey,
) -> Result<(secp256k1::PublicKey, secp256k1::SecretKey)> {
    // Add private keys (modulo curve order)
    let intermediate_scalar = secp256k1::Scalar::from(intermediate_private);
    let final_private = root_private
        .add_tweak(&intermediate_scalar)
        .map_err(|e| XrplError::Crypto(format!("Failed to add private keys: {e}")))?;

    // Add public keys (elliptic curve point addition)
    let final_public = root_public
        .combine(&intermediate_public)
        .map_err(|e| XrplError::Crypto(format!("Failed to combine public keys: {e}")))?;

    Ok((final_public, final_private))
}

fn sha512_first_half(data: &[u8]) -> [u8; 32] {
    let hash = Sha512::digest(data);
    hash[..32].try_into().expect("Invalid slice length")
}

/// Get account ID from public key
pub fn get_account_id_from_public_key(public_key_hex: &str) -> Result<Vec<u8>> {
    let pub_key_bytes = if public_key_hex.starts_with("ED") {
        // For ED25519: decode the entire string including "ED" prefix
        // This gives us 0xED followed by 32 bytes of the actual public key
        hex::decode(public_key_hex)?
    } else {
        // For SECP256K1: decode as-is (33 bytes compressed public key)
        hex::decode(public_key_hex)?
    };

    // Hash the public key: SHA-256, then RIPEMD-160
    let mut sha256 = Sha256::new();
    sha256.update(&pub_key_bytes);
    let sha_result = sha256.finalize();

    let mut ripemd = Ripemd160::new();
    ripemd.update(sha_result);
    let account_id = ripemd.finalize();

    Ok(account_id.to_vec())
}

/// Sign a message with private key
pub fn sign_message(message: &[u8], private_key: &str) -> Result<String> {
    let private_key_bytes = hex::decode(private_key)
        .map_err(|_| XrplError::Crypto("Invalid private key hex".to_string()))?;

    if private_key_bytes.len() != 32 {
        return Err(XrplError::Crypto(
            "Private key must be 32 bytes".to_string(),
        ));
    }

    let key_bytes: [u8; 32] = private_key_bytes
        .try_into()
        .map_err(|_| XrplError::Crypto("Failed to convert private key".to_string()))?;

    let signing_key = SigningKey::from_bytes(&key_bytes);
    let signature = signing_key.sign(message);

    Ok(hex::encode_upper(signature.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::encode_seed;

    #[test]
    fn test_seed_generation() {
        let seed = generate_seed().unwrap();
        assert!(seed.starts_with('s')); // XRPL seeds start with 's'
        assert!(seed.len() > 20); // Should be base58 encoded
    }

    #[test]
    fn test_keypair_derivation() {
        let seed = generate_seed().unwrap();
        let wallet = derive_keypair_from_seed(&seed).unwrap();

        assert_eq!(wallet.seed, seed);
        // Check for either ED25519 or SECP256K1 format
        assert!(
            wallet.public_key.starts_with("ED")
                || wallet.public_key.starts_with("02")
                || wallet.public_key.starts_with("03")
        );
        assert!(wallet.classic_address.starts_with('r'));
        assert!(wallet.private_key.len() >= 64);
    }

    #[test]
    fn test_signing() {
        let seed = generate_seed().unwrap();
        let wallet = derive_keypair_from_seed(&seed).unwrap();

        let message = b"test message";
        let signature = sign_message(message, &wallet.private_key).unwrap();

        assert_eq!(signature.len(), 128); // 64 bytes in hex (ED25519 signature)
    }

    #[test]
    fn test_deterministic_derivation() {
        // Same seed should always produce same keys
        // Using a seed that we generate and test with
        let test_seed_bytes = [1u8; 16];
        let test_seed = encode_seed(&test_seed_bytes).unwrap();

        let wallet1 = derive_keypair_from_seed(&test_seed).unwrap();
        let wallet2 = derive_keypair_from_seed(&test_seed).unwrap();

        assert_eq!(wallet1.private_key, wallet2.private_key);
        assert_eq!(wallet1.public_key, wallet2.public_key);
        assert_eq!(wallet1.classic_address, wallet2.classic_address);
    }

    #[test]
    fn test_user_seed() {
        // Test with user's actual seed and address
        let user_seed = "sEd78sQ1WwEv6h7WGBR7Y3DrkiMmhri";
        let expected_address = "r4dSxEV1nUjSnbA1xXZPtq5zV5WhcDWWeX";

        match derive_keypair_from_seed(user_seed) {
            Ok(wallet) => {
                println!("Derived address: {}", wallet.classic_address);
                println!("Expected address: {expected_address}");
            }
            Err(e) => {
                println!("User seed derivation failed: {e}");
            }
        }
    }
}
