/// SRP-6a implementation for Proton authentication.
///
/// Reference: github.com/ProtonMail/go-srp
///
/// Key differences from textbook SRP-6a:
/// - All integers serialized as LITTLE-ENDIAN on the wire
/// - Hash function is `expandHash` (4x SHA-512 = 256 bytes), not SHA-256
/// - Password hashing uses standard bcrypt ($2y$10$) + expandHash, not bcrypt-pbkdf
/// - Multiplier k = expandHash(pad_le(g) || pad_le(N))  (generator first)
/// - Exponent = (u * x + a) mod (N - 1)
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha512};

use crate::error::{AppError, Result};

const GENERATOR: u32 = 2;
const BIT_LENGTH: usize = 2048;
const BYTE_LEN: usize = BIT_LENGTH / 8; // 256

// -- expandHash: the core hash function used throughout Proton SRP --

/// Proton's expandHash: SHA-512(data || 0) || SHA-512(data || 1) || SHA-512(data || 2) || SHA-512(data || 3)
/// Returns 256 bytes (2048 bits).
fn expand_hash(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(256);
    for i in 0u8..4 {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.update([i]);
        result.extend_from_slice(&hasher.finalize());
    }
    result
}

// -- Password hashing --

/// Hash password using Proton's method (SRP version 3/4).
///
/// Steps:
/// 1. Decode API salt from base64 (typically 10 bytes)
/// 2. Append b"proton" to get 16 bytes
/// 3. Encode with bcrypt base64 to get 22-char salt string
/// 4. Run standard bcrypt ($2y$10$) on raw password bytes with that salt
/// 5. Concatenate full bcrypt output string bytes with modulus LE bytes
/// 6. Return expandHash of the concatenation (256 bytes)
pub fn hash_password(password: &str, salt_b64: &str, modulus_le: &[u8]) -> Result<Vec<u8>> {
    let salt_raw = BASE64
        .decode(salt_b64)
        .map_err(|e| AppError::Srp(format!("invalid salt base64: {}", e)))?;

    // Build bcrypt salt: api_salt_bytes + b"proton"
    let mut combined_salt = salt_raw;
    combined_salt.extend_from_slice(b"proton");

    // The combined salt must be encoded with bcrypt base64, first 22 chars used.
    // For 16-byte combined (10-byte API salt + 6 "proton"), encoding produces exactly 22 chars.
    // For other lengths, we take the first 22 chars and decode back to 16 bytes.
    let salt_16 = bcrypt_salt_16(&combined_salt)?;

    // Run standard bcrypt with cost 10, $2y$ version
    let hash_parts = bcrypt::hash_with_salt(password.as_bytes(), 10, salt_16)
        .map_err(|e| AppError::Srp(format!("bcrypt failed: {}", e)))?;
    let hash_string = hash_parts.format_for_version(bcrypt::Version::TwoY);

    // expandHash(bcrypt_output_string_bytes || modulus_le_256_bytes)
    let modulus_padded = pad_le(modulus_le, BYTE_LEN);
    let mut to_hash = hash_string.into_bytes();
    to_hash.extend_from_slice(&modulus_padded);

    Ok(expand_hash(&to_hash))
}

/// Convert combined salt bytes to the 16-byte array bcrypt expects.
/// This mirrors the Go code: bcrypt_b64_encode(combined) -> take first 22 chars -> bcrypt decodes to 16 bytes.
/// Since bcrypt's base64 uses the same bit packing as standard base64 (just different alphabet),
/// and encoding 16 bytes produces exactly 22 chars, for the common 16-byte case we can pass directly.
fn bcrypt_salt_16(combined: &[u8]) -> Result<[u8; 16]> {
    use base64::alphabet::BCRYPT;
    use base64::engine::{GeneralPurpose, GeneralPurposeConfig};

    let bcrypt_b64 = GeneralPurpose::new(
        &BCRYPT,
        GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

    // Encode with bcrypt base64
    let encoded = bcrypt_b64.encode(combined);

    // Take first 22 chars (what bcrypt reads as salt)
    let salt_str = if encoded.len() >= 22 {
        &encoded[..22]
    } else {
        return Err(AppError::Srp(format!(
            "bcrypt salt encoding too short: {} chars from {} bytes",
            encoded.len(),
            combined.len()
        )));
    };

    // Decode those 22 chars back to raw bytes
    // 22 chars of bcrypt base64 = 16 bytes + 2 padding bits
    // We need to pad to a multiple of 4 for the base64 decoder
    let mut padded_str = salt_str.to_string();
    while padded_str.len() % 4 != 0 {
        padded_str.push('.'); // '.' = value 0 in bcrypt base64 alphabet
    }

    let decoded = bcrypt_b64
        .decode(&padded_str)
        .map_err(|e| AppError::Srp(format!("bcrypt salt decode failed: {}", e)))?;

    let mut salt = [0u8; 16];
    let copy_len = decoded.len().min(16);
    salt[..copy_len].copy_from_slice(&decoded[..copy_len]);
    Ok(salt)
}

// -- Modulus decoding --

/// Decode the modulus from a PGP-signed base64 message.
/// Returns (BigUint for math, raw LE bytes for password hashing).
pub fn decode_modulus(modulus_signed: &str) -> Result<(BigUint, Vec<u8>)> {
    let lines: Vec<&str> = modulus_signed.lines().collect();
    let mut payload = String::new();
    let mut in_body = false;

    for line in &lines {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
            continue;
        }
        if trimmed.starts_with("Hash:") {
            continue;
        }
        if trimmed.starts_with("-----BEGIN PGP SIGNATURE-----") {
            break;
        }
        if trimmed.is_empty() {
            in_body = true;
            continue;
        }
        if in_body {
            payload.push_str(trimmed);
        }
    }

    if payload.is_empty() {
        return Err(AppError::Srp("empty modulus payload".to_string()));
    }

    // The decoded bytes are in LITTLE-ENDIAN order (Proton wire format)
    let modulus_le_bytes = BASE64
        .decode(&payload)
        .map_err(|e| AppError::Srp(format!("modulus base64 decode failed: {}", e)))?;

    let modulus = BigUint::from_bytes_le(&modulus_le_bytes);
    Ok((modulus, modulus_le_bytes))
}

// -- SRP proof computation --

/// Compute SRP-6a client proof.
///
/// Returns (client_ephemeral_b64, client_proof_b64, expected_server_proof_bytes).
pub fn compute_srp_proof(
    hashed_password: &[u8],
    server_ephemeral_b64: &str,
    modulus: &BigUint,
) -> Result<(String, String, Vec<u8>)> {
    let n = modulus;
    let g = BigUint::from(GENERATOR);
    let n_minus_one = n - BigUint::one();

    // Decode server ephemeral B (LE bytes from API)
    let b_le_bytes = BASE64
        .decode(server_ephemeral_b64)
        .map_err(|e| AppError::Srp(format!("server ephemeral decode: {}", e)))?;
    let big_b = BigUint::from_bytes_le(&b_le_bytes);

    // Validate B != 0 and B % N != 0
    if big_b.is_zero() || (&big_b % n).is_zero() {
        return Err(AppError::Srp("invalid server ephemeral".to_string()));
    }

    // Generate client ephemeral: a in (BIT_LENGTH*2, N-1), A = g^a mod N
    let (big_a, a_secret) = generate_client_ephemeral(&g, n, &n_minus_one)?;

    // Serialize A and B as LE bytes padded to BYTE_LEN
    let a_le = to_le_padded(&big_a);
    let b_le = pad_le(&b_le_bytes, BYTE_LEN);

    // u = expandHash(A_le || B_le), interpreted as LE integer
    let u = {
        let mut buf = Vec::with_capacity(BYTE_LEN * 2);
        buf.extend_from_slice(&a_le);
        buf.extend_from_slice(&b_le);
        BigUint::from_bytes_le(&expand_hash(&buf))
    };

    if u.is_zero() {
        return Err(AppError::Srp("SRP parameter u is zero".to_string()));
    }

    // x = hashed password interpreted as LE integer
    let x = BigUint::from_bytes_le(hashed_password);

    // k = expandHash(pad_le(g) || pad_le(N)), interpreted as LE integer, mod N
    let k = {
        let g_le = to_le_padded(&g);
        let n_le = to_le_padded(n);
        let mut buf = Vec::with_capacity(BYTE_LEN * 2);
        buf.extend_from_slice(&g_le);
        buf.extend_from_slice(&n_le);
        BigUint::from_bytes_le(&expand_hash(&buf)) % n
    };

    // S = (B - k * g^x mod N) ^ ((u * x + a) mod (N-1)) mod N
    let gx_mod_n = g.modpow(&x, n);
    let kgx = (&k * &gx_mod_n) % n;

    let base = if big_b >= kgx {
        (&big_b - &kgx) % n
    } else {
        (n - &kgx + &big_b) % n
    };

    // Exponent = (u * x + a) mod (N - 1)
    let exp = ((&u * &x) + &a_secret) % &n_minus_one;
    let big_s = base.modpow(&exp, n);
    let s_le = to_le_padded(&big_s);

    // Client proof M1 = expandHash(A_le || B_le || S_le)
    let client_proof = {
        let mut buf = Vec::with_capacity(BYTE_LEN * 3);
        buf.extend_from_slice(&a_le);
        buf.extend_from_slice(&b_le);
        buf.extend_from_slice(&s_le);
        expand_hash(&buf)
    };

    // Expected server proof M2 = expandHash(A_le || M1 || S_le)
    let server_proof = {
        let mut buf = Vec::with_capacity(BYTE_LEN + 256 + BYTE_LEN);
        buf.extend_from_slice(&a_le);
        buf.extend_from_slice(&client_proof);
        buf.extend_from_slice(&s_le);
        expand_hash(&buf)
    };

    let a_b64 = BASE64.encode(&a_le);
    let proof_b64 = BASE64.encode(&client_proof);

    Ok((a_b64, proof_b64, server_proof))
}

/// Verify the server proof matches our expected value.
pub fn verify_server_proof(expected: &[u8], server_proof_b64: &str) -> Result<()> {
    let server_proof = BASE64
        .decode(server_proof_b64)
        .map_err(|e| AppError::Srp(format!("server proof decode: {}", e)))?;

    if expected != server_proof.as_slice() {
        return Err(AppError::Srp(
            "server proof verification failed".to_string(),
        ));
    }
    Ok(())
}

// -- Helper functions --

fn generate_client_ephemeral(
    g: &BigUint,
    n: &BigUint,
    n_minus_one: &BigUint,
) -> Result<(BigUint, BigUint)> {
    use num_bigint::RandBigInt;
    let mut rng = rand::thread_rng();
    let lower_bound = BigUint::from(BIT_LENGTH * 2);

    for _ in 0..64 {
        // Generate a in range [0, N-1)
        let a_secret = rng.gen_biguint_below(n_minus_one);

        // Reject if too small (must be > BIT_LENGTH * 2 = 4096)
        if a_secret <= lower_bound {
            continue;
        }

        let big_a = g.modpow(&a_secret, n);
        if big_a.is_zero() {
            continue;
        }

        return Ok((big_a, a_secret));
    }

    Err(AppError::Srp(
        "failed to generate valid client ephemeral".to_string(),
    ))
}

/// Convert a BigUint to BYTE_LEN little-endian bytes, zero-padded on the right (high end).
fn to_le_padded(n: &BigUint) -> Vec<u8> {
    let mut le = n.to_bytes_le();
    le.resize(BYTE_LEN, 0);
    le
}

/// Pad raw LE bytes to the given length with zeros on the right (high end).
fn pad_le(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut padded = bytes.to_vec();
    padded.resize(len, 0);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_hash_length() {
        let result = expand_hash(b"test data");
        assert_eq!(result.len(), 256);
    }

    #[test]
    fn test_expand_hash_deterministic() {
        let a = expand_hash(b"hello");
        let b = expand_hash(b"hello");
        assert_eq!(a, b);

        let c = expand_hash(b"world");
        assert_ne!(a, c);
    }

    #[test]
    fn test_to_le_padded() {
        let n = BigUint::from(0x0102u32);
        let le = to_le_padded(&n);
        assert_eq!(le.len(), BYTE_LEN);
        assert_eq!(le[0], 0x02); // least significant byte first
        assert_eq!(le[1], 0x01);
        assert_eq!(le[2], 0x00); // zero padded
    }

    #[test]
    fn test_modulus_decode_le() {
        // base64 of bytes [0xC0] = "wA=="
        let signed = "-----BEGIN PGP SIGNED MESSAGE-----\n\
            Hash: SHA256\n\
            \n\
            wA==\n\
            -----BEGIN PGP SIGNATURE-----\n\
            fake\n\
            -----END PGP SIGNATURE-----";

        let (modulus, le_bytes) = decode_modulus(signed).unwrap();
        // 0xC0 as a single LE byte = 192
        assert_eq!(modulus, BigUint::from(192u32));
        assert_eq!(le_bytes, vec![0xC0]);
    }
}
