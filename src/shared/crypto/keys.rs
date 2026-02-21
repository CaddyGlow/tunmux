#![allow(dead_code)]

/// Ed25519 key generation, X25519 conversion, PEM encoding, and Proton fingerprints.
///
/// Reference: python-proton-vpn-api-core/proton/vpn/session/key_mgr.py
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha512};

use crate::error::{AppError, Result};

/// DER prefix for SubjectPublicKeyInfo wrapping an Ed25519 public key.
/// ASN.1: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (32 bytes) }
const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// DER prefix for PKCS#8 wrapping an Ed25519 private key.
/// ASN.1: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING (32 bytes) } }
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// All derived key material from a single Ed25519 keypair.
pub struct VpnKeys {
    pub ed25519_private_key: [u8; 32],
    pub ed25519_public_key: [u8; 32],
    pub x25519_private_key: [u8; 32],
    pub x25519_public_key: [u8; 32],
}

impl VpnKeys {
    /// Generate a new random Ed25519 keypair and derive X25519 keys.
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        Self::from_ed25519_private_key(signing_key.to_bytes())
    }

    /// Restore keys from a stored Ed25519 private key (32 bytes).
    pub fn from_ed25519_private_key(ed25519_sk: [u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(&ed25519_sk);
        let ed25519_pk = signing_key.verifying_key().to_bytes();

        // Ed25519 -> X25519 private key: SHA-512(ed25519_sk)[0..32] with clamping
        let hash = Sha512::digest(ed25519_sk);
        let mut x25519_sk = [0u8; 32];
        x25519_sk.copy_from_slice(&hash[..32]);
        // Clamp
        x25519_sk[0] &= 248;
        x25519_sk[31] &= 127;
        x25519_sk[31] |= 64;

        // Ed25519 -> X25519 public key: decompress Edwards point, convert to Montgomery
        let compressed = CompressedEdwardsY(ed25519_pk);
        let edwards_point = compressed
            .decompress()
            .ok_or_else(|| AppError::Crypto("failed to decompress Ed25519 public key".into()))?;
        let montgomery = edwards_point.to_montgomery();
        let x25519_pk = montgomery.to_bytes();

        Ok(Self {
            ed25519_private_key: ed25519_sk,
            ed25519_public_key: ed25519_pk,
            x25519_private_key: x25519_sk,
            x25519_public_key: x25519_pk,
        })
    }

    /// Restore keys from base64-encoded Ed25519 private key.
    pub fn from_base64(ed25519_sk_b64: &str) -> Result<Self> {
        let bytes = BASE64
            .decode(ed25519_sk_b64)
            .map_err(|e| AppError::Crypto(format!("invalid ed25519 key base64: {}", e)))?;
        if bytes.len() != 32 {
            return Err(AppError::Crypto(format!(
                "ed25519 key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_ed25519_private_key(arr)
    }

    /// Ed25519 private key as base64 (for storage).
    #[must_use]
    pub fn ed25519_sk_base64(&self) -> String {
        BASE64.encode(self.ed25519_private_key)
    }

    /// Ed25519 public key in PEM format (SubjectPublicKeyInfo).
    #[must_use]
    pub fn ed25519_pk_pem(&self) -> String {
        let mut der = Vec::with_capacity(SPKI_ED25519_PREFIX.len() + 32);
        der.extend_from_slice(&SPKI_ED25519_PREFIX);
        der.extend_from_slice(&self.ed25519_public_key);
        pem_encode("PUBLIC KEY", &der)
    }

    /// Ed25519 private key in PEM format (PKCS#8).
    #[must_use]
    pub fn ed25519_sk_pem(&self) -> String {
        let mut der = Vec::with_capacity(PKCS8_ED25519_PREFIX.len() + 32);
        der.extend_from_slice(&PKCS8_ED25519_PREFIX);
        der.extend_from_slice(&self.ed25519_private_key);
        pem_encode("PRIVATE KEY", &der)
    }

    /// X25519 private key as base64 (WireGuard private key).
    #[must_use]
    pub fn wg_private_key(&self) -> String {
        BASE64.encode(self.x25519_private_key)
    }

    /// X25519 public key as base64 (WireGuard public key).
    #[must_use]
    pub fn wg_public_key(&self) -> String {
        BASE64.encode(self.x25519_public_key)
    }

    /// Proton fingerprint: base64(sha512(x25519_public_key))
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let hash = Sha512::digest(self.x25519_public_key);
        BASE64.encode(hash)
    }
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = BASE64.encode(der);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is valid utf8"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_to_x25519_conversion() {
        // Generate a keypair and verify the conversion produces valid keys
        let keys = VpnKeys::generate().unwrap();

        // Verify key sizes
        assert_eq!(keys.ed25519_private_key.len(), 32);
        assert_eq!(keys.ed25519_public_key.len(), 32);
        assert_eq!(keys.x25519_private_key.len(), 32);
        assert_eq!(keys.x25519_public_key.len(), 32);

        // Verify clamping on X25519 private key
        assert_eq!(keys.x25519_private_key[0] & 7, 0); // low 3 bits clear
        assert_eq!(keys.x25519_private_key[31] & 128, 0); // high bit clear
        assert_eq!(keys.x25519_private_key[31] & 64, 64); // second-highest bit set

        // Verify round-trip from base64
        let b64 = keys.ed25519_sk_base64();
        let restored = VpnKeys::from_base64(&b64).unwrap();
        assert_eq!(keys.ed25519_private_key, restored.ed25519_private_key);
        assert_eq!(keys.x25519_private_key, restored.x25519_private_key);
        assert_eq!(keys.x25519_public_key, restored.x25519_public_key);
        assert_eq!(keys.fingerprint(), restored.fingerprint());
    }

    #[test]
    fn test_pem_format() {
        let keys = VpnKeys::generate().unwrap();
        let pk_pem = keys.ed25519_pk_pem();
        assert!(pk_pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pk_pem.ends_with("-----END PUBLIC KEY-----\n"));

        let sk_pem = keys.ed25519_sk_pem();
        assert!(sk_pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(sk_pem.ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn test_fingerprint_consistency() {
        let keys = VpnKeys::generate().unwrap();
        let fp1 = keys.fingerprint();
        let fp2 = keys.fingerprint();
        assert_eq!(fp1, fp2);

        // Fingerprint should be base64 of sha512, so 88 chars (86 + 2 padding)
        let decoded = BASE64.decode(&fp1).unwrap();
        assert_eq!(decoded.len(), 64); // SHA-512 = 64 bytes
    }

    #[test]
    fn test_known_ed25519_to_x25519() {
        // Known test vector: all-zero ed25519 private key
        // SHA-512(0x00*32)[0..32] clamped should give a specific x25519 key
        let sk = [0u8; 32];
        let keys = VpnKeys::from_ed25519_private_key(sk).unwrap();

        // Verify the x25519 private key matches SHA-512 clamping
        let hash = Sha512::digest(sk);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hash[..32]);
        expected[0] &= 248;
        expected[31] &= 127;
        expected[31] |= 64;

        assert_eq!(keys.x25519_private_key, expected);
    }
}
