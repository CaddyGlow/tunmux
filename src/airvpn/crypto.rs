use aes::cipher::{
    block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyIvInit,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use rsa::{pkcs1v15::Pkcs1v15Encrypt, BigUint, RsaPublicKey};

use crate::error::{AppError, Result};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// RSA-4096 public key modulus (base64) from AirVPN.xml
const RSA_MODULUS_B64: &str = "\
wuQXz7eZeEBwaaRsVK8iEHpueXoKyQzW8sr8qMUkZIcKtKv5iseXMrTbcGYGpRXdiqXp7FqrSjPS\
MDuRGaHfjWgjbnW4PwecmgJSfhkWt4xY8OnIwKkuI2Eo0MAa9lduPOQRKSfa9I1PBogIyEUrf7kSj\
coJQgeY66D429m1BDWY3f65c+8HrCQ8qPg1GY+pSxuwp6+2dV7fd1tiKLQEoJg9NeWGW0he/DDkN\
Se4c8gFfHj3ANYwDhTQijb+VaVZqPmxVJIzLoE1JOom0/P8fKsvpx3cFOtDS4apiI+N7MyVAMcx5\
Jjk2AQ/tyDiybwwZ32fOqYJVGxs13guOlgI6h77QxqNIq2bGEjzSRZ4tem1uN7F8AoVKPls6yAUQ\
K1cWM5AVu4apoNIFG+svS/2kmn0Nx8DRVDvKD+nOByXgqg01Y6r0Se8Tz9EEBTiEopdlKjmO1wlr\
mW3iWKeFIwZnHt2PMceJMqziV8rRGh9gUMLLJC9qdXCAS4vf5VVnZ+Pq3SK9pP87hOislIu4/Kcn\
06cotQChpVnALA83hFW5LXJvc85iloWJkuLGAV3CcAwoSA5CG1Uo2S76MM+GLLkVIqUk1PiJMTTl\
Sw1SlMEflU4bZiZP8di5e2OJI6vOHjdM2oonpPi/Ul5KKmfp+jci+kGMs9+zOyjKFLVIKDE+Vc=";

/// RSA exponent: AQAB = 65537
const RSA_EXPONENT_B64: &str = "AQAB";

/// Holds a generated AES-256 session key and IV for one API request.
pub struct AirVpnCrypto {
    rsa_pub: RsaPublicKey,
}

impl AirVpnCrypto {
    pub fn new() -> Result<Self> {
        let n_bytes = B64
            .decode(RSA_MODULUS_B64)
            .map_err(|e| AppError::AirVpnCrypto(format!("bad RSA modulus: {}", e)))?;
        let e_bytes = B64
            .decode(RSA_EXPONENT_B64)
            .map_err(|e| AppError::AirVpnCrypto(format!("bad RSA exponent: {}", e)))?;

        let n = BigUint::from_bytes_be(&n_bytes);
        let e = BigUint::from_bytes_be(&e_bytes);

        let rsa_pub = RsaPublicKey::new(n, e)
            .map_err(|e| AppError::AirVpnCrypto(format!("invalid RSA key: {}", e)))?;

        Ok(Self { rsa_pub })
    }

    /// Encrypt request parameters, returning (s_param, d_param, session) where
    /// s is the RSA-encrypted AES key info (base64) and d is the AES-encrypted
    /// request data (base64). The returned session is needed to decrypt the response.
    pub fn encrypt_request(
        &self,
        params: &[(&str, &str)],
    ) -> Result<(String, String, SessionKeys)> {
        // Generate random AES-256 key (32 bytes) + IV (16 bytes)
        let mut aes_key = [0u8; 32];
        let mut aes_iv = [0u8; 16];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut aes_key);
        rng.fill_bytes(&mut aes_iv);

        // Build the key:iv associative encoding
        // Format: base64("key"):base64(aes_key)\nbase64("iv"):base64(aes_iv)\n
        let key_iv_data = format!(
            "{}:{}\n{}:{}\n",
            B64.encode(b"key"),
            B64.encode(aes_key),
            B64.encode(b"iv"),
            B64.encode(aes_iv),
        );

        // RSA-PKCS1v15 encrypt the key/iv data
        let encrypted_key_iv = self
            .rsa_pub
            .encrypt(&mut rng, Pkcs1v15Encrypt, key_iv_data.as_bytes())
            .map_err(|e| AppError::AirVpnCrypto(format!("RSA encrypt failed: {}", e)))?;

        let s_param = B64.encode(&encrypted_key_iv);

        // Build the request data associative encoding
        // Format: base64(param_name):base64(param_value)\n per pair
        let mut request_data = String::new();
        for (k, v) in params {
            request_data.push_str(&B64.encode(k.as_bytes()));
            request_data.push(':');
            request_data.push_str(&B64.encode(v.as_bytes()));
            request_data.push('\n');
        }

        // AES-256-CBC encrypt the request data
        let plaintext = request_data.as_bytes();
        let block_size = <Aes256CbcEnc as BlockSizeUser>::block_size();
        let pad_len = block_size - (plaintext.len() % block_size);
        let mut buf = vec![0u8; plaintext.len() + pad_len];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let encrypted = Aes256CbcEnc::new(&aes_key.into(), &aes_iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .map_err(|e| AppError::AirVpnCrypto(format!("AES encrypt failed: {}", e)))?;

        let d_param = B64.encode(encrypted);

        Ok((
            s_param,
            d_param,
            SessionKeys {
                key: aes_key,
                iv: aes_iv,
            },
        ))
    }

    /// Decrypt a response body (raw bytes) using the session keys from encrypt_request.
    pub fn decrypt_response(&self, ciphertext: &[u8], session: &SessionKeys) -> Result<String> {
        let mut buf = ciphertext.to_vec();
        let plaintext = Aes256CbcDec::new(&session.key.into(), &session.iv.into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| AppError::AirVpnCrypto(format!("AES decrypt failed: {}", e)))?;

        String::from_utf8(plaintext.to_vec())
            .map_err(|e| AppError::AirVpnCrypto(format!("response not UTF-8: {}", e)))
    }
}

/// AES session keys for a single request/response pair.
pub struct SessionKeys {
    key: [u8; 32],
    iv: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_round_trip_aes() {
        let crypto = AirVpnCrypto::new().unwrap();

        let params = [("act", "user"), ("login", "test"), ("password", "secret")];
        let (s_param, d_param, session) = crypto.encrypt_request(&params).unwrap();

        // s and d should be non-empty base64
        assert!(!s_param.is_empty());
        assert!(!d_param.is_empty());
        assert!(B64.decode(&s_param).is_ok());
        assert!(B64.decode(&d_param).is_ok());

        // We can decrypt our own d_param with the session keys
        let ciphertext = B64.decode(&d_param).unwrap();
        let decrypted = crypto.decrypt_response(&ciphertext, &session).unwrap();

        // Verify it contains the expected encoded parameters
        assert!(decrypted.contains(&B64.encode(b"act")));
        assert!(decrypted.contains(&B64.encode(b"user")));
    }
}
