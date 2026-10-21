use aes::cipher::{
    block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyIvInit,
};
#[cfg(feature = "crypto-aws-lc")]
use aws_lc_rs::rsa::{Pkcs1PublicEncryptingKey, PublicEncryptingKey};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
#[cfg(all(feature = "crypto-rustcrypto", not(feature = "crypto-aws-lc")))]
use rsa::pkcs8::DecodePublicKey;
#[cfg(all(
    feature = "crypto-rustcrypto",
    any(not(feature = "crypto-aws-lc"), test)
))]
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};

use crate::error::{AppError, Result};

#[cfg(not(any(feature = "crypto-aws-lc", feature = "crypto-rustcrypto")))]
compile_error!("AirVPN requires crypto-rustcrypto or crypto-aws-lc");

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// AirVPN.xml's RSA-4096 public key (exponent 65537), encoded as X.509 SPKI DER.
const RSA_PUBLIC_KEY_DER_B64: &str = "\
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwuQXz7eZeEBwaaRsVK8iEHpueXoKyQzW\
8sr8qMUkZIcKtKv5iseXMrTbcGYGpRXdiqXp7FqrSjPSMDuRGaHfjWgjbnW4PwecmgJSfhkWt4xY\
8OnIwKkuI2Eo0MAa9lduPOQRKSfa9I1PBogIyEUrf7kSjcoJQgeY66D429m1BDWY3f65c+8HrCQ8\
qPg1GY+pSxuwp6+2dV7fd1tiKLQEoJg9NeWGW0he/DDkNSe4c8gFfHj3ANYwDhTQijb+VaVZqPmx\
VJIzLoE1JOom0/P8fKsvpx3cFOtDS4apiI+N7MyVAMcx5Jjk2AQ/tyDiybwwZ32fOqYJVGxs13gu\
OlgI6h77QxqNIq2bGEjzSRZ4tem1uN7F8AoVKPls6yAUQK1cWM5AVu4apoNIFG+svS/2kmn0Nx8D\
RVDvKD+nOByXgqg01Y6r0Se8Tz9EEBTiEopdlKjmO1wlrmW3iWKeFIwZnHt2PMceJMqziV8rRGh9\
gUMLLJC9qdXCAS4vf5VVnZ+Pq3SK9pP87hOislIu4/Kcn06cotQChpVnALA83hFW5LXJvc85iloW\
JkuLGAV3CcAwoSA5CG1Uo2S76MM+GLLkVIqUk1PiJMTTlSw1SlMEflU4bZiZP8di5e2OJI6vOHjd\
M2oonpPi/Ul5KKmfp+jci+kGMs9+zOyjKFLVIKDE+VcCAwEAAQ==";

/// Encrypts AirVPN request envelopes with the provider's RSA public key.
pub struct AirVpnCrypto {
    rsa_pub: RsaBackend,
}

enum RsaBackend {
    #[cfg(feature = "crypto-aws-lc")]
    AwsLc(Pkcs1PublicEncryptingKey),
    #[cfg(all(
        feature = "crypto-rustcrypto",
        any(not(feature = "crypto-aws-lc"), test)
    ))]
    RustCrypto(RsaPublicKey),
}

impl RsaBackend {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        match self {
            #[cfg(feature = "crypto-aws-lc")]
            Self::AwsLc(key) => {
                let mut ciphertext = vec![0; key.ciphertext_size()];
                key.encrypt(plaintext, &mut ciphertext)
                    .map_err(|e| AppError::AirVpnCrypto(format!("RSA encrypt failed: {e}")))?;
                Ok(ciphertext)
            }
            #[cfg(all(
                feature = "crypto-rustcrypto",
                any(not(feature = "crypto-aws-lc"), test)
            ))]
            Self::RustCrypto(key) => key
                .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, plaintext)
                .map_err(|e| AppError::AirVpnCrypto(format!("RSA encrypt failed: {e}"))),
            #[cfg(not(any(feature = "crypto-aws-lc", feature = "crypto-rustcrypto")))]
            _ => unreachable!(),
        }
    }
}

impl AirVpnCrypto {
    pub fn new() -> Result<Self> {
        let der = B64
            .decode(RSA_PUBLIC_KEY_DER_B64)
            .map_err(|e| AppError::AirVpnCrypto(format!("bad RSA public key encoding: {e}")))?;
        // AWS-LC wins when both additive Cargo features are enabled.
        #[cfg(feature = "crypto-aws-lc")]
        {
            let public_key = PublicEncryptingKey::from_der(&der)
                .map_err(|e| AppError::AirVpnCrypto(format!("invalid RSA key: {e}")))?;
            let key = Pkcs1PublicEncryptingKey::new(public_key)
                .map_err(|e| AppError::AirVpnCrypto(format!("invalid RSA encryption key: {e}")))?;
            Ok(Self {
                rsa_pub: RsaBackend::AwsLc(key),
            })
        }
        #[cfg(all(not(feature = "crypto-aws-lc"), feature = "crypto-rustcrypto"))]
        {
            let key = RsaPublicKey::from_public_key_der(&der)
                .map_err(|e| AppError::AirVpnCrypto(format!("invalid RSA key: {e}")))?;
            Ok(Self {
                rsa_pub: RsaBackend::RustCrypto(key),
            })
        }
        #[cfg(not(any(feature = "crypto-aws-lc", feature = "crypto-rustcrypto")))]
        unreachable!()
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
        let encrypted_key_iv = self.rsa_pub.encrypt(key_iv_data.as_bytes())?;

        let s_param = B64.encode(encrypted_key_iv);

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
        assert_eq!(B64.decode(&s_param).unwrap().len(), 512);
        assert!(B64.decode(&d_param).is_ok());

        // We can decrypt our own d_param with the session keys
        let ciphertext = B64.decode(&d_param).unwrap();
        let decrypted = crypto.decrypt_response(&ciphertext, &session).unwrap();

        // Verify it contains the expected encoded parameters
        assert!(decrypted.contains(&B64.encode(b"act")));
        assert!(decrypted.contains(&B64.encode(b"user")));
    }

    #[cfg(feature = "crypto-aws-lc")]
    #[test]
    fn test_aws_lc_request_envelope() {
        use aws_lc_rs::rsa::{KeySize, Pkcs1PrivateDecryptingKey, PrivateDecryptingKey};

        let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let crypto = AirVpnCrypto {
            rsa_pub: RsaBackend::AwsLc(
                Pkcs1PublicEncryptingKey::new(private.public_key()).unwrap(),
            ),
        };
        let decryptor = Pkcs1PrivateDecryptingKey::new(private).unwrap();
        assert_request_envelope(crypto, |ciphertext| {
            let mut plaintext = vec![0; decryptor.min_output_size()];
            decryptor
                .decrypt(ciphertext, &mut plaintext)
                .unwrap()
                .to_vec()
        });
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_rustcrypto_request_envelope() {
        let private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let crypto = AirVpnCrypto {
            rsa_pub: RsaBackend::RustCrypto(RsaPublicKey::from(&private)),
        };
        assert_request_envelope(crypto, |ciphertext| {
            private.decrypt(Pkcs1v15Encrypt, ciphertext).unwrap()
        });
    }

    #[cfg(all(feature = "crypto-aws-lc", feature = "crypto-rustcrypto"))]
    #[test]
    fn test_aws_lc_envelope_decrypts_with_rustcrypto() {
        use rsa::pkcs8::EncodePublicKey;

        let private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let der = RsaPublicKey::from(&private).to_public_key_der().unwrap();
        let key = PublicEncryptingKey::from_der(der.as_bytes()).unwrap();
        let crypto = AirVpnCrypto {
            rsa_pub: RsaBackend::AwsLc(Pkcs1PublicEncryptingKey::new(key).unwrap()),
        };
        assert_request_envelope(crypto, |ciphertext| {
            private.decrypt(Pkcs1v15Encrypt, ciphertext).unwrap()
        });
    }

    fn assert_request_envelope(crypto: AirVpnCrypto, decrypt: impl Fn(&[u8]) -> Vec<u8>) {
        let params = [("act", "user"), ("login", "test"), ("password", "secret")];
        let (s_param, d_param, session) = crypto.encrypt_request(&params).unwrap();

        let encrypted_keys = B64.decode(s_param).unwrap();
        let envelope = decrypt(&encrypted_keys);
        assert_eq!(
            envelope,
            format!(
                "{}:{}\n{}:{}\n",
                B64.encode(b"key"),
                B64.encode(session.key),
                B64.encode(b"iv"),
                B64.encode(session.iv),
            )
            .as_bytes()
        );
        let expected: String = params
            .iter()
            .map(|(key, value)| format!("{}:{}\n", B64.encode(key), B64.encode(value)))
            .collect();
        assert_eq!(
            crypto
                .decrypt_response(&B64.decode(d_param).unwrap(), &session)
                .unwrap(),
            expected
        );

        // PKCS#1 v1.5 encryption must use fresh randomized padding.
        let first = crypto.rsa_pub.encrypt(b"same plaintext").unwrap();
        let second = crypto.rsa_pub.encrypt(b"same plaintext").unwrap();
        assert_ne!(first, second);
    }
}
