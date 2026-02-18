#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Persisted Proton session data written to ~/.config/tunmux/proton/session.json
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Session {
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub vpn_username: String,
    pub vpn_password: String,
    pub plan_name: String,
    pub plan_title: String,
    pub max_tier: i32,
    pub max_connections: i32,
    /// Base64-encoded ed25519 private key (32 bytes)
    pub ed25519_private_key: String,
    /// PEM-encoded ed25519 public key (SubjectPublicKeyInfo)
    pub ed25519_public_key_pem: String,
    /// Base64-encoded x25519 private key (WireGuard private key)
    pub wg_private_key: String,
    /// Base64-encoded x25519 public key
    pub wg_public_key: String,
    /// Proton fingerprint: base64(sha512(x25519_pk))
    pub fingerprint: String,
    /// PEM certificate from API
    #[serde(default)]
    pub certificate_pem: String,
}

/// API response from POST /auth/v4/info
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthInfoResponse {
    pub version: i32,
    pub modulus: String,
    pub server_ephemeral: String,
    pub salt: String,
    #[serde(rename = "SRPSession")]
    pub srp_session: String,
}

/// API response from POST /auth/v4
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthResponse {
    #[serde(rename = "UID")]
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub server_proof: String,
    #[serde(rename = "2FA")]
    pub two_factor: TwoFactorInfo,
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TwoFactorInfo {
    pub enabled: i32,
    #[serde(rename = "TOTP")]
    pub totp: i32,
}

impl TwoFactorInfo {
    #[must_use]
    pub fn totp_required(&self) -> bool {
        self.enabled != 0 && self.totp != 0
    }
}

/// API response from POST /auth/v4/2fa
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TwoFactorResponse {
    pub scopes: Vec<String>,
}

/// API response from GET /vpn/v2
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VpnInfoResponse {
    #[serde(rename = "VPN")]
    pub vpn: VpnInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VpnInfo {
    pub name: String,
    pub password: String,
    pub plan_name: String,
    pub plan_title: String,
    pub max_tier: i32,
    pub max_connect: i32,
}

/// API response from POST /vpn/v1/certificate
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CertificateResponse {
    pub serial_number: String,
    pub client_key_fingerprint: String,
    pub client_key: String,
    pub certificate: String,
    pub expiration_time: i64,
    pub refresh_time: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_persistence_round_trip() {
        let session = Session {
            uid: "test-uid".to_string(),
            access_token: "test-token".to_string(),
            refresh_token: "test-refresh".to_string(),
            vpn_username: "vpnuser".to_string(),
            vpn_password: "vpnpass".to_string(),
            plan_name: "free".to_string(),
            plan_title: "Free".to_string(),
            max_tier: 0,
            max_connections: 1,
            ed25519_private_key: "AAAA".to_string(),
            ed25519_public_key_pem: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
                .to_string(),
            wg_private_key: "BBBB".to_string(),
            wg_public_key: "CCCC".to_string(),
            fingerprint: "DDDD".to_string(),
            certificate_pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
                .to_string(),
        };

        let json = serde_json::to_string_pretty(&session).unwrap();
        let restored: Session = serde_json::from_str(&json).unwrap();

        assert_eq!(session.uid, restored.uid);
        assert_eq!(session.access_token, restored.access_token);
        assert_eq!(session.vpn_username, restored.vpn_username);
        assert_eq!(session.wg_private_key, restored.wg_private_key);
        assert_eq!(session.fingerprint, restored.fingerprint);
        assert_eq!(session.certificate_pem, restored.certificate_pem);
    }
}
