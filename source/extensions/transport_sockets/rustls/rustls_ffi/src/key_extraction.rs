// TLS session key extraction from rustls for kTLS.
//
// This module provides functionality to extract TLS session keys from rustls
// connections after the handshake completes, enabling kernel TLS offload.
//
// Based on the official rustls ktls crate: https://github.com/rustls/ktls

use crate::ktls::{SessionKeys, TlsCipher, TlsVersion};
use rustls::{ClientConnection, ConnectionTrafficSecrets, ServerConnection};

/// Extracts both TX and RX session keys from a rustls client connection.
///
/// Uses rustls's `dangerous_extract_secrets()` API to get traffic keys for kTLS.
/// 
/// Note: This consumes the connection, so it should only be called when transitioning to kTLS.
/// Returns (tx_keys, rx_keys) tuple.
pub fn extract_client_keys(conn: ClientConnection) -> Option<(SessionKeys, SessionKeys)> {
    eprintln!("[KEY EXTRACT] 🔑 Starting client key extraction");
    
    // Get the negotiated cipher suite before extracting secrets (which consumes conn).
    let cipher_suite = conn.negotiated_cipher_suite()?;
    eprintln!("[KEY EXTRACT] 🔑 Cipher suite: {:?}", cipher_suite.suite());
    
    // Get protocol version before consuming conn.
    let protocol_version = conn.protocol_version()?;
    eprintln!("[KEY EXTRACT] 🔑 Protocol version: {:?}", protocol_version);
    
    // Extract secrets from rustls using the official API (consumes conn).
    let extracted = match conn.dangerous_extract_secrets() {
        Ok(secrets) => {
            eprintln!("[KEY EXTRACT] ✅ Successfully extracted secrets from client connection");
            secrets
        },
        Err(e) => {
            eprintln!("[KEY EXTRACT] ❌ Failed to extract secrets from client connection: {:?}", e);
            return None;
        }
    };
    
    // Determine TLS version.
    let version = match protocol_version {
        rustls::ProtocolVersion::TLSv1_2 => {
            eprintln!("[KEY EXTRACT] 🔑 TLS version: 1.2");
            TlsVersion::Tls12
        },
        rustls::ProtocolVersion::TLSv1_3 => {
            eprintln!("[KEY EXTRACT] 🔑 TLS version: 1.3");
            TlsVersion::Tls13
        },
        _ => {
            eprintln!("[KEY EXTRACT] ❌ Unsupported TLS version for kTLS: {:?}", protocol_version);
            return None;
        }
    };

    // Extract BOTH TX and RX secrets.
    let (tx_seq_num, tx_traffic_secrets) = extracted.tx;
    let (rx_seq_num, rx_traffic_secrets) = extracted.rx;
    eprintln!("[KEY EXTRACT] 🔑 TX sequence number: {}", tx_seq_num);
    eprintln!("[KEY EXTRACT] 🔑 RX sequence number: {}", rx_seq_num);

    // Convert both to SessionKeys format.
    let tx_keys = convert_traffic_secrets(version, tx_seq_num, tx_traffic_secrets)?;
    let rx_keys = convert_traffic_secrets(version, rx_seq_num, rx_traffic_secrets)?;
    
    Some((tx_keys, rx_keys))
}

/// Extracts both TX and RX session keys from a rustls server connection.
/// 
/// Note: This consumes the connection, so it should only be called when transitioning to kTLS.
/// Returns (tx_keys, rx_keys) tuple.
pub fn extract_server_keys(conn: ServerConnection) -> Option<(SessionKeys, SessionKeys)> {
    eprintln!("[KEY EXTRACT] 🔑 Starting server key extraction");
    
    // Get the negotiated cipher suite and protocol version before extracting secrets.
    let cipher_suite = conn.negotiated_cipher_suite()?;
    eprintln!("[KEY EXTRACT] 🔑 Cipher suite: {:?}", cipher_suite.suite());
    
    let protocol_version = conn.protocol_version()?;
    eprintln!("[KEY EXTRACT] 🔑 Protocol version: {:?}", protocol_version);
    
    // Extract secrets from rustls using the official API (consumes conn).
    let extracted = match conn.dangerous_extract_secrets() {
        Ok(secrets) => {
            eprintln!("[KEY EXTRACT] ✅ Successfully extracted secrets from server connection");
            secrets
        },
        Err(e) => {
            eprintln!("[KEY EXTRACT] ❌ Failed to extract secrets from server connection: {:?}", e);
            return None;
        }
    };
    
    // Determine TLS version.
    let version = match protocol_version {
        rustls::ProtocolVersion::TLSv1_2 => {
            eprintln!("[KEY EXTRACT] 🔑 TLS version: 1.2");
            TlsVersion::Tls12
        },
        rustls::ProtocolVersion::TLSv1_3 => {
            eprintln!("[KEY EXTRACT] 🔑 TLS version: 1.3");
            TlsVersion::Tls13
        },
        _ => {
            eprintln!("[KEY EXTRACT] ❌ Unsupported TLS version for kTLS: {:?}", protocol_version);
            return None;
        }
    };

    // Extract BOTH TX and RX secrets.
    let (tx_seq_num, tx_traffic_secrets) = extracted.tx;
    let (rx_seq_num, rx_traffic_secrets) = extracted.rx;
    eprintln!("[KEY EXTRACT] 🔑 TX sequence number: {}", tx_seq_num);
    eprintln!("[KEY EXTRACT] 🔑 RX sequence number: {}", rx_seq_num);

    // Convert both to SessionKeys format.
    let tx_keys = convert_traffic_secrets(version, tx_seq_num, tx_traffic_secrets)?;
    let rx_keys = convert_traffic_secrets(version, rx_seq_num, rx_traffic_secrets)?;
    
    Some((tx_keys, rx_keys))
}

/// Converts rustls ConnectionTrafficSecrets to our SessionKeys format.
///
/// This handles the different cipher suite formats and extracts key material
/// in the format required by the Linux kernel's kTLS interface.
fn convert_traffic_secrets(
    version: TlsVersion,
    seq_num: u64,
    secrets: ConnectionTrafficSecrets,
) -> Option<SessionKeys> {
    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            eprintln!("[KEY EXTRACT] 🔑 Cipher: AES-128-GCM");
            // AES-128-GCM: 16-byte key, 12-byte IV (4-byte salt + 8-byte explicit).
            let key_bytes = key.as_ref();
            let iv_bytes = iv.as_ref();
            eprintln!("[KEY EXTRACT] 🔑 Key size: {} bytes, IV size: {} bytes", key_bytes.len(), iv_bytes.len());

            if key_bytes.len() != 16 || iv_bytes.len() != 12 {
                eprintln!("[KEY EXTRACT] ❌ Invalid AES-128-GCM key material: key={}, iv={}", key_bytes.len(), iv_bytes.len());
                return None;
            }

            // For GCM modes, IV is split into salt (first 4 bytes) and explicit IV (last 8 bytes).
            let salt = iv_bytes[..4].to_vec();
            let explicit_iv = iv_bytes[4..].to_vec();
            eprintln!("[KEY EXTRACT] 🔑 Salt: {} bytes, Explicit IV: {} bytes, Seq: {}", salt.len(), explicit_iv.len(), seq_num);

            Some(SessionKeys::new(
                version,
                TlsCipher::AesGcm128,
                key_bytes.to_vec(),
                explicit_iv,
                salt,
                seq_num,
            ))
        }

        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            eprintln!("[KEY EXTRACT] 🔑 Cipher: AES-256-GCM");
            // AES-256-GCM: 32-byte key, 12-byte IV (4-byte salt + 8-byte explicit).
            let key_bytes = key.as_ref();
            let iv_bytes = iv.as_ref();
            eprintln!("[KEY EXTRACT] 🔑 Key size: {} bytes, IV size: {} bytes", key_bytes.len(), iv_bytes.len());

            if key_bytes.len() != 32 || iv_bytes.len() != 12 {
                eprintln!("[KEY EXTRACT] ❌ Invalid AES-256-GCM key material: key={}, iv={}", key_bytes.len(), iv_bytes.len());
                return None;
            }

            let salt = iv_bytes[..4].to_vec();
            let explicit_iv = iv_bytes[4..].to_vec();
            eprintln!("[KEY EXTRACT] 🔑 Salt: {} bytes, Explicit IV: {} bytes, Seq: {}", salt.len(), explicit_iv.len(), seq_num);

            Some(SessionKeys::new(
                version,
                TlsCipher::AesGcm256,
                key_bytes.to_vec(),
                explicit_iv,
                salt,
                seq_num,
            ))
        }

        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            eprintln!("[KEY EXTRACT] 🔑 Cipher: ChaCha20-Poly1305");
            // ChaCha20-Poly1305: 32-byte key, 12-byte IV (no salt separation).
            let key_bytes = key.as_ref();
            let iv_bytes = iv.as_ref();
            eprintln!("[KEY EXTRACT] 🔑 Key size: {} bytes, IV size: {} bytes", key_bytes.len(), iv_bytes.len());

            if key_bytes.len() != 32 || iv_bytes.len() != 12 {
                eprintln!("[KEY EXTRACT] ❌ Invalid ChaCha20-Poly1305 key material: key={}, iv={}", key_bytes.len(), iv_bytes.len());
                return None;
            }

            // ChaCha20 uses the full 12-byte IV, no salt.
            eprintln!("[KEY EXTRACT] 🔑 No salt for ChaCha20, Full IV: {} bytes, Seq: {}", iv_bytes.len(), seq_num);
            Some(SessionKeys::new(
                version,
                TlsCipher::Chacha20Poly1305,
                key_bytes.to_vec(),
                iv_bytes.to_vec(),
                vec![],  // No salt for ChaCha20.
                seq_num,
            ))
        }

        _ => {
            eprintln!("[KEY EXTRACT] ❌ Unsupported cipher suite for kTLS");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_aes128_gcm() {
        let key = rustls::crypto::cipher::AeadKey::from(vec![0u8; 16]);
        let iv = rustls::crypto::cipher::Iv::copy_from_slice(&[0u8; 12]);
        
        let secrets = ConnectionTrafficSecrets::Aes128Gcm { key, iv };
        let session_keys = convert_traffic_secrets(TlsVersion::Tls13, 0, secrets);
        
        assert!(session_keys.is_some());
        let keys = session_keys.unwrap();
        assert_eq!(keys.cipher, TlsCipher::AesGcm128);
        assert_eq!(keys.key.len(), 16);
        assert_eq!(keys.iv.len(), 8);  // Explicit IV.
        assert_eq!(keys.salt.len(), 4);
    }

    #[test]
    fn test_convert_aes256_gcm() {
        let key = rustls::crypto::cipher::AeadKey::from(vec![0u8; 32]);
        let iv = rustls::crypto::cipher::Iv::copy_from_slice(&[0u8; 12]);
        
        let secrets = ConnectionTrafficSecrets::Aes256Gcm { key, iv };
        let session_keys = convert_traffic_secrets(TlsVersion::Tls13, 0, secrets);
        
        assert!(session_keys.is_some());
        let keys = session_keys.unwrap();
        assert_eq!(keys.cipher, TlsCipher::AesGcm256);
        assert_eq!(keys.key.len(), 32);
        assert_eq!(keys.iv.len(), 8);
        assert_eq!(keys.salt.len(), 4);
    }

    #[test]
    fn test_convert_chacha20_poly1305() {
        let key = rustls::crypto::cipher::AeadKey::from(vec![0u8; 32]);
        let iv = rustls::crypto::cipher::Iv::copy_from_slice(&[0u8; 12]);
        
        let secrets = ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv };
        let session_keys = convert_traffic_secrets(TlsVersion::Tls13, 0, secrets);
        
        assert!(session_keys.is_some());
        let keys = session_keys.unwrap();
        assert_eq!(keys.cipher, TlsCipher::Chacha20Poly1305);
        assert_eq!(keys.key.len(), 32);
        assert_eq!(keys.iv.len(), 12);  // Full IV, no salt.
        assert_eq!(keys.salt.len(), 0);
    }
}
