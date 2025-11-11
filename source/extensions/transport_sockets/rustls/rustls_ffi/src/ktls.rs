// Kernel TLS (kTLS) support for Linux.
// This module enables offloading TLS encryption/decryption to the Linux kernel
// for significant performance improvements.

use std::mem;
use std::os::unix::io::RawFd;

#[cfg(target_os = "linux")]
use libc::{c_int, c_void, socklen_t};

// kTLS socket options (from Linux include/uapi/linux/tls.h).
const SOL_TLS: c_int = 282;
const TLS_TX: c_int = 1;
const TLS_RX: c_int = 2;

// TCP Upper Layer Protocol (ULP) options.
const SOL_TCP: c_int = 6;
const TCP_ULP: c_int = 31;

// TLS versions (from Linux kernel).
const TLS_1_2_VERSION: u16 = 0x0303;
const TLS_1_3_VERSION: u16 = 0x0304;

// TLS cipher types (from Linux include/uapi/linux/tls.h).
const TLS_CIPHER_AES_GCM_128: u16 = 51;
const TLS_CIPHER_AES_GCM_256: u16 = 52;
const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;
const TLS_CIPHER_AES_CCM_128: u16 = 55;
const TLS_CIPHER_AES_GCM_128_TAG_SIZE: usize = 16;
const TLS_CIPHER_AES_GCM_256_TAG_SIZE: usize = 16;

// Crypto info structures for kTLS (matching Linux kernel headers).

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct TlsCryptoInfo {
    version: u16,
    cipher_type: u16,
}

#[repr(C)]
#[derive(Debug)]
struct Tls12CryptoInfoAesGcm128 {
    info: TlsCryptoInfo,
    iv: [u8; 8],      // TLS 1.2 uses 8-byte explicit IV.
    key: [u8; 16],    // AES-128 key.
    salt: [u8; 4],    // Implicit IV part.
    rec_seq: [u8; 8], // Record sequence number.
}

#[repr(C)]
#[derive(Debug)]
struct Tls12CryptoInfoAesGcm256 {
    info: TlsCryptoInfo,
    iv: [u8; 8],      // TLS 1.2 uses 8-byte explicit IV.
    key: [u8; 32],    // AES-256 key.
    salt: [u8; 4],    // Implicit IV part.
    rec_seq: [u8; 8], // Record sequence number.
}

#[repr(C)]
#[derive(Debug)]
struct Tls12CryptoInfoChacha20Poly1305 {
    info: TlsCryptoInfo,
    iv: [u8; 12],     // ChaCha20 uses 12-byte IV.
    key: [u8; 32],    // ChaCha20 key.
    rec_seq: [u8; 8], // Record sequence number.
}

/// Session key material extracted from TLS connection.
#[derive(Debug)]
pub struct SessionKeys {
    pub version: TlsVersion,
    pub cipher: TlsCipher,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub salt: Vec<u8>,
    pub seq_num: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsCipher {
    AesGcm128,
    AesGcm256,
    Chacha20Poly1305,
}

impl SessionKeys {
    /// Creates session keys from raw key material.
    pub fn new(
        version: TlsVersion,
        cipher: TlsCipher,
        key: Vec<u8>,
        iv: Vec<u8>,
        salt: Vec<u8>,
        seq_num: u64,
    ) -> Self {
        SessionKeys {
            version,
            cipher,
            key,
            iv,
            salt,
            seq_num,
        }
    }
}

/// Attempts to enable kTLS for transmission (TX) on the given file descriptor.
/// Returns true if successful, false otherwise.
pub fn enable_ktls_tx(fd: RawFd, keys: &SessionKeys) -> bool {
    #[cfg(target_os = "linux")]
    {
        unsafe { enable_ktls_impl(fd, TLS_TX, keys) }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, keys); // Suppress unused variable warning.
        false
    }
}

/// Attempts to enable kTLS for reception (RX) on the given file descriptor.
/// Returns true if successful, false otherwise.
pub fn enable_ktls_rx(fd: RawFd, keys: &SessionKeys) -> bool {
    #[cfg(target_os = "linux")]
    {
        unsafe { enable_ktls_impl(fd, TLS_RX, keys) }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, keys); // Suppress unused variable warning.
        false
    }
}

/// Enables TCP ULP (Upper Layer Protocol) for kTLS on the given socket.
/// This MUST be called before using SOL_TLS socket options.
#[cfg(target_os = "linux")]
unsafe fn enable_tcp_ulp(fd: RawFd) -> bool {
    eprintln!("[KTLS] 🔧 Enabling TCP ULP 'tls' on fd={}", fd);
    
    let ulp_name = b"tls\0";
    let ret = libc::setsockopt(
        fd,
        SOL_TCP,
        TCP_ULP,
        ulp_name.as_ptr() as *const c_void,
        ulp_name.len() as socklen_t,
    );
    
    if ret == 0 {
        eprintln!("[KTLS] ✅ TCP ULP 'tls' enabled successfully on fd={}", fd);
        true
    } else {
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(-1);
        eprintln!("[KTLS] ❌ Failed to enable TCP ULP: ret={}, errno={}, error: {}", ret, errno, err);
        eprintln!("[KTLS] 💡 This usually means kTLS kernel module is not loaded. Try: modprobe tls");
        false
    }
}

/// Checks if the Linux kernel supports kTLS.
#[cfg(target_os = "linux")]
pub fn check_ktls_support() -> bool {
    use std::fs;
    
    // Check if /proc/sys/net/ipv4/tcp_available_ulp contains "tls".
    if let Ok(content) = fs::read_to_string("/proc/sys/net/ipv4/tcp_available_ulp") {
        return content.contains("tls");
    }
    
    false
}

#[cfg(not(target_os = "linux"))]
pub fn check_ktls_support() -> bool {
    false
}

/// Checks if kTLS can actually be enabled on the given socket.
/// This enables TCP ULP, which is required before using kTLS.
/// Call this BEFORE extracting secrets to avoid consuming the connection needlessly.
pub fn can_enable_ktls(fd: RawFd) -> bool {
    #[cfg(target_os = "linux")]
    {
        eprintln!("[KTLS] 🔍 Checking if kTLS can be enabled on fd={}...", fd);
        
        // First check if kernel supports kTLS at all.
        if !check_ktls_support() {
            eprintln!("[KTLS] ❌ Kernel doesn't support kTLS");
            return false;
        }
        
        // Try to enable TCP ULP. This is the real test.
        unsafe {
            if enable_tcp_ulp(fd) {
                eprintln!("[KTLS] ✅ kTLS can be enabled on fd={}", fd);
                true
            } else {
                eprintln!("[KTLS] ❌ Cannot enable kTLS on fd={} (TCP ULP failed)", fd);
                false
            }
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        false
    }
}

/// Internal implementation of kTLS enablement.
#[cfg(target_os = "linux")]
unsafe fn enable_ktls_impl(fd: RawFd, direction: c_int, keys: &SessionKeys) -> bool {
    let dir_str = if direction == TLS_TX { "TX" } else { "RX" };
    eprintln!("[KTLS] 🔧 enable_ktls_impl called for {} on fd={}", dir_str, fd);
    
    // First check if kTLS is supported.
    eprintln!("[KTLS] 🔧 Checking if kernel supports kTLS...");
    if !check_ktls_support() {
        eprintln!("[KTLS] ❌ kTLS is not supported on this kernel - check /proc/sys/net/ipv4/tcp_available_ulp");
        return false;
    }
    eprintln!("[KTLS] ✅ Kernel supports kTLS");
    eprintln!("[KTLS] ℹ️  TCP ULP should already be enabled by can_enable_ktls()");

    // Convert TLS version and cipher to kernel constants.
    let tls_version = match keys.version {
        TlsVersion::Tls12 => {
            eprintln!("[KTLS] 🔧 TLS version: 1.2 (0x{:x})", TLS_1_2_VERSION);
            TLS_1_2_VERSION
        },
        TlsVersion::Tls13 => {
            eprintln!("[KTLS] 🔧 TLS version: 1.3 (0x{:x})", TLS_1_3_VERSION);
            TLS_1_3_VERSION
        },
    };

    let cipher_type = match keys.cipher {
        TlsCipher::AesGcm128 => {
            eprintln!("[KTLS] 🔧 Cipher: AES-128-GCM (type={})", TLS_CIPHER_AES_GCM_128);
            TLS_CIPHER_AES_GCM_128
        },
        TlsCipher::AesGcm256 => {
            eprintln!("[KTLS] 🔧 Cipher: AES-256-GCM (type={})", TLS_CIPHER_AES_GCM_256);
            TLS_CIPHER_AES_GCM_256
        },
        TlsCipher::Chacha20Poly1305 => {
            eprintln!("[KTLS] 🔧 Cipher: ChaCha20-Poly1305 (type={})", TLS_CIPHER_CHACHA20_POLY1305);
            TLS_CIPHER_CHACHA20_POLY1305
        },
    };

    // Prepare crypto info structure based on cipher suite.
    match keys.cipher {
        TlsCipher::AesGcm128 => {
            eprintln!("[KTLS] 🔧 Setting up AES-128-GCM crypto info");
            if keys.key.len() != 16 || keys.salt.len() != 4 {
                eprintln!("[KTLS] ❌ Invalid key material for AES-128-GCM: key={}, salt={}", keys.key.len(), keys.salt.len());
                return false;
            }
            eprintln!("[KTLS] ✅ Key material validated: key=16 bytes, salt=4 bytes, iv={} bytes, seq={}", keys.iv.len(), keys.seq_num);

            let mut crypto_info = Tls12CryptoInfoAesGcm128 {
                info: TlsCryptoInfo {
                    version: tls_version,
                    cipher_type,
                },
                iv: [0u8; 8],
                key: [0u8; 16],
                salt: [0u8; 4],
                rec_seq: [0u8; 8],
            };

            // Copy key material.
            crypto_info.key.copy_from_slice(&keys.key);
            crypto_info.salt.copy_from_slice(&keys.salt);
            
            // For TLS 1.2, IV is explicit (first 8 bytes of keys.iv).
            if keys.iv.len() >= 8 {
                crypto_info.iv[..8].copy_from_slice(&keys.iv[..8]);
            }
            
            // Set sequence number (in network byte order).
            let seq_bytes = keys.seq_num.to_be_bytes();
            crypto_info.rec_seq.copy_from_slice(&seq_bytes);

            eprintln!("[KTLS] 🔧 Calling setsockopt(fd={}, SOL_TLS={}, direction={}, struct_size={})", fd, SOL_TLS, direction, mem::size_of::<Tls12CryptoInfoAesGcm128>());
            
            // Set socket option to enable kTLS.
            let ret = libc::setsockopt(
                fd,
                SOL_TLS,
                direction,
                &crypto_info as *const _ as *const c_void,
                mem::size_of::<Tls12CryptoInfoAesGcm128>() as socklen_t,
            );

            if ret == 0 {
                eprintln!("[KTLS] ✅ setsockopt SUCCESS: kTLS {} enabled for AES-128-GCM on fd={}", dir_str, fd);
                true
            } else {
                let err = std::io::Error::last_os_error();
                let errno = err.raw_os_error().unwrap_or(-1);
                eprintln!("[KTLS] ❌ setsockopt FAILED: ret={}, errno={}, error: {}", ret, errno, err);
                eprintln!("[KTLS] ❌ Failed to enable kTLS {} on fd={}: {}", dir_str, fd, err);
                false
            }
        }

        TlsCipher::AesGcm256 => {
            eprintln!("[KTLS] 🔧 Setting up AES-256-GCM crypto info");
            if keys.key.len() != 32 || keys.salt.len() != 4 {
                eprintln!("[KTLS] ❌ Invalid key material for AES-256-GCM: key={}, salt={}", keys.key.len(), keys.salt.len());
                return false;
            }
            eprintln!("[KTLS] ✅ Key material validated: key=32 bytes, salt=4 bytes, iv={} bytes, seq={}", keys.iv.len(), keys.seq_num);

            let mut crypto_info = Tls12CryptoInfoAesGcm256 {
                info: TlsCryptoInfo {
                    version: tls_version,
                    cipher_type,
                },
                iv: [0u8; 8],
                key: [0u8; 32],
                salt: [0u8; 4],
                rec_seq: [0u8; 8],
            };

            // Copy key material.
            crypto_info.key.copy_from_slice(&keys.key);
            crypto_info.salt.copy_from_slice(&keys.salt);
            
            // For TLS 1.2/1.3, IV is explicit (first 8 bytes of keys.iv).
            if keys.iv.len() >= 8 {
                crypto_info.iv[..8].copy_from_slice(&keys.iv[..8]);
                eprintln!("[KTLS] 🔧 Copied IV: {} bytes", 8);
            } else {
                eprintln!("[KTLS] ❌ IV too short: {} bytes (need >= 8)", keys.iv.len());
                return false;
            }
            
            // Set sequence number (in network byte order).
            let seq_bytes = keys.seq_num.to_be_bytes();
            crypto_info.rec_seq.copy_from_slice(&seq_bytes);
            eprintln!("[KTLS] 🔧 Set sequence number: {}", keys.seq_num);

            eprintln!("[KTLS] 🔧 Calling setsockopt(fd={}, SOL_TLS={}, direction={}, struct_size={})", fd, SOL_TLS, direction, mem::size_of::<Tls12CryptoInfoAesGcm256>());
            
            // Set socket option to enable kTLS.
            let ret = libc::setsockopt(
                fd,
                SOL_TLS,
                direction,
                &crypto_info as *const _ as *const c_void,
                mem::size_of::<Tls12CryptoInfoAesGcm256>() as socklen_t,
            );

            if ret == 0 {
                eprintln!("[KTLS] ✅ setsockopt SUCCESS: kTLS {} enabled for AES-256-GCM on fd={}", dir_str, fd);
                true
            } else {
                let err = std::io::Error::last_os_error();
                let errno = err.raw_os_error().unwrap_or(-1);
                eprintln!("[KTLS] ❌ setsockopt FAILED: ret={}, errno={}, error: {}", ret, errno, err);
                eprintln!("[KTLS] ❌ Failed to enable kTLS {} on fd={}: {}", dir_str, fd, err);
                false
            }
        }

        TlsCipher::Chacha20Poly1305 => {
            eprintln!("[KTLS] 🔧 Setting up ChaCha20-Poly1305 crypto info");
            if keys.key.len() != 32 || keys.iv.len() != 12 {
                eprintln!("[KTLS] ❌ Invalid key material for ChaCha20-Poly1305: key={}, iv={}", keys.key.len(), keys.iv.len());
                return false;
            }
            eprintln!("[KTLS] ✅ Key material validated: key=32 bytes, iv=12 bytes, seq={}", keys.seq_num);

            let mut crypto_info = Tls12CryptoInfoChacha20Poly1305 {
                info: TlsCryptoInfo {
                    version: tls_version,
                    cipher_type,
                },
                iv: [0u8; 12],
                key: [0u8; 32],
                rec_seq: [0u8; 8],
            };

            // Copy key material.
            crypto_info.key.copy_from_slice(&keys.key);
            crypto_info.iv.copy_from_slice(&keys.iv);
            eprintln!("[KTLS] 🔧 Copied key and IV");
            
            // Set sequence number (in network byte order).
            let seq_bytes = keys.seq_num.to_be_bytes();
            crypto_info.rec_seq.copy_from_slice(&seq_bytes);
            eprintln!("[KTLS] 🔧 Set sequence number: {}", keys.seq_num);

            eprintln!("[KTLS] 🔧 Calling setsockopt(fd={}, SOL_TLS={}, direction={}, struct_size={})", fd, SOL_TLS, direction, mem::size_of::<Tls12CryptoInfoChacha20Poly1305>());

            // Set socket option to enable kTLS.
            let ret = libc::setsockopt(
                fd,
                SOL_TLS,
                direction,
                &crypto_info as *const _ as *const c_void,
                mem::size_of::<Tls12CryptoInfoChacha20Poly1305>() as socklen_t,
            );

            if ret == 0 {
                eprintln!("[KTLS] ✅ setsockopt SUCCESS: kTLS {} enabled for ChaCha20-Poly1305 on fd={}", dir_str, fd);
                true
            } else {
                let err = std::io::Error::last_os_error();
                let errno = err.raw_os_error().unwrap_or(-1);
                eprintln!("[KTLS] ❌ setsockopt FAILED: ret={}, errno={}, error: {}", ret, errno, err);
                eprintln!("[KTLS] ❌ Failed to enable kTLS {} on fd={}: {}", dir_str, fd, err);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ktls_support_check() {
        // Just verify the function doesn't panic.
        let _supported = check_ktls_support();
    }

    #[test]
    fn test_session_keys_creation() {
        let keys = SessionKeys::new(
            TlsVersion::Tls13,
            TlsCipher::AesGcm128,
            vec![0u8; 16],
            vec![0u8; 12],
            vec![0u8; 4],
            0,
        );
        
        assert_eq!(keys.version, TlsVersion::Tls13);
        assert_eq!(keys.cipher, TlsCipher::AesGcm128);
        assert_eq!(keys.key.len(), 16);
    }
}
