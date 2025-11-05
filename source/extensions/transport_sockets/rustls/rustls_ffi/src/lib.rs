#![allow(non_camel_case_types)]

use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use std::io::{Read, Write};
use std::os::unix::io::RawFd;
use std::sync::Arc;

mod ktls;
mod key_extraction;

use ktls::{can_enable_ktls, enable_ktls_rx, enable_ktls_tx};
use key_extraction::{extract_client_keys, extract_server_keys};

// Opaque handle types for C FFI.
#[repr(C)]
pub struct rustls_connection_handle {
    _private: [u8; 0],
}

#[repr(C)]
pub struct rustls_config_handle {
    _private: [u8; 0],
}

// Result codes for C FFI.
pub const RUSTLS_OK: i32 = 0;
pub const RUSTLS_ERR_INVALID_PARAM: i32 = -1;
pub const RUSTLS_ERR_IO: i32 = -2;
pub const RUSTLS_ERR_HANDSHAKE: i32 = -3;
pub const RUSTLS_ERR_CERTIFICATE: i32 = -4;
pub const RUSTLS_ERR_KTLS_NOT_SUPPORTED: i32 = -5;

// Internal connection state.
enum Connection {
    Client(Box<ClientConnection>),
    Server(Box<ServerConnection>),
    KtlsEnabled, // Connection consumed for successful kTLS offload.
    Consumed,    // Connection consumed but kTLS failed.
}

struct RustlsConnection {
    connection: Connection,
    fd: RawFd,
    ktls_tx_enabled: bool,
    ktls_rx_enabled: bool,
    rx_keys: Option<ktls::SessionKeys>,
}

struct RustlsConfig {
    client_config: Option<Arc<ClientConfig>>,
    server_config: Option<Arc<ServerConfig>>,
}

/// Creates a new client TLS configuration.
///
/// # Safety
/// cert_pem and key_pem must be valid null-terminated C strings if provided.
#[no_mangle]
pub unsafe extern "C" fn rustls_client_config_new(
    cert_pem: *const libc::c_char,
    cert_len: usize,
    key_pem: *const libc::c_char,
    key_len: usize,
    ca_pem: *const libc::c_char,
    ca_len: usize,
    alpn_protocols: *const *const libc::c_char,
    alpn_count: usize,
) -> *mut rustls_config_handle {
    let root_store = if !ca_pem.is_null() && ca_len > 0 {
        let ca_bytes = std::slice::from_raw_parts(ca_pem as *const u8, ca_len);
        let mut root_store = rustls::RootCertStore::empty();
        
        // rustls_pemfile::certs returns an iterator, not a Result.
        for cert_result in rustls_pemfile::certs(&mut &ca_bytes[..]) {
            if let Ok(cert) = cert_result {
                let _ = root_store.add(cert);
            }
        }
        root_store
    } else {
        // Use webpki-roots for default CA certificates.
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        root_store
    };

    let config_builder = ClientConfig::builder()
        .with_root_certificates(root_store);

    let config = if !cert_pem.is_null() && !key_pem.is_null() {
        let cert_bytes = std::slice::from_raw_parts(cert_pem as *const u8, cert_len);
        let key_bytes = std::slice::from_raw_parts(key_pem as *const u8, key_len);
        
        // rustls_pemfile::certs returns an iterator, not a Result.
        let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_bytes[..])
            .filter_map(|c| c.ok())
            .collect();

        let key = match rustls_pemfile::private_key(&mut &key_bytes[..]) {
            Ok(Some(key)) => key,
            _ => return std::ptr::null_mut(),
        };

        match config_builder.with_client_auth_cert(certs, key) {
            Ok(cfg) => cfg,
            Err(_) => return std::ptr::null_mut(),
        }
    } else {
        config_builder.with_no_client_auth()
    };

    // Add ALPN protocols if provided.
    let mut config = config;
    if !alpn_protocols.is_null() && alpn_count > 0 {
        let protocols: Vec<Vec<u8>> = (0..alpn_count)
            .map(|i| {
                let proto_ptr = *alpn_protocols.add(i);
                let proto_cstr = std::ffi::CStr::from_ptr(proto_ptr);
                proto_cstr.to_bytes().to_vec()
            })
            .collect();
        config.alpn_protocols = protocols;
    }

    // Enable secret extraction for kTLS support.
    config.enable_secret_extraction = true;
    eprintln!("[RUST FFI CONFIG] ✅ Client config: secret extraction enabled for kTLS");

    let rustls_config = Box::new(RustlsConfig {
        client_config: Some(Arc::new(config)),
        server_config: None,
    });

    Box::into_raw(rustls_config) as *mut rustls_config_handle
}

/// Creates a new server TLS configuration.
///
/// # Safety
/// cert_pem and key_pem must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn rustls_server_config_new(
    cert_pem: *const libc::c_char,
    cert_len: usize,
    key_pem: *const libc::c_char,
    key_len: usize,
    alpn_protocols: *const *const libc::c_char,
    alpn_count: usize,
) -> *mut rustls_config_handle {
    let cert_bytes = std::slice::from_raw_parts(cert_pem as *const u8, cert_len);
    let key_bytes = std::slice::from_raw_parts(key_pem as *const u8, key_len);

    // rustls_pemfile::certs returns an iterator, not a Result.
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_bytes[..])
        .filter_map(|c| c.ok())
        .collect();

    let key = match rustls_pemfile::private_key(&mut &key_bytes[..]) {
        Ok(Some(key)) => key,
        _ => return std::ptr::null_mut(),
    };

    let mut config = match ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
    {
        Ok(cfg) => cfg,
        Err(_) => return std::ptr::null_mut(),
    };

    // Add ALPN protocols if provided.
    if !alpn_protocols.is_null() && alpn_count > 0 {
        let protocols: Vec<Vec<u8>> = (0..alpn_count)
            .map(|i| {
                let proto_ptr = *alpn_protocols.add(i);
                let proto_cstr = std::ffi::CStr::from_ptr(proto_ptr);
                proto_cstr.to_bytes().to_vec()
            })
            .collect();
        config.alpn_protocols = protocols;
    }

    // Enable secret extraction for kTLS support.
    config.enable_secret_extraction = true;
    eprintln!("[RUST FFI CONFIG] ✅ Server config: secret extraction enabled for kTLS");

    let rustls_config = Box::new(RustlsConfig {
        client_config: None,
        server_config: Some(Arc::new(config)),
    });

    Box::into_raw(rustls_config) as *mut rustls_config_handle
}

/// Frees a rustls configuration.
///
/// # Safety
/// config must be a valid pointer previously returned from rustls_client_config_new or rustls_server_config_new.
#[no_mangle]
pub unsafe extern "C" fn rustls_config_free(config: *mut rustls_config_handle) {
    if !config.is_null() {
        let _ = Box::from_raw(config as *mut RustlsConfig);
    }
}

/// Creates a new client TLS connection.
///
/// # Safety
/// config must be a valid pointer, server_name must be a valid null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn rustls_client_connection_new(
    config: *const rustls_config_handle,
    fd: RawFd,
    server_name: *const libc::c_char,
) -> *mut rustls_connection_handle {
    if config.is_null() || server_name.is_null() {
        return std::ptr::null_mut();
    }

    let rustls_config = &*(config as *const RustlsConfig);
    let client_config = match &rustls_config.client_config {
        Some(cfg) => cfg.clone(),
        None => return std::ptr::null_mut(),
    };

    let server_name_str = match std::ffi::CStr::from_ptr(server_name).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let server_name = match rustls::pki_types::ServerName::try_from(server_name_str) {
        Ok(name) => name.to_owned(),
        Err(_) => return std::ptr::null_mut(),
    };

    let connection = match ClientConnection::new(client_config, server_name) {
        Ok(conn) => Connection::Client(Box::new(conn)),
        Err(_) => return std::ptr::null_mut(),
    };

    let rustls_conn = Box::new(RustlsConnection {
        connection,
        fd,
        ktls_tx_enabled: false,
        ktls_rx_enabled: false,
        rx_keys: None,
    });

    Box::into_raw(rustls_conn) as *mut rustls_connection_handle
}

/// Creates a new server TLS connection.
///
/// # Safety
/// config must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn rustls_server_connection_new(
    config: *const rustls_config_handle,
    fd: RawFd,
) -> *mut rustls_connection_handle {
    if config.is_null() {
        return std::ptr::null_mut();
    }

    let rustls_config = &*(config as *const RustlsConfig);
    let server_config = match &rustls_config.server_config {
        Some(cfg) => cfg.clone(),
        None => return std::ptr::null_mut(),
    };

    let connection = match ServerConnection::new(server_config) {
        Ok(conn) => Connection::Server(Box::new(conn)),
        Err(_) => return std::ptr::null_mut(),
    };

    let rustls_conn = Box::new(RustlsConnection {
        connection,
        fd,
        ktls_tx_enabled: false,
        ktls_rx_enabled: false,
        rx_keys: None,
    });

    Box::into_raw(rustls_conn) as *mut rustls_connection_handle
}

/// Frees a rustls connection.
///
/// # Safety
/// conn must be a valid pointer previously returned from rustls_client_connection_new or rustls_server_connection_new.
#[no_mangle]
pub unsafe extern "C" fn rustls_connection_free(conn: *mut rustls_connection_handle) {
    if !conn.is_null() {
        let _ = Box::from_raw(conn as *mut RustlsConnection);
    }
}

/// Enables kernel TLS (kTLS) offload for transmission.
///
/// This must be called after the TLS handshake is complete.
///
/// # Safety
/// conn must be a valid pointer and handshake must be complete.
#[no_mangle]
pub unsafe extern "C" fn rustls_enable_ktls_tx(conn: *mut rustls_connection_handle) -> i32 {
    if conn.is_null() {
        return RUSTLS_ERR_INVALID_PARAM;
    }

    let rustls_conn = &mut *(conn as *mut RustlsConnection);
    
    // Check if already using kTLS or if connection was consumed.
    if matches!(rustls_conn.connection, Connection::KtlsEnabled | Connection::Consumed) {
        eprintln!("[RUST FFI] ❌ kTLS TX: connection already consumed or kTLS enabled");
        return RUSTLS_ERR_KTLS_NOT_SUPPORTED;
    }
    
    // Check if FD is valid before attempting kTLS.
    if rustls_conn.fd == -1 {
        eprintln!("[RUST FFI] ❌ Cannot enable kTLS: invalid file descriptor (fd=-1)");
        return RUSTLS_ERR_KTLS_NOT_SUPPORTED;
    }
    
    eprintln!("[RUST FFI] 🔧 Attempting to enable kTLS TX on fd={}", rustls_conn.fd);
    
    // CRITICAL: Check if kTLS can actually be enabled BEFORE extracting secrets.
    // This enables TCP ULP and verifies the kernel supports kTLS.
    // If this fails, we DON'T consume the connection so it can fall back to userspace TLS.
    if !can_enable_ktls(rustls_conn.fd) {
        eprintln!("[RUST FFI] ❌ kTLS cannot be enabled on fd={} - keeping connection for userspace TLS", rustls_conn.fd);
        return RUSTLS_ERR_KTLS_NOT_SUPPORTED;
    }
    
    // Extract BOTH TX and RX session keys by consuming the connection.
    // NOTE: dangerous_extract_secrets() CONSUMES the connection, so we can't put it back.
    // We get both TX and RX keys in one call.
    let connection = std::mem::replace(&mut rustls_conn.connection, Connection::Consumed);
    let (keys, connection_type) = match connection {
        Connection::Client(client_conn) => {
            let keys = extract_client_keys(*client_conn);
            (keys, "client")
        },
        Connection::Server(server_conn) => {
            let keys = extract_server_keys(*server_conn);
            (keys, "server")
        },
        Connection::KtlsEnabled | Connection::Consumed => unreachable!(),
    };

    match keys {
        Some((tx_keys, rx_keys)) => {
            eprintln!("[RUST FFI] 🔧 TX and RX session keys extracted from {}, enabling TX kTLS", connection_type);
            
            // Store RX keys for later use by rustls_enable_ktls_rx
            rustls_conn.rx_keys = Some(rx_keys);
            
            if enable_ktls_tx(rustls_conn.fd, &tx_keys) {
                // SUCCESS: TX kTLS is enabled. Mark the connection state as kTLS.
                rustls_conn.connection = Connection::KtlsEnabled;
                rustls_conn.ktls_tx_enabled = true;
                eprintln!("[RUST FFI] ✅ kTLS TX enabled successfully on fd={}", rustls_conn.fd);
                RUSTLS_OK
            } else {
                // FAILURE: TX kTLS failed. Connection is consumed, leave it in Consumed state.
                // Clear stored RX keys since kTLS failed.
                rustls_conn.rx_keys = None;
                eprintln!("[RUST FFI] ❌ kTLS TX failed on fd={} - connection consumed but kTLS NOT enabled", rustls_conn.fd);
                RUSTLS_ERR_KTLS_NOT_SUPPORTED
            }
        }
        None => {
            // Failed to extract keys. Connection is consumed, leave it in Consumed state.
            eprintln!("[RUST FFI] ❌ Failed to extract session keys for kTLS TX - connection consumed");
            RUSTLS_ERR_KTLS_NOT_SUPPORTED
        }
    }
}

/// Enables kernel TLS (kTLS) offload for reception.
///
/// This must be called AFTER rustls_enable_ktls_tx() has been called successfully.
/// The TX function extracts both TX and RX keys, and this function uses the stored RX keys.
///
/// # Safety
/// conn must be a valid pointer and rustls_enable_ktls_tx must have been called first.
#[no_mangle]
pub unsafe extern "C" fn rustls_enable_ktls_rx(conn: *mut rustls_connection_handle) -> i32 {
    if conn.is_null() {
        return RUSTLS_ERR_INVALID_PARAM;
    }

    let rustls_conn = &mut *(conn as *mut RustlsConnection);
    
    // Check if FD is valid.
    if rustls_conn.fd == -1 {
        eprintln!("[RUST FFI] ❌ Cannot enable kTLS RX: invalid file descriptor (fd=-1)");
        return RUSTLS_ERR_KTLS_NOT_SUPPORTED;
    }
    
    // Check if RX kTLS is already enabled.
    if rustls_conn.ktls_rx_enabled {
        eprintln!("[RUST FFI] ⚠️  kTLS RX: already enabled on fd={}", rustls_conn.fd);
        return RUSTLS_OK;
    }
    
    // Check if TX kTLS succeeded (which means keys were extracted).
    if !rustls_conn.ktls_tx_enabled {
        eprintln!("[RUST FFI] ❌ Cannot enable kTLS RX: TX kTLS must be enabled first (no keys available)");
        return RUSTLS_ERR_KTLS_NOT_SUPPORTED;
    }
    
    // Use the RX keys that were stored by rustls_enable_ktls_tx.
    let rx_keys = match &rustls_conn.rx_keys {
        Some(keys) => keys,
        None => {
            eprintln!("[RUST FFI] ❌ Cannot enable kTLS RX: no RX keys stored (TX extraction may have failed)");
            return RUSTLS_ERR_KTLS_NOT_SUPPORTED;
        }
    };
    
    eprintln!("[RUST FFI] 🔧 Attempting to enable kTLS RX on fd={} using stored keys", rustls_conn.fd);
    
    if enable_ktls_rx(rustls_conn.fd, rx_keys) {
        // SUCCESS: RX kTLS is enabled.
        rustls_conn.ktls_rx_enabled = true;
        eprintln!("[RUST FFI] ✅ kTLS RX enabled successfully on fd={}", rustls_conn.fd);
        RUSTLS_OK
    } else {
        // FAILURE: RX kTLS failed (but TX is still working).
        eprintln!("[RUST FFI] ❌ kTLS RX failed on fd={} (TX kTLS still active)", rustls_conn.fd);
        RUSTLS_ERR_KTLS_NOT_SUPPORTED
    }
}

/// Performs TLS handshake I/O operations.
///
/// # Safety
/// conn must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn rustls_connection_handshake(conn: *mut rustls_connection_handle) -> i32 {
    if conn.is_null() {
        return RUSTLS_ERR_INVALID_PARAM;
    }

    let rustls_conn = &mut *(conn as *mut RustlsConnection);

    // NOTE: This function no longer performs I/O directly.
    // The C++ layer handles I/O via doRead/doWrite methods.
    // This function just processes pending TLS packets.
    
    let result = match &mut rustls_conn.connection {
        Connection::Client(client_conn) => {
            // Process any pending TLS messages.
            match client_conn.process_new_packets() {
                Ok(_) => RUSTLS_OK,
                Err(_) => RUSTLS_ERR_HANDSHAKE,
            }
        }
        Connection::Server(server_conn) => {
            // Process any pending TLS messages.
            match server_conn.process_new_packets() {
                Ok(_) => RUSTLS_OK,
                Err(_) => RUSTLS_ERR_HANDSHAKE,
            }
        }
        Connection::KtlsEnabled => {
            // Connection consumed for kTLS - handshake already complete.
            RUSTLS_OK
        }
        Connection::Consumed => {
            // Connection consumed but kTLS failed - treat as error.
            RUSTLS_ERR_KTLS_NOT_SUPPORTED
        }
    };

    result
}

/// Reads encrypted TLS data from a buffer and feeds it to rustls.
/// Returns number of bytes consumed from input buffer.
///
/// # Safety
/// conn and buf must be valid pointers, buf must have at least len bytes.
#[no_mangle]
pub unsafe extern "C" fn rustls_connection_read_tls(
    conn: *mut rustls_connection_handle,
    buf: *const u8,
    len: usize,
) -> isize {
    if conn.is_null() || buf.is_null() {
        return RUSTLS_ERR_INVALID_PARAM as isize;
    }

    let rustls_conn = &mut *(conn as *mut RustlsConnection);
    let input = std::slice::from_raw_parts(buf, len);

    // Check if rustls wants to read before attempting
    let wants_read = match &rustls_conn.connection {
        Connection::Client(client_conn) => client_conn.wants_read(),
        Connection::Server(server_conn) => server_conn.wants_read(),
        Connection::KtlsEnabled | Connection::Consumed => false,
    };
    
    let is_handshaking = match &rustls_conn.connection {
        Connection::Client(c) => c.is_handshaking(),
        Connection::Server(s) => s.is_handshaking(),
        Connection::KtlsEnabled | Connection::Consumed => false,
    };
    
    eprintln!("[RUST FFI] rustls_connection_read_tls: len={}, wants_read={}, handshaking={}", 
               len, wants_read, is_handshaking);

    // TRY to read anyway, even if wants_read is false
    // The data might be application data that rustls will accept
    eprintln!("[RUST FFI] 🟢 ABOUT TO ENTER MATCH STATEMENT");
    let bytes_read = match &mut rustls_conn.connection {
        Connection::Client(client_conn) => {
            let mut cursor = std::io::Cursor::new(input);
            match client_conn.read_tls(&mut cursor) {
                Ok(n) => {
                    eprintln!("[RUST FFI] Client read_tls returned: {}", n);
                    n
                },
                Err(e) => {
                    eprintln!("[RUST FFI] Client read_tls error: {:?}", e);
                    return RUSTLS_ERR_IO as isize;
                }
            }
        }
        Connection::Server(server_conn) => {
            let mut cursor = std::io::Cursor::new(input);
            eprintln!("[RUST FFI] Calling server_conn.read_tls() with {} bytes (wants_read={})", len, wants_read);
            match server_conn.read_tls(&mut cursor) {
                Ok(n) => {
                    eprintln!("[RUST FFI] Server read_tls returned: {} (cursor position: {})", n, cursor.position());
                    n
                },
                Err(e) => {
                    eprintln!("[RUST FFI] Server read_tls error: {:?}", e);
                    return RUSTLS_ERR_IO as isize;
                }
            }
        }
        Connection::KtlsEnabled | Connection::Consumed => return 0,
    };

    // CRITICAL: Process the TLS packets we just read to decrypt them.
    eprintln!("[RUST FFI] About to call process_new_packets() with bytes_read={}", bytes_read);
    match &mut rustls_conn.connection {
        Connection::Client(client_conn) => {
            match client_conn.process_new_packets() {
                Ok(_) => eprintln!("[RUST FFI] Client process_new_packets() succeeded"),
                Err(e) => {
                    eprintln!("[RUST FFI] Client process_new_packets() error: {:?}", e);
                    return RUSTLS_ERR_IO as isize;
                }
            }
        }
        Connection::Server(server_conn) => {
            match server_conn.process_new_packets() {
                Ok(_) => eprintln!("[RUST FFI] Server process_new_packets() succeeded"),
                Err(e) => {
                    eprintln!("[RUST FFI] Server process_new_packets() error: {:?}", e);
                    return RUSTLS_ERR_IO as isize;
                }
            }
        }
        Connection::KtlsEnabled | Connection::Consumed => {}
    }

    eprintln!("[RUST FFI] rustls_connection_read_tls returning: {}", bytes_read);
    bytes_read as isize
}

/// Writes pending encrypted TLS data from rustls to a buffer.
/// Returns number of bytes written to output buffer.
///
/// # Safety
/// conn and buf must be valid pointers, buf must have at least len capacity.
#[no_mangle]
pub unsafe extern "C" fn rustls_connection_write_tls(
    conn: *mut rustls_connection_handle,
    buf: *mut u8,
    len: usize,
) -> isize {
    if conn.is_null() || buf.is_null() {
        return RUSTLS_ERR_INVALID_PARAM as isize;
    }

    let rustls_conn = &mut *(conn as *mut RustlsConnection);
    let output = std::slice::from_raw_parts_mut(buf, len);

    let result = match &mut rustls_conn.connection {
        Connection::Client(client_conn) => {
            let mut cursor = std::io::Cursor::new(output);
            match client_conn.write_tls(&mut cursor) {
                Ok(n) => {
                    eprintln!("[RUST FFI] 📤 write_tls (client): extracted {} bytes", n);
                    n as isize
                }
                Err(e) => {
                    eprintln!("[RUST FFI] ❌ write_tls (client) error: {:?}", e);
                    RUSTLS_ERR_IO as isize
                }
            }
        }
        Connection::Server(server_conn) => {
            let mut cursor = std::io::Cursor::new(output);
            match server_conn.write_tls(&mut cursor) {
                Ok(n) => {
                    eprintln!("[RUST FFI] 📤 write_tls (server): extracted {} bytes", n);
                    n as isize
                }
                Err(e) => {
                    eprintln!("[RUST FFI] ❌ write_tls (server) error: {:?}", e);
                    RUSTLS_ERR_IO as isize
                }
            }
        }
        Connection::KtlsEnabled | Connection::Consumed => {
            eprintln!("[RUST FFI] 📤 write_tls: 0 bytes (connection not active)");
            0
        }
    };

    result
}

/// Checks if rustls wants to write encrypted TLS data.
///
/// # Safety
/// conn must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn rustls_connection_wants_write(
    conn: *const rustls_connection_handle,
) -> bool {
    if conn.is_null() {
        return false;
    }

    let rustls_conn = &*(conn as *const RustlsConnection);
    
    let result = match &rustls_conn.connection {
        Connection::Client(client_conn) => {
            let wants = client_conn.wants_write();
            eprintln!("[RUST FFI] 🔍 wants_write (client): {}", wants);
            wants
        }
        Connection::Server(server_conn) => {
            let wants = server_conn.wants_write();
            eprintln!("[RUST FFI] 🔍 wants_write (server): {}", wants);
            wants
        }
        Connection::KtlsEnabled | Connection::Consumed => {
            eprintln!("[RUST FFI] 🔍 wants_write: false (connection not active)");
            false
        }
    };
    
    result
}

/// Checks if rustls wants to read encrypted TLS data.
///
/// # Safety
/// conn must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn rustls_connection_wants_read(
    conn: *const rustls_connection_handle,
) -> bool {
    if conn.is_null() {
        return false;
    }

    let rustls_conn = &*(conn as *const RustlsConnection);
    
    match &rustls_conn.connection {
        Connection::Client(client_conn) => client_conn.wants_read(),
        Connection::Server(server_conn) => server_conn.wants_read(),
        Connection::KtlsEnabled | Connection::Consumed => false,
    }
}

/// Updates the file descriptor for kTLS offload.
/// Must be called after the socket is connected.
///
/// # Safety
/// conn must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn rustls_connection_set_fd(
    conn: *mut rustls_connection_handle,
    fd: RawFd,
) {
    if conn.is_null() {
        return;
    }

    let rustls_conn = &mut *(conn as *mut RustlsConnection);
    eprintln!("[RUST FFI] 🔧 Setting file descriptor: old_fd={}, new_fd={}", rustls_conn.fd, fd);
    rustls_conn.fd = fd;
}

/// Checks if TLS handshake is complete.
///
/// # Safety
/// conn must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn rustls_connection_is_handshaking(
    conn: *const rustls_connection_handle,
) -> bool {
    if conn.is_null() {
        return false;
    }

    let rustls_conn = &*(conn as *const RustlsConnection);
    
    match &rustls_conn.connection {
        Connection::Client(client_conn) => client_conn.is_handshaking(),
        Connection::Server(server_conn) => server_conn.is_handshaking(),
        Connection::KtlsEnabled | Connection::Consumed => false, // kTLS enabled means handshake is complete.
    }
}

/// Reads decrypted application data.
///
/// # Safety
/// conn and buf must be valid pointers, buf must have at least len capacity.
#[no_mangle]
pub unsafe extern "C" fn rustls_connection_read(
    conn: *mut rustls_connection_handle,
    buf: *mut u8,
    len: usize,
) -> isize {
    if conn.is_null() || buf.is_null() {
        return RUSTLS_ERR_INVALID_PARAM as isize;
    }

    let rustls_conn = &mut *(conn as *mut RustlsConnection);
    let output = std::slice::from_raw_parts_mut(buf, len);

    // If kTLS RX is enabled, read directly from socket (kernel decrypts).
    if rustls_conn.ktls_rx_enabled {
        eprintln!("[RUST FFI] 🔧 kTLS RX read: attempting to read up to {} bytes from fd={}", len, rustls_conn.fd);
        let result = libc::read(rustls_conn.fd, buf as *mut libc::c_void, len);
        if result < 0 {
            let err = *libc::__errno_location();
            eprintln!("[RUST FFI] ❌ kTLS RX read FAILED: result={}, errno={} ({})", 
                     result, err,
                     if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                         "EAGAIN/WOULDBLOCK - no data ready"
                     } else if err == 5 {
                         "EIO - I/O error"  
                     } else {
                         "other error"
                     });
        } else {
            eprintln!("[RUST FFI] ✅ kTLS RX read SUCCESS: {} bytes from fd={}", result, rustls_conn.fd);
        }
        return result;
    }

    // Otherwise, use rustls userspace decryption.
    let result = match &mut rustls_conn.connection {
        Connection::Client(client_conn) => client_conn.reader().read(output),
        Connection::Server(server_conn) => server_conn.reader().read(output),
        Connection::KtlsEnabled => {
            // With kTLS, read directly from socket (kernel handles decryption).
            return RUSTLS_ERR_KTLS_NOT_SUPPORTED as isize;
        }
        Connection::Consumed => {
            // Connection consumed but kTLS failed - cannot read.
            return RUSTLS_ERR_KTLS_NOT_SUPPORTED as isize;
        }
    };

    match result {
        Ok(n) => n as isize,
        Err(_) => RUSTLS_ERR_IO as isize,
    }
}

/// Writes application data to be encrypted and sent.
///
/// # Safety
/// conn and buf must be valid pointers, buf must have at least len bytes.
#[no_mangle]
pub unsafe extern "C" fn rustls_connection_write(
    conn: *mut rustls_connection_handle,
    buf: *const u8,
    len: usize,
) -> isize {
    if conn.is_null() || buf.is_null() {
        return RUSTLS_ERR_INVALID_PARAM as isize;
    }

    let rustls_conn = &mut *(conn as *mut RustlsConnection);
    let input = std::slice::from_raw_parts(buf, len);

    // If kTLS TX is enabled, write directly to socket (kernel encrypts).
    if rustls_conn.ktls_tx_enabled {
        eprintln!("[RUST FFI] 🔧 kTLS TX write: attempting to write {} bytes to fd={}", len, rustls_conn.fd);
        let result = libc::write(rustls_conn.fd, buf as *const libc::c_void, len);
        if result < 0 {
            let err = *libc::__errno_location();
            eprintln!("[RUST FFI] ❌ kTLS TX write FAILED: result={}, errno={}", result, err);
        } else {
            eprintln!("[RUST FFI] ✅ kTLS TX write SUCCESS: {} bytes to fd={}", result, rustls_conn.fd);
        }
        return result;
    }

    // Otherwise, use rustls userspace encryption.
    let result = match &mut rustls_conn.connection {
        Connection::Client(client_conn) => client_conn.writer().write(input),
        Connection::Server(server_conn) => server_conn.writer().write(input),
        Connection::KtlsEnabled => {
            // With kTLS, write directly to socket (kernel handles encryption).
            return RUSTLS_ERR_KTLS_NOT_SUPPORTED as isize;
        }
        Connection::Consumed => {
            // Connection consumed but kTLS failed - cannot write.
            return RUSTLS_ERR_KTLS_NOT_SUPPORTED as isize;
        }
    };

    match result {
        Ok(n) => n as isize,
        Err(_) => RUSTLS_ERR_IO as isize,
    }
}

/// Gets the negotiated ALPN protocol.
///
/// # Safety
/// conn must be a valid pointer. Returns a pointer to internal buffer or null.
#[no_mangle]
pub unsafe extern "C" fn rustls_connection_get_alpn_protocol(
    conn: *const rustls_connection_handle,
    len: *mut usize,
) -> *const u8 {
    if conn.is_null() || len.is_null() {
        return std::ptr::null();
    }

    let rustls_conn = &*(conn as *const RustlsConnection);
    
    let protocol = match &rustls_conn.connection {
        Connection::Client(client_conn) => client_conn.alpn_protocol(),
        Connection::Server(server_conn) => server_conn.alpn_protocol(),
        Connection::KtlsEnabled | Connection::Consumed => None, // ALPN already negotiated before kTLS.
    };

    match protocol {
        Some(p) => {
            *len = p.len();
            p.as_ptr()
        }
        None => {
            *len = 0;
            std::ptr::null()
        }
    }
}

