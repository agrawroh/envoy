// Fixed handshake function - replace in lib.rs

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
    };

    result
}

