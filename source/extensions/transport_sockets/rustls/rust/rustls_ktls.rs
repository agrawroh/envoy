//! Rustls TLS transport socket with optional Linux kTLS support for Envoy dynamic modules.
//!
//! This module implements a TLS transport socket using rustls, with optional kTLS (kernel TLS)
//! offload on Linux. When kTLS is enabled and the negotiated cipher is supported, the kernel
//! handles encryption and decryption after the handshake completes, bypassing userspace crypto
//! entirely for data transfer.

use envoy_proxy_dynamic_modules_rust_sdk::{
  abi,
  declare_all_init_functions,
  envoy_log_error,
  envoy_log_info,
  ConnectionEvent,
  EnvoyTransportSocket,
  EnvoyTransportSocketImpl,
  IoResult,
  TransportSocket,
  TransportSocketFactoryConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{
  CipherSuite,
  ClientConfig,
  ClientConnection,
  Connection,
  ProtocolVersion,
  RootCertStore,
  ServerConfig,
  ServerConnection,
};
use serde::Deserialize;
use std::ffi::c_void;
use std::io::{self, Cursor, Read, Write};
use std::sync::Arc;

/// Buffer size for socket and kTLS kernel reads.
const IO_BUF_SIZE: usize = 32768;
/// Maximum number of write buffer slices retrieved from Envoy per write call.
const MAX_WRITE_SLICES: usize = 16;

// -------------------------------------------------------------------------------------------------
// JSON configuration.
// -------------------------------------------------------------------------------------------------

/// JSON configuration for the rustls transport socket.
#[derive(Debug, Deserialize)]
struct JsonConfig {
  /// PEM-encoded certificate chain, or path to a PEM file.
  cert_chain: String,
  /// PEM-encoded private key, or path to a PEM file.
  private_key: String,
  /// PEM-encoded trusted CA certificates, or path to a PEM file. If not specified, the default
  /// webpki root certificates are used for upstream connections.
  #[serde(default)]
  trusted_ca: Option<String>,
  /// ALPN protocols to advertise during the TLS handshake.
  #[serde(default)]
  alpn_protocols: Option<Vec<String>>,
  /// When true, enables kTLS offload after the handshake completes on Linux. Defaults to false.
  #[serde(default)]
  enable_ktls: bool,
  /// When true together with `enable_ktls`, only the TX direction is offloaded to the kernel.
  /// The RX direction remains in userspace rustls. Defaults to false.
  #[serde(default)]
  ktls_tx_only: bool,
  /// SNI hostname for upstream client connections. If not specified, defaults to "localhost".
  #[serde(default)]
  server_name: Option<String>,
}

// -------------------------------------------------------------------------------------------------
// PEM / filesystem helpers.
// -------------------------------------------------------------------------------------------------

fn load_pem_bytes(field: &str) -> Result<Vec<u8>, String> {
  let trimmed = field.trim();
  let path = std::path::Path::new(trimmed);
  if path.is_file() {
    std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))
  } else {
    Ok(trimmed.as_bytes().to_vec())
  }
}

fn parse_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
  let mut rd = Cursor::new(pem);
  rustls_pemfile::certs(&mut rd)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| format!("parse cert chain: {e}"))
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, String> {
  let mut rd = Cursor::new(pem);
  rustls_pemfile::private_key(&mut rd)
    .map_err(|e| format!("parse private key: {e}"))?
    .ok_or_else(|| "no private key found in PEM".to_string())
}

fn add_trusted_roots_from_pem(pem: &[u8], roots: &mut RootCertStore) -> Result<(), String> {
  let mut rd = Cursor::new(pem);
  let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut rd)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| format!("parse trusted CA PEM: {e}"))?;
  if certs.is_empty() {
    return Err("trusted_ca contained no certificates".to_string());
  }
  for c in certs {
    roots.add(c).map_err(|e| format!("add trusted root: {e}"))?;
  }
  Ok(())
}

fn alpn_from_config(cfg: &JsonConfig) -> Vec<Vec<u8>> {
  cfg
    .alpn_protocols
    .as_ref()
    .map(|v| v.iter().map(|s| s.as_bytes().to_vec()).collect())
    .unwrap_or_default()
}

// -------------------------------------------------------------------------------------------------
// Factory configuration.
// -------------------------------------------------------------------------------------------------

enum EndpointKind {
  Downstream(Arc<ServerConfig>),
  Upstream {
    cfg: Arc<ClientConfig>,
    server_name: ServerName<'static>,
  },
}

struct RustlsFactoryConfig {
  endpoint: EndpointKind,
  want_ktls: bool,
  ktls_tx_only: bool,
}

impl RustlsFactoryConfig {
  fn new_downstream(cfg: JsonConfig) -> Result<Self, String> {
    if cfg.cert_chain.trim().is_empty() || cfg.private_key.trim().is_empty() {
      return Err("downstream requires non-empty cert_chain and private_key".to_string());
    }
    let cert_pem = load_pem_bytes(&cfg.cert_chain)?;
    let key_pem = load_pem_bytes(&cfg.private_key)?;
    let certs = parse_cert_chain(&cert_pem)?;
    let key = parse_private_key(&key_pem)?;
    let mut server_config = ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(certs, key)
      .map_err(|e| format!("server config: {e}"))?;
    server_config.alpn_protocols = alpn_from_config(&cfg);
    server_config.enable_secret_extraction = cfg.enable_ktls;
    Ok(Self {
      endpoint: EndpointKind::Downstream(Arc::new(server_config)),
      want_ktls: cfg.enable_ktls,
      ktls_tx_only: cfg.ktls_tx_only,
    })
  }

  fn new_upstream(cfg: JsonConfig) -> Result<Self, String> {
    let mut root_store = RootCertStore::empty();
    if let Some(ca) = &cfg.trusted_ca {
      if !ca.trim().is_empty() {
        let pem = load_pem_bytes(ca)?;
        add_trusted_roots_from_pem(&pem, &mut root_store)?;
      }
    }
    if root_store.is_empty() {
      root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let client_cert = if !cfg.cert_chain.trim().is_empty() && !cfg.private_key.trim().is_empty() {
      let cert_pem = load_pem_bytes(&cfg.cert_chain)?;
      let key_pem = load_pem_bytes(&cfg.private_key)?;
      let certs = parse_cert_chain(&cert_pem)?;
      let key = parse_private_key(&key_pem)?;
      Some((certs, key))
    } else {
      None
    };

    let mut client_config = if let Some((certs, key)) = client_cert {
      ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .map_err(|e| format!("client config (mTLS): {e}"))?
    } else {
      ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
    };
    client_config.alpn_protocols = alpn_from_config(&cfg);
    client_config.enable_secret_extraction = cfg.enable_ktls;

    let sn = cfg
      .server_name
      .clone()
      .filter(|s| !s.trim().is_empty())
      .unwrap_or_else(|| "localhost".to_string());
    let server_name = ServerName::try_from(sn.clone())
      .map_err(|_| format!("invalid server_name / SNI for upstream: {sn}"))?;

    Ok(Self {
      endpoint: EndpointKind::Upstream {
        cfg: Arc::new(client_config),
        server_name,
      },
      want_ktls: cfg.enable_ktls,
      ktls_tx_only: cfg.ktls_tx_only,
    })
  }
}

impl TransportSocketFactoryConfig<EnvoyTransportSocketImpl> for RustlsFactoryConfig {
  fn new_transport_socket(
    &self,
    _envoy: &mut EnvoyTransportSocketImpl,
  ) -> Box<dyn TransportSocket<EnvoyTransportSocketImpl>> {
    match &self.endpoint {
      EndpointKind::Downstream(cfg) => Box::new(RustlsTransportSocket::new_server(
        cfg.clone(),
        self.want_ktls,
        self.ktls_tx_only,
      )),
      EndpointKind::Upstream { cfg, server_name } => Box::new(RustlsTransportSocket::new_client(
        cfg.clone(),
        server_name.clone(),
        self.want_ktls,
        self.ktls_tx_only,
      )),
    }
  }
}

// -------------------------------------------------------------------------------------------------
// Per-connection transport socket.
// -------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
  Handshaking,
  Established,
  #[cfg(target_os = "linux")]
  Ktls,
}

struct RustlsTransportSocket {
  server_cfg: Option<Arc<ServerConfig>>,
  client_cfg: Option<Arc<ClientConfig>>,
  server_name: Option<ServerName<'static>>,
  conn: Option<Connection>,
  phase: Phase,
  failure: String,
  want_ktls: bool,
  ktls_tx_only: bool,
  #[cfg(target_os = "linux")]
  ktls_attempted: bool,
  /// Set after the handshake completes when kTLS is desired. Cleared once kTLS is installed
  /// or when the attempt is abandoned.
  #[cfg(target_os = "linux")]
  ktls_pending: bool,
  /// Number of payload bytes remaining in the current TLS record being read from the socket.
  /// Used to track TLS record boundaries so that kTLS RX can be installed at a clean boundary.
  #[cfg(target_os = "linux")]
  tls_record_bytes_remaining: usize,
  /// Number of bytes of the current 5-byte TLS record header that have been accumulated in
  /// `tls_record_header_buf`. When this reaches 5, the payload length is parsed and
  /// `tls_record_bytes_remaining` is set accordingly.
  #[cfg(target_os = "linux")]
  tls_record_header_seen: u8,
  /// Buffer for accumulating a partial TLS record header across socket reads.
  #[cfg(target_os = "linux")]
  tls_record_header_buf: [u8; 5],
  connected_raised: bool,
  negotiated_proto: String,
  tls_write_backlog: Vec<u8>,
  tls_read_backlog: Vec<u8>,
  /// Stored as `usize` because raw pointers are not `Send`.
  io: Option<usize>,
  #[cfg(target_os = "linux")]
  ktls_fd: Option<libc::c_int>,
}

impl RustlsTransportSocket {
  fn new_server(cfg: Arc<ServerConfig>, want_ktls: bool, ktls_tx_only: bool) -> Self {
    Self {
      server_cfg: Some(cfg),
      client_cfg: None,
      server_name: None,
      conn: None,
      phase: Phase::Handshaking,
      failure: String::new(),
      want_ktls,
      ktls_tx_only,
      #[cfg(target_os = "linux")]
      ktls_attempted: false,
      #[cfg(target_os = "linux")]
      ktls_pending: false,
      #[cfg(target_os = "linux")]
      tls_record_bytes_remaining: 0,
      #[cfg(target_os = "linux")]
      tls_record_header_seen: 0,
      #[cfg(target_os = "linux")]
      tls_record_header_buf: [0u8; 5],
      connected_raised: false,
      negotiated_proto: String::new(),
      tls_write_backlog: Vec::new(),
      tls_read_backlog: Vec::new(),
      io: None,
      #[cfg(target_os = "linux")]
      ktls_fd: None,
    }
  }

  fn io_handle_ptr(&self) -> Option<*mut c_void> {
    self.io.map(|p| p as *mut c_void)
  }

  fn set_io_handle(&mut self, p: Option<*mut c_void>) {
    self.io = p.map(|raw| raw as usize);
  }

  fn new_client(
    cfg: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    want_ktls: bool,
    ktls_tx_only: bool,
  ) -> Self {
    Self {
      server_cfg: None,
      client_cfg: Some(cfg),
      server_name: Some(server_name),
      conn: None,
      phase: Phase::Handshaking,
      failure: String::new(),
      want_ktls,
      ktls_tx_only,
      #[cfg(target_os = "linux")]
      ktls_attempted: false,
      #[cfg(target_os = "linux")]
      ktls_pending: false,
      #[cfg(target_os = "linux")]
      tls_record_bytes_remaining: 0,
      #[cfg(target_os = "linux")]
      tls_record_header_seen: 0,
      #[cfg(target_os = "linux")]
      tls_record_header_buf: [0u8; 5],
      connected_raised: false,
      negotiated_proto: String::new(),
      tls_write_backlog: Vec::new(),
      tls_read_backlog: Vec::new(),
      io: None,
      #[cfg(target_os = "linux")]
      ktls_fd: None,
    }
  }

  fn ensure_connection(&mut self) -> Result<(), String> {
    if self.conn.is_some() {
      return Ok(());
    }
    if let Some(cfg) = &self.server_cfg {
      let c =
        ServerConnection::new(Arc::clone(cfg)).map_err(|e| format!("ServerConnection: {e}"))?;
      self.conn = Some(Connection::Server(c));
      return Ok(());
    }
    if let (Some(cfg), Some(sn)) = (&self.client_cfg, &self.server_name) {
      let c = ClientConnection::new(Arc::clone(cfg), sn.clone())
        .map_err(|e| format!("ClientConnection: {e}"))?;
      self.conn = Some(Connection::Client(c));
      return Ok(());
    }
    Err("rustls transport socket missing server or client configuration".to_string())
  }

  fn refresh_negotiated_proto(&mut self) {
    let Some(conn) = self.conn.as_ref() else {
      return;
    };
    if let Some(p) = conn.alpn_protocol() {
      self.negotiated_proto = String::from_utf8_lossy(p).into_owned();
    }
  }

  fn maybe_raise_connected(&mut self, envoy: &mut EnvoyTransportSocketImpl) {
    let Some(conn) = self.conn.as_ref() else {
      return;
    };
    if self.connected_raised || conn.is_handshaking() {
      return;
    }
    self.refresh_negotiated_proto();
    self.phase = Phase::Established;
    self.connected_raised = true;
    envoy_log_info!("rustls: handshake complete.");
    envoy.raise_event(ConnectionEvent::Connected);
    self.maybe_try_ktls(envoy);
  }

  fn maybe_try_ktls(&mut self, _envoy: &mut EnvoyTransportSocketImpl) {
    if !self.want_ktls {
      return;
    }
    #[cfg(not(target_os = "linux"))]
    {
      envoy_log_error!("kTLS is only supported on Linux, continuing with userspace TLS.");
      return;
    }
    #[cfg(target_os = "linux")]
    {
      if self.ktls_attempted || self.phase != Phase::Established {
        return;
      }
      self.ktls_attempted = true;
      let conn = match self.conn.as_ref() {
        Some(c) => c,
        None => return,
      };
      if !ktls_cipher_supported(conn) {
        envoy_log_error!(
          "kTLS: negotiated cipher is not supported, continuing with userspace TLS."
        );
        return;
      }
      // Defer actual kTLS installation to the next on_do_read call. At this point rustls may
      // have buffered application data in `tls_read_backlog` (the client started sending data
      // before we finished the handshake processing). We set a pending flag so that on_do_read
      // will process all buffered data first and then install kTLS at a clean record boundary.
      self.ktls_pending = true;
    }
  }

  /// Attempts to install kTLS on the current connection. Called when `ktls_pending` is set and
  /// record tracking indicates the kernel socket is at a clean TLS record boundary.
  #[cfg(target_os = "linux")]
  fn try_install_ktls(&mut self, envoy: &mut EnvoyTransportSocketImpl) {
    let Some(io) = self.io_handle_ptr() else {
      envoy_log_error!("kTLS: I/O handle missing, continuing with userspace TLS.");
      return;
    };
    let Some(fd) = socket_fd_for_ktls(envoy, io) else {
      envoy_log_error!("kTLS: socket fd unavailable, continuing with userspace TLS.");
      return;
    };
    if let Err(e) = self.run_linux_ktls(envoy, io, fd) {
      envoy_log_error!(
        "kTLS install failed ({}), falling back to userspace TLS.",
        e
      );
    }
  }

  #[cfg(target_os = "linux")]
  fn run_linux_ktls(
    &mut self,
    envoy: &mut EnvoyTransportSocketImpl,
    io: *mut c_void,
    fd: libc::c_int,
  ) -> Result<(), String> {
    // Flush any pending outgoing TLS data before installing kTLS.
    self.drain_tls_backlog(envoy, io)?;
    self.drain_rustls_tls(envoy, io)?;

    // Install TCP_ULP and the crypto info.
    linux_ktls::setup_ulp(fd)?;
    let conn = self
      .conn
      .take()
      .ok_or_else(|| "missing rustls connection".to_string())?;
    linux_ktls::install_crypto(fd, conn, self.ktls_tx_only)?;
    self.ktls_fd = Some(fd);
    self.phase = Phase::Ktls;
    self.connected_raised = true;
    Ok(())
  }

  fn drain_tls_backlog(
    &mut self,
    envoy: &EnvoyTransportSocketImpl,
    io: *mut c_void,
  ) -> Result<(), String> {
    while !self.tls_write_backlog.is_empty() {
      match envoy.io_handle_write(io, &self.tls_write_backlog) {
        Ok(0) => return Err("unexpected zero-length write while flushing TLS backlog".to_string()),
        Ok(n) => {
          self.tls_write_backlog.drain(.. n);
        },
        Err(rc) => {
          if err_would_block(rc) {
            return Err("socket not ready while flushing TLS backlog before kTLS".to_string());
          }
          return Err(format!("TLS backlog write failed (errno {rc})"));
        },
      }
    }
    Ok(())
  }

  fn drain_rustls_tls(
    &mut self,
    envoy: &EnvoyTransportSocketImpl,
    io: *mut c_void,
  ) -> Result<(), String> {
    let conn = self
      .conn
      .as_mut()
      .ok_or_else(|| "missing connection".to_string())?;
    let mut buf = [0u8; IO_BUF_SIZE];
    while conn.wants_write() {
      let mut cursor = Cursor::new(&mut buf[..]);
      let n = conn.write_tls(&mut cursor).map_err(|e| e.to_string())?;
      if n == 0 {
        break;
      }
      let written = cursor.position() as usize;
      let mut off = 0usize;
      while off < written {
        match envoy.io_handle_write(io, &buf[off .. written]) {
          Ok(0) => {
            self
              .tls_write_backlog
              .extend_from_slice(&buf[off .. written]);
            return Err("socket not ready while draining rustls TLS before kTLS".to_string());
          },
          Ok(w) => off += w,
          Err(rc) => {
            if err_would_block(rc) {
              self
                .tls_write_backlog
                .extend_from_slice(&buf[off .. written]);
              return Err("socket would block while draining rustls TLS before kTLS".to_string());
            }
            return Err(format!("drain rustls TLS write failed (errno {rc})"));
          },
        }
      }
    }
    Ok(())
  }

  fn drain_outgoing_tls(&mut self, envoy: &EnvoyTransportSocketImpl) -> Result<(), String> {
    let io = self
      .io_handle_ptr()
      .ok_or_else(|| "no io handle".to_string())?;
    self.drain_tls_backlog(envoy, io)?;
    let conn = self
      .conn
      .as_mut()
      .ok_or_else(|| "missing connection".to_string())?;
    let mut buf = [0u8; IO_BUF_SIZE];
    while conn.wants_write() {
      let mut cursor = Cursor::new(&mut buf[..]);
      let n = conn.write_tls(&mut cursor).map_err(|e| e.to_string())?;
      if n == 0 {
        break;
      }
      let written = cursor.position() as usize;
      let mut off = 0usize;
      while off < written {
        match envoy.io_handle_write(io, &buf[off .. written]) {
          Ok(0) => {
            self
              .tls_write_backlog
              .extend_from_slice(&buf[off .. written]);
            return Ok(());
          },
          Ok(w) => off += w,
          Err(rc) => {
            if err_would_block(rc) {
              self
                .tls_write_backlog
                .extend_from_slice(&buf[off .. written]);
              return Ok(());
            }
            return Err(format!("TLS write to transport failed (errno {rc})"));
          },
        }
      }
    }
    Ok(())
  }

  /// Feeds raw bytes into the rustls connection and stores any unconsumed remainder in the read
  /// backlog. Extracted as a helper to avoid overlapping mutable borrows of `self.conn` and
  /// `self.advance_record_tracking`.
  fn feed_raw_to_rustls(&mut self, data: &[u8]) -> Result<(usize, bool), String> {
    let conn = self
      .conn
      .as_mut()
      .ok_or_else(|| "missing connection".to_string())?;
    let mut cursor = Cursor::new(data);
    let read = conn.read_tls(&mut cursor).map_err(|e| e.to_string())?;
    if read == 0 && !data.is_empty() {
      return Err("rustls read_tls accepted no bytes".to_string());
    }
    let consumed = cursor.position() as usize;
    if consumed < data.len() {
      self.tls_read_backlog.extend_from_slice(&data[consumed ..]);
    }
    Ok((read, false))
  }

  /// Advances the TLS record boundary tracker with newly read raw bytes. This state machine
  /// parses the 5-byte TLS record headers to maintain an accurate count of where the socket
  /// read cursor sits relative to TLS record framing. The tracker handles partial headers that
  /// span multiple reads.
  #[cfg(target_os = "linux")]
  fn advance_record_tracking(&mut self, data: &[u8]) {
    let mut pos = 0usize;
    while pos < data.len() {
      if self.tls_record_bytes_remaining > 0 {
        let take = std::cmp::min(self.tls_record_bytes_remaining, data.len() - pos);
        pos += take;
        self.tls_record_bytes_remaining -= take;
        continue;
      }

      let header_needed = 5 - self.tls_record_header_seen as usize;
      let header_avail = std::cmp::min(header_needed, data.len() - pos);
      let start = self.tls_record_header_seen as usize;
      self.tls_record_header_buf[start .. start + header_avail]
        .copy_from_slice(&data[pos .. pos + header_avail]);
      self.tls_record_header_seen += header_avail as u8;
      pos += header_avail;

      if self.tls_record_header_seen < 5 {
        break;
      }

      let record_payload_len =
        u16::from_be_bytes([self.tls_record_header_buf[3], self.tls_record_header_buf[4]]) as usize;
      self.tls_record_header_seen = 0;

      let payload_avail = data.len() - pos;
      if payload_avail >= record_payload_len {
        pos += record_payload_len;
      } else {
        self.tls_record_bytes_remaining = record_payload_len - payload_avail;
        pos = data.len();
      }
    }
  }

  fn read_tls_from_socket(
    &mut self,
    envoy: &EnvoyTransportSocketImpl,
  ) -> Result<(usize, bool), String> {
    let io = self
      .io_handle_ptr()
      .ok_or_else(|| "no io handle".to_string())?;

    // Drain any previously buffered bytes before reading from the socket.
    if !self.tls_read_backlog.is_empty() {
      let backlog = std::mem::take(&mut self.tls_read_backlog);
      let result = self.feed_raw_to_rustls(&backlog);
      return result;
    }

    // When kTLS installation is pending, clamp socket reads to complete the current TLS record
    // exactly. Once the record boundary is reached, return (0, false) to signal that the caller
    // can proceed with kTLS installation.
    #[cfg(target_os = "linux")]
    if self.ktls_pending {
      if self.tls_record_bytes_remaining == 0 && self.tls_record_header_seen == 0 {
        return Ok((0, false));
      }
      let limit = if self.tls_record_bytes_remaining > 0 {
        self.tls_record_bytes_remaining
      } else {
        5 - self.tls_record_header_seen as usize
      };
      let mut raw = [0u8; IO_BUF_SIZE];
      let read_limit = std::cmp::min(limit, raw.len());
      match envoy.io_handle_read(io, &mut raw[.. read_limit]) {
        Ok(0) => return Ok((0, true)),
        Ok(n) => {
          self.advance_record_tracking(&raw[.. n]);
          return self.feed_raw_to_rustls(&raw[.. n]);
        },
        Err(rc) => {
          if err_would_block(rc) {
            return Ok((0, false));
          }
          return Err(format!("raw read failed (errno {rc})"));
        },
      }
    }

    let mut raw = [0u8; IO_BUF_SIZE];
    match envoy.io_handle_read(io, &mut raw) {
      Ok(0) => Ok((0, true)),
      Ok(n) => {
        #[cfg(target_os = "linux")]
        if self.want_ktls {
          self.advance_record_tracking(&raw[.. n]);
        }
        self.feed_raw_to_rustls(&raw[.. n])
      },
      Err(rc) => {
        if err_would_block(rc) {
          Ok((0, false))
        } else {
          Err(format!("raw read failed (errno {rc})"))
        }
      },
    }
  }

  fn forward_plaintext(
    &mut self,
    envoy: &mut EnvoyTransportSocketImpl,
  ) -> Result<usize, io::Error> {
    let conn = self
      .conn
      .as_mut()
      .ok_or_else(|| io::Error::other("missing connection"))?;
    let mut buf = [0u8; IO_BUF_SIZE];
    let mut total = 0usize;
    loop {
      let n = match conn.reader().read(&mut buf) {
        Ok(n) => n,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
        Err(e) => return Err(e),
      };
      if n == 0 {
        break;
      }
      if !envoy.read_buffer_add(&buf[.. n]) {
        return Err(io::Error::other("read_buffer_add rejected data"));
      }
      total += n;
    }
    Ok(total)
  }
}

impl TransportSocket<EnvoyTransportSocketImpl> for RustlsTransportSocket {
  fn on_set_callbacks(&mut self, envoy: &mut EnvoyTransportSocketImpl) {
    self.set_io_handle(envoy.get_io_handle());
  }

  fn on_connected(&mut self, envoy: &mut EnvoyTransportSocketImpl) {
    if let Err(e) = self.ensure_connection() {
      self.failure = e.clone();
      envoy_log_error!("rustls: failed to create TLS connection: {e}");
      return;
    }
    if let Some(p) = envoy.get_io_handle() {
      self.set_io_handle(Some(p));
    }
    if let Err(e) = self.drain_outgoing_tls(envoy) {
      self.failure = e.clone();
      envoy_log_error!("rustls: initial TLS write failed: {e}");
    }
    envoy.set_is_readable(false);
  }

  fn on_do_read(&mut self, envoy: &mut EnvoyTransportSocketImpl) -> IoResult {
    #[cfg(target_os = "linux")]
    if self.phase == Phase::Ktls {
      return self.on_do_read_ktls(envoy);
    }
    if !self.failure.is_empty() {
      return IoResult::close(0, false);
    }
    if self.conn.is_none() {
      if let Err(e) = self.ensure_connection() {
        self.failure = e;
        return IoResult::close(0, false);
      }
    }
    if envoy.should_drain_read_buffer() {
      let len = envoy.read_buffer_length();
      if len > 0 {
        envoy.read_buffer_drain(len);
      }
    }
    let mut total_plaintext = 0usize;
    loop {
      match self.read_tls_from_socket(envoy) {
        Ok((0, eof)) => {
          if eof {
            self.maybe_raise_connected(envoy);
            let _ = self.drain_outgoing_tls(envoy);
            return IoResult::close(total_plaintext, true);
          }
          break;
        },
        Ok((_n, _eof)) => {},
        Err(e) => {
          self.failure.clone_from(&e);
          envoy_log_error!("rustls: read_tls path failed: {e}");
          return IoResult::close(total_plaintext, false);
        },
      }
      let proc = {
        let conn = match self.conn.as_mut() {
          Some(c) => c,
          None => return IoResult::close(total_plaintext, false),
        };
        match conn.process_new_packets() {
          Ok(_state) => Ok(()),
          Err(e) => Err(e.to_string()),
        }
      };
      if let Err(e) = proc {
        self.failure = e.clone();
        envoy_log_error!("rustls: process_new_packets: {e}");
        return IoResult::close(total_plaintext, false);
      }
      match self.forward_plaintext(envoy) {
        Ok(n) => total_plaintext += n,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {},
        Err(e) => {
          self.failure = e.to_string();
          return IoResult::close(total_plaintext, false);
        },
      }
      self.maybe_raise_connected(envoy);
      if !self.failure.is_empty() {
        return IoResult::close(total_plaintext, false);
      }
    }
    if let Err(e) = self.drain_outgoing_tls(envoy) {
      self.failure = e;
      return IoResult::close(total_plaintext, false);
    }
    // Install kTLS when pending and record tracking confirms the kernel socket is at a clean
    // TLS record boundary (no partial header or payload buffered).
    #[cfg(target_os = "linux")]
    if self.ktls_pending
      && self.tls_read_backlog.is_empty()
      && self.tls_record_bytes_remaining == 0
      && self.tls_record_header_seen == 0
    {
      self.ktls_pending = false;
      self.try_install_ktls(envoy);
    }
    IoResult::keep_open(total_plaintext, false)
  }

  fn on_do_write(&mut self, envoy: &mut EnvoyTransportSocketImpl, _end_stream: bool) -> IoResult {
    #[cfg(target_os = "linux")]
    if self.phase == Phase::Ktls {
      return self.on_do_write_ktls(envoy);
    }
    if !self.failure.is_empty() {
      return IoResult::close(0, false);
    }
    if self.conn.is_none() {
      if let Err(e) = self.ensure_connection() {
        self.failure = e;
        return IoResult::close(0, false);
      }
    }
    let mut envoy_bufs = [abi::envoy_dynamic_module_type_envoy_buffer {
      ptr: std::ptr::null_mut(),
      length: 0,
    }; MAX_WRITE_SLICES];
    let n_slices = envoy.write_buffer_get_slices(&mut envoy_bufs);
    let mut total_plain = 0usize;
    for b in envoy_bufs.iter().take(n_slices) {
      if b.ptr.is_null() || b.length == 0 {
        continue;
      }
      let slice = unsafe { std::slice::from_raw_parts(b.ptr.cast::<u8>(), b.length) };
      let mut off = 0usize;
      while off < slice.len() {
        let conn = match self.conn.as_mut() {
          Some(c) => c,
          None => return IoResult::close(0, false),
        };
        let written = match conn.writer().write(&slice[off ..]) {
          Ok(w) => w,
          Err(e) => {
            self.failure = e.to_string();
            return IoResult::close(0, false);
          },
        };
        off += written;
        total_plain += written;
        if written == 0 {
          break;
        }
      }
    }
    if total_plain > 0 {
      envoy.write_buffer_drain(total_plain);
    }
    if let Err(e) = self.drain_outgoing_tls(envoy) {
      self.failure = e;
      return IoResult::close(0, false);
    }
    let _ = envoy.flush_write_buffer();
    IoResult::keep_open(total_plain, false)
  }

  fn on_close(&mut self, _envoy: &mut EnvoyTransportSocketImpl, _event: ConnectionEvent) {
    #[cfg(target_os = "linux")]
    if let Some(fd) = self.ktls_fd.take() {
      if self.phase == Phase::Ktls && self.failure.is_empty() {
        let _ = linux_ktls::send_close_notify(fd);
      }
    }
    self.conn = None;
    self.tls_write_backlog.clear();
    self.tls_read_backlog.clear();
  }

  fn get_protocol(&self, _envoy: &mut EnvoyTransportSocketImpl) -> String {
    self.negotiated_proto.clone()
  }

  fn get_failure_reason(&self, _envoy: &mut EnvoyTransportSocketImpl) -> String {
    self.failure.clone()
  }

  fn can_flush_close(&self, _envoy: &mut EnvoyTransportSocketImpl) -> bool {
    if !self.failure.is_empty() {
      return true;
    }
    match &self.conn {
      None => true,
      Some(c) => !c.is_handshaking(),
    }
  }
}

#[cfg(target_os = "linux")]
impl RustlsTransportSocket {
  fn on_do_read_ktls(&mut self, envoy: &mut EnvoyTransportSocketImpl) -> IoResult {
    if !self.failure.is_empty() {
      return IoResult::close(0, false);
    }
    let fd = match self.ktls_fd {
      Some(fd) => fd,
      None => {
        let Some(io) = self.io_handle_ptr() else {
          return IoResult::close(0, false);
        };
        let Some(fd) = envoy.io_handle_fd(io) else {
          return IoResult::close(0, false);
        };
        self.ktls_fd = Some(fd);
        fd
      },
    };
    let mut buf = [0u8; IO_BUF_SIZE];
    let mut total = 0usize;
    loop {
      let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
      if n > 0 {
        if !envoy.read_buffer_add(&buf[.. n as usize]) {
          return IoResult::close(total, false);
        }
        total += n as usize;
        continue;
      }
      if n == 0 {
        return IoResult::close(total, true);
      }
      let errno = unsafe { *libc::__errno_location() };
      if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
        return IoResult::keep_open(total, false);
      }
      if errno == libc::EIO {
        match linux_ktls::receive_control_message(fd, &mut buf) {
          linux_ktls::ControlResult::Continue => continue,
          linux_ktls::ControlResult::ApplicationData(len) => {
            if len > 0 && !envoy.read_buffer_add(&buf[.. len]) {
              return IoResult::close(total, false);
            }
            total += len;
            continue;
          },
          linux_ktls::ControlResult::CloseNotify => {
            let _ = linux_ktls::send_close_notify(fd);
            return IoResult::close(total, true);
          },
          linux_ktls::ControlResult::Error(e) => {
            self.failure = format!("kTLS control message error: {e}");
            return IoResult::close(total, false);
          },
        }
      }
      self.failure = format!("kTLS read failed (errno {errno})");
      return IoResult::close(total, false);
    }
  }

  fn on_do_write_ktls(&mut self, envoy: &mut EnvoyTransportSocketImpl) -> IoResult {
    if !self.failure.is_empty() {
      return IoResult::close(0, false);
    }
    let fd = match self.ktls_fd {
      Some(fd) => fd,
      None => return IoResult::close(0, false),
    };
    let mut envoy_bufs = [abi::envoy_dynamic_module_type_envoy_buffer {
      ptr: std::ptr::null_mut(),
      length: 0,
    }; MAX_WRITE_SLICES];
    let n_slices = envoy.write_buffer_get_slices(&mut envoy_bufs);

    // Build iovec array from envoy buffer slices for scatter-gather I/O.
    let mut iovs: [libc::iovec; MAX_WRITE_SLICES] = unsafe { std::mem::zeroed() };
    let mut iov_count = 0usize;
    let mut total_requested = 0usize;
    for b in envoy_bufs.iter().take(n_slices) {
      if b.ptr.is_null() || b.length == 0 {
        continue;
      }
      iovs[iov_count] = libc::iovec {
        iov_base: b.ptr as *mut c_void,
        iov_len: b.length,
      };
      total_requested += b.length;
      iov_count += 1;
    }
    if iov_count == 0 || total_requested == 0 {
      let _ = envoy.flush_write_buffer();
      return IoResult::keep_open(0, false);
    }

    // Use sendmsg to write all slices in a single syscall.
    let mut total = 0usize;
    while total < total_requested {
      let msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: iovs.as_mut_ptr(),
        msg_iovlen: iov_count,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
      };
      let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
      if n > 0 {
        let sent = n as usize;
        total += sent;
        // Advance iovec past the bytes already sent.
        let mut skip = sent;
        while iov_count > 0 && skip > 0 {
          if skip >= iovs[0].iov_len {
            skip -= iovs[0].iov_len;
            iovs.copy_within(1 .. iov_count, 0);
            iov_count -= 1;
          } else {
            iovs[0].iov_base = unsafe { (iovs[0].iov_base as *mut u8).add(skip).cast() };
            iovs[0].iov_len -= skip;
            skip = 0;
          }
        }
        continue;
      }
      if n == 0 {
        break;
      }
      let errno = unsafe { *libc::__errno_location() };
      if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
        break;
      }
      self.failure = format!("kTLS write failed (errno {errno})");
      if total > 0 {
        envoy.write_buffer_drain(total);
      }
      return IoResult::close(total, false);
    }
    if total > 0 {
      envoy.write_buffer_drain(total);
    }
    let _ = envoy.flush_write_buffer();
    IoResult::keep_open(total, false)
  }
}

// -------------------------------------------------------------------------------------------------
// Misc helpers.
// -------------------------------------------------------------------------------------------------

fn err_would_block(rc: i64) -> bool {
  let abs = rc.unsigned_abs() as libc::c_int;
  abs == libc::EAGAIN || abs == libc::EWOULDBLOCK
}

fn ktls_cipher_supported(conn: &Connection) -> bool {
  let Some(cs) = conn.negotiated_cipher_suite() else {
    return false;
  };
  matches!(
    cs.suite(),
    CipherSuite::TLS13_AES_128_GCM_SHA256
      | CipherSuite::TLS13_AES_256_GCM_SHA384
      | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
      | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      | CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
      | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      | CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
      | CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
  )
}

/// Returns the native socket fd from the I/O handle via the ABI callback.
#[cfg(target_os = "linux")]
fn socket_fd_for_ktls(envoy: &EnvoyTransportSocketImpl, io: *mut c_void) -> Option<i32> {
  envoy.io_handle_fd(io)
}

// -------------------------------------------------------------------------------------------------
// Linux kTLS (setsockopt) helpers.
// -------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_ktls {
  use super::*;
  use rustls::ConnectionTrafficSecrets;

  const SOL_TLS: libc::c_int = 282;
  const TLS_TX: libc::c_int = 1;
  const TLS_RX: libc::c_int = 2;
  const SOL_TCP: libc::c_int = 6;
  const TCP_ULP: libc::c_int = 31;
  const TLS_1_2_VERSION: u16 = 0x0303;
  const TLS_1_3_VERSION: u16 = 0x0304;
  const TLS_CIPHER_AES_GCM_128: u16 = 51;
  const TLS_CIPHER_AES_GCM_256: u16 = 52;
  const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

  const AES_GCM_IV: usize = 8;
  const AES_GCM_128_KEY: usize = 16;
  const AES_GCM_256_KEY: usize = 32;
  const AES_GCM_SALT: usize = 4;
  const REC_SEQ: usize = 8;
  const CHACHA20_IV: usize = 12;
  const CHACHA20_KEY: usize = 32;

  const TLS_SET_RECORD_TYPE: libc::c_int = 1;
  const TLS_GET_RECORD_TYPE: libc::c_int = 2;
  const TLS_RX_EXPECT_NO_PAD: libc::c_int = 3;
  const TLS_CONTENT_TYPE_ALERT: u8 = 21;
  const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
  const TLS_CONTENT_TYPE_APP_DATA: u8 = 23;

  /// TLS alert level: warning (1) or fatal (2).
  const TLS_ALERT_LEVEL_FATAL: u8 = 2;
  /// TLS alert description for close_notify.
  const TLS_ALERT_CLOSE_NOTIFY: u8 = 0;

  #[repr(C)]
  struct TlsCryptoInfo {
    version: u16,
    cipher_type: u16,
  }

  #[repr(C)]
  struct Tls12CryptoInfoAesGcm128 {
    info: TlsCryptoInfo,
    iv: [u8; AES_GCM_IV],
    key: [u8; AES_GCM_128_KEY],
    salt: [u8; AES_GCM_SALT],
    rec_seq: [u8; REC_SEQ],
  }

  #[repr(C)]
  struct Tls12CryptoInfoAesGcm256 {
    info: TlsCryptoInfo,
    iv: [u8; AES_GCM_IV],
    key: [u8; AES_GCM_256_KEY],
    salt: [u8; AES_GCM_SALT],
    rec_seq: [u8; REC_SEQ],
  }

  #[repr(C)]
  struct Tls12CryptoInfoChacha20Poly1305 {
    info: TlsCryptoInfo,
    iv: [u8; CHACHA20_IV],
    key: [u8; CHACHA20_KEY],
    rec_seq: [u8; REC_SEQ],
  }

  fn split_aes_gcm_iv(iv: &[u8]) -> Result<([u8; AES_GCM_SALT], [u8; AES_GCM_IV]), String> {
    if iv.len() != 12 {
      return Err(format!(
        "unexpected IV length {} for AES-GCM, expected 12",
        iv.len()
      ));
    }
    let mut salt = [0u8; AES_GCM_SALT];
    let mut out_iv = [0u8; AES_GCM_IV];
    salt.copy_from_slice(&iv[.. AES_GCM_SALT]);
    out_iv.copy_from_slice(&iv[AES_GCM_SALT ..]);
    Ok((salt, out_iv))
  }

  /// Applies the TLS crypto info for a single direction (TX or RX) via `setsockopt`.
  fn apply_direction(
    fd: libc::c_int,
    direction: libc::c_int,
    version: u16,
    seq: u64,
    secret: &ConnectionTrafficSecrets,
  ) -> Result<(), String> {
    let dir_name = if direction == TLS_TX { "TX" } else { "RX" };
    match secret {
      ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
        let kb = key.as_ref();
        match kb.len() {
          AES_GCM_128_KEY => {
            let (salt, iv_part) = split_aes_gcm_iv(iv.as_ref())?;
            let mut info = Tls12CryptoInfoAesGcm128 {
              info: TlsCryptoInfo {
                version,
                cipher_type: TLS_CIPHER_AES_GCM_128,
              },
              iv: iv_part,
              key: kb.try_into().unwrap(),
              salt,
              rec_seq: seq.to_be_bytes(),
            };
            setsockopt_crypto(
              fd,
              direction,
              &mut info as *mut _ as *mut libc::c_void,
              std::mem::size_of_val(&info),
              dir_name,
            )?;
          },
          AES_GCM_256_KEY => {
            let (salt, iv_part) = split_aes_gcm_iv(iv.as_ref())?;
            let mut info = Tls12CryptoInfoAesGcm256 {
              info: TlsCryptoInfo {
                version,
                cipher_type: TLS_CIPHER_AES_GCM_256,
              },
              iv: iv_part,
              key: kb.try_into().unwrap(),
              salt,
              rec_seq: seq.to_be_bytes(),
            };
            setsockopt_crypto(
              fd,
              direction,
              &mut info as *mut _ as *mut libc::c_void,
              std::mem::size_of_val(&info),
              dir_name,
            )?;
          },
          _ => {
            return Err(format!(
              "unexpected AES-GCM key length {} in Aes128Gcm variant",
              kb.len()
            ))
          },
        }
      },
      ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
        let (salt, iv_part) = split_aes_gcm_iv(iv.as_ref())?;
        let kb = key.as_ref();
        if kb.len() != AES_GCM_256_KEY {
          return Err(format!("unexpected AES-256-GCM key length {}", kb.len()));
        }
        let mut info = Tls12CryptoInfoAesGcm256 {
          info: TlsCryptoInfo {
            version,
            cipher_type: TLS_CIPHER_AES_GCM_256,
          },
          iv: iv_part,
          key: kb.try_into().unwrap(),
          salt,
          rec_seq: seq.to_be_bytes(),
        };
        setsockopt_crypto(
          fd,
          direction,
          &mut info as *mut _ as *mut libc::c_void,
          std::mem::size_of_val(&info),
          dir_name,
        )?;
      },
      ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
        let kb = key.as_ref();
        if kb.len() != CHACHA20_KEY {
          return Err(format!(
            "unexpected ChaCha20-Poly1305 key length {}",
            kb.len()
          ));
        }
        let iv_bytes = iv.as_ref();
        if iv_bytes.len() != CHACHA20_IV {
          return Err(format!(
            "unexpected ChaCha20-Poly1305 IV length {}",
            iv_bytes.len()
          ));
        }
        let mut info = Tls12CryptoInfoChacha20Poly1305 {
          info: TlsCryptoInfo {
            version,
            cipher_type: TLS_CIPHER_CHACHA20_POLY1305,
          },
          iv: iv_bytes.try_into().unwrap(),
          key: kb.try_into().unwrap(),
          rec_seq: seq.to_be_bytes(),
        };
        setsockopt_crypto(
          fd,
          direction,
          &mut info as *mut _ as *mut libc::c_void,
          std::mem::size_of_val(&info),
          dir_name,
        )?;
      },
      _ => {
        return Err("unsupported traffic secret variant for kTLS".to_string());
      },
    }
    Ok(())
  }

  fn setsockopt_crypto(
    fd: libc::c_int,
    direction: libc::c_int,
    info_ptr: *mut libc::c_void,
    info_size: usize,
    dir_name: &str,
  ) -> Result<(), String> {
    let ret = unsafe {
      libc::setsockopt(
        fd,
        SOL_TLS,
        direction,
        info_ptr,
        info_size as libc::socklen_t,
      )
    };
    if ret < 0 {
      return Err(format!(
        "TLS_{dir_name} setsockopt: {}",
        std::io::Error::last_os_error()
      ));
    }
    Ok(())
  }

  /// Enables the TLS upper-level protocol on the socket. This must be called before installing
  /// crypto info for TX/RX.
  pub fn setup_ulp(fd: libc::c_int) -> Result<(), String> {
    let ret = unsafe {
      libc::setsockopt(
        fd,
        SOL_TCP,
        TCP_ULP,
        "tls".as_ptr().cast(),
        3 as libc::socklen_t,
      )
    };
    if ret < 0 {
      return Err(format!(
        "TCP_ULP setsockopt: {}",
        std::io::Error::last_os_error()
      ));
    }
    Ok(())
  }

  /// Extracts secrets from a completed rustls `Connection` and installs them into the kernel via
  /// `setsockopt(SOL_TLS, TLS_TX/TLS_RX, ...)`.
  pub fn install_crypto(fd: libc::c_int, conn: Connection, tx_only: bool) -> Result<(), String> {
    let version = match conn.protocol_version() {
      Some(ProtocolVersion::TLSv1_2) => TLS_1_2_VERSION,
      Some(ProtocolVersion::TLSv1_3) => TLS_1_3_VERSION,
      _ => return Err("unsupported TLS protocol version for kTLS".to_string()),
    };
    let secrets = conn
      .dangerous_extract_secrets()
      .map_err(|e| format!("dangerous_extract_secrets: {e}"))?;

    let (tx_seq, tx_sec) = secrets.tx;
    let (rx_seq, rx_sec) = secrets.rx;
    apply_direction(fd, TLS_TX, version, tx_seq, &tx_sec)?;
    if !tx_only {
      apply_direction(fd, TLS_RX, version, rx_seq, &rx_sec)?;
      // TLS 1.3: hint to the kernel that records have no padding, enabling a faster decrypt path.
      if version == TLS_1_3_VERSION {
        let val: libc::c_int = 1;
        unsafe {
          libc::setsockopt(
            fd,
            SOL_TLS,
            TLS_RX_EXPECT_NO_PAD,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
          );
        }
      }
    }
    // Disable Nagle since kTLS handles record framing.
    unsafe {
      let val: libc::c_int = 1;
      libc::setsockopt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_NODELAY,
        &val as *const _ as *const libc::c_void,
        std::mem::size_of_val(&val) as libc::socklen_t,
      );
    }
    envoy_log_info!("kTLS installed (TX={}, RX={}).", true, !tx_only);
    Ok(())
  }

  /// Result of processing a kTLS control message received via `recvmsg`.
  pub enum ControlResult {
    /// Non-fatal control message processed; the caller should continue reading.
    Continue,
    /// Application data was received alongside the control message.
    ApplicationData(usize),
    /// A close_notify alert was received; the connection should be closed gracefully.
    CloseNotify,
    /// An unrecoverable error occurred.
    Error(String),
  }

  /// Aligned buffer for cmsg data. Kernel cmsg convention requires alignment to `c_long`.
  #[repr(C, align(8))]
  struct CmsgBuf {
    data: [u8; 64],
  }

  /// Reads a control message from a kTLS socket using `recvmsg`. This is called when a normal
  /// `recv` returns `EIO`, indicating that the kernel has a non-application-data record available
  /// (e.g., a TLS 1.3 NewSessionTicket or an alert).
  pub fn receive_control_message(fd: libc::c_int, buf: &mut [u8]) -> ControlResult {
    let mut iov = libc::iovec {
      iov_base: buf.as_mut_ptr().cast(),
      iov_len: buf.len(),
    };
    let cmsg_space = unsafe { libc::CMSG_SPACE(1) } as usize;
    let mut cmsg_buf = CmsgBuf { data: [0u8; 64] };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.data.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space;

    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
      let errno = unsafe { *libc::__errno_location() };
      if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
        return ControlResult::Continue;
      }
      return ControlResult::Error(format!("recvmsg failed (errno {errno})"));
    }

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
      return ControlResult::Continue;
    }
    let cmsg_ref = unsafe { &*cmsg };
    if cmsg_ref.cmsg_level != SOL_TLS || cmsg_ref.cmsg_type != TLS_GET_RECORD_TYPE {
      return ControlResult::Continue;
    }
    let record_type = unsafe { *libc::CMSG_DATA(cmsg) };
    match record_type {
      TLS_CONTENT_TYPE_HANDSHAKE => ControlResult::Continue,
      TLS_CONTENT_TYPE_ALERT => {
        let n = n as usize;
        if n >= 2 {
          let level = buf[0];
          let description = buf[1];
          if description == TLS_ALERT_CLOSE_NOTIFY || level == TLS_ALERT_LEVEL_FATAL {
            return ControlResult::CloseNotify;
          }
        } else if n == 1 {
          // Only the level byte was received. Per the reference implementation, assume
          // close_notify when the full description is not available.
          return ControlResult::CloseNotify;
        }
        ControlResult::Continue
      },
      TLS_CONTENT_TYPE_APP_DATA => ControlResult::ApplicationData(n as usize),
      _ => ControlResult::Continue,
    }
  }

  /// Sends a TLS close_notify alert via `sendmsg` with the `TLS_SET_RECORD_TYPE` cmsg.
  pub fn send_close_notify(fd: libc::c_int) -> Result<(), String> {
    let mut alert_data: [u8; 2] = [1, TLS_ALERT_CLOSE_NOTIFY];

    let mut iov = libc::iovec {
      iov_base: alert_data.as_mut_ptr().cast(),
      iov_len: alert_data.len(),
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE(1) } as usize;
    let mut cmsg_buf = CmsgBuf { data: [0u8; 64] };
    let cmsg_ptr = cmsg_buf.data.as_mut_ptr().cast::<libc::cmsghdr>();
    unsafe {
      (*cmsg_ptr).cmsg_level = SOL_TLS;
      (*cmsg_ptr).cmsg_type = TLS_SET_RECORD_TYPE;
      (*cmsg_ptr).cmsg_len = libc::CMSG_LEN(1) as _;
      *libc::CMSG_DATA(cmsg_ptr) = TLS_CONTENT_TYPE_ALERT;
    }

    let msg = libc::msghdr {
      msg_name: std::ptr::null_mut(),
      msg_namelen: 0,
      msg_iov: &mut iov,
      msg_iovlen: 1,
      msg_control: cmsg_buf.data.as_mut_ptr().cast(),
      msg_controllen: cmsg_space,
      msg_flags: 0,
    };

    let ret = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
    if ret < 0 {
      let errno = unsafe { *libc::__errno_location() };
      if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK || errno == libc::EPIPE {
        return Ok(());
      }
      return Err(format!("sendmsg close_notify failed (errno {errno})"));
    }
    Ok(())
  }
}

// -------------------------------------------------------------------------------------------------
// Dynamic module entrypoints.
// -------------------------------------------------------------------------------------------------

fn program_init() -> bool {
  let _ = rustls::crypto::ring::default_provider().install_default();
  true
}

fn new_factory_config(
  _name: &str,
  config: &[u8],
  is_upstream: bool,
) -> Option<Box<dyn TransportSocketFactoryConfig<EnvoyTransportSocketImpl>>> {
  let cfg: JsonConfig = serde_json::from_slice(config).ok()?;
  let factory = if is_upstream {
    RustlsFactoryConfig::new_upstream(cfg).ok()?
  } else {
    RustlsFactoryConfig::new_downstream(cfg).ok()?
  };
  Some(Box::new(factory))
}

declare_all_init_functions!(
  program_init,
  transport_socket: new_factory_config,
);
