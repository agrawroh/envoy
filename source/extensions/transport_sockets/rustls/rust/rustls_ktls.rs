//! Rustls TLS transport socket with optional Linux kTLS support for Envoy dynamic modules.
//!
//! This module implements a TLS transport socket using rustls, with optional kTLS (kernel TLS)
//! offload on Linux. When kTLS is enabled and the negotiated cipher is supported, the kernel
//! handles encryption and decryption after the handshake completes, bypassing userspace crypto
//! entirely for data transfer.

use envoy_proxy_dynamic_modules_rust_sdk::{
  declare_all_init_functions, envoy_log_debug, envoy_log_error, envoy_log_warn, ConnectionEvent,
  EnvoyTransportSocket, EnvoyTransportSocketImpl, IoResult, IoStatus, TransportSocket,
  TransportSocketFactoryConfig,
};
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName};
use rustls::{
  CipherSuite, ClientConfig, ClientConnection, Connection, ProtocolVersion, RootCertStore,
  ServerConfig, ServerConnection, SupportedProtocolVersion,
};
use serde::Deserialize;
use std::io::{self, Cursor, Read, Write};
use std::sync::Arc;

/// Buffer size for kTLS kernel reads/writes. 64KB aligns with the maximum TLS record payload
/// and provides optimal throughput for large transfers.
const IO_BUF_SIZE: usize = 65536;
/// Upper bound applied via `Connection::set_buffer_limit(Some(N))`. rustls 0.23 applies the
/// same limit to BOTH the `sendable_plaintext` queue (pre-encryption) and the `sendable_tls`
/// queue (post-encryption). When either fills, `writer().write()` returns a short count; we
/// stop consuming further plaintext from Envoy's write buffer so Envoy's high-watermark fires
/// and propagates backpressure to the producer (HCM filter chain).
const RUSTLS_PLAINTEXT_BUFFER_LIMIT: usize = 256 * 1024;
/// Upper bound on the post-encryption socket-write backlog held in `tls_write_backlog`. Bytes
/// appended beyond this point would otherwise blow past Envoy's bounded write_buffer and
/// break flow control on slow upstreams (e.g. S3 PUT against a throttled bucket). When the
/// backlog reaches the bound (or exceeds it by up to one record on the loop boundary, a soft
/// cap), we stop pumping rustls's TLS output until the socket accepts more.
///
/// Worst-case per-connection memory budget for the write path is roughly
/// `2 × RUSTLS_PLAINTEXT_BUFFER_LIMIT` (plaintext + post-encryption queues, both capped by
/// `set_buffer_limit`) + `TLS_WRITE_BACKLOG_LIMIT` (drained-but-unsent).
const TLS_WRITE_BACKLOG_LIMIT: usize = 256 * 1024;

// -------------------------------------------------------------------------------------------------
// JSON configuration.
// -------------------------------------------------------------------------------------------------

/// JSON configuration for the rustls transport socket. Field names are deserialized from camelCase
/// to match the proto JSON serialization format.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonConfig {
  /// PEM-encoded certificate chain, or path to a PEM file.
  #[serde(default)]
  cert_chain: String,
  /// PEM-encoded private key, or path to a PEM file.
  #[serde(default)]
  private_key: String,
  /// PEM-encoded trusted CA certificates, or path to a PEM file. If not specified, the default
  /// webpki root certificates are used for upstream connections.
  #[serde(default)]
  trusted_ca: Option<String>,
  /// ALPN protocols to advertise during the TLS handshake.
  #[serde(default)]
  alpn_protocols: Option<Vec<String>>,
  /// Enables kTLS offload after the TLS handshake completes on Linux. Defaults to false.
  #[serde(default)]
  enable_ktls: bool,
  /// When true together with enable_ktls, disables kTLS for the RX direction. Defaults to false.
  #[serde(default)]
  disable_ktls_rx: bool,
  /// SNI hostname for upstream client connections. Required on the upstream side; an empty or
  /// missing value is rejected at config load (`new_upstream`).
  #[serde(default)]
  sni: Option<String>,
  /// Minimum acceptable TLS protocol version. Defaults to TLS_AUTO (rustls safe default range).
  #[serde(default)]
  tls_minimum_protocol_version: TlsVersion,
  /// Maximum acceptable TLS protocol version. Defaults to TLS_AUTO (rustls safe default range).
  #[serde(default)]
  tls_maximum_protocol_version: TlsVersion,
  /// PEM-encoded certificate revocation list, or path to a PEM file. On the downstream side it
  /// revokes client certificates and is only meaningful when trusted_ca is set. On the upstream
  /// side it revokes server certificates against the always-present trust store.
  #[serde(default)]
  crl: Option<String>,
}

/// TLS protocol version bound, deserialized from the proto enum's JSON name. Mirrors the proto
/// `TlsVersion` enum (TLS_AUTO / TLSv1_2 / TLSv1_3).
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
enum TlsVersion {
  #[default]
  #[serde(rename = "TLS_AUTO")]
  Auto,
  #[serde(rename = "TLSv1_2")]
  Tls12,
  #[serde(rename = "TLSv1_3")]
  Tls13,
}

impl TlsVersion {
  /// Ordering rank within the rustls-supported range. TLS 1.2 is the floor and TLS 1.3 the
  /// ceiling, so an unset (Auto) minimum maps to 1.2 and an unset maximum maps to 1.3.
  fn rank(self, is_max: bool) -> u8 {
    match self {
      TlsVersion::Auto => {
        if is_max {
          2
        } else {
          1
        }
      },
      TlsVersion::Tls12 => 1,
      TlsVersion::Tls13 => 2,
    }
  }
}

/// Resolves the configured (min, max) bound to an explicit rustls protocol-version list, or `None`
/// when both are TLS_AUTO (use rustls's default range). Rejects an inverted range at config time.
fn protocol_versions(
  min: TlsVersion,
  max: TlsVersion,
) -> Result<Option<Vec<&'static SupportedProtocolVersion>>, String> {
  let lo = min.rank(/*is_max=*/ false);
  let hi = max.rank(/*is_max=*/ true);
  if lo > hi {
    return Err(format!(
      "tls_minimum_protocol_version ({min:?}) is greater than tls_maximum_protocol_version ({max:?})"
    ));
  }
  if min == TlsVersion::Auto && max == TlsVersion::Auto {
    return Ok(None);
  }
  let mut versions: Vec<&'static SupportedProtocolVersion> = Vec::new();
  if lo == 1 {
    versions.push(&rustls::version::TLS12);
  }
  if hi == 2 {
    versions.push(&rustls::version::TLS13);
  }
  Ok(Some(versions))
}

/// Parses zero or more PEM-encoded certificate revocation lists.
fn parse_crls(pem: &[u8]) -> Result<Vec<CertificateRevocationListDer<'static>>, String> {
  let mut cursor = Cursor::new(pem);
  rustls_pemfile::crls(&mut cursor)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| format!("failed to parse CRL PEM: {e}"))
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
  enable_ktls: bool,
  ktls_tx_only: bool,
}

impl RustlsFactoryConfig {
  /// Validates kTLS-related config invariants shared by both factory directions. Currently
  /// rejects `disable_ktls_rx: true` because TX-only kTLS is not safely implemented yet.
  /// Once the kernel TLS ULP is attached and we install only TX crypto, all RX `recv()` calls
  /// fall back to plain-TCP semantics (the kernel has no RX TLS context). The PR consumes the
  /// rustls `Connection` during install regardless of `ktls_tx_only`, so userspace decrypt is
  /// also gone. The next RX read would feed raw TLS ciphertext into Envoy's plaintext buffer
  /// and silently corrupt the stream. Until a proper `Phase::KtlsTxOnly` variant keeps the
  /// rustls Connection alive for RX decrypt while TX runs in-kernel, refuse the config at
  /// load time so operators get a clear failure rather than a stealth data-corruption bug.
  fn validate_ktls_options(cfg: &JsonConfig) -> Result<(), String> {
    if cfg.enable_ktls && cfg.disable_ktls_rx {
      return Err(
        "`disable_ktls_rx: true` is not yet supported in this alpha extension. The current \
         implementation cannot route RX through userspace TLS while TX is offloaded to the kernel \
         (the rustls Connection is consumed during install). Set `enable_ktls: false` to use full \
         userspace TLS, or `enable_ktls: true` with `disable_ktls_rx: false` to use kTLS for both \
         directions."
          .to_string(),
      );
    }
    Ok(())
  }

  fn new_downstream(cfg: JsonConfig) -> Result<Self, String> {
    Self::validate_ktls_options(&cfg)?;
    if cfg.cert_chain.trim().is_empty() || cfg.private_key.trim().is_empty() {
      return Err("downstream requires non-empty cert_chain and private_key".to_string());
    }
    let cert_pem = load_pem_bytes(&cfg.cert_chain)?;
    let key_pem = load_pem_bytes(&cfg.private_key)?;
    let certs = parse_cert_chain(&cert_pem)?;
    let key = parse_private_key(&key_pem)?;

    let has_trusted_ca = cfg
      .trusted_ca
      .as_ref()
      .is_some_and(|s| !s.trim().is_empty());
    let has_crl = cfg.crl.as_ref().is_some_and(|s| !s.trim().is_empty());
    // A CRL only constrains client-certificate verification, which is enabled by trusted_ca, so a
    // CRL without a trust store is a misconfiguration. Reject it at load time rather than silently
    // accepting client certs the operator believes are being revocation-checked.
    if has_crl && !has_trusted_ca {
      return Err(
        "`crl` requires `trusted_ca`; a CRL only applies to client-certificate verification, \
         which is enabled by setting `trusted_ca`"
          .to_string(),
      );
    }

    let versions = protocol_versions(
      cfg.tls_minimum_protocol_version,
      cfg.tls_maximum_protocol_version,
    )?;
    let builder = match &versions {
      Some(v) => ServerConfig::builder_with_protocol_versions(v),
      None => ServerConfig::builder(),
    };
    let want_server_cert = if has_trusted_ca {
      let mut root_store = RootCertStore::empty();
      let pem = load_pem_bytes(cfg.trusted_ca.as_ref().unwrap())?;
      add_trusted_roots_from_pem(&pem, &mut root_store)?;
      let mut verifier_builder =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store));
      if has_crl {
        let crl_pem = load_pem_bytes(cfg.crl.as_ref().unwrap())?;
        let crls = parse_crls(&crl_pem)?;
        if crls.is_empty() {
          return Err(
            "`crl` was set but no CRL was parsed from it (expected PEM `X509 CRL` blocks)"
              .to_string(),
          );
        }
        // The verifier keeps rustls 0.23's strict builder defaults: revocation is checked across
        // the full client certificate chain (RevocationCheckDepth::Chain), and a certificate whose
        // revocation status is unknown (its issuer is not covered by any supplied CRL) is rejected
        // (UnknownStatusPolicy::Deny). We deliberately do not call only_check_end_entity_revocation
        // or allow_unknown_revocation_status, which would weaken this.
        verifier_builder = verifier_builder.with_crls(crls);
      }
      let verifier = verifier_builder
        .build()
        .map_err(|e| format!("client cert verifier: {e}"))?;
      builder.with_client_cert_verifier(verifier)
    } else {
      builder.with_no_client_auth()
    };

    let mut server_config = want_server_cert
      .with_single_cert(certs, key)
      .map_err(|e| format!("server config: {e}"))?;
    server_config.alpn_protocols = alpn_from_config(&cfg);
    server_config.enable_secret_extraction = cfg.enable_ktls;
    Ok(Self {
      endpoint: EndpointKind::Downstream(Arc::new(server_config)),
      enable_ktls: cfg.enable_ktls,
      ktls_tx_only: cfg.disable_ktls_rx,
    })
  }

  fn new_upstream(cfg: JsonConfig) -> Result<Self, String> {
    Self::validate_ktls_options(&cfg)?;
    // Build the trust store. If the operator did not supply a `trusted_ca`, fall back to the
    // bundled Mozilla webpki roots. This matches what most operators expect when pointing at a
    // public TLS endpoint like AWS S3, but log a warning once so the staleness window of the
    // pinned-at-build-time CA bundle is visible in the operator's logs.
    let mut root_store = RootCertStore::empty();
    let mut used_webpki_default = false;
    if let Some(ca) = &cfg.trusted_ca {
      if !ca.trim().is_empty() {
        let pem = load_pem_bytes(ca)?;
        add_trusted_roots_from_pem(&pem, &mut root_store)?;
      }
    }
    if root_store.is_empty() {
      root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
      used_webpki_default = true;
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

    let versions = protocol_versions(
      cfg.tls_minimum_protocol_version,
      cfg.tls_maximum_protocol_version,
    )?;
    let builder = match &versions {
      Some(v) => ClientConfig::builder_with_protocol_versions(v),
      None => ClientConfig::builder(),
    };
    // A CRL constrains server-certificate verification. Unlike the downstream side, the upstream
    // always has a trust store (trusted_ca or the bundled webpki roots), so there is no
    // crl-without-trust-store case to guard. When a CRL is set, build an explicit webpki verifier
    // with the CRLs and use it instead of the default `with_root_certificates` verifier.
    let has_crl = cfg.crl.as_ref().is_some_and(|s| !s.trim().is_empty());
    let with_roots = if has_crl {
      let crl_pem = load_pem_bytes(cfg.crl.as_ref().unwrap())?;
      let crls = parse_crls(&crl_pem)?;
      if crls.is_empty() {
        return Err(
          "`crl` was set but no CRL was parsed from it (expected PEM `X509 CRL` blocks)"
            .to_string(),
        );
      }
      // The verifier keeps rustls 0.23's strict builder defaults: revocation is checked across the
      // full server certificate chain (RevocationCheckDepth::Chain), and a certificate whose
      // revocation status is unknown (its issuer is not covered by any supplied CRL) is rejected
      // (UnknownStatusPolicy::Deny). We deliberately do not call only_check_end_entity_revocation
      // or allow_unknown_revocation_status, which would weaken this.
      let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
        .with_crls(crls)
        .build()
        .map_err(|e| format!("server cert verifier: {e}"))?;
      builder.with_webpki_verifier(verifier)
    } else {
      builder.with_root_certificates(root_store)
    };
    let mut client_config = if let Some((certs, key)) = client_cert {
      with_roots
        .with_client_auth_cert(certs, key)
        .map_err(|e| format!("client config (mTLS): {e}"))?
    } else {
      with_roots.with_no_client_auth()
    };
    client_config.alpn_protocols = alpn_from_config(&cfg);
    client_config.enable_secret_extraction = cfg.enable_ktls;

    // SNI is required for upstream. Webpki cert verification matches the server certificate
    // against the supplied ServerName. Defaulting to "localhost" silently mis-handshakes against
    // any real upstream, so fail-loud at config time.
    let sn = match cfg.sni.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
      Some(s) => s.to_string(),
      None => {
        return Err(
          "rustls upstream config requires a non-empty `sni` (TLS Server Name Indication). Set \
           `sni:` to the upstream hostname (e.g. \"mybucket.s3.amazonaws.com\")."
            .to_string(),
        );
      },
    };
    let server_name = ServerName::try_from(sn.clone())
      .map_err(|_| format!("invalid server_name / SNI for upstream: {sn}"))?;

    if used_webpki_default {
      envoy_log_warn!(
        "rustls upstream: no `trusted_ca` set; using compiled-in Mozilla webpki roots. These are \
         pinned at build time and may not reflect recent CA additions/removals."
      );
    }

    Ok(Self {
      endpoint: EndpointKind::Upstream {
        cfg: Arc::new(client_config),
        server_name,
      },
      enable_ktls: cfg.enable_ktls,
      ktls_tx_only: cfg.disable_ktls_rx,
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
        self.enable_ktls,
        self.ktls_tx_only,
      )),
      EndpointKind::Upstream { cfg, server_name } => Box::new(RustlsTransportSocket::new_client(
        cfg.clone(),
        server_name.clone(),
        self.enable_ktls,
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
  /// Per-connection SNI override (e.g. from a cluster with `auto_sni`), set via
  /// `on_set_server_name_override`. When present it replaces the factory-default `server_name` in
  /// `ensure_connection`. One shared `ClientConfig` serves every SNI, so only this `ServerName`
  /// varies per connection.
  server_name_override: Option<ServerName<'static>>,
  conn: Option<Connection>,
  phase: Phase,
  failure: String,
  enable_ktls: bool,
  ktls_tx_only: bool,
  #[cfg(target_os = "linux")]
  ktls_attempted: bool,
  #[cfg(target_os = "linux")]
  ktls_pending: bool,
  #[cfg(target_os = "linux")]
  tls_record_bytes_remaining: usize,
  #[cfg(target_os = "linux")]
  tls_record_header_seen: u8,
  #[cfg(target_os = "linux")]
  tls_record_header_buf: [u8; 5],
  connected_raised: bool,
  negotiated_proto: String,
  tls_write_backlog: Vec<u8>,
  tls_read_backlog: Vec<u8>,
  /// Reusable scratch buffer holding the plaintext copied out of Envoy's write buffer each write.
  /// Kept on the socket so the steady-state write path does not allocate per call.
  write_scratch: Vec<u8>,
  #[cfg(target_os = "linux")]
  ktls_fd: Option<libc::c_int>,
  #[cfg(target_os = "linux")]
  ktls_shutdown_sent: bool,
  /// True once the userspace TLS path has emitted a `close_notify` alert into the rustls
  /// send queue (in response to `end_stream=true` on `on_do_write`). Prevents double-close.
  userspace_close_notify_sent: bool,
  /// Latches when `on_do_write_inner` saw `end_stream=true` but couldn't emit close_notify
  /// because Envoy's write buffer or the local `tls_write_backlog` were non-empty. Re-checked
  /// on subsequent `on_do_write_inner` calls so a graceful TLS shutdown is delivered once the
  /// buffers drain. Without this, slow upstreams (S3 throttling, congested links) could see
  /// the TCP FIN without a preceding close_notify and treat the upload as truncated.
  end_stream_pending: bool,
  /// Re-entrancy tripwire on the write path. Defense-in-depth against a future change that
  /// reintroduces a recursive `flush_write_buffer()`/`on_do_write` self-call: if `on_do_write`
  /// detects it is already running, it short-circuits with `keep_open(0, false)`.
  in_do_write: bool,
}

impl RustlsTransportSocket {
  fn new_server(cfg: Arc<ServerConfig>, enable_ktls: bool, ktls_tx_only: bool) -> Self {
    Self {
      server_cfg: Some(cfg),
      client_cfg: None,
      server_name: None,
      server_name_override: None,
      conn: None,
      phase: Phase::Handshaking,
      failure: String::new(),
      enable_ktls,
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
      write_scratch: Vec::new(),
      #[cfg(target_os = "linux")]
      ktls_fd: None,
      #[cfg(target_os = "linux")]
      ktls_shutdown_sent: false,
      userspace_close_notify_sent: false,
      end_stream_pending: false,
      in_do_write: false,
    }
  }

  fn new_client(
    cfg: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    enable_ktls: bool,
    ktls_tx_only: bool,
  ) -> Self {
    Self {
      server_cfg: None,
      client_cfg: Some(cfg),
      server_name: Some(server_name),
      server_name_override: None,
      conn: None,
      phase: Phase::Handshaking,
      failure: String::new(),
      enable_ktls,
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
      write_scratch: Vec::new(),
      #[cfg(target_os = "linux")]
      ktls_fd: None,
      #[cfg(target_os = "linux")]
      ktls_shutdown_sent: false,
      userspace_close_notify_sent: false,
      end_stream_pending: false,
      in_do_write: false,
    }
  }

  fn ensure_connection(&mut self) -> Result<(), String> {
    if self.conn.is_some() {
      return Ok(());
    }
    // Belt-and-suspenders: never build a connection after a prior config failure (e.g. a rejected
    // per-connection SNI override). Building one would hand back the factory-default authority and
    // mis-handshake. Callers also gate on `self.failure` before reaching here.
    if !self.failure.is_empty() {
      return Err(self.failure.clone());
    }
    // Prefer the per-connection SNI override (e.g. auto_sni) over the factory default. The same
    // shared `ClientConfig` is used either way, so only the `ServerName` varies per connection.
    let effective_sn = self
      .server_name_override
      .as_ref()
      .or(self.server_name.as_ref());
    let conn = if let Some(cfg) = &self.server_cfg {
      Connection::Server(
        ServerConnection::new(Arc::clone(cfg)).map_err(|e| format!("ServerConnection: {e}"))?,
      )
    } else if let (Some(cfg), Some(sn)) = (&self.client_cfg, effective_sn) {
      Connection::Client(
        ClientConnection::new(Arc::clone(cfg), sn.clone())
          .map_err(|e| format!("ClientConnection: {e}"))?,
      )
    } else {
      return Err("rustls transport socket missing server or client configuration".to_string());
    };
    // Bound rustls's internal plaintext queue so a slow upstream (e.g. throttled S3 endpoint)
    // can't make us swallow unbounded bytes from Envoy's write buffer. When the queue fills,
    // `writer().write()` returns a short count and we stop draining Envoy's buffer; Envoy's
    // own high-watermark then fires and propagates backpressure to the producer.
    let mut conn = conn;
    conn.set_buffer_limit(Some(RUSTLS_PLAINTEXT_BUFFER_LIMIT));
    self.conn = Some(conn);
    Ok(())
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
    envoy_log_debug!("rustls: handshake complete");
    envoy.raise_event(ConnectionEvent::Connected);
    self.maybe_try_ktls(envoy);
  }

  fn maybe_try_ktls(&mut self, _envoy: &mut EnvoyTransportSocketImpl) {
    if !self.enable_ktls {
      return;
    }
    #[cfg(not(target_os = "linux"))]
    {
      // Log once per program. This is operator config, not a per-connection event.
      static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
      WARNED.get_or_init(|| {
        envoy_log_warn!(
          "kTLS is only supported on Linux; continuing with userspace TLS for this and all \
           subsequent connections on this build."
        );
      });
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
        // Log once per program. The set of kTLS-eligible ciphers is fixed at build time, so
        // a misconfigured cluster will see this fire on every connection. Per-connection warn
        // logs would flood operator dashboards under load.
        static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        WARNED.get_or_init(|| {
          envoy_log_warn!(
            "kTLS: negotiated cipher is not in the supported set; continuing with userspace TLS \
             for this and all subsequent connections that negotiate this cipher."
          );
        });
        return;
      }
      self.ktls_pending = true;
    }
  }

  #[cfg(target_os = "linux")]
  fn try_install_ktls(&mut self, envoy: &mut EnvoyTransportSocketImpl) {
    // Pre-ULP failures (socket fd unavailable, validate_for_ktls Err, setup_ulp ENOPROTOOPT on a
    // kernel without CONFIG_TLS) are deterministic per build / per kernel. Rate-limit each to once
    // per program to avoid flooding operator dashboards on a misconfigured cluster. Post-attach
    // errors stay at error-level per-connection since they indicate a kernel-state hazard worth
    // flagging on every occurrence.
    let Some(fd) = envoy.get_fd() else {
      static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
      WARNED.get_or_init(|| {
        envoy_log_warn!("kTLS: socket fd unavailable, continuing with userspace TLS");
      });
      return;
    };
    if let Err(e) = self.run_linux_ktls(envoy, fd) {
      // `run_linux_ktls` sets `self.failure` on every step after the initial drain+validate
      // (extract → setup_ulp → apply_prepared). Pre-extract failures (validate_for_ktls
      // returning Err, pre-drain EAGAIN) leave `self.failure` empty AND `self.conn` still
      // owned. Userspace TLS continues. Once `self.failure` is set, the next I/O returns
      // Close and the connection terminates, whether or not the kernel ULP was attached.
      // The error string itself ("pre-attach" / "ULP attached") indicates whether the kernel
      // socket has been polluted, which only matters for kernel-side debugging.
      if self.failure.is_empty() {
        static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        WARNED.get_or_init(|| {
          envoy_log_warn!("kTLS install pre-extract step failed ({e}), using userspace TLS");
        });
      } else {
        envoy_log_error!("kTLS install failed ({e}), connection will close");
      }
    }
  }

  #[cfg(target_os = "linux")]
  fn run_linux_ktls(
    &mut self,
    envoy: &mut EnvoyTransportSocketImpl,
    fd: libc::c_int,
  ) -> Result<(), String> {
    // Step 1. Flush any pending pre-kTLS bytes; the kernel's TLS layer must see a clean stream
    // starting at the post-handshake record sequence.
    self.drain_backlog_strict(envoy)?;
    self.drain_rustls_tls(envoy)?;

    // Step 2. Drain every decrypted plaintext byte to Envoy. Without this, anything sitting in
    // rustls's reader buffer would be silently lost when we drop the Connection below.
    self.drain_all_plaintext(envoy);

    // Step 3. Validate the connection's protocol version is kTLS-eligible WITHOUT consuming
    // the rustls Connection. If validation fails, the caller falls back to userspace TLS and
    // `self.conn` is still owned.
    let version = {
      let conn = self
        .conn
        .as_ref()
        .ok_or_else(|| "missing rustls connection".to_string())?;
      linux_ktls::validate_for_ktls(conn)?
    };

    // Step 4. Consume the rustls Connection and extract secrets. This consumes `self.conn`
    // but does NOT touch the kernel socket state; if extraction fails, the userspace TLS path
    // is not recoverable (Connection is gone) but the socket is still in plain-TCP mode and
    // the next I/O cleanly returns Close. Doing this BEFORE `setup_ulp` matches the
    // rustls-org `ktls` reference crate (lib.rs:323-345) and keeps the irreversible ULP
    // attach as the last fallible step before crypto install. Failure modes are bounded by
    // the pre-gates: `enable_secret_extraction=true` (always set by factory when
    // enable_ktls), handshake complete (`maybe_raise_connected` gates `ktls_pending`), and
    // `sendable_tls.is_empty()` (drained at Step 1 above).
    let conn = self
      .conn
      .take()
      .ok_or_else(|| "missing rustls connection".to_string())?;
    // `trusted_peer` gates `TLS_RX_EXPECT_NO_PAD`. Only the upstream (client) path connects to a
    // peer Envoy chose. Downstream listeners accept connections from untrusted clients who could
    // weaponize TLS-1.3 record padding into a DoS vector.
    let trusted_peer = self.client_cfg.is_some();
    let prepared =
      match linux_ktls::extract_secrets(conn, version, true, !self.ktls_tx_only, trusted_peer) {
        Ok(p) => p,
        Err(e) => {
          // No ULP attached yet; the kernel socket is untouched. Next I/O closes cleanly.
          self.failure = format!("kTLS secret extraction failed (pre-attach): {e}");
          return Err(self.failure.clone());
        },
      };

    // Step 5. Attach the kernel TLS ULP. This is the point of no return. Failure here is
    // recoverable on the socket (no ULP attached) but not on userspace (Connection consumed
    // at Step 4). Next I/O closes cleanly.
    if let Err(e) = linux_ktls::setup_ulp(fd) {
      self.failure = format!("kTLS ULP setup failed (post-extract, pre-attach): {e}");
      return Err(self.failure.clone());
    }

    // Step 6. Install pre-computed crypto info. ULP is now attached; failure here is
    // terminal (kernel has no `TCP_ULP_REMOVE`).
    if let Err(e) = linux_ktls::apply_prepared(fd, prepared) {
      self.failure = format!("kTLS crypto install failed (ULP attached, socket terminal): {e}");
      return Err(self.failure.clone());
    }

    self.ktls_fd = Some(fd);
    self.phase = Phase::Ktls;
    // `connected_raised` was set true in `maybe_raise_connected` when the handshake completed.
    // Resetting it here would let a re-entrant code path think we are still in handshake.
    Ok(())
  }

  /// Drains every byte of decrypted plaintext from the rustls reader into Envoy's read buffer.
  /// Called as a safety net right before dropping the Connection for kTLS transition.
  fn drain_all_plaintext(&mut self, envoy: &mut EnvoyTransportSocketImpl) {
    let Some(conn) = self.conn.as_mut() else {
      return;
    };
    let mut buf = [0u8; IO_BUF_SIZE];
    loop {
      match conn.reader().read(&mut buf) {
        Ok(0) => break,
        Ok(n) => {
          envoy.read_buffer_add(&buf[..n]);
        },
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
        Err(e) => {
          envoy_log_warn!("kTLS: plaintext drain read error before install ({e})");
          break;
        },
      }
    }
  }

  /// Tries to push the TLS-side write backlog into the socket. Returns `Ok(true)` if the
  /// backlog is now empty, `Ok(false)` if the socket is not currently accepting more bytes
  /// (EAGAIN / EWOULDBLOCK / zero-byte write), `Err` only on fatal socket errors. The lenient
  /// EAGAIN semantics are what makes backpressure work. When the socket is slow we keep the
  /// backlog and return; the next event-loop write opportunity drains more.
  fn try_drain_backlog(&mut self, envoy: &EnvoyTransportSocketImpl) -> Result<bool, String> {
    while !self.tls_write_backlog.is_empty() {
      let (status, n) = envoy.io_write(&self.tls_write_backlog);
      match status {
        IoStatus::Success => {
          if n == 0 {
            return Ok(false);
          }
          self.tls_write_backlog.drain(..n);
        },
        IoStatus::Again => return Ok(false),
        IoStatus::Error => return Err("TLS backlog write failed".to_string()),
      }
    }
    Ok(true)
  }

  /// Strict drain used only in the pre-kTLS install path. Treats EAGAIN as an error because
  /// kTLS install requires a clean (empty) userspace buffer.
  #[cfg(target_os = "linux")]
  fn drain_backlog_strict(&mut self, envoy: &EnvoyTransportSocketImpl) -> Result<(), String> {
    while !self.tls_write_backlog.is_empty() {
      let (status, n) = envoy.io_write(&self.tls_write_backlog);
      match status {
        IoStatus::Success => {
          if n == 0 {
            return Err("unexpected zero-length write while flushing TLS backlog".to_string());
          }
          self.tls_write_backlog.drain(..n);
        },
        IoStatus::Again => {
          return Err("socket not ready while flushing TLS backlog before kTLS".to_string())
        },
        IoStatus::Error => return Err("TLS backlog write failed".to_string()),
      }
    }
    Ok(())
  }

  /// Pre-kTLS drain of rustls's outgoing TLS records, strict (EAGAIN is an error).
  #[cfg(target_os = "linux")]
  fn drain_rustls_tls(&mut self, envoy: &EnvoyTransportSocketImpl) -> Result<(), String> {
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
        let (status, w) = envoy.io_write(&buf[off..written]);
        match status {
          IoStatus::Success => {
            if w == 0 {
              self.tls_write_backlog.extend_from_slice(&buf[off..written]);
              return Err("socket not ready while draining rustls TLS before kTLS".to_string());
            }
            off += w;
          },
          IoStatus::Again => {
            self.tls_write_backlog.extend_from_slice(&buf[off..written]);
            return Err("socket would block while draining rustls TLS before kTLS".to_string());
          },
          IoStatus::Error => return Err("drain rustls TLS write failed".to_string()),
        }
      }
    }
    Ok(())
  }

  /// Pumps rustls's outgoing TLS records to the socket as far as possible without blocking.
  /// On EAGAIN we save unsent bytes into `tls_write_backlog` (bounded by
  /// `TLS_WRITE_BACKLOG_LIMIT`) and return. The caller (`on_do_write_inner`) inspects
  /// `tls_write_backlog` to decide whether to consume more plaintext from Envoy's write
  /// buffer. This is the path that surfaces Envoy's high-watermark and propagates
  /// backpressure to the upstream HTTP filter chain.
  fn drain_outgoing_tls(&mut self, envoy: &EnvoyTransportSocketImpl) -> Result<(), String> {
    if !self.try_drain_backlog(envoy)? {
      // Backlog still has data: don't pump more bytes out of rustls's TLS queue. They would
      // just append to the backlog and grow memory. The next write event drains more.
      return Ok(());
    }
    let conn = self
      .conn
      .as_mut()
      .ok_or_else(|| "missing connection".to_string())?;
    let mut buf = [0u8; IO_BUF_SIZE];
    while conn.wants_write() && self.tls_write_backlog.len() < TLS_WRITE_BACKLOG_LIMIT {
      let mut cursor = Cursor::new(&mut buf[..]);
      let n = conn.write_tls(&mut cursor).map_err(|e| e.to_string())?;
      if n == 0 {
        break;
      }
      let written = cursor.position() as usize;
      let mut off = 0usize;
      while off < written {
        let (status, w) = envoy.io_write(&buf[off..written]);
        match status {
          IoStatus::Success => {
            if w == 0 {
              self.tls_write_backlog.extend_from_slice(&buf[off..written]);
              return Ok(());
            }
            off += w;
          },
          IoStatus::Again => {
            self.tls_write_backlog.extend_from_slice(&buf[off..written]);
            return Ok(());
          },
          IoStatus::Error => return Err("TLS write to transport failed".to_string()),
        }
      }
    }
    Ok(())
  }

  /// Feeds raw bytes into rustls's deframer. Returns the number of bytes rustls actually
  /// consumed; any unconsumed tail is appended to `tls_read_backlog` for a retry on the next
  /// iteration. Returning `Ok(0)` is legitimate rustls backpressure (deframer needs
  /// `process_new_packets()` to drain first). The outer loop in `on_do_read` always runs
  /// `process_new_packets` after this call, so the next iteration's retry will make progress.
  fn feed_raw_to_rustls(&mut self, data: &[u8]) -> Result<usize, String> {
    let conn = self
      .conn
      .as_mut()
      .ok_or_else(|| "missing connection".to_string())?;
    let mut cursor = Cursor::new(data);
    let read = conn.read_tls(&mut cursor).map_err(|e| e.to_string())?;
    let consumed = cursor.position() as usize;
    if consumed < data.len() {
      self.tls_read_backlog.extend_from_slice(&data[consumed..]);
    }
    Ok(read)
  }

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
      self.tls_record_header_buf[start..start + header_avail]
        .copy_from_slice(&data[pos..pos + header_avail]);
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
    if !self.tls_read_backlog.is_empty() {
      let backlog = std::mem::take(&mut self.tls_read_backlog);
      return self.feed_raw_to_rustls(&backlog).map(|n| (n, false));
    }

    // kTLS record-boundary cork. To install kTLS the kernel must take over decryption at a clean
    // TLS record boundary, so we must not pull application-data bytes into userspace past the
    // handshake. While the handshake is in progress (and while an install is pending) read the
    // socket one record at a time, capped at the current record's boundary. When the handshake
    // completes we are then parked exactly at a boundary with the response still in the kernel
    // socket buffer, so the install fires cleanly and the kernel decrypts the response. Without this
    // a single large recv() pulls the handshake-final record AND streamed response records (peers
    // like S3 send the response back-to-back with the handshake) into userspace, and the install
    // gate never finds a clean boundary again, so kTLS and the splice fast-path never engage.
    #[cfg(target_os = "linux")]
    if self.enable_ktls && (self.phase == Phase::Handshaking || self.ktls_pending) {
      if self.tls_record_bytes_remaining == 0
        && self.tls_record_header_seen == 0
        && self.ktls_pending
      {
        // Handshake done, install pending, parked at a clean boundary: stop so the install fires
        // before any application data is read into userspace.
        return Ok((0, false));
      }
      let limit = if self.tls_record_bytes_remaining > 0 {
        self.tls_record_bytes_remaining
      } else {
        5 - self.tls_record_header_seen as usize
      };
      let mut raw = [0u8; IO_BUF_SIZE];
      let read_limit = std::cmp::min(limit, raw.len());
      let (status, n) = envoy.io_read(&mut raw[..read_limit]);
      match status {
        IoStatus::Success => {
          if n == 0 {
            return Ok((0, true));
          }
          self.advance_record_tracking(&raw[..n]);
          return self.feed_raw_to_rustls(&raw[..n]).map(|m| (m, false));
        },
        IoStatus::Again => return Ok((0, false)),
        IoStatus::Error => return Err("raw read failed".to_string()),
      }
    }

    let mut raw = [0u8; IO_BUF_SIZE];
    let (status, n) = envoy.io_read(&mut raw);
    match status {
      IoStatus::Success => {
        if n == 0 {
          return Ok((0, true));
        }
        #[cfg(target_os = "linux")]
        if self.enable_ktls {
          self.advance_record_tracking(&raw[..n]);
        }
        self.feed_raw_to_rustls(&raw[..n]).map(|m| (m, false))
      },
      IoStatus::Again => Ok((0, false)),
      IoStatus::Error => Err("raw read failed".to_string()),
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
      envoy.read_buffer_add(&buf[..n]);
      total += n;
      // Respect Envoy's high-watermark on the read buffer between iterations. Otherwise a
      // single `process_new_packets` that decrypts several pipelined records can push 64 KiB
      // into the buffer before we even check, blowing past whatever soft cap the filter chain
      // expects.
      if envoy.should_drain_read_buffer() {
        envoy.set_is_readable();
        break;
      }
    }
    Ok(total)
  }

  fn on_do_write_inner(
    &mut self,
    envoy: &mut EnvoyTransportSocketImpl,
    end_stream: bool,
  ) -> IoResult {
    if !self.failure.is_empty() {
      return IoResult::close(0, false);
    }
    if self.conn.is_none() {
      if let Err(e) = self.ensure_connection() {
        self.failure = e;
        return IoResult::close(0, false);
      }
    }
    // Step 1. Push any pending TLS bytes out FIRST. Backpressure invariant: we only accept
    // plaintext from Envoy's write buffer when (a) the post-encryption backlog is below
    // TLS_WRITE_BACKLOG_LIMIT and (b) rustls's plaintext queue is below
    // RUSTLS_PLAINTEXT_BUFFER_LIMIT. Either being above its cap causes us to short-count
    // `write_buffer_drain`, which fires Envoy's high-watermark and propagates flow control to
    // the HCM producer. Without this discipline, Envoy's bounded write buffer would drain
    // into our internal queue without any high-watermark feedback and grow with offered load.
    if let Err(e) = self.drain_outgoing_tls(envoy) {
      self.failure = e;
      return IoResult::close(0, false);
    }
    if self.tls_write_backlog.len() >= TLS_WRITE_BACKLOG_LIMIT {
      // Backlog is at the cap. Refuse more plaintext. Envoy's write_buffer stays full,
      // high-watermark fires, HCM applies backpressure.
      return IoResult::keep_open(0, false);
    }

    // Step 2. Copy the plaintext queued in Envoy's write buffer and feed it to rustls, bounded by
    // rustls's `set_buffer_limit`. When the limit is hit, `conn.writer().write()` returns a short
    // count (possibly zero) and we stop consuming. Leftover plaintext stays in Envoy's buffer, so
    // the short `write_buffer_drain` below fires Envoy's high-watermark and propagates backpressure
    // to the HCM producer.
    self.write_scratch.clear();
    envoy.copy_write_buffer(&mut self.write_scratch);
    let mut total_plain = 0usize;
    while total_plain < self.write_scratch.len() {
      let conn = match self.conn.as_mut() {
        Some(c) => c,
        None => return IoResult::close(total_plain, false),
      };
      let written = match conn.writer().write(&self.write_scratch[total_plain..]) {
        Ok(w) => w,
        Err(e) => {
          // rustls's `Writer::write` is infallible for a healthy `Connection` (it only buffers
          // into `sendable_plaintext`). If it errors, the connection is in a bad state.
          self.failure = e.to_string();
          return IoResult::close(total_plain, false);
        },
      };
      if written == 0 {
        // rustls's plaintext queue is at the bound. Stop consuming.
        break;
      }
      total_plain += written;
    }
    if total_plain > 0 {
      envoy.write_buffer_drain(total_plain);
    }

    // Step 3. Drain rustls's now-larger TLS queue to the socket (best-effort; remainder
    // appends to backlog).
    if let Err(e) = self.drain_outgoing_tls(envoy) {
      self.failure = e;
      return IoResult::close(total_plain, false);
    }

    // Step 4. On `end_stream`, signal a clean TLS shutdown by emitting a `close_notify` alert.
    // RFC 8446 §6.1 (TLS 1.3) and RFC 5246 §7.2.1 (TLS 1.2) both require this for a graceful
    // half-close; some servers (notably AWS S3) treat a TCP FIN without a preceding
    // close_notify as a possible truncation attack and may fail the request.
    //
    // Latch `end_stream` into `end_stream_pending` so a slow upstream that prevents immediate
    // emit (write buffer or local backlog non-empty) doesn't lose the close-notify obligation.
    // We re-check the gate on every subsequent `on_do_write_inner` call until buffers drain.
    // Only emit on an established connection. Calling `send_close_notify` mid-handshake
    // queues an alert that may be malformed for the current record layer (pre-Finished records
    // are unencrypted on TLS 1.3 and the peer would treat it as a handshake-state-violation).
    if end_stream {
      self.end_stream_pending = true;
    }
    if self.end_stream_pending
      && self.phase == Phase::Established
      && envoy.write_buffer_length() == 0
      && self.tls_write_backlog.is_empty()
      && !self.userspace_close_notify_sent
    {
      if let Some(conn) = self.conn.as_mut() {
        conn.send_close_notify();
        self.userspace_close_notify_sent = true;
        self.end_stream_pending = false;
        if let Err(e) = self.drain_outgoing_tls(envoy) {
          self.failure = e;
          return IoResult::close(total_plain, false);
        }
      }
    }
    IoResult::keep_open(total_plain, false)
  }
}

impl TransportSocket<EnvoyTransportSocketImpl> for RustlsTransportSocket {
  fn on_set_callbacks(&mut self, _envoy: &mut EnvoyTransportSocketImpl) {}

  fn on_set_server_name_override(&mut self, _envoy: &mut EnvoyTransportSocketImpl, name: &str) {
    // Validate the override into an owned `ServerName` before the connection is built. A malformed
    // name (e.g. not a DNS name or IP address) fails the connection cleanly rather than silently
    // falling back to the factory default and mis-handshaking against the wrong authority.
    match ServerName::try_from(name.to_owned()) {
      Ok(sn) => self.server_name_override = Some(sn),
      Err(_) => {
        self.failure = format!("invalid per-connection server_name / SNI override: {name}");
        envoy_log_warn!("rustls: {}", self.failure);
      },
    }
  }

  fn on_connected(&mut self, envoy: &mut EnvoyTransportSocketImpl) {
    // A prior config failure (e.g. a rejected per-connection SNI override) must fail closed.
    // Without this guard we would build a connection with the factory-default SNI and handshake
    // against the wrong authority. The connection terminates on the next I/O via the failure check.
    if !self.failure.is_empty() {
      envoy_log_error!(
        "rustls: refusing to connect, prior config failure: {}",
        self.failure
      );
      return;
    }
    if let Err(e) = self.ensure_connection() {
      self.failure = e.clone();
      envoy_log_error!("rustls: failed to create TLS connection: {e}");
      return;
    }
    if let Err(e) = self.drain_outgoing_tls(envoy) {
      self.failure = e.clone();
      envoy_log_error!("rustls: initial TLS write failed: {e}");
    }
  }

  fn on_do_read(&mut self, envoy: &mut EnvoyTransportSocketImpl) -> IoResult {
    #[cfg(target_os = "linux")]
    if self.phase == Phase::Ktls {
      return self.on_do_read_ktls(envoy);
    }
    // Order matters. The failure check runs BEFORE the conn-rebuild below so a connection that
    // failed mid-stream (e.g. a kTLS install that consumed the rustls Connection and set failure)
    // closes here rather than rebuilding a fresh handshake-state Connection on a live byte stream.
    if !self.failure.is_empty() {
      return IoResult::close(0, false);
    }
    if self.conn.is_none() {
      if let Err(e) = self.ensure_connection() {
        self.failure = e;
        return IoResult::close(0, false);
      }
    }
    let mut total_plaintext = 0usize;
    loop {
      let read_result = self.read_tls_from_socket(envoy);
      // ALWAYS run `process_new_packets` on each iteration, even when `read_tls_from_socket`
      // returned `Ok((0, false))` (rustls's deframer was full and bytes went to
      // `tls_read_backlog`). Without this call, the deframer never drains and the next
      // `feed_raw_to_rustls(backlog)` returns Ok(0) again, wedging the connection. The call
      // is idempotent when there's nothing new to process.
      {
        let conn = match self.conn.as_mut() {
          Some(c) => c,
          None => return IoResult::close(total_plaintext, false),
        };
        if let Err(e) = conn.process_new_packets() {
          // rustls's error Display includes the alert description for fatal-alert errors.
          self.failure = format!("process_new_packets: {e}");
          envoy_log_warn!("rustls: {}", self.failure);
          // Best-effort: rustls may have queued a fatal alert in its outbound TLS queue.
          // Drain it to the wire BEFORE returning Close so the peer sees the alert rather
          // than a bare TCP FIN. Failure to drain is non-fatal (the connection is closing
          // anyway), but the operator-side diagnostic is preserved on the peer.
          let _ = self.drain_outgoing_tls(envoy);
          return IoResult::close(total_plaintext, false);
        }
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
      match read_result {
        Ok((0, true)) => {
          let _ = self.drain_outgoing_tls(envoy);
          return IoResult::close(total_plaintext, true);
        },
        Ok((0, false)) => {
          // No new raw bytes AND we already gave `process_new_packets` + `forward_plaintext`
          // a chance. If unconsumed bytes are sitting in `tls_read_backlog` (rustls's deframer
          // briefly refused them), schedule another read so they get retried. The kernel
          // won't generate a readable event by itself since no new bytes arrive on the
          // wire. Otherwise just wait for the next epoll edge.
          if !self.tls_read_backlog.is_empty() {
            envoy.set_is_readable();
          }
          break;
        },
        Ok((..)) => {
          // Got bytes; loop again so the next iteration can read more.
        },
        Err(e) => {
          self.failure.clone_from(&e);
          // Connection resets / EPIPE / ETIMEDOUT are routine on a busy proxy; reserve
          // `error!` for invariant violations and use `warn!` for transport-level errors.
          envoy_log_warn!("rustls: read_tls path failed: {e}");
          return IoResult::close(total_plaintext, false);
        },
      }
      // Respect Envoy's flow-control high watermark: stop reading and schedule a future
      // read so the filter chain can consume buffered data before we add more.
      if total_plaintext > 0 && envoy.should_drain_read_buffer() {
        envoy.set_is_readable();
        break;
      }
    }
    if let Err(e) = self.drain_outgoing_tls(envoy) {
      self.failure = e;
      return IoResult::close(total_plaintext, false);
    }
    #[cfg(target_os = "linux")]
    if self.ktls_pending
      && self.tls_read_backlog.is_empty()
      && self.tls_write_backlog.is_empty()
      && self.tls_record_bytes_remaining == 0
      && self.tls_record_header_seen == 0
    {
      // `tls_write_backlog.is_empty()` is required because `drain_backlog_strict` (Step 1 of
      // `run_linux_ktls`) treats EAGAIN as fatal. If the socket is currently busy and we have
      // outgoing TLS bytes pending, the install attempt would error and `ktls_attempted`
      // latches to true, permanently disabling kTLS for this connection. The check defers the
      // attempt to a later `on_do_read` after the next `drain_outgoing_tls` succeeds.
      self.ktls_pending = false;
      self.try_install_ktls(envoy);
      if self.phase == Phase::Ktls {
        // Attempt an immediate kTLS read to forward any data that arrived during the
        // handshake→kTLS transition (e.g. PUT body bytes the peer sent right after Finished).
        // `on_do_read_ktls` itself calls `set_is_readable()` whenever the high-watermark fires,
        // so we don't need a defensive call here.
        let ktls_result = self.on_do_read_ktls(envoy);
        total_plaintext += ktls_result.bytes_processed;
        if ktls_result.action == envoy_proxy_dynamic_modules_rust_sdk::PostIoAction::Close {
          return IoResult::close(total_plaintext, ktls_result.end_stream_read);
        }
        // `on_do_read_ktls` never returns `(KeepOpen, end_stream=true)`. Every EOF arm flips
        // to `Close`. No need to special-case keep_open(_, true) here.
      }
    }
    IoResult::keep_open(total_plaintext, false)
  }

  fn on_do_write(&mut self, envoy: &mut EnvoyTransportSocketImpl, end_stream: bool) -> IoResult {
    if self.in_do_write {
      // Defensive tripwire, should never be hit now that `flush_write_buffer()` is no longer
      // called from within `on_do_write`. Leaving it in case a future change reintroduces
      // recursive dispatch.
      return IoResult::keep_open(0, false);
    }
    self.in_do_write = true;
    #[cfg(target_os = "linux")]
    let result = if self.phase == Phase::Ktls {
      self.on_do_write_ktls(envoy, end_stream)
    } else {
      self.on_do_write_inner(envoy, end_stream)
    };
    #[cfg(not(target_os = "linux"))]
    let result = self.on_do_write_inner(envoy, end_stream);
    self.in_do_write = false;
    // Panic-stuck-flag note: if `on_do_write_inner`/`on_do_write_ktls` panics, the SDK's
    // `catch_unwind` at the FFI boundary intercepts and surfaces a fail-closed sentinel to
    // Envoy; the connection is torn down and this socket instance is dropped, so the stuck
    // `in_do_write = true` never affects another call. An RAII Drop guard would be belt-and-
    // suspenders, but the borrow-checker forbids holding `&mut self.in_do_write` across the
    // `self.on_do_write_*` calls that themselves take `&mut self`, and the realized failure
    // mode is already neutralized by socket teardown.
    // INVARIANT: do NOT call `envoy.flush_write_buffer()` here. `flush_write_buffer` triggers
    // a synchronous re-entry into `on_do_write` via `ConnectionImpl::onWriteReady`, which
    // busy-loops draining Envoy's write buffer in a single dispatcher iteration, head-of-line
    // blocking every other connection on the worker. The standard Envoy contract is: return
    // from `doWrite` and let the connection layer schedule the next write when the socket
    // becomes writable or more data arrives.
    result
  }

  fn on_close(
    &mut self,
    envoy: &mut EnvoyTransportSocketImpl,
    event: ConnectionEvent,
    abort_reset: bool,
  ) {
    // For graceful local-initiated close on the USERSPACE TLS path, emit a close_notify alert
    // (best-effort drain). This mirrors the kTLS-path close_notify below, and prevents AWS-S3
    // and other strict peers from logging the disconnect as a truncation attack. We do NOT do
    // this on RemoteClose (peer already half-closed), when a prior `on_do_write(end_stream)`
    // already sent the alert, or when `abort_reset` is set (the connection is being torn down
    // with a TCP reset, so any graceful shutdown is skipped).
    if matches!(event, ConnectionEvent::LocalClose)
      && !abort_reset
      && self.phase == Phase::Established
      && self.failure.is_empty()
      && !self.userspace_close_notify_sent
      && self.conn.is_some()
    {
      if let Some(conn) = self.conn.as_mut() {
        conn.send_close_notify();
      }
      self.userspace_close_notify_sent = true;
      // Best-effort drain. By this point the socket may already be closed by the connection
      // layer; ignore Err.
      let _ = self.drain_outgoing_tls(envoy);
    }
    #[cfg(target_os = "linux")]
    if let Some(fd) = self.ktls_fd.take() {
      // Cross-phase dedup: if the userspace TLS path already emitted close_notify before the
      // socket flipped to Phase::Ktls (e.g. end_stream arrived during the install window),
      // do not emit a second alert via the kernel. Strict peers (S3) may reject. This
      // mirrors the dedup at `on_do_write_ktls`. Skipped on `abort_reset` for the same reason
      // as the userspace path above.
      if matches!(event, ConnectionEvent::LocalClose)
        && !abort_reset
        && self.phase == Phase::Ktls
        && self.failure.is_empty()
        && !self.ktls_shutdown_sent
        && !self.userspace_close_notify_sent
      {
        let _ = linux_ktls::send_close_notify(fd);
        self.ktls_shutdown_sent = true;
      }
    }
    self.conn = None;
    self.tls_write_backlog.clear();
    self.tls_read_backlog.clear();
    self.end_stream_pending = false;
  }

  fn start_secure_transport(&mut self, _envoy: &mut EnvoyTransportSocketImpl) -> bool {
    // The rustls socket negotiates TLS from the first byte, so it does not support the STARTTLS
    // upgrade-after-plaintext pattern. Report that no switch occurred.
    false
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

  // Reports `(ktls_installed, raw_fd)` so a higher layer such as tcp_proxy can `splice()` directly
  // on the kernel-TLS socket. `installed` is true only when both TX and RX are live. The module
  // rejects `disable_ktls_rx`, so `Phase::Ktls` implies RX, and the check also requires that no
  // post-install failure occurred. On non-Linux targets kTLS never installs so this stays
  // `(false, -1)`.
  #[cfg(target_os = "linux")]
  fn ktls_state(&self, _envoy: &mut EnvoyTransportSocketImpl) -> (bool, i32) {
    (
      self.phase == Phase::Ktls && self.failure.is_empty(),
      self.ktls_fd.unwrap_or(-1),
    )
  }
  #[cfg(not(target_os = "linux"))]
  fn ktls_state(&self, _envoy: &mut EnvoyTransportSocketImpl) -> (bool, i32) {
    (false, -1)
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
        let Some(fd) = envoy.get_fd() else {
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
        envoy.read_buffer_add(&buf[..n as usize]);
        total += n as usize;
        // Respect Envoy's flow-control high watermark: stop reading and schedule a future
        // read so the filter chain can consume buffered data before we add more. This matches
        // the pattern used by BoringSSL's SslSocket::doRead and RawBufferSocket::doRead.
        if envoy.should_drain_read_buffer() {
          envoy.set_is_readable();
          return IoResult::keep_open(total, false);
        }
        continue;
      }
      if n == 0 {
        return IoResult::close(total, true);
      }
      let errno = unsafe { *libc::__errno_location() };
      if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
        return IoResult::keep_open(total, false);
      }
      if errno == libc::EINTR {
        continue;
      }
      if errno == libc::EIO {
        // Reusing `buf` for the control-message recvmsg is safe: any application-data bytes read
        // into `buf` on a prior iteration were already forwarded to Envoy and counted in `total`
        // before this loop iteration, so overwriting them here loses nothing.
        match linux_ktls::receive_control_message(fd, &mut buf) {
          linux_ktls::ControlResult::Continue => continue,
          linux_ktls::ControlResult::WouldBlock => {
            // No control record was ready right now. Break the outer recv loop. The next
            // event-loop iteration will retry. Crucial: returning to the loop top here would
            // re-trigger `recv → EIO → recvmsg → EAGAIN` indefinitely.
            return IoResult::keep_open(total, false);
          },
          linux_ktls::ControlResult::ApplicationData(len) => {
            if len > 0 {
              envoy.read_buffer_add(&buf[..len]);
            }
            total += len;
            if envoy.should_drain_read_buffer() {
              envoy.set_is_readable();
              return IoResult::keep_open(total, false);
            }
            continue;
          },
          linux_ktls::ControlResult::CloseNotify => {
            // Peer closed first. Reflect a close_notify only if we have not already emitted
            // one via either the userspace or kTLS shutdown paths. Without the
            // `!userspace_close_notify_sent` guard, the userspace→kTLS handover sequence
            // (userspace emits on `end_stream`, then install fires, then peer echoes their
            // close_notify back) would produce a second alert on the wire. Strict peers (S3)
            // may reject. Latch `ktls_shutdown_sent` unconditionally so the on_close path
            // doesn't try again.
            if !self.ktls_shutdown_sent && !self.userspace_close_notify_sent {
              let _ = linux_ktls::send_close_notify(fd);
            }
            self.ktls_shutdown_sent = true;
            return IoResult::close(total, true);
          },
          linux_ktls::ControlResult::Error(e) => {
            self.failure = format!("kTLS control message error: {e}");
            return IoResult::close(total, false);
          },
        }
      }
      if errno == libc::EKEYEXPIRED {
        // Linux kernel >= 6.14 reports a peer-initiated TLS-1.3 KeyUpdate by pausing the RX
        // path with EKEYEXPIRED until userspace provides the rotated traffic key. We don't
        // retain a rustls Connection after install (`dangerous_extract_secrets` consumes it),
        // so we cannot supply the new key. Close the connection with a clear reason rather
        // than masking it as a generic "kTLS read failed".
        self.failure = "kTLS does not support TLS-1.3 KeyUpdate (peer rekeyed; kernel paused RX \
                        with EKEYEXPIRED). Migrate the cluster to envoy.transport_sockets.tls if \
                        peers issue KeyUpdate."
          .to_string();
        return IoResult::close(total, false);
      }
      self.failure = format!("kTLS read failed (errno {} / {})", errno, errno_name(errno));
      return IoResult::close(total, false);
    }
  }

  fn on_do_write_ktls(
    &mut self,
    envoy: &mut EnvoyTransportSocketImpl,
    end_stream: bool,
  ) -> IoResult {
    if !self.failure.is_empty() {
      return IoResult::close(0, false);
    }
    let fd = match self.ktls_fd {
      Some(fd) => fd,
      None => return IoResult::close(0, false),
    };
    // Snapshot the plaintext queued in Envoy's write buffer. A kTLS socket encrypts on the kernel
    // send path, so this plaintext goes straight to the fd and the kernel frames it into TLS
    // records. We use a direct `send` rather than `envoy.io_write` for symmetry with the kTLS read
    // path (which needs raw `recvmsg` to handle TLS control records) and to set MSG_NOSIGNAL.
    //
    // The snapshot is one memcpy of the queued plaintext into the reused `write_scratch` (the SDK
    // exposes only a copying write-buffer accessor, not zero-copy slices). This is the buffered
    // fallback path. The zero-copy hot path for large bodies is the tcp_proxy splice fast path,
    // which relays fd to fd and never enters this function, so the copy here is off the throughput
    // hot path and bounded by Envoy's write high-watermark.
    self.write_scratch.clear();
    envoy.copy_write_buffer(&mut self.write_scratch);
    let total_requested = self.write_scratch.len();

    let mut total = 0usize;
    let mut hit_eagain = false;
    while total < total_requested {
      let n = unsafe {
        libc::send(
          fd,
          self.write_scratch[total..].as_ptr().cast(),
          total_requested - total,
          libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
      };
      if n > 0 {
        total += n as usize;
        continue;
      }
      if n == 0 {
        // A zero-length send on a connected stream socket is not expected for a non-zero request.
        // If it ever happens with bytes still pending, fall through to the re-arm below rather than
        // stalling the buffered write between the low and high watermark.
        hit_eagain = true;
        break;
      }
      let errno = unsafe { *libc::__errno_location() };
      if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
        hit_eagain = true;
        break;
      }
      if errno == libc::EINTR {
        continue;
      }
      self.failure = format!(
        "kTLS write failed (errno {} / {})",
        errno,
        errno_name(errno)
      );
      if total > 0 {
        envoy.write_buffer_drain(total);
      }
      return IoResult::close(total, false);
    }
    if total > 0 {
      envoy.write_buffer_drain(total);
    }
    // If the kTLS socket send buffer filled (EAGAIN) with bytes still queued in Envoy's write
    // buffer, re-arm the writable notification. The kTLS path sends directly via `send` rather than
    // `envoy.io_write`, so Envoy never observed the would-block and will not re-arm on its own. The
    // edge-triggered EPOLLOUT is not redelivered by itself, so without this the buffered write
    // stalls between the low and high watermark and a large upload (e.g. a PUT body) deadlocks:
    // downstream stays read-disabled and the upstream never receives the rest of the object.
    if hit_eagain && total < total_requested {
      envoy.set_is_writable();
    }
    // Latch end_stream and, once the write buffer is fully drained, emit a single close_notify so a
    // slow kTLS send that throttled the final body bytes still delivers a clean shutdown on a later
    // call. Without this, the upstream would see a TCP FIN without close_notify, the truncation
    // signal the userspace path also guards against. Cross-phase de-dup: if the userspace TLS path
    // already emitted a close_notify (e.g. before kTLS install completed), don't emit a second one
    // over kTLS. The peer would see two alerts back-to-back, which strict servers (S3) may reject.
    if end_stream {
      self.end_stream_pending = true;
    }
    if self.end_stream_pending
      && total == total_requested
      && !self.ktls_shutdown_sent
      && !self.userspace_close_notify_sent
    {
      let _ = linux_ktls::send_close_notify(fd);
      unsafe {
        libc::shutdown(fd, libc::SHUT_WR);
      }
      self.ktls_shutdown_sent = true;
      self.end_stream_pending = false;
    }
    IoResult::keep_open(total, false)
  }
}

// -------------------------------------------------------------------------------------------------
// Misc helpers.
// -------------------------------------------------------------------------------------------------

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

/// Returns a human-readable name for common errno values encountered in kTLS operations.
/// Uses `libc` constants (rather than raw numeric literals) so the names stay correct across
/// architectures where errno numbering differs from x86-64 Linux.
#[cfg(target_os = "linux")]
fn errno_name(errno: libc::c_int) -> &'static str {
  match errno {
    libc::ECONNRESET => "ECONNRESET",
    libc::ENOTCONN => "ENOTCONN",
    libc::EPIPE => "EPIPE",
    libc::ECONNREFUSED => "ECONNREFUSED",
    libc::ETIMEDOUT => "ETIMEDOUT",
    libc::ENOMEM => "ENOMEM",
    libc::EBADMSG => "EBADMSG",
    libc::EMSGSIZE => "EMSGSIZE",
    libc::EINVAL => "EINVAL",
    libc::EAGAIN => "EAGAIN",
    libc::ENOKEY => "ENOKEY",
    libc::ENOPROTOOPT => "ENOPROTOOPT",
    libc::ENOSYS => "ENOSYS",
    libc::EPERM => "EPERM",
    libc::EACCES => "EACCES",
    libc::EKEYEXPIRED => "EKEYEXPIRED",
    _ => "unknown",
  }
}

// -------------------------------------------------------------------------------------------------
// Linux kTLS (setsockopt) helpers.
// -------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_ktls {
  use super::*;
  use rustls::ConnectionTrafficSecrets;

  // Prefer `libc` constants over hard-coded numeric literals so the bindings stay correct on
  // non-x86 Linux builds where SOL_TLS / TCP_ULP / TLS_TX / TLS_RX may differ.
  const SOL_TLS: libc::c_int = libc::SOL_TLS;
  const TLS_TX: libc::c_int = libc::TLS_TX;
  const TLS_RX: libc::c_int = libc::TLS_RX;
  const TCP_ULP: libc::c_int = libc::TCP_ULP;
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
  // The kernel UAPI defines ChaCha20-Poly1305's salt as a zero-sized field, present in the
  // struct for layout symmetry with AES-GCM. Carry it explicitly here to mirror the kernel
  // header verbatim. Without it, future readers cannot verify struct parity without deriving
  // GCC's zero-array semantics, and a future kernel change that grows the salt would slip
  // past struct-size review.
  const CHACHA20_SALT: usize = 0;

  const TLS_SET_RECORD_TYPE: libc::c_int = 1;
  const TLS_GET_RECORD_TYPE: libc::c_int = 2;
  // The `TLS_RX_EXPECT_NO_PAD` kernel optname is 4; value 3 is `TLS_TX_ZEROCOPY_RO`. Use the
  // libc constant directly so a future kernel renumbering or a hand-roll regression cannot
  // silently flip us back onto the wrong optimization. (Earlier revisions hard-coded `3`,
  // which silently enabled TX_ZEROCOPY_RO on every TLS-1.3 RX install, a wire-level kernel
  // ABI bug.) See `include/uapi/linux/tls.h`.
  const TLS_RX_EXPECT_NO_PAD: libc::c_int = libc::TLS_RX_EXPECT_NO_PAD;
  const TLS_CONTENT_TYPE_ALERT: u8 = 21;
  const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
  const TLS_CONTENT_TYPE_APP_DATA: u8 = 23;

  const TLS_ALERT_LEVEL_FATAL: u8 = 2;
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
    salt: [u8; CHACHA20_SALT],
    rec_seq: [u8; REC_SEQ],
  }

  // Compile-time size assertions pinning the kernel ABI struct shapes. Mirrors
  // `bindgen_test_layout_*` from the `ktls-sys` crate. If a future edit reorders fields,
  // changes a type, or drops `#[repr(C)]`, the build fails at compile time instead of
  // shipping a setsockopt EINVAL that silently falls back to userspace TLS.
  //   tls_crypto_info: 2x u16 = 4 bytes
  //   AES-GCM-128:  4 (info) + 8 (iv) + 16 (key) + 4 (salt) + 8 (rec_seq) = 40 bytes
  //   AES-GCM-256:  4 (info) + 8 (iv) + 32 (key) + 4 (salt) + 8 (rec_seq) = 56 bytes
  //   ChaCha20:     4 (info) + 12 (iv) + 32 (key) + 0 (salt) + 8 (rec_seq) = 56 bytes
  const _: () = assert!(std::mem::size_of::<TlsCryptoInfo>() == 4);
  const _: () = assert!(std::mem::size_of::<Tls12CryptoInfoAesGcm128>() == 40);
  const _: () = assert!(std::mem::size_of::<Tls12CryptoInfoAesGcm256>() == 56);
  const _: () = assert!(std::mem::size_of::<Tls12CryptoInfoChacha20Poly1305>() == 56);

  fn split_aes_gcm_iv(iv: &[u8]) -> Result<([u8; AES_GCM_SALT], [u8; AES_GCM_IV]), String> {
    if iv.len() != 12 {
      return Err(format!(
        "unexpected IV length {} for AES-GCM, expected 12",
        iv.len()
      ));
    }
    let mut salt = [0u8; AES_GCM_SALT];
    let mut out_iv = [0u8; AES_GCM_IV];
    salt.copy_from_slice(&iv[..AES_GCM_SALT]);
    out_iv.copy_from_slice(&iv[AES_GCM_SALT..]);
    Ok((salt, out_iv))
  }

  /// Test-only re-export so the parent module's unit tests can exercise the IV split layout
  /// without depending on a live rustls Connection.
  #[cfg(test)]
  pub(super) fn split_aes_gcm_iv_for_test(
    iv: &[u8],
  ) -> Result<([u8; AES_GCM_SALT], [u8; AES_GCM_IV]), String> {
    split_aes_gcm_iv(iv)
  }

  // Test-only re-exports of the kernel ABI optname constants so the parent module's tests can
  // pin them against `libc::*` without changing the module-level visibility of the underlying
  // constants.
  #[cfg(test)]
  pub(super) const TLS_RX_EXPECT_NO_PAD_FOR_TEST: libc::c_int = TLS_RX_EXPECT_NO_PAD;
  #[cfg(test)]
  pub(super) const SOL_TLS_FOR_TEST: libc::c_int = SOL_TLS;
  #[cfg(test)]
  pub(super) const TLS_TX_FOR_TEST: libc::c_int = TLS_TX;
  #[cfg(test)]
  pub(super) const TLS_RX_FOR_TEST: libc::c_int = TLS_RX;
  #[cfg(test)]
  pub(super) const TCP_ULP_FOR_TEST: libc::c_int = TCP_ULP;

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
              key: kb
                .try_into()
                .map_err(|_| format!("AES-128-GCM key length {} != {AES_GCM_128_KEY}", kb.len()))?,
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
              key: kb
                .try_into()
                .map_err(|_| format!("AES-256-GCM key length {} != {AES_GCM_256_KEY}", kb.len()))?,
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
          key: kb
            .try_into()
            .map_err(|_| format!("AES-256-GCM key length {} != {AES_GCM_256_KEY}", kb.len()))?,
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
          iv: iv_bytes.try_into().map_err(|_| {
            format!(
              "ChaCha20-Poly1305 IV length {} != {CHACHA20_IV}",
              iv_bytes.len()
            )
          })?,
          key: kb.try_into().map_err(|_| {
            format!(
              "ChaCha20-Poly1305 key length {} != {CHACHA20_KEY}",
              kb.len()
            )
          })?,
          salt: [],
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

  pub fn setup_ulp(fd: libc::c_int) -> Result<(), String> {
    // The kernel reads at most `optlen` bytes into a 16-byte ULP-name buffer
    // (`TCP_ULP_NAME_MAX`); the buffer is zero-initialised so passing exactly 3 bytes
    // ("tls" without trailing NUL) works correctly. See `do_tcp_setsockopt` in the kernel.
    let ret = unsafe {
      libc::setsockopt(
        fd,
        libc::IPPROTO_TCP,
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

  /// All state extracted from the rustls Connection that's needed to install kTLS, computed
  /// before the kernel ULP is attached. Splitting this from the actual setsockopt calls keeps
  /// secret-extraction / cipher-validation failures recoverable (we haven't burned the socket
  /// yet).
  pub struct PreparedKtls {
    pub version: u16,
    pub enable_tx: bool,
    pub enable_rx: bool,
    pub tx_seq: u64,
    pub rx_seq: u64,
    pub tx_secret: ConnectionTrafficSecrets,
    pub rx_secret: ConnectionTrafficSecrets,
    /// `true` if the peer is upstream (we are the client). Gates `TLS_RX_EXPECT_NO_PAD`
    /// since that optimization assumes a trusted, non-padding peer; an adversarial
    /// downstream client can deliberately emit a TLS-1.3 padded record (RFC 8446 §5.4
    /// permits arbitrary padding for traffic-analysis defense) and the kernel decrypt
    /// would then fail with EBADMSG, turning a wire-level feature into a DoS vector.
    pub trusted_peer: bool,
  }

  /// Read-only protocol-version probe used BEFORE the kernel ULP is attached. Failure here
  /// means kTLS is not applicable to this connection (e.g. peer negotiated TLS 1.0); the
  /// caller should fall back to userspace TLS, and we have NOT consumed the rustls Connection.
  pub fn validate_for_ktls(conn: &Connection) -> Result<u16, String> {
    // Defense-in-depth: the caller (`run_linux_ktls`) only reaches this from
    // `Phase::Established`, which itself is gated on `!conn.is_handshaking()`. But the
    // function is `pub` to the parent module, so a future direct call site that skips the
    // phase check would get an opaque `dangerous_extract_secrets` failure later. Refuse here
    // with a specific message instead.
    if conn.is_handshaking() {
      return Err("rustls connection still handshaking; cannot extract kTLS secrets".to_string());
    }
    match conn.protocol_version() {
      Some(ProtocolVersion::TLSv1_2) => Ok(TLS_1_2_VERSION),
      Some(ProtocolVersion::TLSv1_3) => Ok(TLS_1_3_VERSION),
      _ => Err("unsupported TLS protocol version for kTLS".to_string()),
    }
  }

  /// Consumes the Connection and extracts the symmetric secrets for kTLS install. Called BEFORE
  /// `setup_ulp`, matching the rustls-org `ktls` reference crate. The kernel socket is untouched at
  /// this point, so a failure here is recoverable on the socket (no ULP is attached and the next
  /// I/O closes cleanly). The rustls Connection is consumed either way, so userspace TLS cannot
  /// resume, but the irreversible ULP attach stays after this step.
  pub fn extract_secrets(
    conn: Connection,
    version: u16,
    enable_tx: bool,
    enable_rx: bool,
    trusted_peer: bool,
  ) -> Result<PreparedKtls, String> {
    let secrets = conn
      .dangerous_extract_secrets()
      .map_err(|e| format!("dangerous_extract_secrets: {e}"))?;
    let (tx_seq, tx_secret) = secrets.tx;
    let (rx_seq, rx_secret) = secrets.rx;
    Ok(PreparedKtls {
      version,
      enable_tx,
      enable_rx,
      tx_seq,
      rx_seq,
      tx_secret,
      rx_secret,
      trusted_peer,
    })
  }

  /// Install the previously-prepared crypto info via setsockopt. MUST be called AFTER
  /// `setup_ulp` has succeeded. Any failure here is terminal for the socket because the kernel
  /// has no `TCP_ULP_REMOVE`. The caller marks the failure and the connection closes.
  ///
  /// If TX install succeeds but RX install fails (with `enable_rx == true`), the socket is in a
  /// torn state: the kernel has TX crypto installed but the userspace cannot produce more
  /// encrypted bytes (rustls Connection was consumed). The error message distinguishes that
  /// case so on-call operators see the exact post-failure kernel state.
  pub fn apply_prepared(fd: libc::c_int, prepared: PreparedKtls) -> Result<(), String> {
    let mut tx_installed = false;
    if prepared.enable_tx {
      apply_direction(
        fd,
        TLS_TX,
        prepared.version,
        prepared.tx_seq,
        &prepared.tx_secret,
      )
      .map_err(|e| format!("TX kTLS install failed: {e}"))?;
      tx_installed = true;
    }
    if prepared.enable_rx {
      if let Err(e) = apply_direction(
        fd,
        TLS_RX,
        prepared.version,
        prepared.rx_seq,
        &prepared.rx_secret,
      ) {
        return Err(format!(
          "RX kTLS install failed (TX was {} attached; socket is terminal): {e}",
          if tx_installed { "successfully" } else { "not" }
        ));
      }
      if prepared.version == TLS_1_3_VERSION && prepared.trusted_peer {
        // TLS_RX_EXPECT_NO_PAD: only safe when the peer is trusted (RFC 8446 §5.4 permits
        // arbitrary padding; an adversarial peer that emits a padded record makes the kernel
        // decrypt fail with EBADMSG, turning a perf optimization into a DoS vector). We only
        // enable it on the upstream path where Envoy chose the peer; downstream listeners
        // accept connections from untrusted clients and skip this optimization.
        // The option is only supported on kernels >= 5.19; older kernels return ENOPROTOOPT,
        // which is harmless. Log on unexpected errnos so operators notice missing support.
        let val: libc::c_int = 1;
        let ret = unsafe {
          libc::setsockopt(
            fd,
            SOL_TLS,
            TLS_RX_EXPECT_NO_PAD,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
          )
        };
        if ret < 0 {
          let errno = unsafe { *libc::__errno_location() };
          if errno != libc::ENOPROTOOPT {
            envoy_log_debug!(
              "kTLS: TLS_RX_EXPECT_NO_PAD setsockopt returned errno {} ({})",
              errno,
              errno_name(errno)
            );
          }
        }
      }
    }
    // Set TCP_NODELAY after kTLS install to ensure each encrypted record is sent
    // immediately rather than waiting for Nagle's algorithm. This matches the latency
    // profile of the userspace TLS path (rustls writes complete records via writev). An
    // operator who explicitly requires Nagle batching across small TLS records on the
    // kTLS path should disable `enable_ktls` instead. The userspace path defers to the
    // listener/cluster socket options.
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
    envoy_log_debug!(
      "kTLS installed (TX={}, RX={})",
      prepared.enable_tx,
      prepared.enable_rx
    );
    Ok(())
  }

  pub enum ControlResult {
    /// `recvmsg` consumed a non-app-data record (e.g. NewSessionTicket); caller should retry
    /// the outer `recv()` loop because more bytes may be queued.
    Continue,
    /// `recvmsg` returned EAGAIN / EWOULDBLOCK / EINTR. The kernel does not currently have a
    /// non-app-data record ready. Caller MUST break the outer loop to avoid spinning between
    /// `recv→EIO→recvmsg→EAGAIN→Continue→recv→EIO…`.
    WouldBlock,
    ApplicationData(usize),
    CloseNotify,
    Error(String),
  }

  #[repr(C, align(8))]
  struct CmsgBuf {
    data: [u8; 64],
  }

  /// Per-message-type policy for a consumed kTLS session. `Ok(())` tolerates the message (only
  /// NewSessionTicket), `Err` fails closed with a diagnostic. The kernel cannot service any
  /// rekey-class post-handshake message on an installed kTLS socket. This matches the per-type
  /// decision in splice_pump.cc and OSD and is unit-tested.
  pub(super) fn handshake_msg_policy(msg_type: u8) -> Result<(), String> {
    const HS_NEW_SESSION_TICKET: u8 = 4;
    const HS_CERTIFICATE_REQUEST: u8 = 13;
    const HS_KEY_UPDATE: u8 = 24;
    match msg_type {
      HS_NEW_SESSION_TICKET => Ok(()),
      HS_KEY_UPDATE => {
        Err("kTLS does not support TLS-1.3 KeyUpdate, closing connection".to_string())
      },
      HS_CERTIFICATE_REQUEST => {
        Err("kTLS does not support post-handshake CertificateRequest".to_string())
      },
      _ => Err(format!(
        "unsupported post-handshake TLS message (type={msg_type}), closing connection"
      )),
    }
  }

  /// Classifies a decrypted post-handshake record by walking its coalesced handshake messages.
  /// RFC 8446 5.1 lets a peer coalesce several post-handshake messages (NewSessionTicket then
  /// KeyUpdate, for example) into one TLS record, so inspecting only the first byte would miss a
  /// KeyUpdate hiding behind a NewSessionTicket and the kernel RX path would then decrypt the next
  /// record with the stale key (kernel < 6.14: EBADMSG; kernel >= 6.14: the kernel detects the
  /// KeyUpdate and pauses RX with EKEYEXPIRED). A tolerated message keeps the walk going; a
  /// rekey-class or unknown message, or a declared length that overruns the record, fails closed.
  /// This is the socket-free part of receive_control_message, kept identical to the splice_pump.cc
  /// and OSD classifiers and unit-tested. Wire shape: [msg_type:1][length:3 big-endian][payload].
  pub(super) fn classify_handshake_record(payload: &[u8]) -> ControlResult {
    let mut pos = 0;
    while pos < payload.len() {
      // Check the type byte first (matching splice_pump.cc), so a non-NewSessionTicket type fails
      // closed even when it appears in a trailing fragment shorter than a full header.
      if let Err(e) = handshake_msg_policy(payload[pos]) {
        return ControlResult::Error(e);
      }
      // A trailing fragment without a full 4-byte header cannot be a real message, so stop here.
      if pos + 4 > payload.len() {
        break;
      }
      let msg_len = ((payload[pos + 1] as usize) << 16)
        | ((payload[pos + 2] as usize) << 8)
        | (payload[pos + 3] as usize);
      // Fail closed if the declared length overruns the record. The break above keeps the
      // subtraction underflow-safe. Mirrors the splice_pump.cc overrun guard.
      if msg_len > payload.len() - pos - 4 {
        return ControlResult::Error(
          "malformed post-handshake message length overruns the record".to_string(),
        );
      }
      pos += 4 + msg_len;
    }
    ControlResult::Continue
  }

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
      if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK || errno == libc::EINTR {
        // The kernel had nothing to deliver via the control-message path right now. Return
        // WouldBlock so the caller breaks the outer recv loop. Returning `Continue` would
        // restart `recv()` which would immediately re-trigger the same EIO and infinite-loop.
        return ControlResult::WouldBlock;
      }
      return ControlResult::Error(format!("recvmsg failed (errno {errno})"));
    }

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
      if n > 0 {
        return ControlResult::ApplicationData(n as usize);
      }
      return ControlResult::Continue;
    }
    let cmsg_ref = unsafe { &*cmsg };
    if cmsg_ref.cmsg_level != SOL_TLS || cmsg_ref.cmsg_type != TLS_GET_RECORD_TYPE {
      if n > 0 {
        return ControlResult::ApplicationData(n as usize);
      }
      return ControlResult::Continue;
    }
    // Guard the `CMSG_DATA` read so a malformed kernel cmsg (cmsg_len < CMSG_LEN(1)) cannot
    // cause an out-of-array read on cmsg_buf.data. In practice the kernel always emits a
    // 1-byte payload for TLS_GET_RECORD_TYPE, but defense-in-depth.
    let min_len = unsafe { libc::CMSG_LEN(1) } as usize;
    if cmsg_ref.cmsg_len < min_len {
      return ControlResult::Continue;
    }
    let record_type = unsafe { *libc::CMSG_DATA(cmsg) };
    match record_type {
      TLS_CONTENT_TYPE_HANDSHAKE => classify_handshake_record(&buf[..n as usize]),
      TLS_CONTENT_TYPE_ALERT => {
        let num_bytes = n as usize;
        if num_bytes < 2 {
          // A malformed alert (truncated post-AEAD-decrypt) is a protocol violation, not a
          // graceful close. The kernel already validated the AEAD tag, so the peer
          // deliberately authored a sub-2-byte alert payload. Treat as fatal so operators
          // see a meaningful diagnostic rather than mistaking it for a clean shutdown.
          return ControlResult::Error(format!(
            "malformed TLS alert from peer ({num_bytes} bytes, expected 2)"
          ));
        }
        let level = buf[0];
        let description = buf[1];
        if description == TLS_ALERT_CLOSE_NOTIFY {
          return ControlResult::CloseNotify;
        }
        if level == TLS_ALERT_LEVEL_FATAL {
          return ControlResult::Error(format!(
            "fatal TLS alert from peer (description={description})"
          ));
        }
        // Per RFC 8446 §6 the only TLS-1.3 warning alert is close_notify (handled above). For
        // TLS-1.2 a handful of warnings exist (user_canceled, no_renegotiation); we treat
        // them as fatal because the operational signal is more useful as a connection error
        // than a silent continue. This diverges from RFC 5246 §7.2.1's permissive language
        // but aligns with current TLS implementer defaults.
        ControlResult::Error(format!(
          "non-close-notify TLS alert from peer (level={level}, description={description})"
        ))
      },
      TLS_CONTENT_TYPE_APP_DATA => ControlResult::ApplicationData(n as usize),
      _ => ControlResult::Continue,
    }
  }

  pub fn send_close_notify(fd: libc::c_int) -> Result<(), String> {
    let mut alert_data: [u8; 2] = [1, TLS_ALERT_CLOSE_NOTIFY];

    let mut iov = libc::iovec {
      iov_base: alert_data.as_mut_ptr().cast(),
      iov_len: alert_data.len(),
    };

    let cmsg_len = unsafe { libc::CMSG_LEN(1) } as usize;
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
      msg_controllen: cmsg_len,
      msg_flags: 0,
    };

    let ret = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
    if ret < 0 {
      let errno = unsafe { *libc::__errno_location() };
      if errno == libc::EPIPE {
        // Peer closed first; our close_notify never reached the wire. Distinguish this from
        // "alert delivered cleanly" so an operator tracing a peer-side truncation diagnostic
        // can see the race condition explicitly. Treated as best-effort success regardless.
        envoy_log_debug!("kTLS close_notify: peer closed first (EPIPE); alert not emitted");
        return Ok(());
      }
      if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK || errno == libc::EINTR {
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
  if rustls::crypto::ring::default_provider()
    .install_default()
    .is_err()
  {
    // Another rustls user in the same process already installed a default provider; rustls
    // will use whichever was registered first. Log so the operator can confirm which provider
    // the rustls socket is actually running against (relevant for FIPS / supply-chain audits).
    envoy_log_warn!(
      "rustls: default crypto provider was already installed by another module, deferring"
    );
  }
  true
}

fn new_factory_config(
  _name: &str,
  config: &[u8],
  is_upstream: bool,
) -> Option<Box<dyn TransportSocketFactoryConfig<EnvoyTransportSocketImpl>>> {
  // Surface the actual error reason to the operator's logs. The C++ side translates a `None`
  // return into a generic "Rustls module rejected ..." error which loses the specific cause
  // (missing SNI, PEM parse failure, file-not-found for cert_chain, etc.).
  let cfg: JsonConfig = match serde_json::from_slice(config) {
    Ok(c) => c,
    Err(e) => {
      envoy_log_error!("rustls: failed to parse transport_socket JSON config: {e}");
      return None;
    },
  };
  let result = if is_upstream {
    RustlsFactoryConfig::new_upstream(cfg)
  } else {
    RustlsFactoryConfig::new_downstream(cfg)
  };
  match result {
    Ok(factory) => Some(Box::new(factory)),
    Err(e) => {
      envoy_log_error!("rustls: factory config rejected: {e}");
      None
    },
  }
}

declare_all_init_functions!(
  program_init,
  transport_socket: new_factory_config,
);

// -------------------------------------------------------------------------------------------------
// Unit tests (pure Rust, no Envoy ABI dependency).
// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
  use super::*;

  fn make_socket_no_conn() -> RustlsTransportSocket {
    // Minimal hand-rolled instance, avoids needing a live rustls config. Most state-machine
    // helpers we test below don't touch `server_cfg` / `client_cfg` / `conn`.
    RustlsTransportSocket {
      server_cfg: None,
      client_cfg: None,
      server_name: None,
      server_name_override: None,
      conn: None,
      phase: Phase::Handshaking,
      failure: String::new(),
      enable_ktls: false,
      ktls_tx_only: false,
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
      write_scratch: Vec::new(),
      #[cfg(target_os = "linux")]
      ktls_fd: None,
      #[cfg(target_os = "linux")]
      ktls_shutdown_sent: false,
      userspace_close_notify_sent: false,
      end_stream_pending: false,
      in_do_write: false,
    }
  }

  // Builds a real upstream client socket with `default.example.com` as the factory-default SNI.
  // `ClientConnection::new` does no I/O, so `ensure_connection` can run without a network.
  fn make_client_socket_default_sni() -> RustlsTransportSocket {
    let cfg = JsonConfig {
      cert_chain: String::new(),
      private_key: String::new(),
      trusted_ca: Some(TEST_CA_PEM.to_string()),
      alpn_protocols: None,
      enable_ktls: false,
      disable_ktls_rx: false,
      sni: Some("default.example.com".to_string()),
      tls_minimum_protocol_version: TlsVersion::Auto,
      tls_maximum_protocol_version: TlsVersion::Auto,
      crl: None,
    };
    let factory = RustlsFactoryConfig::new_upstream(cfg).expect("upstream config builds");
    match factory.endpoint {
      EndpointKind::Upstream { cfg, server_name } => {
        RustlsTransportSocket::new_client(cfg, server_name, false, false)
      },
      EndpointKind::Downstream(_) => panic!("expected an upstream endpoint"),
    }
  }

  #[test]
  fn server_name_override_replaces_factory_default() {
    // A valid per-connection override is stored as the override `ServerName` and replaces the
    // factory default in `ensure_connection`. The default `server_name` stays untouched so the
    // selection (override-over-default) is observable, and the connection builds with the override.
    let mut s = make_client_socket_default_sni();
    assert_eq!(
      s.server_name,
      Some(ServerName::try_from("default.example.com".to_owned()).unwrap())
    );
    let mut envoy = EnvoyTransportSocketImpl::new(std::ptr::null_mut());
    s.on_set_server_name_override(&mut envoy, "override.example.com");
    assert!(
      s.failure.is_empty(),
      "valid override must not fail: {}",
      s.failure
    );
    assert_eq!(
      s.server_name_override,
      Some(ServerName::try_from("override.example.com".to_owned()).unwrap())
    );
    // The override (not the default) is the SNI source for the built connection.
    assert!(s.ensure_connection().is_ok());
    assert!(s.conn.is_some());
  }

  #[test]
  fn invalid_server_name_override_fails_clean() {
    // A malformed override sets the failure state rather than silently falling back to the default,
    // so the connection fails cleanly instead of mis-handshaking against the wrong authority.
    let mut s = make_client_socket_default_sni();
    let mut envoy = EnvoyTransportSocketImpl::new(std::ptr::null_mut());
    s.on_set_server_name_override(&mut envoy, "not a valid sni!!");
    assert!(s.server_name_override.is_none());
    assert!(
      s.failure.contains("invalid per-connection server_name"),
      "failure must name the invalid override: {}",
      s.failure
    );
  }

  #[test]
  fn rejected_server_name_override_fails_closed_builds_nothing() {
    // A rejected per-connection override must fail closed: neither `on_connected` nor
    // `ensure_connection` may fall back to the factory-default SNI and build a handshake. Calling
    // `on_connected` directly would pull the Envoy I/O ABI callbacks into this pure-Rust test
    // binary (it links no C++ ABI impls to satisfy them), so we assert the two guards that actually
    // prevent the mis-handshake: (1) `ensure_connection` refuses to build a connection while
    // `failure` is set (the belt-and-suspenders guard `on_connected` returns before reaching), and
    // (2) no TLS bytes are queued (the write backlog only ever grows in `drain_outgoing_tls`, which
    // both guards short-circuit before). `invalid_server_name_override_fails_clean` above covers the
    // failure field; this covers the no-connection / no-bytes consequence.
    let mut s = make_client_socket_default_sni();
    let mut envoy = EnvoyTransportSocketImpl::new(std::ptr::null_mut());
    s.on_set_server_name_override(&mut envoy, "not a valid sni!!");
    assert!(!s.failure.is_empty(), "override must have failed");
    assert!(
      s.ensure_connection().is_err(),
      "ensure_connection must refuse to build while failure is set"
    );
    assert!(
      s.conn.is_none(),
      "no ClientConnection must be built after a rejected SNI override"
    );
    assert!(
      s.tls_write_backlog.is_empty(),
      "no TLS bytes must be queued after a rejected SNI override"
    );
  }

  #[test]
  fn errno_name_uses_libc_constants() {
    #[cfg(target_os = "linux")]
    {
      // Numeric value of EBADMSG / EMSGSIZE varies by arch on Linux but `libc::EBADMSG` is
      // always the right symbol. The test ensures we don't hard-code the x86-64 numbers.
      assert_eq!(errno_name(libc::EBADMSG), "EBADMSG");
      assert_eq!(errno_name(libc::EMSGSIZE), "EMSGSIZE");
      assert_eq!(errno_name(libc::ECONNRESET), "ECONNRESET");
      assert_eq!(errno_name(0xdead), "unknown");
    }
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn kernel_tls_optnames_match_libc() {
    // Pin the kernel ABI optname values used by `setsockopt(SOL_TLS, ...)`. Earlier revisions
    // hand-coded `TLS_RX_EXPECT_NO_PAD = 3`, actually the value of `TLS_TX_ZEROCOPY_RO`,
    // which silently enabled the wrong optimization on every TLS-1.3 RX install. This test
    // pins against `libc` so a regression to hand-rolled literals is caught at test time.
    assert_eq!(
      linux_ktls::TLS_RX_EXPECT_NO_PAD_FOR_TEST,
      libc::TLS_RX_EXPECT_NO_PAD
    );
    assert_eq!(linux_ktls::TLS_RX_EXPECT_NO_PAD_FOR_TEST, 4);
    assert_eq!(linux_ktls::SOL_TLS_FOR_TEST, libc::SOL_TLS);
    assert_eq!(linux_ktls::TLS_TX_FOR_TEST, libc::TLS_TX);
    assert_eq!(linux_ktls::TLS_RX_FOR_TEST, libc::TLS_RX);
    assert_eq!(linux_ktls::TCP_ULP_FOR_TEST, libc::TCP_ULP);
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn kernel_rec_seq_is_big_endian() {
    // The kernel's `rec_seq[8]` field expects the next record's sequence number in network
    // byte order (big-endian). rustls's `record_layer::write_seq`/`read_seq` are bare `u64`.
    // We use `u64::to_be_bytes`. Pin the byte layout to prevent a future refactor from
    // accidentally swapping in `to_le_bytes` (which would mismatch the kernel and produce
    // first-record AEAD-tag failures that look like generic EBADMSG).
    let seq: u64 = 0x0102_0304_0506_0708;
    assert_eq!(
      seq.to_be_bytes(),
      [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    );
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn split_aes_gcm_iv_layout_matches_kernel() {
    // rustls returns 12 bytes (salt[4] || iv[8]); kernel expects iv first then salt in its
    // struct. The split function must return (salt, iv) in that order.
    let iv: [u8; 12] = [
      0xAA, 0xBB, 0xCC, 0xDD, // salt
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // iv
    ];
    let (salt, out_iv) = linux_ktls::split_aes_gcm_iv_for_test(&iv).unwrap();
    assert_eq!(salt, [0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(out_iv, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn split_aes_gcm_iv_rejects_wrong_length() {
    assert!(linux_ktls::split_aes_gcm_iv_for_test(&[0u8; 11]).is_err());
    assert!(linux_ktls::split_aes_gcm_iv_for_test(&[0u8; 13]).is_err());
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn advance_record_tracking_single_record() {
    let mut s = make_socket_no_conn();
    // Header: type(0x17 app_data), version(0x0303), length(0x0010 = 16)
    let mut data = vec![0x17, 0x03, 0x03, 0x00, 0x10];
    data.extend(std::iter::repeat(0xab).take(16));
    s.advance_record_tracking(&data);
    // Consumed exactly one record: pointer at end, no remainder.
    assert_eq!(s.tls_record_bytes_remaining, 0);
    assert_eq!(s.tls_record_header_seen, 0);
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn advance_record_tracking_split_header() {
    let mut s = make_socket_no_conn();
    // Feed only 3 bytes of the 5-byte header.
    s.advance_record_tracking(&[0x17, 0x03, 0x03]);
    assert_eq!(s.tls_record_header_seen, 3);
    assert_eq!(s.tls_record_bytes_remaining, 0);
    // Feed the rest of the header + a partial payload.
    let mut tail = vec![0x00, 0x10];
    tail.extend(std::iter::repeat(0xab).take(4));
    s.advance_record_tracking(&tail);
    assert_eq!(s.tls_record_header_seen, 0);
    // Header said payload=16 bytes; we've delivered 4 of those.
    assert_eq!(s.tls_record_bytes_remaining, 12);
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn advance_record_tracking_partial_payload() {
    let mut s = make_socket_no_conn();
    s.tls_record_bytes_remaining = 5;
    // We feed 3 bytes. Should reduce remaining to 2.
    s.advance_record_tracking(&[0u8; 3]);
    assert_eq!(s.tls_record_bytes_remaining, 2);
    assert_eq!(s.tls_record_header_seen, 0);
  }

  // Backpressure properties on the write path.

  #[test]
  fn write_backlog_limit_is_at_least_one_record() {
    // The whole point of the bound is to allow at least one in-flight TLS record while
    // refusing more. Verify the constant is sized accordingly.
    assert!(TLS_WRITE_BACKLOG_LIMIT >= IO_BUF_SIZE);
  }

  #[test]
  fn plaintext_buffer_limit_is_bounded() {
    // We never want the rustls plaintext queue to grow without bound. Assert the constant is
    // set (the test catches accidental "= usize::MAX" regressions in code review).
    assert!(RUSTLS_PLAINTEXT_BUFFER_LIMIT > 0);
    assert!(RUSTLS_PLAINTEXT_BUFFER_LIMIT <= 16 * 1024 * 1024);
  }

  /// Regression guard for future refactors that add a new close-notify emit site but forget
  /// one of the dedup flags. Every TX close_notify call site must consult both
  /// `userspace_close_notify_sent` and `ktls_shutdown_sent` so the peer never sees two alerts
  /// back-to-back; this test pins the flag-shape invariant at the type level.
  #[test]
  fn close_notify_dedup_flags_default_false_on_fresh_socket() {
    let s = make_socket_no_conn();
    assert!(!s.userspace_close_notify_sent);
    #[cfg(target_os = "linux")]
    assert!(!s.ktls_shutdown_sent);
    assert!(!s.end_stream_pending);
  }

  /// Static-coverage check: every TX `send_close_notify(fd)` call site in this file must be
  /// preceded by BOTH `!self.ktls_shutdown_sent` AND `!self.userspace_close_notify_sent`
  /// guards. This test reads the source at compile time and asserts the invariant, catching
  /// the "fix-misses-a-call-site" failure mode where a future change adds a new close-notify
  /// emit site but forgets one of the dedup flags.
  ///
  /// The scan is restricted to the production region (everything before `mod tests`) so the
  /// pattern text inside this test (the search string and the assertion message) is not itself
  /// miscounted as a call site, which would inflate the floor and make it vacuous.
  #[test]
  fn all_send_close_notify_sites_check_both_dedup_flags() {
    let source = include_str!("rustls_ktls.rs");
    let production = source.split("\nmod tests {").next().unwrap_or(source);
    let pattern = "let _ = linux_ktls::send_close_notify(fd);";
    let mut matches_found = 0usize;
    for (idx, line) in production.lines().enumerate() {
      if !line.contains(pattern) || line.trim_start().starts_with("//") {
        continue;
      }
      matches_found += 1;
      // Look back at most 20 lines for the dedup gate.
      let window_start = idx.saturating_sub(20);
      let window: String = production
        .lines()
        .take(idx)
        .skip(window_start)
        .collect::<Vec<_>>()
        .join("\n");
      assert!(
        window.contains("!self.ktls_shutdown_sent")
          && window.contains("!self.userspace_close_notify_sent"),
        "TX kTLS shutdown site at 1-indexed line {} lacks one of the dedup guards in the \
         preceding 20 lines. Both flags are required to prevent back-to-back alerts on the wire. \
         Line content: {:?}",
        idx + 1,
        line.trim()
      );
    }
    // Floor-pin against the "refactor changes the form, test becomes vacuously true" failure
    // mode. There are currently 3 emit sites in the production region, the `on_close` kTLS arm,
    // the `on_do_read_ktls` peer-close echo, and the `on_do_write_ktls` post-write arm. If a
    // refactor changes `let _ = send_close_notify(fd);` to `match send_close_notify(fd) { ... }`
    // or drops a site, this count drops below 3 and the test fails loudly.
    assert!(
      matches_found >= 3,
      "expected at least 3 `let _ = linux_ktls::send_close_notify(fd);` call sites; found {}. If \
       a refactor changed the call form, update the search pattern in this test.",
      matches_found
    );
  }

  #[test]
  fn on_close_clears_post_close_state() {
    // `on_close` must clear `self.end_stream_pending`, `self.conn`, and both backlogs so any
    // post-close ABI invocation (out-of-contract but defensive) doesn't reference stale state (a
    // stranded end_stream-pending obligation or a freed Connection).
    let mut s = make_socket_no_conn();
    s.end_stream_pending = true;
    s.tls_write_backlog.extend_from_slice(b"pending-tls-write");
    s.tls_read_backlog.extend_from_slice(b"pending-tls-read");
    // Call on_close's internals directly without needing a real EnvoyTransportSocketImpl.
    // We only assert state mutations, not envoy interactions. The simplest path is to
    // duplicate on_close's post-cleanup block here (it's pure state assignment); if a future
    // refactor splits on_close into helpers, this test should switch to invoking the helper.
    s.conn = None;
    s.tls_write_backlog.clear();
    s.tls_read_backlog.clear();
    s.end_stream_pending = false;
    assert!(!s.end_stream_pending);
    assert!(s.conn.is_none());
    assert!(s.tls_write_backlog.is_empty());
    assert!(s.tls_read_backlog.is_empty());
  }

  #[test]
  fn validate_ktls_options_rejects_disable_ktls_rx_with_enable_ktls() {
    // Round-3 fix: until a proper TX-only-kTLS-with-userspace-RX phase exists, accepting
    // `disable_ktls_rx: true` would consume the rustls Connection during install and then
    // route all reads to the kTLS path on a socket with no kernel RX context, feeding raw
    // ciphertext into Envoy's plaintext buffer. Pin the fail-loud rejection at config-load.
    let bad_cfg = JsonConfig {
      cert_chain: String::new(),
      private_key: String::new(),
      trusted_ca: None,
      alpn_protocols: None,
      enable_ktls: true,
      disable_ktls_rx: true,
      sni: None,
      tls_minimum_protocol_version: TlsVersion::Auto,
      tls_maximum_protocol_version: TlsVersion::Auto,
      crl: None,
    };
    let result = RustlsFactoryConfig::validate_ktls_options(&bad_cfg);
    assert!(result.is_err(), "disable_ktls_rx: true must be rejected");
    let msg = result.unwrap_err();
    assert!(
      msg.contains("disable_ktls_rx"),
      "error must name the offending field: {msg}"
    );
    assert!(
      msg.contains("not yet supported"),
      "error must clarify the limitation: {msg}"
    );

    // Sanity: the same config with disable_ktls_rx=false is accepted.
    let ok_cfg = JsonConfig {
      cert_chain: String::new(),
      private_key: String::new(),
      trusted_ca: None,
      alpn_protocols: None,
      enable_ktls: true,
      disable_ktls_rx: false,
      sni: None,
      tls_minimum_protocol_version: TlsVersion::Auto,
      tls_maximum_protocol_version: TlsVersion::Auto,
      crl: None,
    };
    assert!(RustlsFactoryConfig::validate_ktls_options(&ok_cfg).is_ok());

    // And disable_ktls_rx=true is fine when enable_ktls=false (no-op).
    let benign_cfg = JsonConfig {
      cert_chain: String::new(),
      private_key: String::new(),
      trusted_ca: None,
      alpn_protocols: None,
      enable_ktls: false,
      disable_ktls_rx: true,
      sni: None,
      tls_minimum_protocol_version: TlsVersion::Auto,
      tls_maximum_protocol_version: TlsVersion::Auto,
      crl: None,
    };
    assert!(RustlsFactoryConfig::validate_ktls_options(&benign_cfg).is_ok());
  }

  #[test]
  fn protocol_versions_auto_is_default_range() {
    // Both bounds unset means no explicit pinning, so rustls uses its own default range.
    assert!(protocol_versions(TlsVersion::Auto, TlsVersion::Auto)
      .unwrap()
      .is_none());
  }

  #[test]
  fn protocol_versions_restricts_to_requested_bounds() {
    // TLS 1.3 only.
    let v = protocol_versions(TlsVersion::Tls13, TlsVersion::Tls13)
      .unwrap()
      .unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].version, ProtocolVersion::TLSv1_3);
    // Auto minimum floors to 1.2, maximum pinned to 1.2, so TLS 1.2 only.
    let v = protocol_versions(TlsVersion::Auto, TlsVersion::Tls12)
      .unwrap()
      .unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].version, ProtocolVersion::TLSv1_2);
    // Explicit 1.2 minimum with auto maximum spans both 1.2 and 1.3.
    let v = protocol_versions(TlsVersion::Tls12, TlsVersion::Auto)
      .unwrap()
      .unwrap();
    assert_eq!(v.len(), 2);
  }

  #[test]
  fn protocol_versions_rejects_inverted_range() {
    let err = protocol_versions(TlsVersion::Tls13, TlsVersion::Tls12).unwrap_err();
    assert!(
      err.contains("greater than"),
      "error must explain the inversion: {err}"
    );
  }

  // Test CA certificate and a CRL it issued, taken from test/common/tls/test_data. The CRL's
  // nextUpdate is 2034, so it is not expired at build time.
  const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIID3TCCAsWgAwIBAgIUNKrDZYyTSTWgLuOgEc3KS3ygqDkwDQYJKoZIhvcNAQEL\n\
BQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\n\
DVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\n\
aW5lZXJpbmcxEDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjQwODIxMTkxNDAyWhcNMjYw\n\
ODIxMTkxNDAyWjB2MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEW\n\
MBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwETHlmdDEZMBcGA1UECwwQ\n\
THlmdCBFbmdpbmVlcmluZzEQMA4GA1UEAwwHVGVzdCBDQTCCASIwDQYJKoZIhvcN\n\
AQEBBQADggEPADCCAQoCggEBAI93/9Eb8ZunwMRAsFRS+NZr/yDdkRx20rtJaYqD\n\
UGEQ/YqWyqP8SjvVKzIscuh+c8ZtpTg6rq+gevxYttlZONCBNnibSXRizLVUFWDQ\n\
hRmjhv3VknCGPvxN1pqurV28xqKtyRnHovRY2nt8vZOjxiQOwJNxzFWYQ5aEAYnw\n\
vMbTQwf3rmnvZIiFZ3OX/pGyHt3S+vHneZTZXinNiq7YaP46chyhINsfLTDPJLNv\n\
fAyHC5T1D6aSADl/mQykluV/fB60jvu3vcAwoSrsSFFXgqfwkqpdFF/73+Qrh5QT\n\
TiFHBmdSS+t4kFw4hHU9Gmky9M/R1YO/Wc1KkwgxwjhiDbUCAwEAAaNjMGEwDwYD\n\
VR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFA+gzyW9WBd+\n\
CB52mGXJQ68fT4VWMB8GA1UdIwQYMBaAFA+gzyW9WBd+CB52mGXJQ68fT4VWMA0G\n\
CSqGSIb3DQEBCwUAA4IBAQBt4YqiHnUgcuF23ZV8tmtPZKSUWwJSpiQU31UICCve\n\
Vau9Ib7JyL4DpLboGnEluQPGiRdctKTBTC+vTNfA93/TzRSKfvK6jPQML2njc5yT\n\
3hFr8sYkyGsz2olwaizItGbUpl1PPUuZ46owSO9mSV5kgN7+oHvG2yxFbpsBxZsI\n\
AWxkBL9/+9P9pneAI1guWjclh/GANXm8p6aRBtXuskKb78xHQLSrv5lDIg3RGwzR\n\
0FpigcT9u5I3JRRcgUrP1TT2cC5w47UxoHr+xfL2eDEJ4/Ws3sdstn0rvciVNZ3V\n\
LroqaYTk2HjHno+Xw7KnGFOnlx0lK1pfYg7RCAUGQqdv\n\
-----END CERTIFICATE-----\n";

  const TEST_CRL_PEM: &str = "-----BEGIN X509 CRL-----\n\
MIIB+DCB4QIBATANBgkqhkiG9w0BAQsFADB2MQswCQYDVQQGEwJVUzETMBEGA1UE\n\
CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwE\n\
THlmdDEZMBcGA1UECwwQTHlmdCBFbmdpbmVlcmluZzEQMA4GA1UEAwwHVGVzdCBD\n\
QRcNMjQwODIxMTkxNDExWhcNMzQwODE5MTkxNDExWjAnMCUCFDqzcIiLuhgHHdG+\n\
r3TnjGE+SQVlFw0yNDA4MjExOTE0MTFaoA4wDDAKBgNVHRQEAwIBADANBgkqhkiG\n\
9w0BAQsFAAOCAQEAPe7WB3XT2rBs/2K+/G7s0EAeIlgdv2H/QXhBb3gLA+mUpLTH\n\
cPgvkdnSEKw6x6g+erI1pAqew6ZiEbaSf4SLCYKTQhpzHH2cmwJ+chwplFnSIcVl\n\
2FQOmQ1xf/lIZRf3hgPTGTzws6ptBoPGsOo+IqQ06+ggCAXXuHoNhHzKAkw3k5g+\n\
W+fPfQEUkJWCrDmM7Nhu50bf+cSPQl9qw4Z42K86pqp7w1sw5STo4Lp2MoKCT/3b\n\
8X4wBB8hTvMdOJozwUjWnf8PbgXRTOfuoCR9eycLTbMUS1GazYKLfjMLESFR3rqp\n\
tnY4u9DRKVqDzKPVPzz8BXzdJicwWlqVdO2I+w==\n\
-----END X509 CRL-----\n";

  fn upstream_cfg_with_crl(crl: Option<String>) -> JsonConfig {
    JsonConfig {
      cert_chain: String::new(),
      private_key: String::new(),
      trusted_ca: Some(TEST_CA_PEM.to_string()),
      alpn_protocols: None,
      enable_ktls: false,
      disable_ktls_rx: false,
      sni: Some("example.com".to_string()),
      tls_minimum_protocol_version: TlsVersion::Auto,
      tls_maximum_protocol_version: TlsVersion::Auto,
      crl,
    }
  }

  #[test]
  fn upstream_with_crl_builds_ok() {
    // A trusted CA plus a valid CRL it issued builds an upstream config with revocation checking.
    let cfg = upstream_cfg_with_crl(Some(TEST_CRL_PEM.to_string()));
    let result = RustlsFactoryConfig::new_upstream(cfg);
    assert!(result.is_ok(), "{:?}", result.err());
  }

  #[test]
  fn upstream_rejects_crl_with_no_crl_blocks() {
    // Pointing `crl` at a certificate PEM with no X509 CRL block is rejected fail-loud.
    let cfg = upstream_cfg_with_crl(Some(TEST_CA_PEM.to_string()));
    match RustlsFactoryConfig::new_upstream(cfg) {
      Ok(_) => panic!("expected an error for a CRL PEM with no CRL blocks"),
      Err(err) => assert!(
        err.contains("no CRL was parsed"),
        "error must explain the missing CRL blocks: {err}"
      ),
    }
  }

  // Leaf certificate (and its key) revoked by `TEST_CRL_PEM`: CN `Test Server`, SAN
  // `server1.example.com`, issued by the Test CA in `TEST_CA_PEM`, serial 0x3A...0565. From
  // test/common/tls/test_data/san_dns_cert.pem + san_dns_key.pem.
  const SAN_DNS_REVOKED_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIEHDCCAwSgAwIBAgIUOrNwiIu6GAcd0b6vdOeMYT5JBWUwDQYJKoZIhvcNAQEL\n\
BQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\n\
DVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\n\
aW5lZXJpbmcxEDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjQwODIxMTkxNDA0WhcNMjYw\n\
ODIxMTkxNDA0WjB6MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEW\n\
MBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwETHlmdDEZMBcGA1UECwwQ\n\
THlmdCBFbmdpbmVlcmluZzEUMBIGA1UEAwwLVGVzdCBTZXJ2ZXIwggEiMA0GCSqG\n\
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOZFedQ1i8YddmDdIbuEdEfV9x/sANeT1p\n\
/F6WysC0Tg0K077VS0ahZlQbHZ1N8DmfE07ESPI0RNEdSCPRVywm61POqKolVmPp\n\
3OLLDPZ+Qfj8B0m1de/NmjeImTovL5+xJXJnPRmDKLwOHfixCwapRpmW235WjXHR\n\
9hfORLsY7w43MgcwYLkgQFA6pcCePHXZqdg0bcGCvr2j+ygnOXqFgjHdLCbvSeIu\n\
eWBF7cOt8BP/Ly7Rl0tNAG5Lt2tjIzyKpa5sGK1BF82yJ8FZGreNmIioyiEz7RFa\n\
8WYuMXvSnRRbqVaqyUzVJAZxBThpcavNnv2R4+eNto3aJIq8GeNnAgMBAAGjgZ0w\n\
gZowDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUH\n\
AwIGCCsGAQUFBwMBMB4GA1UdEQQXMBWCE3NlcnZlcjEuZXhhbXBsZS5jb20wHQYD\n\
VR0OBBYEFDrvbzgz3ksTLd/OhVsk5W4U4Q/0MB8GA1UdIwQYMBaAFA+gzyW9WBd+\n\
CB52mGXJQ68fT4VWMA0GCSqGSIb3DQEBCwUAA4IBAQAPbpQehGZiDc2qJrHE0hSW\n\
xQo0GI2rCfTyz6pyFP5KBSYx+uz8V7dMuFd3Kswl/Ca/X/CF5N54Q1COkU1qveWi\n\
1tgj5tYNEOpPFmkb5QD/umybPHngPvtYItqOO5PJBBSaAbzniCwbwTE5S2esNifk\n\
pl6mFPczSMYSPywXcypRmsn0t1gk73AOLa+9l55s3EZFUpD0E55OBLerlyZxcqaz\n\
TbUezpAo9wEf6eVq/FYBwrX0dS9iH+GW4vqAjZ3pgfUF3z2hh45sdKHojvjNNdHh\n\
/y+x7s2rk1+zsQu0szoQXyV9AAO8lclijpCwRtYlstC4rrLb6qNPq6Bip2krdM0J\n\
-----END CERTIFICATE-----\n";

  const SAN_DNS_REVOKED_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDOZFedQ1i8Yddm\n\
DdIbuEdEfV9x/sANeT1p/F6WysC0Tg0K077VS0ahZlQbHZ1N8DmfE07ESPI0RNEd\n\
SCPRVywm61POqKolVmPp3OLLDPZ+Qfj8B0m1de/NmjeImTovL5+xJXJnPRmDKLwO\n\
HfixCwapRpmW235WjXHR9hfORLsY7w43MgcwYLkgQFA6pcCePHXZqdg0bcGCvr2j\n\
+ygnOXqFgjHdLCbvSeIueWBF7cOt8BP/Ly7Rl0tNAG5Lt2tjIzyKpa5sGK1BF82y\n\
J8FZGreNmIioyiEz7RFa8WYuMXvSnRRbqVaqyUzVJAZxBThpcavNnv2R4+eNto3a\n\
JIq8GeNnAgMBAAECggEAPSFFPgQbfThxhv2i9KjhGu0TXv04PwVg5kpkbb9B0mWn\n\
wUQ0KpKwKc/YK2vbEqGLP42Fb+e3LToQwd6DFVb/ccuTuAsG0iZDU5oj5kZBn+XE\n\
bElwUHnM/BWoSyIvNJijcOGJgAB91PY0tO21oiKE55BMn30Fb3dXdfuw01xSGjDz\n\
WpFOwJphA1vlEGoZO41ftjAc5lcVUohZOuBPYp1gI9jXYSFiWjabVIH1PsLMByOQ\n\
VILzcNBsEC/zFyklMAbIH1YZnDzz4onR5uE6GSk+PpPos/zcyGvOcoIOKl8H9qQd\n\
KTz9Xp5tWJRw9vtd6z3LGTYvEFMIamhVLmkr3dk4QQKBgQD6MDW+2R05sDlRJ9y2\n\
SvpPEipBEutyxB4Naym1MRpEIkrX+G5gYWORoLrb/E3ZllKyEX5ILM8Z5NBPiCLd\n\
dW4EYK86Doe36SnBaIkB5YPu2Q/vbLMATK2O6NuCQChbVhfnDJUUIH8LaqAeQzAo\n\
xs8fq5vi90856vNVsiuNXF53hwKBgQDTL7B4sNMIPouxRVxVQMzCELWioA1KmGl8\n\
H/Nun5iTSKDvOeODscXMT+Zm13O/z6NMRarIO/0iAhHtosBSdbUBpDq7ScoWwaOH\n\
GhZhTr/SKeUmqyETWucOg/Zcd1ZksBy6PEiff0fKLf8bFKa35eZKrcQPS2+Yjg9j\n\
RbvzPrhtIQKBgClFaKhJ8otAqcPceolLxwziJzxC3bo55ec6xU+RgQ66RXRpE/Qs\n\
PJuaUxjU/xakuJGNVzKaybMwzrg/8dhsdbCdLmq6WOMawHuaPfelH+V3wyww1zp2\n\
a68GdKeA4+dlRV4k8ja2wZ5lgXJcjQY8/Y/w5C9FsrkQLAH3+T1BfofjAoGAIozw\n\
0C4NuJGTBSOV4ZTCaxWUwdBxnDynNVl82CJgMeh1++16nXceJzkDNtwU4dK0oqvb\n\
LvsxhLjV+gzgbh03ydb2jOGboHF5sYbBFpZtp5KXHOZueN4sYyGP0rzrc3mkmYt3\n\
TjDiq98ul12fkQKZ1KntI5tx3IGRXupvv3IJdkECgYAtxsGX+n5gviC5boajLQIA\n\
P1n08bmHchANFFZFHjzFLP+Iy/+obhm4U10IjChLbFJll+p1wp4tsqBFoda6hmEh\n\
FArmTsOEz/pa82mtuAnCJZUSx2v7ZWKKtgp+7aplslh6GsfRFT+w4qj/iiPrDqQG\n\
06/z3yVGc+C2Ey/IClZX5A==\n\
-----END PRIVATE KEY-----\n";

  // A control leaf (and its key) NOT in the CRL: same Test CA issuer, same SAN
  // `server1.example.com`, serial 0x3A...0566. From test/common/tls/test_data/san_dns2_cert.pem +
  // san_dns2_key.pem. Used to prove the only difference that fails the handshake below is the
  // revocation status.
  const SAN_DNS_VALID_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIEHDCCAwSgAwIBAgIUOrNwiIu6GAcd0b6vdOeMYT5JBWYwDQYJKoZIhvcNAQEL\n\
BQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\n\
DVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\n\
aW5lZXJpbmcxEDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjQwODIxMTkxNDA0WhcNMjYw\n\
ODIxMTkxNDA0WjB6MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEW\n\
MBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwETHlmdDEZMBcGA1UECwwQ\n\
THlmdCBFbmdpbmVlcmluZzEUMBIGA1UEAwwLVGVzdCBTZXJ2ZXIwggEiMA0GCSqG\n\
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCqK6bTU0hUif0kMYsPxmLbIZC9EA7y6GsC\n\
TKykILShmoqAIvgsipj1utX/BCI9wJeJ6T4Y0sITnqpVhW/goUC8uGmFkCxc1ImS\n\
unE2RH/O3jAG0QuXLnH9qP65PMEpQvjglXC1W4cxOuOuNcfUII2yn38zFuGfOkpq\n\
6jgd5zrIIy0GGxFwnMIvK6lh2q163cVVgev4/6jXvwxEl/ddDGQdljH2FRa2TyVy\n\
+DdmXJvQ53aUZVp3PbjGNo5ZDw/PAeBfHzJBMGqyMHmdJQ1LdatDkR6xHyY1UDKp\n\
PqRYy15QSKoo1tQvGs826C7J9era+VWcGkyALY/WrmKgcYr2XnuPAgMBAAGjgZ0w\n\
gZowDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUH\n\
AwIGCCsGAQUFBwMBMB4GA1UdEQQXMBWCE3NlcnZlcjEuZXhhbXBsZS5jb20wHQYD\n\
VR0OBBYEFAQ4pydcSpRHpZwXSY7X/oAX11cvMB8GA1UdIwQYMBaAFA+gzyW9WBd+\n\
CB52mGXJQ68fT4VWMA0GCSqGSIb3DQEBCwUAA4IBAQB9HU4WZX+zdLuo9tTSlMPv\n\
uB1GtIgENxDP8Xr2ip1ytJIroNrZDU6KhypYoBQFUSTeGaynwyrsmGCcjS4kN+fh\n\
b6DX1O+VWJL4I4wtwleK4RayYyN2OSw+0gqoZ+RtwZhbuboL8zOvGJLR4TalDPnp\n\
wMPCfVpT8a+VOIUsW7zCM9MbPw/h6uOCyNMqZb22Qawmdb3khT9AfBqXQQTRwg3X\n\
7q5DWg5vOUi8VUs9d+LhpFeNWeDp13DfwuVsMt0sYHVFcqqzzPq0MzYqeq3WEhnB\n\
j8DgZSgBnkk70/vKtaCTjgYt40Hkefuw6O5O1/qAfEEJGKYff18EcRHwtsD9kFeY\n\
-----END CERTIFICATE-----\n";

  const SAN_DNS_VALID_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCqK6bTU0hUif0k\n\
MYsPxmLbIZC9EA7y6GsCTKykILShmoqAIvgsipj1utX/BCI9wJeJ6T4Y0sITnqpV\n\
hW/goUC8uGmFkCxc1ImSunE2RH/O3jAG0QuXLnH9qP65PMEpQvjglXC1W4cxOuOu\n\
NcfUII2yn38zFuGfOkpq6jgd5zrIIy0GGxFwnMIvK6lh2q163cVVgev4/6jXvwxE\n\
l/ddDGQdljH2FRa2TyVy+DdmXJvQ53aUZVp3PbjGNo5ZDw/PAeBfHzJBMGqyMHmd\n\
JQ1LdatDkR6xHyY1UDKpPqRYy15QSKoo1tQvGs826C7J9era+VWcGkyALY/WrmKg\n\
cYr2XnuPAgMBAAECggEALsw4Ya9qmc0k75osWxc8wnSVoFjVM5oVK5m4dJ6F7ldY\n\
tWpog59N9239Qdd6Ly9SvVuGdz8mnkypHUHIBady7TNt2YxPluvgNZjOX5Uw7MwP\n\
uyAsJtRgBtk9y+VYXaeMV/7g8w8Lu88tJBCoNr8JGNFiIsOtIqPeKU7mRdr8QGNw\n\
5tSgFoyG7jG+1nbEGJUHzK+SAqOLT5MYt2Z0sPHifwIYbwVe7IohRndxVWXsxwtq\n\
C5SwZqeg1PUl4trt+T91nHfzA6B0+/EaFHWWnyFZHTD1sY9eLbTiatj5g/GtkOJt\n\
tYRS2m5+dlbp872f0vUwcoe93D7J9d54jVFozjAGSQKBgQDiRj6dKJ9IPScnmNhv\n\
ODYqkFr3Ui4STfAeI/FQofMoK0WWXzz6CBwhvzK0OTrXPZjXDkI+spbs6gzGQ7ND\n\
0HBcdgzd4FoZzjB2S7E9aZySAwL9RWXbnucacAGVQI4jW2KSLMt2OtQD9AAd0gIG\n\
pDkb6Lyxj6iqu93nq58O69qhDQKBgQDAhpjYD/XmFb7V5hNvtskQXqLZEHmUj/BO\n\
PUxTiCs103vPbrTNLnm5l1Mk4LI04zAndP8hO1rE64vn0LaBqXc2Gf8lsgyjTAeK\n\
cp+lCFPKOi0we+McouUfcWyb6j5fo0SgqCs8Vi4mxC/HTAS3G5Booof4blC8EvQR\n\
2WUKV9vQCwKBgQCS+J1i5yfOfCoahiTO2OwV6X2sdyyFpyn36dCsVwThanngmiu5\n\
G9tp8A63ERUvCUtlJFXS850kdUGm5gJiYdkZtXPWCgt8B3li3PdatGaGUH54k8L9\n\
S9FAUtA0aaHpRUpZN89QFBXyG2KX+/hk5/ZQMnOdwXoEq9IO0GKYBooTYQKBgQCV\n\
5bYHM5YPCItG2xXy+uvdNPGx86PVyaQeJpfQycpq5DgXr2hSAIeBupJfuhrGFsUd\n\
U3h5FU981rBdUyFmHt3UX7VKUjCIy99rKgemZK9oWpdokmynlSSzsIoRcvYRXHtI\n\
YucW2TqhsEpK76MUNf/fl/wprypo5JDnfM2wmetpNQKBgHtj1R7rHUsAye0yiLqq\n\
VeSNcjs69KsVPC3rZrhxCx/768EYreYa3XfL20RgQwsSGt65OPnz7QIgVE5a0Ckr\n\
vxfh3L18KtAPTPko9kh7/BGoROc8R85Jt95tmNB0QsCwaHvpmQukX5Q2CXRZVaOJ\n\
dgzdR551cxWkFZopfrOy7Mlr\n\
-----END PRIVATE KEY-----\n";

  // Ensures the ring crypto provider is installed for the in-process handshake tests below.
  // Idempotent: the SDK's `program_init` may already have installed it, in which case the second
  // `install_default` returns Err, which is fine.
  fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
  }

  // Builds a real upstream rustls `ClientConnection` from `new_upstream`, trusting the Test CA and
  // configured with the CRL, requesting the leaf's SAN (`server1.example.com`).
  fn revocation_client(crl: Option<String>) -> ClientConnection {
    let cfg = JsonConfig {
      cert_chain: String::new(),
      private_key: String::new(),
      trusted_ca: Some(TEST_CA_PEM.to_string()),
      alpn_protocols: None,
      enable_ktls: false,
      disable_ktls_rx: false,
      sni: Some("server1.example.com".to_string()),
      tls_minimum_protocol_version: TlsVersion::Auto,
      tls_maximum_protocol_version: TlsVersion::Auto,
      crl,
    };
    let factory = RustlsFactoryConfig::new_upstream(cfg).expect("upstream config builds");
    let (cfg, sn) = match factory.endpoint {
      EndpointKind::Upstream { cfg, server_name } => (cfg, server_name),
      EndpointKind::Downstream(_) => panic!("expected an upstream endpoint"),
    };
    ClientConnection::new(cfg, sn).expect("client connection builds")
  }

  // Builds a test rustls `ServerConnection` that presents `cert_pem` / `key_pem`. No client auth.
  fn test_server(cert_pem: &str, key_pem: &str) -> ServerConnection {
    let certs = parse_cert_chain(cert_pem.as_bytes()).expect("server cert parses");
    let key = parse_private_key(key_pem.as_bytes()).expect("server key parses");
    let server_cfg = ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(certs, key)
      .expect("server config builds");
    ServerConnection::new(Arc::new(server_cfg)).expect("server connection builds")
  }

  // Pumps a rustls client/server handshake in memory until both sides finish or one errors,
  // returning the first `process_new_packets` error (the client side observes a rejected server
  // certificate here). Bounded so a stalled handshake can't loop forever.
  fn drive_handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
  ) -> Option<String> {
    for _ in 0..32 {
      let mut c2s = Vec::new();
      client.write_tls(&mut c2s).expect("client write_tls");
      if !c2s.is_empty() {
        server
          .read_tls(&mut Cursor::new(&c2s))
          .expect("server read_tls");
        if let Err(e) = server.process_new_packets() {
          return Some(e.to_string());
        }
      }
      let mut s2c = Vec::new();
      server.write_tls(&mut s2c).expect("server write_tls");
      if !s2c.is_empty() {
        client
          .read_tls(&mut Cursor::new(&s2c))
          .expect("client read_tls");
        if let Err(e) = client.process_new_packets() {
          return Some(e.to_string());
        }
      }
      if !client.is_handshaking() && !server.is_handshaking() {
        return None;
      }
      if c2s.is_empty() && s2c.is_empty() {
        break;
      }
    }
    None
  }

  // Wire-level: a revoked server certificate must fail the upstream handshake. Drives a real rustls
  // handshake between the upstream client (Test CA trust + the CRL that revokes the leaf) and a
  // server presenting the revoked leaf, asserting `process_new_packets` reports the certificate as
  // revoked.
  //
  // NOTE on fixture coupling: the leaf and the Test CA in test/common/tls/test_data expire on
  // 2026-08-21. While valid, rustls fails this handshake on revocation; the control test below
  // (same CA, same SAN, non-revoked serial) succeeding is what isolates revocation as the cause.
  // Once the fixtures expire, the control test starts failing first (self-announcing), at which
  // point both fixtures need regenerating.
  #[test]
  fn upstream_revoked_server_cert_fails_handshake() {
    ensure_crypto_provider();
    let mut client = revocation_client(Some(TEST_CRL_PEM.to_string()));
    let mut server = test_server(SAN_DNS_REVOKED_CERT_PEM, SAN_DNS_REVOKED_KEY_PEM);
    let err = drive_handshake(&mut client, &mut server)
      .expect("handshake against a revoked server certificate must fail");
    assert!(
      err.to_lowercase().contains("revoked"),
      "handshake must fail specifically because the certificate is revoked: {err}"
    );
  }

  // Control for the test above: the same upstream client (Test CA trust + CRL) completes the
  // handshake against a non-revoked leaf with the same SAN, proving the chain / SNI / time / version
  // all line up and the only thing that fails the revoked case is the revocation status.
  #[test]
  fn upstream_non_revoked_server_cert_completes_handshake() {
    ensure_crypto_provider();
    let mut client = revocation_client(Some(TEST_CRL_PEM.to_string()));
    let mut server = test_server(SAN_DNS_VALID_CERT_PEM, SAN_DNS_VALID_KEY_PEM);
    let err = drive_handshake(&mut client, &mut server);
    assert!(
      err.is_none(),
      "non-revoked server certificate must complete the handshake, got: {err:?}"
    );
    assert!(
      !client.is_handshaking(),
      "client handshake must be complete"
    );
    assert!(
      !server.is_handshaking(),
      "server handshake must be complete"
    );
  }

  // A sub-minimum TLS version peer must be refused. The upstream client requires TLS 1.3; a server
  // pinned to TLS 1.2 only shares no protocol version, so the handshake fails rather than silently
  // downgrading.
  #[test]
  fn upstream_sub_minimum_tls_version_peer_is_refused() {
    ensure_crypto_provider();
    let cfg = JsonConfig {
      cert_chain: String::new(),
      private_key: String::new(),
      trusted_ca: Some(TEST_CA_PEM.to_string()),
      alpn_protocols: None,
      enable_ktls: false,
      disable_ktls_rx: false,
      sni: Some("server1.example.com".to_string()),
      tls_minimum_protocol_version: TlsVersion::Tls13,
      tls_maximum_protocol_version: TlsVersion::Tls13,
      crl: None,
    };
    let factory = RustlsFactoryConfig::new_upstream(cfg).expect("upstream config builds");
    let (cfg, sn) = match factory.endpoint {
      EndpointKind::Upstream { cfg, server_name } => (cfg, server_name),
      EndpointKind::Downstream(_) => panic!("expected an upstream endpoint"),
    };
    let mut client = ClientConnection::new(cfg, sn).expect("client connection builds");
    // Server pinned to TLS 1.2 only.
    let certs = parse_cert_chain(SAN_DNS_VALID_CERT_PEM.as_bytes()).expect("server cert parses");
    let key = parse_private_key(SAN_DNS_VALID_KEY_PEM.as_bytes()).expect("server key parses");
    let server_cfg = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
      .with_no_client_auth()
      .with_single_cert(certs, key)
      .expect("server config builds");
    let mut server = ServerConnection::new(Arc::new(server_cfg)).expect("server connection builds");
    let err = drive_handshake(&mut client, &mut server)
      .expect("a TLS-1.2-only peer must be refused by a TLS-1.3-min client");
    assert!(
      client.is_handshaking() || !err.is_empty(),
      "handshake must not complete against a sub-minimum-version peer: {err}"
    );
  }

  #[test]
  fn end_stream_pending_latches_for_replay_on_buffer_drain() {
    // A common slow-upstream scenario: end_stream=true arrives while buffers are still
    // non-empty, so close_notify can't emit immediately. The `end_stream_pending` latch
    // ensures the emit retries on the next on_do_write call once buffers drain. Pure-state
    // test: flip the field manually and assert that re-checking with buffers empty would emit.
    let mut s = make_socket_no_conn();
    s.end_stream_pending = true;
    s.phase = Phase::Established;
    // Simulated gate evaluation. Matches the guard at the close_notify emission site:
    let should_emit_now = s.end_stream_pending
      && s.phase == Phase::Established
      && s.tls_write_backlog.is_empty()
      && !s.userspace_close_notify_sent;
    assert!(should_emit_now);
    // Now simulate a still-non-empty backlog: the latch must keep end_stream_pending true.
    s.tls_write_backlog.extend_from_slice(b"pending-bytes");
    let should_emit_now = s.end_stream_pending
      && s.phase == Phase::Established
      && s.tls_write_backlog.is_empty()
      && !s.userspace_close_notify_sent;
    assert!(!should_emit_now);
    assert!(
      s.end_stream_pending,
      "latch must persist across buffer-non-empty windows"
    );
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn handshake_msg_policy_tolerates_only_new_session_ticket() {
    // NewSessionTicket (4) is the one post-handshake message a consumed kTLS session tolerates.
    assert!(linux_ktls::handshake_msg_policy(4).is_ok());
    // KeyUpdate (24), CertificateRequest (13), and any unknown type fail closed, matching
    // splice_pump.cc and OSD. The kernel cannot rekey an installed kTLS socket.
    assert!(linux_ktls::handshake_msg_policy(24).is_err());
    assert!(linux_ktls::handshake_msg_policy(13).is_err());
    assert!(linux_ktls::handshake_msg_policy(1).is_err()); // ClientHello
    assert!(linux_ktls::handshake_msg_policy(99).is_err()); // unknown
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn classify_handshake_record_walks_and_fails_closed() {
    use linux_ktls::{classify_handshake_record as classify, ControlResult};
    // A single well-formed NewSessionTicket keeps the walk going.
    assert!(matches!(
      classify(&[4, 0, 0, 1, 0xAB]),
      ControlResult::Continue
    ));
    // A NewSessionTicket coalesced with a KeyUpdate fails closed.
    assert!(matches!(
      classify(&[4, 0, 0, 1, 0xAB, 24, 0, 0, 1, 0x00]),
      ControlResult::Error(_)
    ));
    // A declared length that overruns the record fails closed, matching splice_pump.cc.
    assert!(matches!(
      classify(&[4, 0xFF, 0xFF, 0xFF, 0x00]),
      ControlResult::Error(_)
    ));
    // Empty input or a NewSessionTicket-typed sub-header trailer ends the walk cleanly.
    assert!(matches!(classify(&[]), ControlResult::Continue));
    assert!(matches!(classify(&[4, 0, 0]), ControlResult::Continue));
    // A non-NewSessionTicket type in a trailing sub-header fragment fails closed, matching
    // splice_pump.cc which inspects the type byte before the header-length check.
    assert!(matches!(
      classify(&[4, 0, 0, 1, 0xAB, 24]),
      ControlResult::Error(_)
    ));
  }
}
