#include "source/extensions/filters/listener/tls_inspector/tls_inspector.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/common/platform.h"
#include "envoy/event/dispatcher.h"
#include "envoy/network/listen_socket.h"
#include "envoy/stats/scope.h"

#include "source/common/api/os_sys_calls_impl.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/hex.h"
#include "source/common/protobuf/utility.h"

#include "absl/strings/ascii.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "openssl/md5.h"
#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace TlsInspector {
namespace {

// First 12 hex characters (6 bytes)
constexpr size_t JA4_HASH_LENGTH = 12;

uint64_t computeClientHelloSize(const BIO* bio, uint64_t prior_bytes_read,
                                size_t original_bio_length) {
  const uint8_t* remaining_buffer;
  size_t remaining_bytes;
  const int rc = BIO_mem_contents(bio, &remaining_buffer, &remaining_bytes);
  ASSERT(rc == 1);
  ASSERT(original_bio_length >= remaining_bytes);
  const size_t processed_bio_bytes = original_bio_length - remaining_bytes;
  return processed_bio_bytes + prior_bytes_read;
}

} // namespace

// Min/max TLS version recognized by the underlying TLS/SSL library.
const unsigned Config::TLS_MIN_SUPPORTED_VERSION = TLS1_VERSION;
const unsigned Config::TLS_MAX_SUPPORTED_VERSION = TLS1_3_VERSION;

Config::Config(
    Stats::Scope& scope,
    const envoy::extensions::filters::listener::tls_inspector::v3::TlsInspector& proto_config,
    uint32_t max_client_hello_size)
    : stats_{ALL_TLS_INSPECTOR_STATS(POOL_COUNTER_PREFIX(scope, "tls_inspector."),
                                     POOL_HISTOGRAM_PREFIX(scope, "tls_inspector."))},
      ssl_ctx_(SSL_CTX_new(TLS_with_buffers_method())),
      enable_ja3_fingerprinting_(
          PROTOBUF_GET_WRAPPED_OR_DEFAULT(proto_config, enable_ja3_fingerprinting, false)),
      enable_ja4_fingerprinting_(
          PROTOBUF_GET_WRAPPED_OR_DEFAULT(proto_config, enable_ja4_fingerprinting, false)),
      max_client_hello_size_(max_client_hello_size),
      initial_read_buffer_size_(
          std::min(PROTOBUF_GET_WRAPPED_OR_DEFAULT(proto_config, initial_read_buffer_size,
                                                   max_client_hello_size),
                   max_client_hello_size)) {
  if (max_client_hello_size_ > TLS_MAX_CLIENT_HELLO) {
    throw EnvoyException(fmt::format("max_client_hello_size of {} is greater than maximum of {}.",
                                     max_client_hello_size_, size_t(TLS_MAX_CLIENT_HELLO)));
  }

  SSL_CTX_set_min_proto_version(ssl_ctx_.get(), TLS_MIN_SUPPORTED_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx_.get(), TLS_MAX_SUPPORTED_VERSION);
  SSL_CTX_set_options(ssl_ctx_.get(), SSL_OP_NO_TICKET);
  SSL_CTX_set_session_cache_mode(ssl_ctx_.get(), SSL_SESS_CACHE_OFF);
  SSL_CTX_set_select_certificate_cb(
      ssl_ctx_.get(), [](const SSL_CLIENT_HELLO* client_hello) -> ssl_select_cert_result_t {
        Filter* filter = static_cast<Filter*>(SSL_get_app_data(client_hello->ssl));
        filter->createJA3Hash(client_hello);
        filter->createJA4Hash(client_hello);

        const uint8_t* data;
        size_t len;
        if (SSL_early_callback_ctx_extension_get(
                client_hello, TLSEXT_TYPE_application_layer_protocol_negotiation, &data, &len)) {
          filter->onALPN(data, len);
        }
        return ssl_select_cert_success;
      });
  SSL_CTX_set_tlsext_servername_callback(
      ssl_ctx_.get(), [](SSL* ssl, int* out_alert, void*) -> int {
        Filter* filter = static_cast<Filter*>(SSL_get_app_data(ssl));
        filter->onServername(
            absl::NullSafeStringView(SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)));

        // Return an error to stop the handshake; we have what we wanted already.
        *out_alert = SSL_AD_USER_CANCELLED;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
      });
}

bssl::UniquePtr<SSL> Config::newSsl() { return bssl::UniquePtr<SSL>{SSL_new(ssl_ctx_.get())}; }

Filter::Filter(const ConfigSharedPtr& config)
    : config_(config), ssl_(config_->newSsl()),
      requested_read_bytes_(config->initialReadBufferSize()) {
  SSL_set_app_data(ssl_.get(), this);
  SSL_set_accept_state(ssl_.get());
}

Network::FilterStatus Filter::onAccept(Network::ListenerFilterCallbacks& cb) {
  ENVOY_LOG(trace, "tls inspector: new connection accepted");
  cb_ = &cb;

  return Network::FilterStatus::StopIteration;
}

void Filter::onALPN(const unsigned char* data, unsigned int len) {
  CBS wire, list;
  CBS_init(&wire, reinterpret_cast<const uint8_t*>(data), static_cast<size_t>(len));
  if (!CBS_get_u16_length_prefixed(&wire, &list) || CBS_len(&wire) != 0 || CBS_len(&list) < 2) {
    // Don't produce errors, let the real TLS stack do it.
    return;
  }
  CBS name;
  std::vector<absl::string_view> protocols;
  while (CBS_len(&list) > 0) {
    if (!CBS_get_u8_length_prefixed(&list, &name) || CBS_len(&name) == 0) {
      // Don't produce errors, let the real TLS stack do it.
      return;
    }
    protocols.emplace_back(reinterpret_cast<const char*>(CBS_data(&name)), CBS_len(&name));
  }
  ENVOY_LOG(trace, "tls:onALPN(), ALPN: {}", absl::StrJoin(protocols, ","));
  cb_->socket().setRequestedApplicationProtocols(protocols);
  alpn_found_ = true;
}

void Filter::onServername(absl::string_view name) {
  if (!name.empty()) {
    config_->stats().sni_found_.inc();
    cb_->socket().setRequestedServerName(name);
    ENVOY_LOG(debug, "tls:onServerName(), requestedServerName: {}", name);
  } else {
    config_->stats().sni_not_found_.inc();
  }
  clienthello_success_ = true;
}

Network::FilterStatus Filter::onData(Network::ListenerFilterBuffer& buffer) {
  auto raw_slice = buffer.rawSlice();
  ENVOY_LOG(trace, "tls inspector: recv: {}", raw_slice.len_);

  // Because we're doing a MSG_PEEK, data we've seen before gets returned every time, so
  // skip over what we've already processed.
  if (static_cast<uint64_t>(raw_slice.len_) > read_) {
    const uint8_t* data = static_cast<const uint8_t*>(raw_slice.mem_) + read_;
    const size_t len = raw_slice.len_ - read_;
    const uint64_t bytes_already_processed = read_;
    read_ = raw_slice.len_;
    ParseState parse_state = parseClientHello(data, len, bytes_already_processed);
    switch (parse_state) {
    case ParseState::Error:
      cb_->socket().ioHandle().close();
      return Network::FilterStatus::StopIteration;
    case ParseState::Done:
      // Finish the inspect.
      return Network::FilterStatus::Continue;
    case ParseState::Continue:
      // Do nothing but wait for the next event.
      return Network::FilterStatus::StopIteration;
    }
    IS_ENVOY_BUG("unexpected tcp filter parse_state");
  }
  return Network::FilterStatus::StopIteration;
}

ParseState Filter::parseClientHello(const void* data, size_t len,
                                    uint64_t bytes_already_processed) {
  // Ownership remains here though we pass a reference to it in `SSL_set0_rbio()`.
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(data, len));

  // Make the mem-BIO return that there is more data
  // available beyond it's end.
  BIO_set_mem_eof_return(bio.get(), -1);

  // We only do reading as we abort the handshake early.
  SSL_set0_rbio(ssl_.get(), bssl::UpRef(bio).release());

  int ret = SSL_do_handshake(ssl_.get());

  // This should never succeed because an error is always returned from the SNI callback.
  ASSERT(ret <= 0);
  ParseState state = [this, ret]() {
    switch (SSL_get_error(ssl_.get(), ret)) {
    case SSL_ERROR_WANT_READ:
      if (read_ == maxConfigReadBytes()) {
        // We've hit the specified size limit. This is an unreasonably large ClientHello;
        // indicate failure.
        config_->stats().client_hello_too_large_.inc();
        return ParseState::Error;
      }
      if (read_ == requested_read_bytes_) {
        // Double requested bytes up to the maximum configured.
        requested_read_bytes_ = std::min<uint32_t>(2 * requested_read_bytes_, maxConfigReadBytes());
      }
      return ParseState::Continue;
    case SSL_ERROR_SSL:
      if (clienthello_success_) {
        config_->stats().tls_found_.inc();
        if (alpn_found_) {
          config_->stats().alpn_found_.inc();
        } else {
          config_->stats().alpn_not_found_.inc();
        }
        cb_->socket().setDetectedTransportProtocol("tls");
      } else {
        config_->stats().tls_not_found_.inc();
      }
      return ParseState::Done;
    default:
      return ParseState::Error;
    }
  }();

  if (state != ParseState::Continue) {
    // Record bytes analyzed as we're done processing.
    config_->stats().bytes_processed_.recordValue(
        computeClientHelloSize(bio.get(), bytes_already_processed, len));
  }

  return state;
}

// Google GREASE values (https://datatracker.ietf.org/doc/html/rfc8701)
static constexpr std::array<uint16_t, 16> GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
};

bool isNotGrease(uint16_t id) {
  return std::find(GREASE.begin(), GREASE.end(), id) == GREASE.end();
}

void writeCipherSuites(const SSL_CLIENT_HELLO* ssl_client_hello, std::string& fingerprint) {
  CBS cipher_suites;
  CBS_init(&cipher_suites, ssl_client_hello->cipher_suites, ssl_client_hello->cipher_suites_len);

  bool write_cipher = true;
  bool first = true;
  while (write_cipher && CBS_len(&cipher_suites) > 0) {
    uint16_t id;
    write_cipher = CBS_get_u16(&cipher_suites, &id);
    if (write_cipher && isNotGrease(id)) {
      if (!first) {
        absl::StrAppend(&fingerprint, "-");
      }
      absl::StrAppendFormat(&fingerprint, "%d", id);
      first = false;
    }
  }
}

void writeExtensions(const SSL_CLIENT_HELLO* ssl_client_hello, std::string& fingerprint) {
  CBS extensions;
  CBS_init(&extensions, ssl_client_hello->extensions, ssl_client_hello->extensions_len);

  bool write_extension = true;
  bool first = true;
  while (write_extension && CBS_len(&extensions) > 0) {
    uint16_t id;
    CBS extension;

    write_extension =
        (CBS_get_u16(&extensions, &id) && CBS_get_u16_length_prefixed(&extensions, &extension));
    if (write_extension && isNotGrease(id)) {
      if (!first) {
        absl::StrAppend(&fingerprint, "-");
      }
      absl::StrAppendFormat(&fingerprint, "%d", id);
      first = false;
    }
  }
}

void writeEllipticCurves(const SSL_CLIENT_HELLO* ssl_client_hello, std::string& fingerprint) {
  const uint8_t* ec_data;
  size_t ec_len;
  if (SSL_early_callback_ctx_extension_get(ssl_client_hello, TLSEXT_TYPE_supported_groups, &ec_data,
                                           &ec_len)) {
    CBS ec;
    CBS_init(&ec, ec_data, ec_len);

    // skip list length
    uint16_t id;
    bool write_elliptic_curve = CBS_get_u16(&ec, &id);

    bool first = true;
    while (write_elliptic_curve && CBS_len(&ec) > 0) {
      write_elliptic_curve = CBS_get_u16(&ec, &id);
      if (write_elliptic_curve) {
        if (!first) {
          absl::StrAppend(&fingerprint, "-");
        }
        absl::StrAppendFormat(&fingerprint, "%d", id);
        first = false;
      }
    }
  }
}

void writeEllipticCurvePointFormats(const SSL_CLIENT_HELLO* ssl_client_hello,
                                    std::string& fingerprint) {
  const uint8_t* ecpf_data;
  size_t ecpf_len;
  if (SSL_early_callback_ctx_extension_get(ssl_client_hello, TLSEXT_TYPE_ec_point_formats,
                                           &ecpf_data, &ecpf_len)) {
    CBS ecpf;
    CBS_init(&ecpf, ecpf_data, ecpf_len);

    // skip list length
    uint8_t id;
    bool write_point_format = CBS_get_u8(&ecpf, &id);

    bool first = true;
    while (write_point_format && CBS_len(&ecpf) > 0) {
      write_point_format = CBS_get_u8(&ecpf, &id);
      if (write_point_format) {
        if (!first) {
          absl::StrAppend(&fingerprint, "-");
        }
        absl::StrAppendFormat(&fingerprint, "%d", id);
        first = false;
      }
    }
  }
}

// Maps a TLS version uint16_t to its string representation.
absl::string_view mapVersionToString(uint16_t version) {
  switch (version) {
  case TLS1_3_VERSION:
    return "13";
  case TLS1_2_VERSION:
    return "12";
  case TLS1_1_VERSION:
    return "11";
  case TLS1_VERSION:
    return "10";
  default:
    return "00";
  }
}

absl::string_view getJA4TlsVersion(const SSL_CLIENT_HELLO* ssl_client_hello) {
  const uint8_t* data;
  size_t size;
  if (SSL_early_callback_ctx_extension_get(ssl_client_hello, TLSEXT_TYPE_supported_versions, &data,
                                           &size)) {
    CBS cbs;
    CBS_init(&cbs, data, size);
    CBS versions;

    if (!CBS_get_u8_length_prefixed(&cbs, &versions)) {
      return "00";
    }

    uint16_t highest_version = 0;
    uint16_t version;
    while (CBS_get_u16(&versions, &version)) {
      if (isNotGrease(version) && version > highest_version) {
        highest_version = version;
      }
    }

    if (highest_version != 0) {
      return mapVersionToString(highest_version);
    }
  }

  // Fallback to the protocol version if the supported_versions extension is not present
  return mapVersionToString(ssl_client_hello->version);
}

bool hasSNI(const SSL_CLIENT_HELLO* ssl_client_hello) {
  const uint8_t* data;
  size_t size;
  return SSL_early_callback_ctx_extension_get(ssl_client_hello, TLSEXT_TYPE_server_name, &data,
                                              &size);
}

int countCiphers(const SSL_CLIENT_HELLO* ssl_client_hello) {
  CBS cipher_suites;
  CBS_init(&cipher_suites, ssl_client_hello->cipher_suites, ssl_client_hello->cipher_suites_len);

  int count = 0;
  while (CBS_len(&cipher_suites) > 0) {
    uint16_t cipher;
    if (!CBS_get_u16(&cipher_suites, &cipher)) {
      break;
    }
    if (isNotGrease(cipher)) {
      count++;
    }
  }

  return count;
}

int countExtensions(const SSL_CLIENT_HELLO* ssl_client_hello) {
  CBS extensions;
  CBS_init(&extensions, ssl_client_hello->extensions, ssl_client_hello->extensions_len);

  int count = 0;
  while (CBS_len(&extensions) > 0) {
    uint16_t type;
    CBS extension;
    if (!CBS_get_u16(&extensions, &type) || !CBS_get_u16_length_prefixed(&extensions, &extension)) {
      break;
    }
    if (isNotGrease(type)) {
      count++;
    }
  }

  return count;
}

std::string formatTwoDigits(int value) { return absl::StrFormat("%02d", std::min(value, 99)); }

std::string getJA4AlpnChars(const SSL_CLIENT_HELLO* ssl_client_hello) {
  const uint8_t* data;
  size_t size;
  if (!SSL_early_callback_ctx_extension_get(
          ssl_client_hello, TLSEXT_TYPE_application_layer_protocol_negotiation, &data, &size)) {
    return "00";
  }

  CBS cbs;
  CBS_init(&cbs, data, size);
  uint16_t list_length;
  if (!CBS_get_u16(&cbs, &list_length) || CBS_len(&cbs) < 1) {
    return "00";
  }

  uint8_t proto_length;
  if (!CBS_get_u8(&cbs, &proto_length) || CBS_len(&cbs) < proto_length) {
    return "00";
  }

  const uint8_t* proto_data = CBS_data(&cbs);
  absl::string_view proto(reinterpret_cast<const char*>(proto_data), proto_length);

  if (proto.empty()) {
    return "00";
  }

  char first = proto[0];
  char last = proto[proto.length() - 1];
  if (!absl::ascii_isalnum(first) || !absl::ascii_isalnum(last)) {
    // Convert to hex if non-alphanumeric
    return absl::StrFormat("%02x%02x", static_cast<uint8_t>(first), static_cast<uint8_t>(last));
  }
  return absl::StrFormat("%c%c", first, last);
}

std::string getJA4CipherHash(const SSL_CLIENT_HELLO* ssl_client_hello) {
  CBS cipher_suites;
  CBS_init(&cipher_suites, ssl_client_hello->cipher_suites, ssl_client_hello->cipher_suites_len);

  std::vector<uint16_t> ciphers;
  // Each cipher suite is 2 bytes long, so we reserve half the length of the buffer
  ciphers.reserve(ssl_client_hello->cipher_suites_len / 2);
  while (CBS_len(&cipher_suites) > 0) {
    uint16_t cipher;
    if (!CBS_get_u16(&cipher_suites, &cipher)) {
      break;
    }
    if (isNotGrease(cipher)) {
      ciphers.push_back(cipher);
    }
  }

  if (ciphers.empty()) {
    return std::string(12, '0');
  }

  std::sort(ciphers.begin(), ciphers.end());

  std::string cipher_list;
  for (size_t i = 0; i < ciphers.size(); ++i) {
    if (i > 0) {
      absl::StrAppend(&cipher_list, ",");
    }
    absl::StrAppendFormat(&cipher_list, "%04x", ciphers[i]);
  }

  std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
  EVP_Digest(cipher_list.data(), cipher_list.length(), hash.data(), nullptr, EVP_sha256(), nullptr);

  return Hex::encode(hash.data(), JA4_HASH_LENGTH / 2);
}

std::string getJA4ExtensionHash(const SSL_CLIENT_HELLO* ssl_client_hello) {
  std::vector<uint16_t> extensions;
  std::vector<uint16_t> sig_algs;
  CBS exts;
  CBS_init(&exts, ssl_client_hello->extensions, ssl_client_hello->extensions_len);

  while (CBS_len(&exts) > 0) {
    uint16_t type;
    CBS extension;
    if (!CBS_get_u16(&exts, &type) || !CBS_get_u16_length_prefixed(&exts, &extension)) {
      break;
    }

    if (isNotGrease(type) && type != TLSEXT_TYPE_server_name &&
        type != TLSEXT_TYPE_application_layer_protocol_negotiation) {
      extensions.push_back(type);

      // Collect signature algorithms
      if (type == TLSEXT_TYPE_signature_algorithms) {
        CBS sig_alg_data;
        CBS_init(&sig_alg_data, CBS_data(&extension), CBS_len(&extension));
        uint16_t sig_alg_len;
        if (CBS_get_u16(&sig_alg_data, &sig_alg_len)) {
          while (CBS_len(&sig_alg_data) >= 2) {
            uint16_t sig_alg;
            if (!CBS_get_u16(&sig_alg_data, &sig_alg)) {
              break;
            }
            sig_algs.push_back(sig_alg);
          }
        }
      }
    }
  }

  if (extensions.empty()) {
    return std::string(12, '0');
  }

  std::sort(extensions.begin(), extensions.end());

  std::string extension_list;
  for (size_t i = 0; i < extensions.size(); ++i) {
    if (i > 0) {
      absl::StrAppend(&extension_list, ",");
    }
    absl::StrAppendFormat(&extension_list, "%04x", extensions[i]);
  }

  if (!sig_algs.empty()) {
    absl::StrAppend(&extension_list, "_");
    for (size_t i = 0; i < sig_algs.size(); ++i) {
      if (i > 0) {
        absl::StrAppend(&extension_list, ",");
      }
      absl::StrAppendFormat(&extension_list, "%04x", sig_algs[i]);
    }
  }

  std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
  EVP_Digest(extension_list.data(), extension_list.length(), hash.data(), nullptr, EVP_sha256(),
             nullptr);

  return Hex::encode(hash.data(), JA4_HASH_LENGTH / 2);
}

void Filter::createJA3Hash(const SSL_CLIENT_HELLO* ssl_client_hello) {
  if (config_->enableJA3Fingerprinting()) {
    std::string fingerprint;
    const uint16_t client_version = ssl_client_hello->version;
    absl::StrAppendFormat(&fingerprint, "%d,", client_version);
    writeCipherSuites(ssl_client_hello, fingerprint);
    absl::StrAppend(&fingerprint, ",");
    writeExtensions(ssl_client_hello, fingerprint);
    absl::StrAppend(&fingerprint, ",");
    writeEllipticCurves(ssl_client_hello, fingerprint);
    absl::StrAppend(&fingerprint, ",");
    writeEllipticCurvePointFormats(ssl_client_hello, fingerprint);

    ENVOY_LOG(trace, "tls:createJA3Hash(), fingerprint: {}", fingerprint);

    uint8_t buf[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const uint8_t*>(fingerprint.data()), fingerprint.size(), buf);
    std::string md5 = Envoy::Hex::encode(buf, MD5_DIGEST_LENGTH);
    ENVOY_LOG(trace, "tls:createJA3Hash(), hash: {}", md5);

    cb_->socket().setJA3Hash(md5);
  }
}

void Filter::createJA4Hash(const SSL_CLIENT_HELLO* ssl_client_hello) {
  if (!config_->enableJA4Fingerprinting()) {
    return;
  }

  std::string fingerprint;
  absl::StrAppend(&fingerprint,
                  // Protocol type (t for TLS, q for QUIC, d for `DTLS`)
                  // In this implementation, we only handle TLS
                  "t",

                  // TLS Version
                  getJA4TlsVersion(ssl_client_hello),

                  // SNI presence
                  hasSNI(ssl_client_hello) ? "d" : "i",

                  // Cipher count
                  formatTwoDigits(countCiphers(ssl_client_hello)),

                  // Extension count
                  formatTwoDigits(countExtensions(ssl_client_hello)),

                  // ALPN first/last chars
                  getJA4AlpnChars(ssl_client_hello),

                  // Separator
                  "_",

                  // Cipher hash
                  getJA4CipherHash(ssl_client_hello),

                  // Separator
                  "_",

                  // Extension and signature algorithm hash
                  getJA4ExtensionHash(ssl_client_hello));

  ENVOY_LOG(trace, "tls:createJA4Hash(), fingerprint: {}", fingerprint);
  cb_->socket().setJA4Hash(fingerprint);
}

} // namespace TlsInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
