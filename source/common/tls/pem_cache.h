#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/singleton/instance.h"
#include "envoy/singleton/manager.h"

#include "source/common/common/thread.h"

#include "absl/algorithm/container.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "openssl/sha.h"
#include "openssl/ssl.h"
#include "openssl/x509v3.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

// Base of every cached entry. Holds the owning cache alive for as long as the entry is referenced,
// so a caller only has to keep the entry.
struct PemCacheEntry {
  std::shared_ptr<Singleton::Instance> cache;
};

// Process-wide cache that parses each distinct PEM blob once and shares the parsed representation
// with every TLS context that references identical content. Without this, material referenced from
// many `common_tls_context`s is parsed and held once per context, which for a large trust bundle or
// CRL dominates a context's memory, and for a cluster carrying a certificate per endpoint grows
// config apply time with the number of transport socket matches.
//
// Threading and lifetime model (mirrors SharedPool::ObjectSharedPool):
//   - All methods must be called on the main (or test) thread. TLS context creation, the only
//     caller, is confined to that thread.
//   - Only a weak_ptr is stored, so an entry is released as soon as the last context referencing it
//     is destroyed (for example after an xDS update). Each entry holds a shared_ptr back to this
//     cache, so the cache outlives every entry handed out from it.
//   - The parsed BoringSSL structures are reference counted. Each SSL_CTX or X509_STORE they are
//     bound to holds its own reference, so they stay valid for that context's lifetime independent
//     of this cache. Only the immutable parsed material is shared, so a context keeps its own store
//     and therefore its own store flags.
template <class Entry>
class PemCache : public Singleton::Instance, public std::enable_shared_from_this<PemCache<Entry>> {
public:
  using EntrySharedPtr = std::shared_ptr<Entry>;

  // Returns the shared parsed representation of `pem`, calling Entry::parse() on first use and
  // returning its error if the blob cannot be parsed. `path` is only used to build that error.
  absl::StatusOr<EntrySharedPtr> getOrCreate(const std::string& pem, const std::string& path) {
    ASSERT_IS_MAIN_OR_TEST_THREAD();

    // Key by a SHA-256 digest of the PEM rather than the PEM itself, to avoid holding a second full
    // copy of potentially large material. SHA-256 is collision resistant, so distinct blobs never
    // share an entry.
    std::array<uint8_t, SHA256_DIGEST_LENGTH> key;
    SHA256(reinterpret_cast<const uint8_t*>(pem.data()), pem.size(), key.data());

    if (auto it = cache_.find(key); it != cache_.end()) {
      if (EntrySharedPtr existing = it->second.lock(); existing != nullptr) {
        return existing;
      }
    }

    // Only reached when a new distinct blob is seen, which is uncommon. Release entries whose last
    // referencing context has been torn down so the map does not grow without bound across xDS
    // updates.
    absl::erase_if(cache_, [](const auto& entry) { return entry.second.expired(); });

    absl::StatusOr<EntrySharedPtr> entry = Entry::parse(pem, path);
    RETURN_IF_NOT_OK_REF(entry.status());
    (*entry)->cache = this->shared_from_this();
    cache_[key] = *entry;
    return entry;
  }

  // Number of distinct blobs currently referenced by at least one context. Exposed for testing.
  size_t size() const {
    ASSERT_IS_MAIN_OR_TEST_THREAD();
    return absl::c_count_if(cache_, [](const auto& entry) { return !entry.second.expired(); });
  }

private:
  absl::flat_hash_map<std::array<uint8_t, SHA256_DIGEST_LENGTH>, std::weak_ptr<Entry>> cache_;
};

// Parses `pem` through `cache` when one is given, and for this caller alone when it is absent.
template <class Entry>
absl::StatusOr<std::shared_ptr<Entry>> getOrParsePem(PemCache<Entry>* cache, const std::string& pem,
                                                     const std::string& path) {
  return cache != nullptr ? cache->getOrCreate(pem, path) : Entry::parse(pem, path);
}

// The CRLs parsed from a single CRL PEM blob. A blob may carry more than one CRL.
struct CrlList : public PemCacheEntry {
  std::vector<bssl::UniquePtr<X509_CRL>> crls;

  static absl::StatusOr<std::shared_ptr<CrlList>> parse(const std::string& pem,
                                                        const std::string& path);
};
using CrlListSharedPtr = std::shared_ptr<CrlList>;
using CrlCache = PemCache<CrlList>;

// The certificates parsed from a single trusted CA PEM blob, plus any CRLs it carries, since a
// trusted CA blob is allowed to hold both.
struct CaCertList : public PemCacheEntry {
  std::vector<bssl::UniquePtr<X509>> certs;
  std::vector<bssl::UniquePtr<X509_CRL>> crls;

  // Returns an error if the blob cannot be parsed or carries no certificate.
  static absl::StatusOr<std::shared_ptr<CaCertList>> parse(const std::string& pem,
                                                           const std::string& path);
};
using CaCertListSharedPtr = std::shared_ptr<CaCertList>;
using CaCertCache = PemCache<CaCertList>;

// The local certificate chain parsed from a single certificate-chain PEM blob, the leaf plus any
// intermediates.
struct CertChain : public PemCacheEntry {
  bssl::UniquePtr<X509> leaf;
  std::vector<bssl::UniquePtr<X509>> intermediates;

  // Returns an error if the blob cannot be parsed or carries no leaf certificate.
  static absl::StatusOr<std::shared_ptr<CertChain>> parse(const std::string& pem,
                                                          const std::string& path);
};
using CertChainSharedPtr = std::shared_ptr<CertChain>;
using CertChainCache = PemCache<CertChain>;

// The private key parsed from a single private-key PEM blob.
struct ParsedPrivateKey : public PemCacheEntry {
  bssl::UniquePtr<EVP_PKEY> pkey;

  // `password` is always empty for the material a cache holds, since the digest it keys on covers
  // the blob but not the password, so a password protected key is never shared.
  static absl::StatusOr<std::shared_ptr<ParsedPrivateKey>>
  parse(const std::string& pem, const std::string& path, const std::string& password = "");
};
using ParsedPrivateKeySharedPtr = std::shared_ptr<ParsedPrivateKey>;
using PrivateKeyCache = PemCache<ParsedPrivateKey>;

// The process-wide caches, each created on first use.
std::shared_ptr<CrlCache> getCrlCache(Singleton::Manager& singleton_manager);
std::shared_ptr<CaCertCache> getCaCertCache(Singleton::Manager& singleton_manager);
std::shared_ptr<CertChainCache> getCertChainCache(Singleton::Manager& singleton_manager);
std::shared_ptr<PrivateKeyCache> getPrivateKeyCache(Singleton::Manager& singleton_manager);

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
