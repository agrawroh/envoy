#include "source/common/tls/pem_cache.h"

#include "source/common/common/assert.h"
#include "source/common/common/fmt.h"
#include "source/common/tls/utility.h"

#include "absl/strings/str_cat.h"
#include "openssl/err.h"
#include "openssl/pem.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

SINGLETON_MANAGER_REGISTRATION(crl_cache);
SINGLETON_MANAGER_REGISTRATION(ca_cert_cache);
SINGLETON_MANAGER_REGISTRATION(cert_chain_cache);
SINGLETON_MANAGER_REGISTRATION(private_key_cache);

namespace {

bssl::UniquePtr<BIO> memBio(const std::string& pem) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(const_cast<char*>(pem.data()), pem.size()));
  RELEASE_ASSERT(bio != nullptr, "");
  return bio;
}

// Reads a PEM blob carrying certificates, CRLs or both. Based on BoringSSL's
// X509_load_cert_crl_file().
bssl::UniquePtr<STACK_OF(X509_INFO)> readPemInfo(const std::string& pem) {
  return bssl::UniquePtr<STACK_OF(X509_INFO)>(
      PEM_X509_INFO_read_bio(memBio(pem).get(), nullptr, nullptr, nullptr));
}

} // namespace

absl::StatusOr<CrlListSharedPtr> CrlList::parse(const std::string& pem, const std::string& path) {
  bssl::UniquePtr<STACK_OF(X509_INFO)> list = readPemInfo(pem);
  if (list == nullptr) {
    return absl::InvalidArgumentError(absl::StrCat("Failed to load CRL from ", path));
  }
  auto crl_list = std::make_shared<CrlList>();
  for (const X509_INFO* item : list.get()) {
    if (item->crl) {
      crl_list->crls.push_back(bssl::UpRef(item->crl));
    }
  }
  return crl_list;
}

absl::StatusOr<CaCertListSharedPtr> CaCertList::parse(const std::string& pem,
                                                      const std::string& path) {
  bssl::UniquePtr<STACK_OF(X509_INFO)> list = readPemInfo(pem);
  if (list == nullptr) {
    return absl::InvalidArgumentError(
        absl::StrCat("Failed to load trusted CA certificates from ", path));
  }
  auto ca_cert_list = std::make_shared<CaCertList>();
  for (const X509_INFO* item : list.get()) {
    if (item->x509) {
      ca_cert_list->certs.push_back(bssl::UpRef(item->x509));
    }
    if (item->crl) {
      ca_cert_list->crls.push_back(bssl::UpRef(item->crl));
    }
  }
  // A blob that parses but carries no certificate is not a usable trust bundle.
  if (ca_cert_list->certs.empty()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Failed to load trusted CA certificates from ", path));
  }
  return ca_cert_list;
}

absl::StatusOr<CertChainSharedPtr> CertChain::parse(const std::string& pem,
                                                    const std::string& path) {
  auto error = [&path]() {
    return absl::InvalidArgumentError(absl::StrCat("Failed to load certificate chain from ", path));
  };
  bssl::UniquePtr<BIO> bio = memBio(pem);
  auto cert_chain = std::make_shared<CertChain>();
  // The leaf carries trust settings, so read it with the AUX variant. Anything after it is the
  // intermediate chain.
  cert_chain->leaf.reset(PEM_read_bio_X509_AUX(bio.get(), nullptr, nullptr, nullptr));
  if (cert_chain->leaf == nullptr) {
    return error();
  }
  while (true) {
    bssl::UniquePtr<X509> cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (cert == nullptr) {
      break;
    }
    cert_chain->intermediates.push_back(std::move(cert));
  }
  // The read that ended the loop pushed an error. "No start line" is just EOF after the last
  // certificate. Any other reason is a real parse failure.
  const uint32_t err = ERR_peek_last_error();
  if (ERR_GET_LIB(err) != ERR_LIB_PEM || ERR_GET_REASON(err) != PEM_R_NO_START_LINE) {
    return error();
  }
  ERR_clear_error();
  return cert_chain;
}

absl::StatusOr<ParsedPrivateKeySharedPtr> ParsedPrivateKey::parse(const std::string& pem,
                                                                  const std::string& path,
                                                                  const std::string& password) {
  auto parsed_key = std::make_shared<ParsedPrivateKey>();
  parsed_key->pkey.reset(
      PEM_read_bio_PrivateKey(memBio(pem).get(), nullptr, nullptr,
                              !password.empty() ? const_cast<char*>(password.c_str()) : nullptr));
  if (parsed_key->pkey == nullptr) {
    return absl::InvalidArgumentError(
        fmt::format("Failed to load private key from {}, Cause: {}", path,
                    Utility::getLastCryptoError().value_or("unknown")));
  }
  return parsed_key;
}

std::shared_ptr<CrlCache> getCrlCache(Singleton::Manager& singleton_manager) {
  return singleton_manager.getTyped<CrlCache>(SINGLETON_MANAGER_REGISTERED_NAME(crl_cache),
                                              [] { return std::make_shared<CrlCache>(); });
}

std::shared_ptr<CaCertCache> getCaCertCache(Singleton::Manager& singleton_manager) {
  return singleton_manager.getTyped<CaCertCache>(SINGLETON_MANAGER_REGISTERED_NAME(ca_cert_cache),
                                                 [] { return std::make_shared<CaCertCache>(); });
}

std::shared_ptr<CertChainCache> getCertChainCache(Singleton::Manager& singleton_manager) {
  return singleton_manager.getTyped<CertChainCache>(
      SINGLETON_MANAGER_REGISTERED_NAME(cert_chain_cache),
      [] { return std::make_shared<CertChainCache>(); });
}

std::shared_ptr<PrivateKeyCache> getPrivateKeyCache(Singleton::Manager& singleton_manager) {
  return singleton_manager.getTyped<PrivateKeyCache>(
      SINGLETON_MANAGER_REGISTERED_NAME(private_key_cache),
      [] { return std::make_shared<PrivateKeyCache>(); });
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
