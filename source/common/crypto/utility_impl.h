#pragma once

#include "source/common/crypto/utility.h"

#include "openssl/bytestring.h"
#include "openssl/hmac.h"
#include "openssl/sha.h"

namespace Envoy {
namespace Common {
namespace Crypto {

class UtilityImpl : public Envoy::Common::Crypto::Utility {
public:
  std::vector<uint8_t> getSha256Digest(const Buffer::Instance& buffer) override;
  std::vector<uint8_t> getSha256Hmac(const std::vector<uint8_t>& key,
                                     absl::string_view message) override;
  const EncryptionDecryptionOutput encryptSymmetric(const std::vector<uint8_t>& key,
                                                    const std::vector<uint8_t>& plaintext) override;
  const EncryptionDecryptionOutput
  decryptSymmetric(const std::vector<uint8_t>& key,
                   const std::vector<uint8_t>& ciphertext) override;
  const VerificationOutput verifySignature(absl::string_view hash, CryptoObject& key,
                                           const std::vector<uint8_t>& signature,
                                           const std::vector<uint8_t>& text) override;
  const EncryptionDecryptionOutput decrypt(CryptoObject& key,
                                           const std::vector<uint8_t>& cipher_text) override;
  const EncryptionDecryptionOutput encrypt(CryptoObject& key,
                                           const std::vector<uint8_t>& plaintext) override;
  CryptoObjectPtr importPublicKey(const std::vector<uint8_t>& key) override;
  CryptoObjectPtr importPrivateKey(const std::vector<uint8_t>& key) override;

private:
  const EVP_MD* getHashFunction(absl::string_view name);
};

} // namespace Crypto
} // namespace Common
} // namespace Envoy
