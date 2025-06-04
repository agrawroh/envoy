#pragma once

#include <array>
#include <memory>
#include <string>
#include <vector>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"

#include "openssl/sha.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

/**
 * Helper class for MySQL native password authentication.
 * Implements the mysql_native_password authentication protocol.
 */
class MySQLAuthHelper : public Logger::Loggable<Logger::Id::filter> {
public:
  static constexpr uint32_t SHA1_HASH_SIZE = 20;
  using SHA1Hash = std::array<uint8_t, SHA1_HASH_SIZE>;

  /**
   * Extracts SHA1(password) from client authentication response.
   *
   * @param client_response The 20-byte response from client
   * @param server_scramble The 20-byte scramble sent by server
   * @param double_hashed_password SHA1(SHA1(password)) from mysql.user table
   * @return SHA1(password) if extraction successful, empty array otherwise
   */
  static SHA1Hash extractPasswordHash(const std::vector<uint8_t>& client_response,
                                      const std::vector<uint8_t>& server_scramble,
                                      const SHA1Hash& double_hashed_password);

  /**
   * Computes authentication response for mysql_native_password.
   *
   * @param password_hash SHA1(password)
   * @param scramble Server's scramble buffer (20 bytes)
   * @param double_hashed_password SHA1(SHA1(password))
   * @return 20-byte authentication response
   */
  static std::vector<uint8_t> computeAuthResponse(const SHA1Hash& password_hash,
                                                  const std::vector<uint8_t>& scramble,
                                                  const SHA1Hash& double_hashed_password);

  /**
   * Validates if auth response is for mysql_native_password.
   *
   * @param auth_response The authentication response data
   * @return true if this appears to be mysql_native_password response
   */
  static bool isNativePasswordResponse(const std::vector<uint8_t>& auth_response);

  /**
   * Computes SHA1 hash of input data.
   */
  static SHA1Hash computeSHA1(const uint8_t* data, size_t length);

  /**
   * XOR two SHA1 hashes.
   */
  static SHA1Hash xorHashes(const SHA1Hash& a, const SHA1Hash& b);
};

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
