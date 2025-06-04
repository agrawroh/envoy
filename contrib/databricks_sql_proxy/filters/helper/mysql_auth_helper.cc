#include "contrib/databricks_sql_proxy/filters/helper/mysql_auth_helper.h"

#include <cstring>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

MySQLAuthHelper::SHA1Hash
MySQLAuthHelper::extractPasswordHash(const std::vector<uint8_t>& client_response,
                                     const std::vector<uint8_t>& server_scramble,
                                     const SHA1Hash& double_hashed_password) {

  // Validate input sizes
  if (client_response.size() != SHA1_HASH_SIZE || server_scramble.size() != SHA1_HASH_SIZE) {
    ENVOY_LOG(debug, "mysql_auth: invalid input sizes for password extraction");
    return SHA1Hash{};
  }

  // Compute SHA1(scramble + SHA1(SHA1(password)))
  std::vector<uint8_t> concat_data;
  concat_data.reserve(server_scramble.size() + SHA1_HASH_SIZE);
  concat_data.insert(concat_data.end(), server_scramble.begin(), server_scramble.end());
  concat_data.insert(concat_data.end(), double_hashed_password.begin(),
                     double_hashed_password.end());

  SHA1Hash scramble_hash = computeSHA1(concat_data.data(), concat_data.size());

  // Extract SHA1(password) = client_response XOR scramble_hash
  SHA1Hash password_hash;
  for (size_t i = 0; i < SHA1_HASH_SIZE; ++i) {
    password_hash[i] = client_response[i] ^ scramble_hash[i];
  }

  ENVOY_LOG(trace, "mysql_auth: extracted password hash");
  return password_hash;
}

std::vector<uint8_t> MySQLAuthHelper::computeAuthResponse(const SHA1Hash& password_hash,
                                                          const std::vector<uint8_t>& scramble,
                                                          const SHA1Hash& double_hashed_password) {

  if (scramble.size() != SHA1_HASH_SIZE) {
    ENVOY_LOG(error, "mysql_auth: invalid scramble size: {}", scramble.size());
    return std::vector<uint8_t>(SHA1_HASH_SIZE, 0);
  }

  // Compute SHA1(scramble + SHA1(SHA1(password)))
  std::vector<uint8_t> concat_data;
  concat_data.reserve(scramble.size() + SHA1_HASH_SIZE);
  concat_data.insert(concat_data.end(), scramble.begin(), scramble.end());
  concat_data.insert(concat_data.end(), double_hashed_password.begin(),
                     double_hashed_password.end());

  SHA1Hash scramble_hash = computeSHA1(concat_data.data(), concat_data.size());

  // Compute response = SHA1(password) XOR scramble_hash
  std::vector<uint8_t> response(SHA1_HASH_SIZE);
  for (size_t i = 0; i < SHA1_HASH_SIZE; ++i) {
    response[i] = password_hash[i] ^ scramble_hash[i];
  }

  return response;
}

bool MySQLAuthHelper::isNativePasswordResponse(const std::vector<uint8_t>& auth_response) {
  // mysql_native_password always produces 20-byte responses
  return auth_response.size() == SHA1_HASH_SIZE;
}

MySQLAuthHelper::SHA1Hash MySQLAuthHelper::computeSHA1(const uint8_t* data, size_t length) {
  SHA1Hash result;
  SHA_CTX ctx;
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, data, length);
  SHA1_Final(result.data(), &ctx);
  return result;
}

MySQLAuthHelper::SHA1Hash MySQLAuthHelper::xorHashes(const SHA1Hash& a, const SHA1Hash& b) {
  SHA1Hash result;
  for (size_t i = 0; i < SHA1_HASH_SIZE; ++i) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
