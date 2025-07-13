#pragma once

#include <sys/types.h>

#include <string_view>

#include "source/common/buffer/buffer_impl.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Postgres {

/**
 * Helper function to create a PostgreSQL ErrorResponse message.
 * For error response message format see
 * https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-ERRORRESPONSE
 * For error field code see https://www.postgresql.org/docs/current/protocol-error-fields.html
 * error_code is a string of 5 characters. See
 * https://www.postgresql.org/docs/current/errcodes-appendix.html
 * @param error_code PostgreSQL error severity code
 * @param sql_state SQL state code (5 characters)
 * @param error_message Human-readable error message
 * @param detail_message Additional detail message (optional)
 * @return Buffer containing the PostgreSQL ErrorResponse message
 */
Buffer::OwnedImpl createPostgresErrorResponse(int16_t error_code, absl::string_view sql_state,
                                              absl::string_view error_message,
                                              absl::string_view detail_message);

} // namespace Postgres
} // namespace Common
} // namespace Extensions
} // namespace Envoy
