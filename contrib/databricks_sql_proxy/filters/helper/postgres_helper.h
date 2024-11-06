#pragma once

#include <sys/types.h>

#include <string_view>

#include "source/common/buffer/buffer_impl.h"

namespace Envoy {
namespace Extensions {
namespace DatabricksSqlProxy {
namespace Helper {

// Helper function to create a Postgres ErrorResponse message.
// For error response message format see
// https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-ERRORRESPONSE
// For error field code see https://www.postgresql.org/docs/current/protocol-error-fields.html
// error_code is a string of 5 characters. See
// https://www.postgresql.org/docs/current/errcodes-appendix.html
Buffer::OwnedImpl createPostgresErrorResponse(int16_t error_code, absl::string_view sql_state,
                                              absl::string_view error_message,
                                              absl::string_view detail_message);

} // namespace Helper
} // namespace DatabricksSqlProxy
} // namespace Extensions
} // namespace Envoy
