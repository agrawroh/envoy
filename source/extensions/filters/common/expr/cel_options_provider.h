#pragma once

#include "envoy/config/bootstrap/v3/cel.pb.h"
#include "envoy/singleton/instance.h"

namespace Envoy {
namespace Extensions {
namespace Filters {
namespace Common {
namespace Expr {

/**
 * Provider for CEL extension options that can be used across the codebase.
 */
class CelOptionsProvider : public Singleton::Instance {
public:
  /**
   * The singleton name used to register the provider.
   */
  static constexpr char name[] = "cel_options_provider";

  /**
   * Update the options from bootstrap config.
   * @param options The CEL extension options to use.
   */
  void setOptions(const envoy::config::bootstrap::v3::CelExtensionOptions& options) {
    options_ = options;
  }

  /**
   * Get current options.
   * @return The current CEL extension options.
   */
  const envoy::config::bootstrap::v3::CelExtensionOptions& options() const { return options_; }

private:
  envoy::config::bootstrap::v3::CelExtensionOptions options_;
};

} // namespace Expr
} // namespace Common
} // namespace Filters
} // namespace Extensions
} // namespace Envoy
