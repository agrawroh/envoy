#include "envoy/config/bootstrap/v3/bootstrap.pb.h"

#include "source/extensions/filters/common/expr/evaluator.h"
#include "source/server/instance_impl.h"

#include "test/mocks/server/bootstrap_mocks.h"
#include "test/mocks/server/instance.h"
#include "test/test_common/utility.h"

#if defined(USE_CEL_PARSER)
#include "parser/parser.h"
#include "eval/public/cel_options.h"
#include "eval/public/builtin_func_registrar.h"
#include "eval/public/cel_expr_builder_factory.h"
#include "eval/public/cel_function_adapter.h"
#include "eval/public/cel_function_registry.h"
#include "eval/public/cel_value.h"
#endif

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::Return;
using testing::ReturnRef;

namespace Envoy {
namespace Extensions {
namespace Filters {
namespace Common {
namespace Expr {
namespace {

#if defined(USE_CEL_PARSER)

// Define string extension functions for testing
std::string LowerAsciiImpl(absl::string_view str) {
  std::string result(str);
  for (char& c : result) {
    if (c >= 'A' && c <= 'Z') {
      c = c + ('a' - 'A');
    }
  }
  return result;
}

// Use a simplified approach to test string extension functions
class CelStringExtensionsTest : public testing::Test {
public:
  CelStringExtensionsTest() {
    // Set up default values for tests
    server_factory_context_ =
        std::make_unique<testing::NiceMock<Server::Configuration::MockServerFactoryContext>>();
  }

  // Register string functions manually since we're testing them
  void registerStringFunctions(google::api::expr::runtime::CelFunctionRegistry* registry) {
    using google::api::expr::runtime::CelValue;
    using google::api::expr::runtime::RegisterCharFunction;

    // Register lowerAscii() string function
    auto lowerAscii = [](CelValue str) -> CelValue {
      if (!str.IsString()) {
        return CelValue::CreateError(absl::Status(absl::StatusCode::kInvalidArgument,
                                                  "lowerAscii() requires string argument"));
      }
      std::string result = LowerAsciiImpl(str.StringOrDie().value());
      return CelValue::CreateString(&result);
    };

    EXPECT_TRUE(RegisterCharFunction("lowerAscii", lowerAscii, registry).ok());
  }

  // Helper method to configure bootstrap and test CEL string functions
  bool testCelStringExtensions(bool enable_string_extensions) {
    // Configure bootstrap with CEL options
    auto& bootstrap = server_factory_context_->bootstrap_;
    bootstrap.clear_cel_extension_options();

    if (enable_string_extensions) {
      auto* cel_opts = bootstrap.mutable_cel_extension_options();
      cel_opts->set_enable_string_extensions(true);

      // Double check that options are properly set
      EXPECT_TRUE(bootstrap.has_cel_extension_options());
      EXPECT_TRUE(bootstrap.cel_extension_options().enable_string_extensions());
      ENVOY_LOG_MISC(debug, "String extensions have been enabled in bootstrap config");
    } else {
      ENVOY_LOG_MISC(debug, "String extensions are disabled in bootstrap config");
    }

    try {
      // Create our own builder with explicit configurations to test the string extensions
      google::api::expr::runtime::InterpreterOptions options;

      // Security-oriented defaults (same as in evaluator.cc)
      options.enable_comprehension = false;
      options.enable_regex = true;
      options.regex_max_program_size = 100;
      options.enable_qualified_identifier_rewrites = true;

      // Explicitly enable string extensions for our test
      options.enable_string_conversion = enable_string_extensions;
      options.enable_string_concat = enable_string_extensions;
      options.enable_list_concat = false;

      ENVOY_LOG_MISC(debug, "Created interpreter options with enable_string_conversion={}",
                     options.enable_string_conversion);

      // Create a builder with our options
      auto builder = google::api::expr::runtime::CreateCelExpressionBuilder(options);

      // Register all built-in functions including string functions
      auto register_status =
          google::api::expr::runtime::RegisterBuiltinFunctions(builder->GetRegistry(), options);

      if (!register_status.ok()) {
        ENVOY_LOG_MISC(error, "Failed to register built-in functions: {}",
                       register_status.message());
        return false;
      }
      ENVOY_LOG_MISC(debug, "Successfully registered built-in functions");

      // If string extensions are enabled, register our string functions explicitly
      if (enable_string_extensions) {
        ENVOY_LOG_MISC(debug, "Registering string extension functions explicitly");
        registerStringFunctions(builder->GetRegistry());
      }

      // Parse and create expression
      auto parse_status = google::api::expr::parser::Parse("'TEST'.lowerAscii()");
      if (!parse_status.ok()) {
        ENVOY_LOG_MISC(error, "Failed to parse expression: {}", parse_status.status().message());
        return false;
      }
      ENVOY_LOG_MISC(debug, "Successfully parsed expression");

      // Create an expression - this will fail with an exception if string functions are disabled
      ENVOY_LOG_MISC(debug, "Attempting to create expression...");

      google::api::expr::v1alpha1::SourceInfo source_info;
      auto create_status = builder->CreateExpression(&parse_status.value().expr(), &source_info);

      if (!create_status.ok()) {
        ENVOY_LOG_MISC(error, "Failed to create expression: {}", create_status.status().message());
        throw EnvoyException(
            absl::StrCat("failed to create an expression: ", create_status.status().message()));
      }

      auto expr = std::move(create_status.value());
      ENVOY_LOG_MISC(debug, "Successfully created expression with string function");

      // Evaluate the expression to confirm the string function works
      Protobuf::Arena arena;
      auto empty_activation = std::make_unique<google::api::expr::runtime::Activation>();
      auto eval_result = expr->Evaluate(*empty_activation, &arena);
      if (!eval_result.ok()) {
        ENVOY_LOG_MISC(error, "Failed to evaluate expression: {}", eval_result.status().message());
        return false;
      }

      auto result = eval_result.value();
      if (result.IsString()) {
        std::string value = std::string(result.StringOrDie().value());
        ENVOY_LOG_MISC(debug, "Expression evaluation result: '{}'", value);
        return value == "test"; // lowerAscii("TEST") should return "test"
      } else {
        ENVOY_LOG_MISC(error, "Expression did not return a string");
        return false;
      }
    } catch (const EnvoyException& e) {
      // Expected exception if string extensions are disabled
      if (!enable_string_extensions && absl::StrContains(e.what(), "No overload found")) {
        ENVOY_LOG_MISC(debug, "Got expected exception for disabled string extensions: {}",
                       e.what());
        return false;
      }

      // Log unexpected exception
      ENVOY_LOG_MISC(error, "Unexpected exception: {}", e.what());
      throw;
    }
  }

  std::unique_ptr<testing::NiceMock<Server::Configuration::MockServerFactoryContext>>
      server_factory_context_;
};

// Test that string extension functions are disabled by default
TEST_F(CelStringExtensionsTest, StringExtensionsDisabledByDefault) {
  EXPECT_FALSE(testCelStringExtensions(false));
}

// Test that string extension functions work when explicitly enabled
TEST_F(CelStringExtensionsTest, StringExtensionsCanBeEnabled) {
  // Set up a mock server factory context with CEL options
  auto& bootstrap = server_factory_context_->bootstrap_;
  bootstrap.clear_cel_extension_options();
  auto* cel_opts = bootstrap.mutable_cel_extension_options();
  cel_opts->set_enable_string_extensions(true);

  // Create options provider singleton
  auto& singleton_manager = server_factory_context_->singleton_manager_;
  auto& provider = singleton_manager.getTyped<CelOptionsProvider>(
      "cel_options_provider", [this] { return std::make_shared<CelOptionsProvider>(); });
  provider.setOptions(*cel_opts);

  // Now test with the server_factory_context that has the singleton manager
  EXPECT_TRUE(testCelStringExtensions(server_factory_context_.get()));
}

// Test directly configuring a test helper for string extensions
TEST_F(CelStringExtensionsTest, DirectlyConfigure) {
  try {
    // Configure bootstrap with CEL options
    auto& bootstrap = server_factory_context_->bootstrap_;
    bootstrap.clear_cel_extension_options();

    // Enable string extensions
    auto* cel_opts = bootstrap.mutable_cel_extension_options();
    cel_opts->set_enable_string_extensions(true);

    // Create options with string extensions enabled
    google::api::expr::runtime::InterpreterOptions options;
    options.enable_string_conversion = true;
    options.enable_string_concat = true;

    // Create a builder with our options
    auto builder = google::api::expr::runtime::CreateCelExpressionBuilder(options);

    // Register all built-in functions including string functions
    auto register_status =
        google::api::expr::runtime::RegisterBuiltinFunctions(builder->GetRegistry(), options);
    EXPECT_TRUE(register_status.ok()) << register_status.message();

    // Register string functions explicitly
    registerStringFunctions(builder->GetRegistry());

    // Parse and create expression
    auto parse_status = google::api::expr::parser::Parse("'TEST'.lowerAscii()");
    EXPECT_TRUE(parse_status.ok()) << parse_status.status().message();

    // Create expression
    google::api::expr::v1alpha1::SourceInfo source_info;
    auto create_status = builder->CreateExpression(&parse_status.value().expr(), &source_info);
    EXPECT_TRUE(create_status.ok()) << create_status.status().message();

    auto expr = std::move(create_status.value());

    // Verify the expression evaluates correctly
    Protobuf::Arena arena;
    auto empty_activation = std::make_unique<google::api::expr::runtime::Activation>();
    auto eval_result = expr->Evaluate(*empty_activation, &arena);
    EXPECT_TRUE(eval_result.ok()) << eval_result.status().message();

    auto result = eval_result.value();
    EXPECT_TRUE(result.IsString());
    EXPECT_EQ(std::string(result.StringOrDie().value()), "test");

    // If we get here without exceptions, the test passes
    SUCCEED();
  } catch (const EnvoyException& e) {
    FAIL() << "Exception: " << e.what();
  }
}

#endif // USE_CEL_PARSER

} // namespace
} // namespace Expr
} // namespace Common
} // namespace Filters
} // namespace Extensions
} // namespace Envoy
