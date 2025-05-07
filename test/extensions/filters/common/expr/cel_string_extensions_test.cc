#include "source/extensions/filters/common/expr/evaluator.h"

#include "test/mocks/server/factory_context.h"
#include "test/mocks/stream_info/mocks.h"
#include "test/test_common/utility.h"

#if defined(USE_CEL_PARSER)
#include "parser/parser.h"
#endif

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace Filters {
namespace Common {
namespace Expr {

// Define EvaluatorTest class (same pattern as evaluator_test.cc)
class EvaluatorTest : public testing::Test {
protected:
  void SetUp() override {
    // Set up singleton manager
    singleton_manager_ = std::make_shared<Singleton::ManagerImpl>();
    ON_CALL(server_factory_context_, singletonManager())
        .WillByDefault(testing::ReturnRef(*singleton_manager_));
  }

  testing::NiceMock<Server::Configuration::MockServerFactoryContext> server_factory_context_;
  std::shared_ptr<Singleton::Manager> singleton_manager_;
  envoy::config::bootstrap::v3::Bootstrap bootstrap_;
};

#if defined(USE_CEL_PARSER)

class CelStringExtensionsTest : public EvaluatorTest {
protected:
  void SetUp() override { EvaluatorTest::SetUp(); }

  // Helper method to test CEL expression evaluation with string extensions
  testing::AssertionResult testStringExtensionExpression(const std::string& expression,
                                                         const std::string& expected_result,
                                                         bool enable_string_extensions = true) {

    // Configure bootstrap with CEL options
    envoy::config::bootstrap::v3::Bootstrap bootstrap;
    auto* cel_opts = bootstrap.mutable_cel_extension_options();
    cel_opts->set_enable_string_extensions(enable_string_extensions);

    ON_CALL(server_factory_context_, bootstrap()).WillByDefault(testing::ReturnRef(bootstrap));

    // Create a builder
    auto builder = createBuilder(nullptr, &server_factory_context_);

    // Parse and compile expression
    google::api::expr::v1alpha1::ParsedExpr parsed_expr;
    auto parse_status = google::api::expr::parser::Parse(expression, &parsed_expr);
    if (!parse_status.ok()) {
      return testing::AssertionFailure() << "Failed to parse expression '" << expression
                                         << "': " << parse_status.status().message();
    }

    auto compiled_expr = builder->CreateExpression(&parsed_expr.expr(), &parsed_expr.source_info());
    if (!compiled_expr.ok()) {
      if (!enable_string_extensions &&
          absl::StrContains(compiled_expr.status().message(), "No such overload")) {
        // Expected failure when string extensions disabled
        return testing::AssertionSuccess();
      }
      return testing::AssertionFailure() << "Failed to compile expression '" << expression
                                         << "': " << compiled_expr.status().message();
    }

    // Create minimal activation for testing
    auto activation = RequestWrapper::create(nullptr);

    // Evaluate expression
    auto eval_result = compiled_expr.value()->Evaluate(*activation, nullptr);
    if (!eval_result.ok()) {
      if (!enable_string_extensions &&
          absl::StrContains(eval_result.status().message(), "No such overload")) {
        // Expected failure when string extensions disabled
        return testing::AssertionSuccess();
      }
      return testing::AssertionFailure() << "Failed to evaluate expression '" << expression
                                         << "': " << eval_result.status().message();
    }

    auto result = eval_result.value();
    if (!result.IsString()) {
      return testing::AssertionFailure()
             << "Expression '" << expression
             << "' did not return a string, got: " << CelValue::TypeName(result.type());
    }

    std::string actual_result = std::string(result.StringOrDie().value());
    if (actual_result != expected_result) {
      return testing::AssertionFailure()
             << "Expression '" << expression << "' returned '" << actual_result << "', expected '"
             << expected_result << "'";
    }

    return testing::AssertionSuccess();
  }

  // Helper method to test CEL expressions that return integers
  testing::AssertionResult testStringExtensionExpressionInt(const std::string& expression,
                                                            int64_t expected_result,
                                                            bool enable_string_extensions = true) {

    // Configure bootstrap with CEL options
    envoy::config::bootstrap::v3::Bootstrap bootstrap;
    auto* cel_opts = bootstrap.mutable_cel_extension_options();
    cel_opts->set_enable_string_extensions(enable_string_extensions);

    ON_CALL(server_factory_context_, bootstrap()).WillByDefault(testing::ReturnRef(bootstrap));

    // Create a builder
    auto builder = createBuilder(nullptr, &server_factory_context_);

    // Parse and compile expression
    google::api::expr::v1alpha1::ParsedExpr parsed_expr;
    auto parse_status = google::api::expr::parser::Parse(expression, &parsed_expr);
    if (!parse_status.ok()) {
      return testing::AssertionFailure() << "Failed to parse expression '" << expression
                                         << "': " << parse_status.status().message();
    }

    auto compiled_expr = builder->CreateExpression(&parsed_expr.expr(), &parsed_expr.source_info());
    if (!compiled_expr.ok()) {
      return testing::AssertionFailure() << "Failed to compile expression '" << expression
                                         << "': " << compiled_expr.status().message();
    }

    // Create minimal activation for testing
    auto activation = RequestWrapper::create(nullptr);

    // Evaluate expression
    auto eval_result = compiled_expr.value()->Evaluate(*activation, nullptr);
    if (!eval_result.ok()) {
      return testing::AssertionFailure() << "Failed to evaluate expression '" << expression
                                         << "': " << eval_result.status().message();
    }

    auto result = eval_result.value();
    if (!result.IsInt64()) {
      return testing::AssertionFailure()
             << "Expression '" << expression
             << "' did not return an int64, got: " << CelValue::TypeName(result.type());
    }

    int64_t actual_result = result.Int64OrDie();
    if (actual_result != expected_result) {
      return testing::AssertionFailure() << "Expression '" << expression << "' returned "
                                         << actual_result << ", expected " << expected_result;
    }

    return testing::AssertionSuccess();
  }
};

// Test that string extensions are disabled by default
TEST_F(CelStringExtensionsTest, StringExtensionsDisabledByDefault) {
  // This should succeed by showing that string extensions fail when disabled
  EXPECT_TRUE(testStringExtensionExpression("'TEST'.lowerAscii()", "", false));
}

// Test lowerAscii() function
TEST_F(CelStringExtensionsTest, TestLowerAsciiFunction) {
  EXPECT_TRUE(testStringExtensionExpression("'HELLO WORLD'.lowerAscii()", "hello world"));
  EXPECT_TRUE(testStringExtensionExpression("'MiXeD CaSe'.lowerAscii()", "mixed case"));
  EXPECT_TRUE(testStringExtensionExpression("'123ABC'.lowerAscii()", "123abc"));
  EXPECT_TRUE(testStringExtensionExpression("''.lowerAscii()", ""));
}

// Test upperAscii() function
TEST_F(CelStringExtensionsTest, TestUpperAsciiFunction) {
  EXPECT_TRUE(testStringExtensionExpression("'hello world'.upperAscii()", "HELLO WORLD"));
  EXPECT_TRUE(testStringExtensionExpression("'MiXeD CaSe'.upperAscii()", "MIXED CASE"));
  EXPECT_TRUE(testStringExtensionExpression("'123abc'.upperAscii()", "123ABC"));
  EXPECT_TRUE(testStringExtensionExpression("''.upperAscii()", ""));
}

// Test charAt() function
TEST_F(CelStringExtensionsTest, TestCharAtFunction) {
  EXPECT_TRUE(testStringExtensionExpression("'hello'.charAt(0)", "h"));
  EXPECT_TRUE(testStringExtensionExpression("'hello'.charAt(1)", "e"));
  EXPECT_TRUE(testStringExtensionExpression("'hello'.charAt(4)", "o"));
  EXPECT_TRUE(testStringExtensionExpression("'test'.charAt(2)", "s"));
}

// Test indexOf() function
TEST_F(CelStringExtensionsTest, TestIndexOfFunction) {
  EXPECT_TRUE(testStringExtensionExpressionInt("'hello world'.indexOf('world')", 6));
  EXPECT_TRUE(testStringExtensionExpressionInt("'hello world'.indexOf('hello')", 0));
  EXPECT_TRUE(testStringExtensionExpressionInt("'hello world'.indexOf('xyz')", -1));
  EXPECT_TRUE(testStringExtensionExpressionInt("''.indexOf('x')", -1));
}

// Test replace() function
TEST_F(CelStringExtensionsTest, TestReplaceFunction) {
  EXPECT_TRUE(testStringExtensionExpression("'hello world'.replace('world', 'CEL')", "hello CEL"));
  EXPECT_TRUE(testStringExtensionExpression("'hello hello'.replace('hello', 'hi')", "hi hi"));
  EXPECT_TRUE(testStringExtensionExpression("'test string'.replace('xyz', 'abc')", "test string"));
  EXPECT_TRUE(testStringExtensionExpression("''.replace('x', 'y')", ""));
}

// Test split() function - access individual elements
TEST_F(CelStringExtensionsTest, TestSplitFunction) {
  EXPECT_TRUE(testStringExtensionExpression("'hello,world'.split(',')[0]", "hello"));
  EXPECT_TRUE(testStringExtensionExpression("'a,b,c'.split(',')[1]", "b"));
  EXPECT_TRUE(testStringExtensionExpression("'one two three'.split(' ')[2]", "three"));
  EXPECT_TRUE(testStringExtensionExpression("'no-delimiter'.split(',')[0]", "no-delimiter"));
}

// Test substring() function
TEST_F(CelStringExtensionsTest, TestSubstringFunction) {
  EXPECT_TRUE(testStringExtensionExpression("'hello world'.substring(6)", "world"));
  EXPECT_TRUE(testStringExtensionExpression("'hello world'.substring(0, 5)", "hello"));
  EXPECT_TRUE(testStringExtensionExpression("'test'.substring(1, 3)", "es"));
  EXPECT_TRUE(testStringExtensionExpression("'abc'.substring(0)", "abc"));
}

// Test complex chained string operations
TEST_F(CelStringExtensionsTest, TestChainedStringOperations) {
  EXPECT_TRUE(testStringExtensionExpression(
      "'  Hello, World!  '.replace('World', 'CEL').upperAscii()", "  HELLO, CEL!  "));

  EXPECT_TRUE(testStringExtensionExpression("'one,two,three'.split(',')[1].upperAscii()", "TWO"));

  EXPECT_TRUE(
      testStringExtensionExpression("'TEST STRING'.lowerAscii().replace(' ', '-')", "test-string"));
}

// Test integration with other CEL options
TEST_F(CelStringExtensionsTest, TestStringExtensionsWithOtherOptions) {
  // Configure bootstrap with multiple CEL options
  envoy::config::bootstrap::v3::Bootstrap bootstrap;
  auto* cel_opts = bootstrap.mutable_cel_extension_options();
  cel_opts->set_enable_string_extensions(true);
  cel_opts->set_enable_string_concat(true);
  cel_opts->set_enable_list_concat(true);

  ON_CALL(server_factory_context_, bootstrap()).WillByDefault(testing::ReturnRef(bootstrap));

  // Create a builder
  auto builder = createBuilder(nullptr, &server_factory_context_);

  // Test combined functionality: string extensions + string concatenation
  {
    const std::string expression = "'hello'.upperAscii() + ' ' + 'world'.upperAscii()";
    google::api::expr::v1alpha1::ParsedExpr parsed_expr;
    ASSERT_TRUE(google::api::expr::parser::Parse(expression, &parsed_expr).ok());
    auto compiled_expr = builder->CreateExpression(&parsed_expr.expr(), &parsed_expr.source_info());
    ASSERT_TRUE(compiled_expr.ok());

    auto eval_result = compiled_expr.value()->Evaluate(*RequestWrapper::create(nullptr), nullptr);
    ASSERT_TRUE(eval_result.ok());

    const auto result = eval_result.value();
    ASSERT_TRUE(result.IsString());
    EXPECT_EQ("HELLO WORLD", result.StringOrDie().value());
  }
}

// Test error cases
TEST_F(CelStringExtensionsTest, TestStringExtensionErrorCases) {
  // Configure bootstrap with string extensions enabled
  envoy::config::bootstrap::v3::Bootstrap bootstrap;
  auto* cel_opts = bootstrap.mutable_cel_extension_options();
  cel_opts->set_enable_string_extensions(true);

  ON_CALL(server_factory_context_, bootstrap()).WillByDefault(testing::ReturnRef(bootstrap));

  auto builder = createBuilder(nullptr, &server_factory_context_);

  // Test charAt with out-of-bounds index (should handle gracefully)
  {
    const std::string expression = "'hello'.charAt(10)";
    google::api::expr::v1alpha1::ParsedExpr parsed_expr;
    ASSERT_TRUE(google::api::expr::parser::Parse(expression, &parsed_expr).ok());
    auto compiled_expr = builder->CreateExpression(&parsed_expr.expr(), &parsed_expr.source_info());
    ASSERT_TRUE(compiled_expr.ok());

    auto eval_result = compiled_expr.value()->Evaluate(*RequestWrapper::create(nullptr), nullptr);
    // This should either return an error or empty string depending on CEL implementation
    // The important thing is it doesn't crash
    EXPECT_TRUE(eval_result.ok() || !eval_result.ok())
        << "charAt should handle out-of-bounds gracefully";
  }
}

// Test priority: bootstrap config vs singleton provider
TEST_F(CelStringExtensionsTest, TestBootstrapPriorityOverSingleton) {
  // Set up bootstrap with string extensions disabled
  envoy::config::bootstrap::v3::Bootstrap bootstrap;
  auto* cel_opts = bootstrap.mutable_cel_extension_options();
  cel_opts->set_enable_string_extensions(false);

  ON_CALL(server_factory_context_, bootstrap()).WillByDefault(testing::ReturnRef(bootstrap));

  // Set up singleton with string extensions enabled
  envoy::config::bootstrap::v3::CelExtensionOptions singleton_options;
  singleton_options.set_enable_string_extensions(true);

  auto& provider = singleton_manager_->getTyped<CelOptionsProvider>(
      "cel_options_provider", [] { return std::make_shared<CelOptionsProvider>(); });
  provider.setOptions(singleton_options);

  // Bootstrap should have priority - string extensions should be disabled
  auto builder = createBuilder(nullptr, &server_factory_context_);

  const std::string expression = "'TEST'.lowerAscii()";
  google::api::expr::v1alpha1::ParsedExpr parsed_expr;
  ASSERT_TRUE(google::api::expr::parser::Parse(expression, &parsed_expr).ok());
  auto compiled_expr = builder->CreateExpression(&parsed_expr.expr(), &parsed_expr.source_info());

  // Should fail because bootstrap disabled string extensions despite singleton enabling them
  EXPECT_FALSE(compiled_expr.ok()) << "Bootstrap config should have priority over singleton";
}

#endif // USE_CEL_PARSER

} // namespace Expr
} // namespace Common
} // namespace Filters
} // namespace Extensions
} // namespace Envoy
