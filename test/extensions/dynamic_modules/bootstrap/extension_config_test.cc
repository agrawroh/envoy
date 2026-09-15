#include "source/extensions/bootstrap/dynamic_modules/extension_config.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/server/listener_manager.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/environment.h"
#include "test/test_common/status_utility.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace Bootstrap {
namespace DynamicModules {

using ::Envoy::StatusHelpers::HasStatusMessage;

class ExtensionConfigTest : public testing::Test {
protected:
  std::string testDataDir() {
    return TestEnvironment::runfilesPath("test/extensions/dynamic_modules/test_data/c");
  }

  testing::NiceMock<Event::MockDispatcher> dispatcher_;
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> context_;
};

TEST_F(ExtensionConfigTest, LoadOK) {
  auto dynamic_module =
      Extensions::DynamicModules::newDynamicModule(testDataDir() + "/libbootstrap_no_op.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  ASSERT_OK(config);
  EXPECT_NE(config.value()->in_module_config_, nullptr);
  EXPECT_NE(config.value()->on_bootstrap_extension_config_destroy_, nullptr);
  EXPECT_NE(config.value()->on_bootstrap_extension_new_, nullptr);
  EXPECT_NE(config.value()->on_bootstrap_extension_server_initialized_, nullptr);
  EXPECT_NE(config.value()->on_bootstrap_extension_worker_thread_initialized_, nullptr);
  EXPECT_NE(config.value()->on_bootstrap_extension_destroy_, nullptr);
  EXPECT_NE(config.value()->on_bootstrap_extension_drain_started_, nullptr);
  EXPECT_NE(config.value()->on_bootstrap_extension_shutdown_, nullptr);
  EXPECT_NE(config.value()->on_bootstrap_extension_config_scheduled_, nullptr);
  EXPECT_NE(config.value()->on_bootstrap_extension_http_callout_done_, nullptr);
  EXPECT_NE(config.value()->on_bootstrap_extension_timer_fired_, nullptr);
  EXPECT_NE(config.value()->on_bootstrap_extension_admin_request_, nullptr);
  // The secret hooks are resolved optionally, so a module that does not export them still loads.
  EXPECT_EQ(config.value()->on_bootstrap_extension_secret_add_or_update_, nullptr);
  EXPECT_EQ(config.value()->on_bootstrap_extension_secret_removal_, nullptr);
}

TEST_F(ExtensionConfigTest, ConfigNewFail) {
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_config_new.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage("Failed to initialize dynamic module"));
}

TEST_F(ExtensionConfigTest, MissingConfigDestroy) {
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_config_destroy.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_config_destroy")));
}

TEST_F(ExtensionConfigTest, MissingExtensionNew) {
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_extension_new.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(
                          testing::HasSubstr("envoy_dynamic_module_on_bootstrap_extension_new")));
}

TEST_F(ExtensionConfigTest, MissingServerInitialized) {
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_server_initialized.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_server_initialized")));
}

TEST_F(ExtensionConfigTest, MissingWorkerThreadInitialized) {
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_worker_initialized.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config,
              HasStatusMessage(testing::HasSubstr(
                  "envoy_dynamic_module_on_bootstrap_extension_worker_thread_initialized")));
}

TEST_F(ExtensionConfigTest, MissingExtensionDestroy) {
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_extension_destroy.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_destroy")));
}

TEST_F(ExtensionConfigTest, MissingConstructor) {
  // Test that config creation fails when envoy_dynamic_module_on_bootstrap_extension_config_new
  // symbol is missing.
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_constructor.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_config_new")));
}

TEST_F(ExtensionConfigTest, MissingDrainStarted) {
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_drain_started.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_drain_started")));
}

TEST_F(ExtensionConfigTest, MissingShutdown) {
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_shutdown.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_shutdown")));
}

TEST_F(ExtensionConfigTest, MissingConfigScheduled) {
  // Test that config creation fails when
  // envoy_dynamic_module_on_bootstrap_extension_config_scheduled symbol is missing.
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_config_scheduled.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_config_scheduled")));
}

TEST_F(ExtensionConfigTest, MissingHttpCalloutDone) {
  // Test that config creation fails when
  // envoy_dynamic_module_on_bootstrap_extension_http_callout_done symbol is missing.
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_http_callout_done.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_http_callout_done")));
}

TEST_F(ExtensionConfigTest, MissingTimerFired) {
  // Test that config creation fails when
  // envoy_dynamic_module_on_bootstrap_extension_timer_fired symbol is missing.
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_timer_fired.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_timer_fired")));
}

TEST_F(ExtensionConfigTest, MissingFileChanged) {
  // Test that config creation fails when
  // envoy_dynamic_module_on_bootstrap_extension_file_changed symbol is missing.
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_file_changed.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_file_changed")));
}

TEST_F(ExtensionConfigTest, MissingAdminRequest) {
  // Test that config creation fails when
  // envoy_dynamic_module_on_bootstrap_extension_admin_request symbol is missing.
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_admin_request.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_admin_request")));
}

TEST_F(ExtensionConfigTest, MissingClusterAddOrUpdate) {
  // Test that config creation fails when
  // envoy_dynamic_module_on_bootstrap_extension_cluster_add_or_update symbol is missing.
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_cluster_add_or_update.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_cluster_add_or_update")));
}

TEST_F(ExtensionConfigTest, MissingClusterRemoval) {
  // Test that config creation fails when
  // envoy_dynamic_module_on_bootstrap_extension_cluster_removal symbol is missing.
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_cluster_removal.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_cluster_removal")));
}

TEST_F(ExtensionConfigTest, MissingListenerAddOrUpdate) {
  // Test that config creation fails when
  // envoy_dynamic_module_on_bootstrap_extension_listener_add_or_update symbol is missing.
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_listener_add_or_update.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_listener_add_or_update")));
}

TEST_F(ExtensionConfigTest, MissingListenerRemoval) {
  // Test that config creation fails when
  // envoy_dynamic_module_on_bootstrap_extension_listener_removal symbol is missing.
  auto dynamic_module = Extensions::DynamicModules::newDynamicModule(
      testDataDir() + "/libbootstrap_no_listener_removal.so", false);
  ASSERT_OK(dynamic_module);

  auto config = newDynamicModuleBootstrapExtensionConfig("test", "config", DefaultMetricsNamespace,
                                                         std::move(dynamic_module.value()),
                                                         dispatcher_, context_, context_.store_);
  EXPECT_THAT(config, HasStatusMessage(testing::HasSubstr(
                          "envoy_dynamic_module_on_bootstrap_extension_listener_removal")));
}

TEST_F(ExtensionConfigTest, ClusterAccessRequiresServerInitialized) {
  auto dynamic_module =
      Extensions::DynamicModules::newDynamicModule(testDataDir() + "/libbootstrap_no_op.so", false);
  ASSERT_OK(dynamic_module);
  auto config_or = newDynamicModuleBootstrapExtensionConfig(
      "test", "config", DefaultMetricsNamespace, std::move(dynamic_module.value()), dispatcher_,
      context_, context_.store_);
  ASSERT_OK(config_or);
  auto config = config_or.value();

  // Before the server is initialized the cluster manager is unavailable, so cluster access is
  // refused rather than dereferencing a null cluster manager.
  EXPECT_FALSE(config->enableClusterLifecycle());
  uint64_t callout_id = 0;
  EXPECT_EQ(envoy_dynamic_module_type_http_callout_init_result_ClusterNotFound,
            config->sendHttpCallout(&callout_id, "some_cluster",
                                    std::make_unique<Http::RequestMessageImpl>(), 1000));

  // After the server is initialized cluster lifecycle can be enabled.
  testing::NiceMock<Server::MockListenerManager> listener_manager;
  config->setListenerManager(listener_manager);
  EXPECT_TRUE(config->enableClusterLifecycle());
}

// Resource enumeration reaches the listener, cluster and secret managers, none of which exist until
// the server is initialized, so it emits nothing until then rather than dereferencing a null
// manager.
TEST_F(ExtensionConfigTest, ActiveResourceNamesRequireServerInitialized) {
  auto dynamic_module =
      Extensions::DynamicModules::newDynamicModule(testDataDir() + "/libbootstrap_no_op.so", false);
  ASSERT_OK(dynamic_module);
  auto config_or = newDynamicModuleBootstrapExtensionConfig(
      "test", "config", DefaultMetricsNamespace, std::move(dynamic_module.value()), dispatcher_,
      context_, context_.store_);
  ASSERT_OK(config_or);
  auto config = config_or.value();

  std::vector<std::string> names;
  auto collect = [&names](absl::string_view name) { names.emplace_back(name); };
  for (const auto kind :
       {envoy_dynamic_module_type_bootstrap_active_resource_kind_FilterChain,
        envoy_dynamic_module_type_bootstrap_active_resource_kind_Cluster,
        envoy_dynamic_module_type_bootstrap_active_resource_kind_Secret,
        envoy_dynamic_module_type_bootstrap_active_resource_kind_TransportSocketMatch}) {
    config->forEachActiveResourceName(kind, collect);
  }
  EXPECT_THAT(names, testing::IsEmpty());

  // Once initialized every kind is served from its manager. The mock managers hold nothing, so the
  // result stays empty while now exercising each accessor.
  testing::NiceMock<Server::MockListenerManager> listener_manager;
  config->setListenerManager(listener_manager);
  for (const auto kind :
       {envoy_dynamic_module_type_bootstrap_active_resource_kind_FilterChain,
        envoy_dynamic_module_type_bootstrap_active_resource_kind_Cluster,
        envoy_dynamic_module_type_bootstrap_active_resource_kind_Secret,
        envoy_dynamic_module_type_bootstrap_active_resource_kind_TransportSocketMatch}) {
    config->forEachActiveResourceName(kind, collect);
  }
  EXPECT_THAT(names, testing::IsEmpty());
}

// Secret lifecycle reaches the SecretManager, which is not available until the server is
// initialized, and registering twice would leak a second set of subscriptions.
TEST_F(ExtensionConfigTest, EnableSecretLifecycleRequiresServerInitialized) {
  auto dynamic_module =
      Extensions::DynamicModules::newDynamicModule(testDataDir() + "/libbootstrap_no_op.so", false);
  ASSERT_OK(dynamic_module);
  auto config_or = newDynamicModuleBootstrapExtensionConfig(
      "test", "config", DefaultMetricsNamespace, std::move(dynamic_module.value()), dispatcher_,
      context_, context_.store_);
  ASSERT_OK(config_or);
  auto config = config_or.value();

  EXPECT_FALSE(config->enableSecretLifecycle());

  // After initialization it registers once, and a second call is refused rather than registering a
  // duplicate set of subscriptions.
  testing::NiceMock<Server::MockListenerManager> listener_manager;
  config->setListenerManager(listener_manager);
  EXPECT_TRUE(config->enableSecretLifecycle());
  EXPECT_FALSE(config->enableSecretLifecycle());
}

} // namespace DynamicModules
} // namespace Bootstrap
} // namespace Extensions
} // namespace Envoy
