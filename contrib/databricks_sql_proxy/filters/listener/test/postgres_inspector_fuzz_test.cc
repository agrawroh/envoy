#include "test/extensions/filters/listener/common/fuzz/listener_filter_fuzzer.h"
#include "test/fuzz/fuzz_runner.h"

#include "contrib/databricks_sql_proxy/filters/listener/source/databricks_sql_inspector.h"

using DatabricksSqlInspectorProto =
    envoy::extensions::filters::listener::databricks_sql_inspector::v3::DatabricksSqlInspector;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace DatabricksSqlInspector {

DEFINE_PROTO_FUZZER(const test::extensions::filters::listener::FilterFuzzWithDataTestCase& input) {
  const std::string yaml = R"EOF(
  stat_prefix: "test"
  protocol: POSTGRES
  )EOF";

  DatabricksSqlInspectorProto proto_config;
  TestUtility::loadFromYaml(yaml, proto_config);

  Stats::IsolatedStoreImpl store;
  ConfigSharedPtr cfg =
      std::make_shared<Config>(*store.rootScope(), proto_config, proto_config.stat_prefix());
  auto filter = std::make_unique<Filter>(cfg);

  ListenerFilterWithDataFuzzer fuzzer;
  fuzzer.fuzz(std::move(filter), input);
}

} // namespace DatabricksSqlInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
