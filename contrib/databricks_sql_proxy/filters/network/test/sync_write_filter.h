#pragma once

#include "envoy/network/filter.h"

#include "source/extensions/filters/network/common/factory_base.h"

#include "contrib/databricks_sql_proxy/filters/network/test/sync_write_filter.pb.h"
#include "contrib/databricks_sql_proxy/filters/network/test/sync_write_filter.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

// Helper synchronization filter which is injected between postgres filter and tcp proxy.
// Its goal is to eliminate race conditions and synchronize operations between fake upstream and
// postgres filter.
class SyncWriteFilter : public Network::WriteFilter {
public:
  SyncWriteFilter(absl::Notification& proceed_sync, absl::Notification& recv_sync)
      : proceed_sync_(proceed_sync), recv_sync_(recv_sync) {}

  Network::FilterStatus onWrite(Buffer::Instance& data, bool) override {
    if ((data.length() > 0) && !recv_sync_.HasBeenNotified()) {
      // Notify fake upstream that payload has been received.
      recv_sync_.Notify();
      // Wait for signal to continue. This is to give fake upstream
      // some time to create and attach TLS transport socket.
      proceed_sync_.WaitForNotification();
    }
    return Network::FilterStatus::Continue;
  }

  void initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) override {
    read_callbacks_ = &callbacks;
  }

  Network::WriteFilterCallbacks* read_callbacks_{};
  // Synchronization object used to stop Envoy processing to allow fake upstream to
  // create and attach TLS transport socket.
  absl::Notification& proceed_sync_;
  // Synchronization object used to notify fake upstream that a message sent
  // by fake upstream was received by Envoy.
  absl::Notification& recv_sync_;
};

// Config factory for sync helper filter.
class SyncWriteFilterConfigFactory
    : public Extensions::NetworkFilters::Common::FactoryBase<
          test::integration::databricks_sql_proxy::SyncWriteFilterConfig> {
public:
  explicit SyncWriteFilterConfigFactory(const std::string& name,
                                        Network::ConnectionCallbacks& /* upstream_callbacks*/)
      : FactoryBase(name) {}

  Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const test::integration::databricks_sql_proxy::SyncWriteFilterConfig&,
      Server::Configuration::FactoryContext&) override {
    return [&](Network::FilterManager& filter_manager) -> void {
      filter_manager.addWriteFilter(std::make_shared<SyncWriteFilter>(proceed_sync_, recv_sync_));
    };
  }

  std::string name() const override { return name_; }

  // See SyncWriteFilter for purpose and description of the following sync objects.
  absl::Notification proceed_sync_, recv_sync_;

private:
  const std::string name_;
};

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
