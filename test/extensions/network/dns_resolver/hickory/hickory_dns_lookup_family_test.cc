#include "envoy/extensions/network/dns_resolver/hickory/v3/hickory_dns_resolver.pb.h"

#include "source/common/network/address_impl.h"
#include "source/common/network/dns_resolver/dns_factory_util.h"

#include "test/extensions/network/dns_resolver/common/fake_udp_dns_server.h"
#include "test/test_common/status_utility.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Network {
namespace {

using testing::ElementsAre;
using testing::UnorderedElementsAre;

constexpr absl::string_view kIpv4Address = "192.0.2.1";
constexpr absl::string_view kIpv6Address = "2001:db8::1";

// Resolves names through the Hickory resolver against a fake name server on loopback, so each test
// decides which address families a name has. The fake answers a family it has no record for with
// NXDOMAIN.
class HickoryDnsLookupFamilyTest : public testing::Test {
public:
  HickoryDnsLookupFamilyTest()
      : api_(Api::createApiForTest()), dispatcher_(api_->allocateDispatcher("test_thread")),
        dns_server_(*dispatcher_) {}

  void initialize() {
    envoy::extensions::network::dns_resolver::hickory::v3::HickoryDnsResolverConfig config;
    auto* address = config.add_resolvers()->mutable_socket_address();
    address->set_address(dns_server_.address());
    address->set_port_value(dns_server_.port());
    // Ask only the fake server, and send every lookup to it.
    config.mutable_use_system_config()->set_value(false);
    config.mutable_cache_size()->set_value(0);

    envoy::config::core::v3::TypedExtensionConfig typed_config;
    typed_config.set_name("envoy.network.dns_resolver.hickory");
    std::ignore = typed_config.mutable_typed_config()->PackFrom(config);
    auto resolver_or = createDnsResolverFactoryFromTypedConfig(typed_config)
                           .createDnsResolver(*dispatcher_, *api_, typed_config);
    ASSERT_OK(resolver_or);
    resolver_ = std::move(*resolver_or);
  }

  // Resolves a name for the family and returns the addresses in the order the resolver gave them.
  std::vector<std::string> resolve(DnsLookupFamily family) {
    std::vector<std::string> addresses;
    bool callback_called = false;
    resolver_->resolve("example.com", family,
                       [&](DnsResolver::ResolutionStatus status, absl::string_view details,
                           std::list<DnsResponse>&& response) {
                         callback_called = true;
                         EXPECT_EQ(status, DnsResolver::ResolutionStatus::Completed) << details;
                         for (const auto& resp : response) {
                           addresses.push_back(resp.addrInfo().address_->ip()->addressAsString());
                         }
                         dispatcher_->exit();
                       });
    dispatcher_->run(Event::Dispatcher::RunType::RunUntilExit);
    EXPECT_TRUE(callback_called);
    return addresses;
  }

  Api::ApiPtr api_;
  Event::DispatcherPtr dispatcher_;
  Network::Test::FakeUdpDnsServer dns_server_;
  DnsResolverSharedPtr resolver_;
};

TEST_F(HickoryDnsLookupFamilyTest, AutoFallsBackToV4WithoutV6) {
  dns_server_.setDefaultAResponse(std::string(kIpv4Address));
  initialize();
  EXPECT_THAT(resolve(DnsLookupFamily::Auto), ElementsAre(kIpv4Address));
}

TEST_F(HickoryDnsLookupFamilyTest, V4PreferredFallsBackToV6WithoutV4) {
  dns_server_.setDefaultAAAAResponse(std::string(kIpv6Address));
  initialize();
  EXPECT_THAT(resolve(DnsLookupFamily::V4Preferred), ElementsAre(kIpv6Address));
}

TEST_F(HickoryDnsLookupFamilyTest, AutoReturnsOnlyV6ForDualStackName) {
  dns_server_.setDefaultAResponse(std::string(kIpv4Address));
  dns_server_.setDefaultAAAAResponse(std::string(kIpv6Address));
  initialize();
  EXPECT_THAT(resolve(DnsLookupFamily::Auto), ElementsAre(kIpv6Address));
}

TEST_F(HickoryDnsLookupFamilyTest, V4PreferredReturnsOnlyV4ForDualStackName) {
  dns_server_.setDefaultAResponse(std::string(kIpv4Address));
  dns_server_.setDefaultAAAAResponse(std::string(kIpv6Address));
  initialize();
  EXPECT_THAT(resolve(DnsLookupFamily::V4Preferred), ElementsAre(kIpv4Address));
}

TEST_F(HickoryDnsLookupFamilyTest, AllReturnsBothFamiliesForDualStackName) {
  dns_server_.setDefaultAResponse(std::string(kIpv4Address));
  dns_server_.setDefaultAAAAResponse(std::string(kIpv6Address));
  initialize();
  EXPECT_THAT(resolve(DnsLookupFamily::All), UnorderedElementsAre(kIpv4Address, kIpv6Address));
}

// A name neither family answers fails the resolution, since both lookups report no records.
TEST_F(HickoryDnsLookupFamilyTest, AutoFailsWhenNeitherFamilyAnswers) {
  initialize();
  bool callback_called = false;
  resolver_->resolve("example.com", DnsLookupFamily::Auto,
                     [&](DnsResolver::ResolutionStatus status, absl::string_view,
                         std::list<DnsResponse>&& response) {
                       callback_called = true;
                       EXPECT_EQ(status, DnsResolver::ResolutionStatus::Failure);
                       EXPECT_TRUE(response.empty());
                       dispatcher_->exit();
                     });
  dispatcher_->run(Event::Dispatcher::RunType::RunUntilExit);
  EXPECT_TRUE(callback_called);
}

// On a host where Envoy cannot build an IPv6 address, AUTO picks among the addresses Envoy can use,
// so a dual-stack name still resolves to its IPv4 address instead of an empty list.
TEST_F(HickoryDnsLookupFamilyTest, AutoFallsBackToV4WhenIpv6IsUnsupported) {
  dns_server_.setDefaultAResponse(std::string(kIpv4Address));
  dns_server_.setDefaultAAAAResponse(std::string(kIpv6Address));
  initialize();
  auto cleanup = Address::Ipv6Instance::forceProtocolUnsupportedForTest(true);
  EXPECT_THAT(resolve(DnsLookupFamily::Auto), ElementsAre(kIpv4Address));
}

} // namespace
} // namespace Network
} // namespace Envoy
