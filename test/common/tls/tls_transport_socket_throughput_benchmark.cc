// TLS transport socket throughput benchmark.
//
// Measures sustained data throughput through Envoy's BoringSSL SslSocket transport socket
// on TCP loopback connections. Uses the full Envoy event dispatcher, real TCP sockets,
// and the actual doRead/doWrite code path — not raw SSL_read/SSL_write.
//
// Benchmark parameters:
//   state.range(0)  — total bytes to transfer per iteration.

#include "source/common/buffer/buffer_impl.h"
#include "source/common/event/dispatcher_impl.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/listen_socket_impl.h"
#include "source/common/network/tcp_listener_impl.h"
#include "source/common/network/utility.h"
#include "source/common/stream_info/stream_info_impl.h"
#include "source/common/tls/client_ssl_socket.h"
#include "source/common/tls/context_config_impl.h"
#include "source/common/tls/context_impl.h"
#include "source/common/tls/server_context_config_impl.h"
#include "source/common/tls/server_ssl_socket.h"

#include "test/benchmark/main.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/runtime/mocks.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/environment.h"
#include "test/test_common/network_utility.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/utility.h"

#include "benchmark/benchmark.h"
#include "tools/cpp/runfiles/runfiles.h"

using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

// Drives the dispatcher until `predicate` returns true or `timeout` elapses.
static void runUntil(Event::Dispatcher& dispatcher, std::function<bool()> predicate,
                     std::chrono::milliseconds timeout = std::chrono::milliseconds(30000)) {
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!predicate() && std::chrono::steady_clock::now() < deadline) {
    dispatcher.run(Event::Dispatcher::RunType::NonBlock);
  }
  RELEASE_ASSERT(predicate(), "Timed out waiting for predicate");
}

// Write throughput: client writes large payloads, server reads them.
// This simulates the upload path through BoringSSL's SslSocket.
static void BM_SslSocketWriteThroughput(benchmark::State& state) {
  if (Envoy::benchmark::skipExpensiveBenchmarks() && state.range(0) > 1048576) {
    state.SkipWithError("Skipping expensive benchmark");
    return;
  }

  std::string error;
  std::unique_ptr<bazel::tools::cpp::runfiles::Runfiles> runfiles(
      bazel::tools::cpp::runfiles::Runfiles::Create("tls_transport_socket_throughput_benchmark",
                                                     &error));
  TestEnvironment::setRunfiles(runfiles.get());

  const uint64_t payload_bytes = static_cast<uint64_t>(state.range(0));

  // Pre-allocate the payload outside the timed loop.
  std::string payload_data(payload_bytes, 'x');

  Event::SimulatedTimeSystem time_system;
  NiceMock<Server::Configuration::MockTransportSocketFactoryContext> factory_context;
  Stats::TestUtil::TestStore server_stats_store;
  Api::ApiPtr api = Api::createApiForTest(server_stats_store, time_system);
  ON_CALL(factory_context.server_context_, api()).WillByDefault(ReturnRef(*api));
  NiceMock<Runtime::MockLoader> runtime;

  // Server TLS config.
  const std::string server_ctx_yaml = R"EOF(
  common_tls_context:
    tls_certificates:
      certificate_chain:
        filename: "{{ test_rundir }}/test/common/tls/test_data/san_dns_cert.pem"
      private_key:
        filename: "{{ test_rundir }}/test/common/tls/test_data/san_dns_key.pem"
)EOF";

  envoy::extensions::transport_sockets::tls::v3::DownstreamTlsContext server_tls_context;
  TestUtility::loadFromYaml(TestEnvironment::substitute(server_ctx_yaml), server_tls_context);
  auto server_cfg =
      THROW_OR_RETURN_VALUE(ServerContextConfigImpl::create(server_tls_context, factory_context,
                                                             {}, false),
                            std::unique_ptr<ServerContextConfigImpl>);
  NiceMock<Server::Configuration::MockServerFactoryContext> server_factory_context;
  ContextManagerImpl manager(server_factory_context);
  auto server_ssl_socket_factory =
      THROW_OR_RETURN_VALUE(ServerSslSocketFactory::create(std::move(server_cfg), manager,
                                                           *server_stats_store.rootScope()),
                            std::unique_ptr<ServerSslSocketFactory>);

  // Client TLS config (no verification for benchmark simplicity).
  const std::string client_ctx_yaml = R"EOF(
    common_tls_context:
  )EOF";

  envoy::extensions::transport_sockets::tls::v3::UpstreamTlsContext client_tls_context;
  TestUtility::loadFromYaml(TestEnvironment::substitute(client_ctx_yaml), client_tls_context);
  Stats::TestUtil::TestStore client_stats_store;
  Api::ApiPtr client_api = Api::createApiForTest(client_stats_store, time_system);
  NiceMock<Server::Configuration::MockTransportSocketFactoryContext> client_factory_context;
  ON_CALL(client_factory_context.server_context_, api()).WillByDefault(ReturnRef(*client_api));
  auto client_cfg =
      *ClientContextConfigImpl::create(client_tls_context, client_factory_context);
  auto client_ssl_socket_factory =
      *ClientSslSocketFactory::create(std::move(client_cfg), manager,
                                       *client_stats_store.rootScope());

  Event::DispatcherPtr dispatcher = api->allocateDispatcher("benchmark_thread");

  auto listen_socket = std::make_shared<Network::Test::TcpListenSocketImmediateListen>(
      Network::Test::getCanonicalLoopbackAddress(Network::Address::IpVersion::v4));

  Network::MockTcpListenerCallbacks listener_callbacks;
  NiceMock<Network::MockListenerConfig> listener_config;
  Server::ThreadLocalOverloadStateOptRef overload_state;
  Network::ListenerPtr listener = std::make_unique<Network::TcpListenerImpl>(
      *dispatcher, api->randomGenerator(), runtime, *listen_socket, listener_callbacks,
      listener_config.bindToPort(), listener_config.ignoreGlobalConnLimit(),
      listener_config.shouldBypassOverloadManager(),
      listener_config.maxConnectionsToAcceptPerSocketEvent(), overload_state);

  uint64_t total_bytes_written = 0;

  for (auto _ : state) {
    UNREFERENCED_PARAMETER(_);
    state.PauseTiming();

    bool client_connected = false;
    bool server_connected = false;
    uint64_t server_bytes_received = 0;
    bool transfer_complete = false;

    Network::ConnectionPtr server_connection;
    auto server_read_filter = std::make_shared<NiceMock<Network::MockReadFilter>>();
    Network::MockConnectionCallbacks server_conn_callbacks;
    NiceMock<StreamInfo::MockStreamInfo> stream_info;

    ON_CALL(*server_read_filter, onNewConnection())
        .WillByDefault(Return(Network::FilterStatus::Continue));
    ON_CALL(*server_read_filter, onData(_, _))
        .WillByDefault(
            Invoke([&](Buffer::Instance& data, bool) -> Network::FilterStatus {
              server_bytes_received += data.length();
              data.drain(data.length());
              if (server_bytes_received >= payload_bytes) {
                transfer_complete = true;
              }
              return Network::FilterStatus::Continue;
            }));

    EXPECT_CALL(listener_callbacks, onAccept_(_))
        .WillOnce(Invoke([&](Network::ConnectionSocketPtr& socket) -> void {
          server_connection = dispatcher->createServerConnection(
              std::move(socket), server_ssl_socket_factory->createDownstreamTransportSocket(),
              stream_info);
          server_connection->addReadFilter(server_read_filter);
          server_connection->addConnectionCallbacks(server_conn_callbacks);
        }));
    EXPECT_CALL(listener_callbacks, recordConnectionsAcceptedOnSocketEvent(_));

    ON_CALL(server_conn_callbacks, onEvent(_))
        .WillByDefault(Invoke([&](Network::ConnectionEvent event) {
          if (event == Network::ConnectionEvent::Connected) {
            server_connected = true;
          }
        }));

    Network::ClientConnectionPtr client_connection = dispatcher->createClientConnection(
        listen_socket->connectionInfoProvider().localAddress(),
        Network::Address::InstanceConstSharedPtr(),
        client_ssl_socket_factory->createTransportSocket(nullptr, nullptr), nullptr, nullptr);
    Network::MockConnectionCallbacks client_conn_callbacks;
    client_connection->addConnectionCallbacks(client_conn_callbacks);
    ON_CALL(client_conn_callbacks, onEvent(_))
        .WillByDefault(Invoke([&](Network::ConnectionEvent event) {
          if (event == Network::ConnectionEvent::Connected) {
            client_connected = true;
          }
        }));
    client_connection->connect();

    // Wait for TLS handshake to complete on both sides.
    runUntil(*dispatcher, [&] { return client_connected && server_connected; });

    state.ResumeTiming();

    // Write the payload from client → server (simulating upload).
    Buffer::OwnedImpl write_buf(payload_data);
    client_connection->write(write_buf, false);

    // Pump the dispatcher until the server has received everything.
    runUntil(*dispatcher, [&] { return transfer_complete; });

    state.PauseTiming();
    total_bytes_written += payload_bytes;

    client_connection->close(Network::ConnectionCloseType::NoFlush);
    if (server_connection) {
      server_connection->close(Network::ConnectionCloseType::NoFlush);
    }
    dispatcher->run(Event::Dispatcher::RunType::NonBlock);
    state.ResumeTiming();
  }

  state.counters["throughput"] =
      benchmark::Counter(total_bytes_written, benchmark::Counter::kIsRate,
                         benchmark::Counter::kIs1024);
  state.counters["throughput_bytes"] =
      benchmark::Counter(total_bytes_written, benchmark::Counter::kIsRate);
}

// Read throughput: server writes large payloads, client reads them.
// This simulates the download path through BoringSSL's SslSocket.
static void BM_SslSocketReadThroughput(benchmark::State& state) {
  if (Envoy::benchmark::skipExpensiveBenchmarks() && state.range(0) > 1048576) {
    state.SkipWithError("Skipping expensive benchmark");
    return;
  }

  std::string error;
  std::unique_ptr<bazel::tools::cpp::runfiles::Runfiles> runfiles(
      bazel::tools::cpp::runfiles::Runfiles::Create("tls_transport_socket_throughput_benchmark",
                                                     &error));
  TestEnvironment::setRunfiles(runfiles.get());

  const uint64_t payload_bytes = static_cast<uint64_t>(state.range(0));
  std::string payload_data(payload_bytes, 'x');

  Event::SimulatedTimeSystem time_system;
  NiceMock<Server::Configuration::MockTransportSocketFactoryContext> factory_context;
  Stats::TestUtil::TestStore server_stats_store;
  Api::ApiPtr api = Api::createApiForTest(server_stats_store, time_system);
  ON_CALL(factory_context.server_context_, api()).WillByDefault(ReturnRef(*api));
  NiceMock<Runtime::MockLoader> runtime;

  const std::string server_ctx_yaml = R"EOF(
  common_tls_context:
    tls_certificates:
      certificate_chain:
        filename: "{{ test_rundir }}/test/common/tls/test_data/san_dns_cert.pem"
      private_key:
        filename: "{{ test_rundir }}/test/common/tls/test_data/san_dns_key.pem"
)EOF";

  envoy::extensions::transport_sockets::tls::v3::DownstreamTlsContext server_tls_context;
  TestUtility::loadFromYaml(TestEnvironment::substitute(server_ctx_yaml), server_tls_context);
  auto server_cfg =
      THROW_OR_RETURN_VALUE(ServerContextConfigImpl::create(server_tls_context, factory_context,
                                                             {}, false),
                            std::unique_ptr<ServerContextConfigImpl>);
  NiceMock<Server::Configuration::MockServerFactoryContext> server_factory_context;
  ContextManagerImpl manager(server_factory_context);
  auto server_ssl_socket_factory =
      THROW_OR_RETURN_VALUE(ServerSslSocketFactory::create(std::move(server_cfg), manager,
                                                           *server_stats_store.rootScope()),
                            std::unique_ptr<ServerSslSocketFactory>);

  const std::string client_ctx_yaml = R"EOF(
    common_tls_context:
  )EOF";

  envoy::extensions::transport_sockets::tls::v3::UpstreamTlsContext client_tls_context;
  TestUtility::loadFromYaml(TestEnvironment::substitute(client_ctx_yaml), client_tls_context);
  Stats::TestUtil::TestStore client_stats_store;
  Api::ApiPtr client_api = Api::createApiForTest(client_stats_store, time_system);
  NiceMock<Server::Configuration::MockTransportSocketFactoryContext> client_factory_context;
  ON_CALL(client_factory_context.server_context_, api()).WillByDefault(ReturnRef(*client_api));
  auto client_cfg =
      *ClientContextConfigImpl::create(client_tls_context, client_factory_context);
  auto client_ssl_socket_factory =
      *ClientSslSocketFactory::create(std::move(client_cfg), manager,
                                       *client_stats_store.rootScope());

  Event::DispatcherPtr dispatcher = api->allocateDispatcher("benchmark_thread");

  auto listen_socket = std::make_shared<Network::Test::TcpListenSocketImmediateListen>(
      Network::Test::getCanonicalLoopbackAddress(Network::Address::IpVersion::v4));

  Network::MockTcpListenerCallbacks listener_callbacks;
  NiceMock<Network::MockListenerConfig> listener_config;
  Server::ThreadLocalOverloadStateOptRef overload_state;
  Network::ListenerPtr listener_ptr = std::make_unique<Network::TcpListenerImpl>(
      *dispatcher, api->randomGenerator(), runtime, *listen_socket, listener_callbacks,
      listener_config.bindToPort(), listener_config.ignoreGlobalConnLimit(),
      listener_config.shouldBypassOverloadManager(),
      listener_config.maxConnectionsToAcceptPerSocketEvent(), overload_state);

  uint64_t total_bytes_read = 0;

  for (auto _ : state) {
    UNREFERENCED_PARAMETER(_);
    state.PauseTiming();

    bool client_connected = false;
    bool server_connected = false;
    uint64_t client_bytes_received = 0;
    bool transfer_complete = false;

    Network::ConnectionPtr server_connection;
    NiceMock<StreamInfo::MockStreamInfo> stream_info;
    Network::MockConnectionCallbacks server_conn_callbacks;

    auto client_read_filter = std::make_shared<NiceMock<Network::MockReadFilter>>();
    ON_CALL(*client_read_filter, onNewConnection())
        .WillByDefault(Return(Network::FilterStatus::Continue));
    ON_CALL(*client_read_filter, onData(_, _))
        .WillByDefault(
            Invoke([&](Buffer::Instance& data, bool) -> Network::FilterStatus {
              client_bytes_received += data.length();
              data.drain(data.length());
              if (client_bytes_received >= payload_bytes) {
                transfer_complete = true;
              }
              return Network::FilterStatus::Continue;
            }));

    EXPECT_CALL(listener_callbacks, onAccept_(_))
        .WillOnce(Invoke([&](Network::ConnectionSocketPtr& socket) -> void {
          server_connection = dispatcher->createServerConnection(
              std::move(socket), server_ssl_socket_factory->createDownstreamTransportSocket(),
              stream_info);
          server_connection->addConnectionCallbacks(server_conn_callbacks);
        }));
    EXPECT_CALL(listener_callbacks, recordConnectionsAcceptedOnSocketEvent(_));

    ON_CALL(server_conn_callbacks, onEvent(_))
        .WillByDefault(Invoke([&](Network::ConnectionEvent event) {
          if (event == Network::ConnectionEvent::Connected) {
            server_connected = true;
          }
        }));

    Network::ClientConnectionPtr client_connection = dispatcher->createClientConnection(
        listen_socket->connectionInfoProvider().localAddress(),
        Network::Address::InstanceConstSharedPtr(),
        client_ssl_socket_factory->createTransportSocket(nullptr, nullptr), nullptr, nullptr);
    client_connection->addReadFilter(client_read_filter);
    Network::MockConnectionCallbacks client_conn_callbacks;
    client_connection->addConnectionCallbacks(client_conn_callbacks);
    ON_CALL(client_conn_callbacks, onEvent(_))
        .WillByDefault(Invoke([&](Network::ConnectionEvent event) {
          if (event == Network::ConnectionEvent::Connected) {
            client_connected = true;
          }
        }));
    client_connection->connect();

    runUntil(*dispatcher, [&] { return client_connected && server_connected; });

    state.ResumeTiming();

    // Write the payload from server → client (simulating download).
    Buffer::OwnedImpl write_buf(payload_data);
    server_connection->write(write_buf, false);

    runUntil(*dispatcher, [&] { return transfer_complete; });

    state.PauseTiming();
    total_bytes_read += payload_bytes;

    client_connection->close(Network::ConnectionCloseType::NoFlush);
    if (server_connection) {
      server_connection->close(Network::ConnectionCloseType::NoFlush);
    }
    dispatcher->run(Event::Dispatcher::RunType::NonBlock);
    state.ResumeTiming();
  }

  state.counters["throughput"] =
      benchmark::Counter(total_bytes_read, benchmark::Counter::kIsRate,
                         benchmark::Counter::kIs1024);
  state.counters["throughput_bytes"] =
      benchmark::Counter(total_bytes_read, benchmark::Counter::kIsRate);
}

BENCHMARK(BM_SslSocketWriteThroughput)
    ->Unit(::benchmark::kMillisecond)
    ->Arg(1 << 20)   // 1 MB
    ->Arg(4 << 20)   // 4 MB
    ->Arg(8 << 20)   // 8 MB
    ->Arg(16 << 20); // 16 MB

BENCHMARK(BM_SslSocketReadThroughput)
    ->Unit(::benchmark::kMillisecond)
    ->Arg(1 << 20)   // 1 MB
    ->Arg(4 << 20)   // 4 MB
    ->Arg(8 << 20)   // 8 MB
    ->Arg(16 << 20); // 16 MB

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
