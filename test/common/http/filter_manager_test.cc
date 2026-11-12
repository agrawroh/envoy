#include <array>
#include <memory>
#include <optional>

#include "envoy/common/optref.h"
#include "envoy/http/filter.h"
#include "envoy/http/header_map.h"
#include "envoy/matcher/matcher.h"
#include "envoy/stream_info/filter_state.h"

#include "source/common/filter/config_discovery_impl.h"
#include "source/common/http/filter_chain_helper.h"
#include "source/common/http/filter_manager.h"
#include "source/common/http/matching/inputs.h"
#include "source/common/matcher/exact_map_matcher.h"
#include "source/common/matcher/matcher.h"
#include "source/common/stream_info/filter_state_impl.h"
#include "source/common/stream_info/stream_info_impl.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/local_reply/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/server/overload_manager.h"
#include "test/test_common/test_runtime.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

using testing::_;
using testing::InSequence;
using testing::Return;

namespace Envoy {
namespace Http {

// Reads the sizes and capacities of the filter vectors that a filter chain creation fills, in the
// order filters_, the decoder vector and the encoder vector. The tests assert exact capacities,
// which are those of libc++ and libstdc++, the standard libraries CI builds.
class FilterManagerTestPeer {
public:
  static std::array<size_t, 3> sizes(const FilterManager& manager) {
    return {manager.filters_.size(), manager.decoder_filters_.entries_.size(),
            manager.encoder_filters_.entries_.size()};
  }
  static std::array<size_t, 3> capacities(const FilterManager& manager) {
    return {manager.filters_.capacity(), manager.decoder_filters_.entries_.capacity(),
            manager.encoder_filters_.entries_.capacity()};
  }
};

namespace {
using Protobuf::util::MessageDifferencer;

class FilterManagerTest : public testing::Test {
public:
  void initialize() {
    filter_manager_ = std::make_unique<DownstreamFilterManager>(
        filter_manager_callbacks_, dispatcher_, connection_, 0, nullptr, true, 10000,
        filter_factory_, local_reply_, protocol_, time_source_, filter_state_, overload_manager_);
  }

  // Simple helper to wrapper filter to the factory function.
  FilterFactoryCb createDecoderFilterFactoryCb(StreamDecoderFilterSharedPtr filter) {
    return [filter](FilterChainFactoryCallbacks& callbacks) {
      callbacks.addStreamDecoderFilter(filter);
    };
  }
  FilterFactoryCb createEncoderFilterFactoryCb(StreamEncoderFilterSharedPtr filter) {
    return [filter](FilterChainFactoryCallbacks& callbacks) {
      callbacks.addStreamEncoderFilter(filter);
    };
  }
  FilterFactoryCb createStreamFilterFactoryCb(StreamFilterSharedPtr filter) {
    return [filter](FilterChainFactoryCallbacks& callbacks) { callbacks.addStreamFilter(filter); };
  }
  FilterFactoryCb createLogHandlerFactoryCb(AccessLog::InstanceSharedPtr handler) {
    return [handler](FilterChainFactoryCallbacks& callbacks) {
      callbacks.addAccessLogHandler(handler);
    };
  }
  // Creates the stream's chain through the helper the HTTP connection manager uses.
  void createChainFromFactories(const FilterChainUtility::FilterFactoriesList& filter_factories) {
    EXPECT_CALL(filter_factory_, createFilterChain(_))
        .WillOnce([&filter_factories](FilterChainFactoryCallbacks& callbacks) -> bool {
          FilterChainUtility::createFilterChainForFactories(callbacks, filter_factories);
          return true;
        });
    EXPECT_TRUE(filter_manager_->createDownstreamFilterChain().created());
  }
  // Expects the sizes and capacities of filters_, the decoder vector and the encoder vector.
  void expectFilterVectors(std::array<size_t, 3> sizes, std::array<size_t, 3> capacities) {
    EXPECT_EQ(sizes, FilterManagerTestPeer::sizes(*filter_manager_));
    EXPECT_EQ(capacities, FilterManagerTestPeer::capacities(*filter_manager_));
  }

  void validateFilterStateData(const std::string& expected_name) {
    ASSERT_TRUE(filter_manager_->streamInfo().filterState()->hasData<LocalReplyOwnerObject>(
        LocalReplyFilterStateKey));
    auto fs_value =
        filter_manager_->streamInfo().filterState()->getDataReadOnly<LocalReplyOwnerObject>(
            LocalReplyFilterStateKey);
    EXPECT_EQ(fs_value->serializeAsString(), expected_name);

    auto expected = std::make_unique<Protobuf::StringValue>();
    expected->set_value(expected_name);
    EXPECT_TRUE(MessageDifferencer::Equals(*(fs_value->serializeAsProto()), *expected));
  }

  void runSendDirectLocalReplySavedResponseMetadataTest(bool flush_saved_response_metadata) {
    initialize();

    std::shared_ptr<MockStreamFilter> filter_1(new NiceMock<MockStreamFilter>());
    std::shared_ptr<MockStreamFilter> filter_2(new NiceMock<MockStreamFilter>());

    EXPECT_CALL(filter_factory_, createFilterChain(_))
        .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
          auto factory = createStreamFilterFactoryCb(filter_1);
          callbacks.setFilterConfigName("configName1");
          factory(callbacks);
          factory = createStreamFilterFactoryCb(filter_2);
          callbacks.setFilterConfigName("configName2");
          factory(callbacks);
          return true;
        });

    RequestHeaderMapPtr request_headers{
        new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "GET"}}};
    ON_CALL(filter_manager_callbacks_, requestHeaders())
        .WillByDefault(Return(makeOptRef(*request_headers)));
    ON_CALL(filter_manager_callbacks_, responseHeaders())
        .WillByDefault([this]() -> ResponseHeaderMapOptRef {
          return makeOptRefFromPtr(filter_manager_callbacks_.response_headers_.get());
        });

    filter_manager_->createDownstreamFilterChain();
    filter_manager_->requestHeadersInitialized();

    EXPECT_CALL(*filter_1, decodeHeaders(_, _)).WillOnce(Return(FilterHeadersStatus::Continue));
    EXPECT_CALL(*filter_2, decodeHeaders(_, _)).WillOnce(Return(FilterHeadersStatus::Continue));
    filter_manager_->decodeHeaders(*request_headers, false);

    MetadataMap metadata_map = {{"local-reply", "metadata"}};
    EXPECT_CALL(filter_manager_callbacks_, setResponseHeaders_(_)).Times(2);
    EXPECT_CALL(local_reply_, rewrite(_, _, _, _, _, _));
    if (!flush_saved_response_metadata) {
      EXPECT_CALL(filter_manager_callbacks_, encodeMetadata(_)).Times(0);
    }

    {
      InSequence s;
      EXPECT_CALL(*filter_2, encodeHeaders(_, false))
          .WillOnce([&](ResponseHeaderMap&, bool) -> FilterHeadersStatus {
            filter_2->encoder_callbacks_->addEncodedMetadata(
                std::make_unique<MetadataMap>(metadata_map));
            return FilterHeadersStatus::Continue;
          });
      EXPECT_CALL(*filter_1, encodeHeaders(_, false))
          .WillOnce([&](ResponseHeaderMap&, bool) -> FilterHeadersStatus {
            filter_1->encoder_callbacks_->sendLocalReply(Code::InternalServerError, "body", nullptr,
                                                         std::nullopt, "direct_local_reply");
            return FilterHeadersStatus::StopIteration;
          });
      EXPECT_CALL(filter_manager_callbacks_, encodeHeaders(_, false));
      EXPECT_CALL(filter_manager_callbacks_, encodeData(_, !flush_saved_response_metadata))
          .WillOnce([&](Buffer::Instance& data, bool end_stream) -> void {
            EXPECT_EQ("body", data.toString());
            EXPECT_EQ(!flush_saved_response_metadata, end_stream);
          });
      if (flush_saved_response_metadata) {
        EXPECT_CALL(filter_manager_callbacks_, encodeMetadata(_))
            .WillOnce([&](MetadataMapPtr&& metadata_map_ptr) -> void {
              EXPECT_EQ(metadata_map, *metadata_map_ptr);
            });
        EXPECT_CALL(filter_manager_callbacks_, encodeData(_, true))
            .WillOnce([](Buffer::Instance& data, bool) -> void { EXPECT_EQ(0, data.length()); });
      }
      EXPECT_CALL(filter_manager_callbacks_, endStream());
    }

    filter_2->decoder_callbacks_->encodeHeaders(
        std::make_unique<TestResponseHeaderMapImpl>(TestResponseHeaderMapImpl{{":status", "200"}}),
        false, "upstream_response");

    validateFilterStateData("configName1");

    filter_manager_->destroyFilters();
  }

  void runAddDecodedDataOnContinueTest(bool forward_data);

  std::unique_ptr<DownstreamFilterManager> filter_manager_;
  NiceMock<MockFilterManagerCallbacks> filter_manager_callbacks_;
  NiceMock<Event::MockDispatcher> dispatcher_;
  NiceMock<Network::MockConnection> connection_;
  Envoy::Http::MockFilterChainFactory filter_factory_;
  NiceMock<LocalReply::MockLocalReply> local_reply_;
  Protocol protocol_{Protocol::Http2};
  NiceMock<MockTimeSystem> time_source_;
  StreamInfo::FilterStateSharedPtr filter_state_ =
      std::make_shared<StreamInfo::FilterStateImpl>(StreamInfo::FilterState::LifeSpan::Connection);
  NiceMock<Server::MockOverloadManager> overload_manager_;
};

TEST_F(FilterManagerTest, LowWatermarkWithoutHighWatermark) {
  initialize();

  EXPECT_ENVOY_BUG(
      filter_manager_->callLowWatermarkCallbacks(),
      "HTTP filter manager low watermark callback without a preceding high watermark callback");
  EXPECT_FALSE(filter_manager_->aboveHighWatermark());
  filter_manager_->destroyFilters();
}

TEST_F(FilterManagerTest, RequestHeadersOrResponseHeadersAccess) {
  initialize();

  auto decoder_filter = std::make_shared<NiceMock<MockStreamDecoderFilter>>();
  auto encoder_filter = std::make_shared<NiceMock<MockStreamEncoderFilter>>();

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillOnce([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto decoder_factory = createDecoderFilterFactoryCb(decoder_filter);
        callbacks.setFilterConfigName("");
        decoder_factory(callbacks);
        auto encoder_factory = createEncoderFilterFactoryCb(encoder_filter);
        callbacks.setFilterConfigName("");
        encoder_factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  RequestHeaderMapPtr request_headers{
      new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "GET"}}};
  ResponseHeaderMapPtr response_headers{new TestResponseHeaderMapImpl{{":status", "200"}}};
  RequestTrailerMapPtr request_trailers{new TestRequestTrailerMapImpl{{"foo", "bar"}}};
  ResponseTrailerMapPtr response_trailers{new TestResponseTrailerMapImpl{{"foo", "bar"}}};
  ResponseHeaderMapPtr informational_headers{
      new TestResponseHeaderMapImpl{{":status", "100"}, {"foo", "bar"}}};

  EXPECT_CALL(filter_manager_callbacks_, requestHeaders())
      .Times(2)
      .WillRepeatedly(Return(makeOptRef(*request_headers)));
  EXPECT_CALL(filter_manager_callbacks_, responseHeaders())
      .Times(2)
      .WillRepeatedly(Return(makeOptRef(*response_headers)));
  EXPECT_CALL(filter_manager_callbacks_, requestTrailers())
      .Times(2)
      .WillRepeatedly(Return(makeOptRef(*request_trailers)));
  EXPECT_CALL(filter_manager_callbacks_, responseTrailers())
      .Times(2)
      .WillRepeatedly(Return(makeOptRef(*response_trailers)));
  EXPECT_CALL(filter_manager_callbacks_, informationalHeaders())
      .Times(2)
      .WillRepeatedly(Return(makeOptRef(*informational_headers)));

  EXPECT_EQ(decoder_filter->callbacks_->requestHeaders().ptr(), request_headers.get());
  EXPECT_EQ(decoder_filter->callbacks_->responseHeaders().ptr(), response_headers.get());
  EXPECT_EQ(decoder_filter->callbacks_->requestTrailers().ptr(), request_trailers.get());
  EXPECT_EQ(decoder_filter->callbacks_->responseTrailers().ptr(), response_trailers.get());
  EXPECT_EQ(decoder_filter->callbacks_->informationalHeaders().ptr(), informational_headers.get());

  EXPECT_EQ(encoder_filter->callbacks_->requestHeaders().ptr(), request_headers.get());
  EXPECT_EQ(encoder_filter->callbacks_->responseHeaders().ptr(), response_headers.get());
  EXPECT_EQ(encoder_filter->callbacks_->requestTrailers().ptr(), request_trailers.get());
  EXPECT_EQ(encoder_filter->callbacks_->responseTrailers().ptr(), response_trailers.get());
  EXPECT_EQ(encoder_filter->callbacks_->informationalHeaders().ptr(), informational_headers.get());

  filter_manager_->destroyFilters();
}

// Verifies that the local reply persists the gRPC classification even if the request headers are
// modified.
TEST_F(FilterManagerTest, SendLocalReplyDuringDecodingGrpcClassiciation) {
  initialize();

  std::shared_ptr<MockStreamDecoderFilter> filter(new NiceMock<MockStreamDecoderFilter>());

  EXPECT_CALL(*filter, decodeHeaders(_, true))
      .WillRepeatedly([&](RequestHeaderMap& headers, bool) -> FilterHeadersStatus {
        headers.setContentType("text/plain");

        filter->callbacks_->sendLocalReply(Code::InternalServerError, "", nullptr, std::nullopt,
                                           "details");

        return FilterHeadersStatus::StopIteration;
      });

  RequestHeaderMapPtr grpc_headers{
      new TestRequestHeaderMapImpl{{":authority", "host"},
                                   {":path", "/"},
                                   {":method", "GET"},
                                   {"content-type", "application/grpc"}}};

  ON_CALL(filter_manager_callbacks_, requestHeaders())
      .WillByDefault(Return(makeOptRef(*grpc_headers)));

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto factory = createDecoderFilterFactoryCb(filter);
        callbacks.setFilterConfigName("configName1");
        factory(callbacks);
        return true;
      });

  filter_manager_->createDownstreamFilterChain();

  filter_manager_->requestHeadersInitialized();

  EXPECT_CALL(local_reply_, rewrite(_, _, _, _, _, _));
  EXPECT_CALL(filter_manager_callbacks_, setResponseHeaders_(_))
      .WillOnce([](auto& response_headers) {
        EXPECT_THAT(response_headers,
                    ContainsHeader(Http::Headers::get().ContentType, "application/grpc"));
      });
  EXPECT_CALL(filter_manager_callbacks_, resetIdleTimer());
  EXPECT_CALL(filter_manager_callbacks_, encodeHeaders(_, _));
  EXPECT_CALL(filter_manager_callbacks_, endStream());

  filter_manager_->decodeHeaders(*grpc_headers, true);

  validateFilterStateData("configName1");

  filter_manager_->destroyFilters();
}

// Verifies that the local reply persists the gRPC classification even if the request headers are
// modified when directly encoding a response.
TEST_F(FilterManagerTest, SendLocalReplyDuringEncodingGrpcClassiciation) {
  initialize();

  std::shared_ptr<MockStreamDecoderFilter> decoder_filter(new NiceMock<MockStreamDecoderFilter>());

  EXPECT_CALL(*decoder_filter, decodeHeaders(_, true))
      .WillRepeatedly([&](RequestHeaderMap& headers, bool) -> FilterHeadersStatus {
        headers.setContentType("text/plain");

        ResponseHeaderMapPtr response_headers{new TestResponseHeaderMapImpl{{":status", "200"}}};
        decoder_filter->callbacks_->encodeHeaders(std::move(response_headers), true, "test");

        return FilterHeadersStatus::StopIteration;
      });

  std::shared_ptr<MockStreamFilter> encoder_filter(new NiceMock<MockStreamFilter>());

  EXPECT_CALL(*encoder_filter, encodeHeaders(_, true))
      .WillRepeatedly([&](auto&, bool) -> FilterHeadersStatus {
        encoder_filter->encoder_callbacks_->sendLocalReply(Code::InternalServerError, "", nullptr,
                                                           std::nullopt, "details");
        return FilterHeadersStatus::StopIteration;
      });

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto decoder_factory = createDecoderFilterFactoryCb(decoder_filter);
        callbacks.setFilterConfigName("configName1");
        decoder_factory(callbacks);

        auto stream_factory = createStreamFilterFactoryCb(encoder_filter);
        callbacks.setFilterConfigName("configName2");
        stream_factory(callbacks);
        return true;
      });

  RequestHeaderMapPtr grpc_headers{
      new TestRequestHeaderMapImpl{{":authority", "host"},
                                   {":path", "/"},
                                   {":method", "GET"},
                                   {"content-type", "application/grpc"}}};

  ON_CALL(filter_manager_callbacks_, requestHeaders())
      .WillByDefault(Return(makeOptRef(*grpc_headers)));
  filter_manager_->createDownstreamFilterChain();

  filter_manager_->requestHeadersInitialized();
  EXPECT_CALL(local_reply_, rewrite(_, _, _, _, _, _));
  EXPECT_CALL(filter_manager_callbacks_, setResponseHeaders_(_))
      .WillOnce([](auto&) {})
      .WillOnce([](auto& response_headers) {
        EXPECT_THAT(response_headers,
                    ContainsHeader(Http::Headers::get().ContentType, "application/grpc"));
      });
  EXPECT_CALL(filter_manager_callbacks_, encodeHeaders(_, _));
  EXPECT_CALL(filter_manager_callbacks_, endStream());

  filter_manager_->decodeHeaders(*grpc_headers, true);

  validateFilterStateData("configName2");

  filter_manager_->destroyFilters();
}

TEST_F(FilterManagerTest, SendDirectLocalReplyEncodesSavedResponseMetadata) {
  runSendDirectLocalReplySavedResponseMetadataTest(true);
}

TEST_F(FilterManagerTest, SendDirectLocalReplySkipsSavedResponseMetadataWhenRuntimeGuardDisabled) {
  TestScopedRuntime scoped_runtime;
  scoped_runtime.mergeValues(
      {{"envoy.reloadable_features.direct_local_reply_flush_saved_response_metadata", "false"}});
  runSendDirectLocalReplySavedResponseMetadataTest(false);
}

TEST_F(FilterManagerTest, OnLocalReply) {
  initialize();

  std::shared_ptr<MockStreamDecoderFilter> decoder_filter(new NiceMock<MockStreamDecoderFilter>());
  std::shared_ptr<MockStreamEncoderFilter> encoder_filter(new NiceMock<MockStreamEncoderFilter>());
  std::shared_ptr<MockStreamFilter> stream_filter(new NiceMock<MockStreamFilter>());

  RequestHeaderMapPtr headers{
      new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "GET"}}};

  ON_CALL(filter_manager_callbacks_, requestHeaders()).WillByDefault(Return(makeOptRef(*headers)));

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto decoder_factory = createDecoderFilterFactoryCb(decoder_filter);
        callbacks.setFilterConfigName("configName1");
        decoder_factory(callbacks);
        auto stream_factory = createStreamFilterFactoryCb(stream_filter);
        callbacks.setFilterConfigName("configName2");
        stream_factory(callbacks);
        auto encoder_factory = createEncoderFilterFactoryCb(encoder_filter);
        callbacks.setFilterConfigName("configName3");
        encoder_factory(callbacks);
        return true;
      });

  filter_manager_->createDownstreamFilterChain();
  filter_manager_->requestHeadersInitialized();
  filter_manager_->decodeHeaders(*headers, true);

  // Make sure all 3 filters get onLocalReply, and that the reset is preserved
  // even if not the last return.
  EXPECT_CALL(*decoder_filter, onLocalReply(_))
      .WillOnce(
          [&](const StreamFilterBase::LocalReplyData& local_reply_data) -> Http::LocalErrorStatus {
            EXPECT_THAT(local_reply_data.grpc_status_, testing::Optional(Grpc::Status::Internal));
            EXPECT_EQ(local_reply_data.body_, "body");
            return Http::LocalErrorStatus::Continue;
          });
  EXPECT_CALL(*stream_filter, onLocalReply(_))
      .WillOnce(
          [&](const StreamFilterBase::LocalReplyData& local_reply_data) -> Http::LocalErrorStatus {
            EXPECT_THAT(local_reply_data.grpc_status_, testing::Optional(Grpc::Status::Internal));
            EXPECT_EQ(local_reply_data.body_, "body");
            return LocalErrorStatus::ContinueAndResetStream;
          });
  EXPECT_CALL(*encoder_filter, onLocalReply(_))
      .WillOnce(
          [&](const StreamFilterBase::LocalReplyData& local_reply_data) -> Http::LocalErrorStatus {
            EXPECT_THAT(local_reply_data.grpc_status_, testing::Optional(Grpc::Status::Internal));
            EXPECT_EQ(local_reply_data.body_, "body");
            return Http::LocalErrorStatus::Continue;
          });
  EXPECT_CALL(filter_manager_callbacks_, resetStream(_, _));
  decoder_filter->callbacks_->sendLocalReply(Code::InternalServerError, "body", nullptr,
                                             Grpc::Status::Internal, "details");

  // The reason for the response (in this case the reset) will still be tracked
  // but as no response is sent the response code will remain absent.

  ASSERT_TRUE(filter_manager_->streamInfo().responseCodeDetails().has_value());
  EXPECT_EQ(filter_manager_->streamInfo().responseCodeDetails().value(), "details");
  EXPECT_FALSE(filter_manager_->streamInfo().responseCode().has_value());

  validateFilterStateData("configName1");

  filter_manager_->destroyFilters();
}

TEST_F(FilterManagerTest, MultipleOnLocalReply) {
  initialize();

  std::shared_ptr<MockStreamDecoderFilter> decoder_filter(new NiceMock<MockStreamDecoderFilter>());
  std::shared_ptr<MockStreamEncoderFilter> encoder_filter(new NiceMock<MockStreamEncoderFilter>());
  std::shared_ptr<MockStreamFilter> stream_filter(new NiceMock<MockStreamFilter>());

  RequestHeaderMapPtr headers{
      new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "GET"}}};

  ON_CALL(filter_manager_callbacks_, requestHeaders()).WillByDefault(Return(makeOptRef(*headers)));

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto decoder_factory = createDecoderFilterFactoryCb(decoder_filter);
        callbacks.setFilterConfigName("configName1");
        decoder_factory(callbacks);
        auto stream_factory = createStreamFilterFactoryCb(stream_filter);
        callbacks.setFilterConfigName("configName2");
        stream_factory(callbacks);
        auto encoder_factory = createEncoderFilterFactoryCb(encoder_filter);
        callbacks.setFilterConfigName("configName3");
        encoder_factory(callbacks);
        return true;
      });

  filter_manager_->createDownstreamFilterChain();
  filter_manager_->requestHeadersInitialized();
  filter_manager_->decodeHeaders(*headers, true);

  {
    // Set up expectations to be triggered by sendLocalReply at the bottom of
    // this block.
    InSequence s;

    // Make sure all 3 filters get onLocalReply
    EXPECT_CALL(*decoder_filter, onLocalReply(_));
    EXPECT_CALL(*stream_filter, onLocalReply(_));
    EXPECT_CALL(*encoder_filter, onLocalReply(_));

    // Now response encoding begins. Assume a filter co-opts the original reply
    // with a new local reply.
    EXPECT_CALL(*encoder_filter, encodeHeaders(_, _))
        .WillOnce([&](ResponseHeaderMap&, bool) -> FilterHeadersStatus {
          decoder_filter->callbacks_->sendLocalReply(Code::InternalServerError, "body2", nullptr,
                                                     std::nullopt, "details2");
          return FilterHeadersStatus::StopIteration;
        });

    // All 3 filters should get the second onLocalReply.
    EXPECT_CALL(*decoder_filter, onLocalReply(_));
    EXPECT_CALL(*stream_filter, onLocalReply(_));
    EXPECT_CALL(*encoder_filter, onLocalReply(_));
    // trackedObjectStackIsEmpty() is never called since sendLocalReply will abort encoder filter
    // iteration.
    EXPECT_CALL(dispatcher_, trackedObjectStackIsEmpty()).Times(0);

    decoder_filter->callbacks_->sendLocalReply(Code::InternalServerError, "body", nullptr,
                                               std::nullopt, "details");
  }

  // The final details should be details2.
  ASSERT_TRUE(filter_manager_->streamInfo().responseCodeDetails().has_value());
  EXPECT_EQ(filter_manager_->streamInfo().responseCodeDetails().value(), "details2");
  EXPECT_FALSE(filter_manager_->streamInfo().responseCode().has_value());

  validateFilterStateData("configName1");

  filter_manager_->destroyFilters();
}

TEST_F(FilterManagerTest, ResetIdleTimer) {
  initialize();

  std::shared_ptr<MockStreamDecoderFilter> decoder_filter(new NiceMock<MockStreamDecoderFilter>());

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto decoder_factory = createDecoderFilterFactoryCb(decoder_filter);
        callbacks.setFilterConfigName("");
        decoder_factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  EXPECT_CALL(filter_manager_callbacks_, resetIdleTimer());
  decoder_filter->callbacks_->resetIdleTimer();

  filter_manager_->destroyFilters();
}

TEST_F(FilterManagerTest, SetAndGetUpstreamOverrideHost) {
  initialize();

  std::shared_ptr<MockStreamDecoderFilter> decoder_filter(new NiceMock<MockStreamDecoderFilter>());

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto decoder_factory = createDecoderFilterFactoryCb(decoder_filter);
        callbacks.setFilterConfigName("");
        decoder_factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  decoder_filter->callbacks_->setUpstreamOverrideHost(
      Upstream::LoadBalancerContext::OverrideHost{"1.2.3.4", true});

  OptRef<const Upstream::LoadBalancerContext::OverrideHost> override_host =
      decoder_filter->callbacks_->upstreamOverrideHost();
  EXPECT_TRUE(override_host.has_value());
  EXPECT_EQ(override_host->host, "1.2.3.4");
  EXPECT_TRUE(override_host->strict);

  filter_manager_->destroyFilters();
};

// Builds the factory list that the HTTP connection manager builds from its filter config, with
// one static provider per factory.
FilterChainUtility::FilterFactoriesList
makeFilterFactories(std::vector<std::pair<std::string, FilterFactoryCb>> factories,
                    bool disabled = false) {
  FilterChainUtility::FilterFactoriesList filter_factories;
  for (auto& [name, factory] : factories) {
    filter_factories.push_back(
        {std::make_unique<Filter::StaticFilterConfigProviderImpl<Filter::HttpFilterFactoryCb>>(
             std::move(factory), name),
         disabled});
  }
  return filter_factories;
}

RequestHeaderMapPtr makeRequestHeaders() {
  return RequestHeaderMapPtr{
      new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "GET"}}};
}

TEST_F(FilterManagerTest, CreateFilterChainReservesFactoryCount) {
  initialize();

  auto decoder_filter_0 = std::make_shared<NiceMock<MockStreamDecoderFilter>>();
  auto encoder_filter_1 = std::make_shared<NiceMock<MockStreamEncoderFilter>>();
  auto stream_filter_2 = std::make_shared<NiceMock<MockStreamFilter>>();
  auto stream_filter_3 = std::make_shared<NiceMock<MockStreamFilter>>();
  auto decoder_filter_4 = std::make_shared<NiceMock<MockStreamDecoderFilter>>();
  const auto filter_factories = makeFilterFactories({
      {"decoder_filter_0", createDecoderFilterFactoryCb(decoder_filter_0)},
      {"encoder_filter_1", createEncoderFilterFactoryCb(encoder_filter_1)},
      {"stream_filter_2", createStreamFilterFactoryCb(stream_filter_2)},
      {"stream_filter_3", createStreamFilterFactoryCb(stream_filter_3)},
      {"decoder_filter_4", createDecoderFilterFactoryCb(decoder_filter_4)},
  });
  createChainFromFactories(filter_factories);

  // Five factories add five filters, four of them decoders and three encoders. Each vector takes
  // five slots on its first filter, where growing one filter at a time would leave capacities of
  // 8, 4 and 4.
  expectFilterVectors({5, 4, 3}, {5, 5, 5});

  auto request_headers = makeRequestHeaders();
  {
    InSequence s;
    EXPECT_CALL(*decoder_filter_0, decodeHeaders(_, true))
        .WillOnce(Return(FilterHeadersStatus::Continue));
    EXPECT_CALL(*stream_filter_2, decodeHeaders(_, true))
        .WillOnce(Return(FilterHeadersStatus::Continue));
    EXPECT_CALL(*stream_filter_3, decodeHeaders(_, true))
        .WillOnce(Return(FilterHeadersStatus::Continue));
    EXPECT_CALL(*decoder_filter_4, decodeHeaders(_, true))
        .WillOnce(Return(FilterHeadersStatus::StopIteration));
  }
  filter_manager_->decodeHeaders(*request_headers, true);

  {
    InSequence s;
    EXPECT_CALL(*stream_filter_3, encodeHeaders(_, true))
        .WillOnce(Return(FilterHeadersStatus::Continue));
    EXPECT_CALL(*stream_filter_2, encodeHeaders(_, true))
        .WillOnce(Return(FilterHeadersStatus::Continue));
    EXPECT_CALL(*encoder_filter_1, encodeHeaders(_, true))
        .WillOnce(Return(FilterHeadersStatus::Continue));
    EXPECT_CALL(filter_manager_callbacks_, encodeHeaders(_, true));
  }
  decoder_filter_4->callbacks_->encodeHeaders(
      std::make_unique<TestResponseHeaderMapImpl>(TestResponseHeaderMapImpl{{":status", "200"}}),
      true, "details");

  filter_manager_->destroyFilters();
  // The providers own the filter config names the filter wrappers view.
  filter_manager_.reset();
}

// An encoder filter that comes first reserves filters_ and the encoder vector, and the stream
// filter after it reserves the decoder vector.
TEST_F(FilterManagerTest, CreateFilterChainEncoderFirstReservesFactoryCount) {
  initialize();

  auto encoder_filter = std::make_shared<NiceMock<MockStreamEncoderFilter>>();
  auto stream_filter = std::make_shared<NiceMock<MockStreamFilter>>();
  auto decoder_filter = std::make_shared<NiceMock<MockStreamDecoderFilter>>();
  const auto filter_factories = makeFilterFactories({
      {"encoder_filter", createEncoderFilterFactoryCb(encoder_filter)},
      {"stream_filter", createStreamFilterFactoryCb(stream_filter)},
      {"decoder_filter", createDecoderFilterFactoryCb(decoder_filter)},
  });
  createChainFromFactories(filter_factories);

  // Growing one filter at a time would leave capacities of 4, 2 and 2.
  expectFilterVectors({3, 2, 2}, {3, 3, 3});

  filter_manager_->destroyFilters();
  // The providers own the filter config names the filter wrappers view.
  filter_manager_.reset();
}

// The factory count is a hint, so a chain whose factories each add two filters outgrows it and
// still runs every filter in configured order.
TEST_F(FilterManagerTest, CreateFilterChainWithTwoFiltersPerFactory) {
  initialize();

  std::vector<std::shared_ptr<NiceMock<MockStreamFilter>>> stream_filters;
  for (int i = 0; i < 6; ++i) {
    stream_filters.push_back(std::make_shared<NiceMock<MockStreamFilter>>());
  }
  auto add_two_filters = [&stream_filters](size_t first) -> FilterFactoryCb {
    return [&stream_filters, first](FilterChainFactoryCallbacks& callbacks) {
      callbacks.addStreamFilter(stream_filters[first]);
      callbacks.addStreamFilter(stream_filters[first + 1]);
    };
  };
  const auto filter_factories = makeFilterFactories({
      {"filters_0_1", add_two_filters(0)},
      {"filters_2_3", add_two_filters(2)},
      {"filters_4_5", add_two_filters(4)},
  });
  createChainFromFactories(filter_factories);

  // Each vector takes the three hinted slots on its first filter and doubles them on the fourth.
  expectFilterVectors({6, 6, 6}, {6, 6, 6});

  auto request_headers = makeRequestHeaders();
  {
    InSequence s;
    for (size_t i = 0; i < 5; ++i) {
      EXPECT_CALL(*stream_filters[i], decodeHeaders(_, true))
          .WillOnce(Return(FilterHeadersStatus::Continue));
    }
    EXPECT_CALL(*stream_filters[5], decodeHeaders(_, true))
        .WillOnce(Return(FilterHeadersStatus::StopIteration));
  }
  filter_manager_->decodeHeaders(*request_headers, true);

  {
    InSequence s;
    for (size_t i = 6; i > 0; --i) {
      EXPECT_CALL(*stream_filters[i - 1], encodeHeaders(_, true))
          .WillOnce(Return(FilterHeadersStatus::Continue));
    }
    EXPECT_CALL(filter_manager_callbacks_, encodeHeaders(_, true));
  }
  stream_filters[5]->decoder_callbacks_->encodeHeaders(
      std::make_unique<TestResponseHeaderMapImpl>(TestResponseHeaderMapImpl{{":status", "200"}}),
      true, "details");

  filter_manager_->destroyFilters();
  // The providers own the filter config names the filter wrappers view.
  filter_manager_.reset();
}

// A router-only chain adds one decoder filter, so the encoder vector stays unallocated.
TEST_F(FilterManagerTest, CreateFilterChainRouterOnlyLeavesEncoderVectorUnallocated) {
  initialize();

  auto router_filter = std::make_shared<NiceMock<MockStreamDecoderFilter>>();
  const auto filter_factories =
      makeFilterFactories({{"router", createDecoderFilterFactoryCb(router_filter)}});
  createChainFromFactories(filter_factories);

  expectFilterVectors({1, 1, 0}, {1, 1, 0});

  auto request_headers = makeRequestHeaders();
  EXPECT_CALL(*router_filter, decodeHeaders(_, true))
      .WillOnce(Return(FilterHeadersStatus::StopIteration));
  filter_manager_->decodeHeaders(*request_headers, true);

  filter_manager_->destroyFilters();
  // The providers own the filter config names the filter wrappers view.
  filter_manager_.reset();
}

// A dynamic filter config provider before its first config arrives, which the helper replaces with
// a filter that answers every request with a local reply.
class MissingConfigProvider : public Filter::FilterConfigProvider<Filter::HttpFilterFactoryCb> {
public:
  const std::string& name() override { return name_; }
  OptRef<Filter::HttpFilterFactoryCb> config() override { return {}; }

private:
  const std::string name_{"missing_config"};
};

// The hint counts only the factories enabled by default, a missing config included, so a factory
// disabled by default adds no slot.
TEST_F(FilterManagerTest, CreateFilterChainHintSkipsDefaultDisabledFactories) {
  initialize();

  std::vector<std::shared_ptr<NiceMock<MockStreamFilter>>> stream_filters;
  FilterChainUtility::FilterFactoriesList filter_factories;
  for (size_t i = 0; i < 36; ++i) {
    // Factories 0, 11, 22 and 33 are enabled, and the other 32 are disabled by default.
    const bool enabled = i % 11 == 0;
    stream_filters.push_back(std::make_shared<NiceMock<MockStreamFilter>>());
    auto factory = makeFilterFactories(
        {{"filter_" + std::to_string(i), createStreamFilterFactoryCb(stream_filters.back())}},
        /*disabled=*/!enabled);
    filter_factories.push_back(std::move(factory.front()));
  }
  filter_factories.push_back({std::make_unique<MissingConfigProvider>(), false});
  createChainFromFactories(filter_factories);

  // The 32 factories disabled by default add no slot, so four stream filters and the decoder
  // filter for the missing config take five, where counting them would take 37. Leaving the missing
  // config out of the count would grow filters_ and the decoder vector from 4 to 8.
  expectFilterVectors({5, 5, 4}, {5, 5, 5});

  filter_manager_->destroyFilters();
  // The providers own the filter config names the filter wrappers view.
  filter_manager_.reset();
}

// A route that enables factories disabled by default can add more filters than the hint, and a
// vector that takes more filters than the hint grows from it. A route that disables a factory
// enabled by default leaves its slot unused.
TEST_F(FilterManagerTest, CreateFilterChainRouteOverridesGrowFromHint) {
  initialize();

  auto route = std::make_shared<NiceMock<Router::MockRoute>>();
  ON_CALL(*route, filterDisabled(_)).WillByDefault(Return(std::nullopt));
  ON_CALL(*route, filterDisabled(testing::Eq("disabled_by_route")))
      .WillByDefault(Return(std::make_optional(true)));
  ON_CALL(*route, filterDisabled(testing::Eq("enabled_by_route_0")))
      .WillByDefault(Return(std::make_optional(false)));
  ON_CALL(*route, filterDisabled(testing::Eq("enabled_by_route_1")))
      .WillByDefault(Return(std::make_optional(false)));
  filter_manager_->streamInfo().route_ = route;

  std::vector<std::shared_ptr<NiceMock<MockStreamFilter>>> stream_filters;
  for (int i = 0; i < 5; ++i) {
    stream_filters.push_back(std::make_shared<NiceMock<MockStreamFilter>>());
  }
  auto filter_factories = makeFilterFactories({
      {"enabled_0", createStreamFilterFactoryCb(stream_filters[0])},
      {"enabled_1", createStreamFilterFactoryCb(stream_filters[1])},
      {"disabled_by_route", createStreamFilterFactoryCb(stream_filters[2])},
  });
  auto disabled_by_default = makeFilterFactories(
      {
          {"enabled_by_route_0", createStreamFilterFactoryCb(stream_filters[3])},
          {"enabled_by_route_1", createStreamFilterFactoryCb(stream_filters[4])},
      },
      /*disabled=*/true);
  for (auto& filter_factory : disabled_by_default) {
    filter_factories.push_back(std::move(filter_factory));
  }
  createChainFromFactories(filter_factories);

  // Three factories enabled by default give a hint of 3, and the route runs four, so each vector
  // takes three slots on its first filter and doubles them on the fourth, where growing one filter
  // at a time would take 4.
  expectFilterVectors({4, 4, 4}, {6, 6, 6});

  filter_manager_->destroyFilters();
  // The providers own the filter config names the filter wrappers view.
  filter_manager_.reset();
}

// A factory enabled by default may add no filter, so the hint is 1 while no vector takes a filter.
// Each vector reserves only when it takes its first filter, so none is allocated.
TEST_F(FilterManagerTest, CreateFilterChainFactoryAddingNoFilterAllocatesNoVector) {
  initialize();

  const auto filter_factories =
      makeFilterFactories({{"adds_no_filter", [](FilterChainFactoryCallbacks&) {}}});
  createChainFromFactories(filter_factories);

  expectFilterVectors({0, 0, 0}, {0, 0, 0});

  filter_manager_->destroyFilters();
  filter_manager_.reset();
}

TEST_F(FilterManagerTest, CreateFilterChainWithNoFactories) {
  initialize();

  const FilterChainUtility::FilterFactoriesList filter_factories;
  createChainFromFactories(filter_factories);

  expectFilterVectors({0, 0, 0}, {0, 0, 0});

  // A header-only request walks the empty chain to its end.
  auto request_headers = makeRequestHeaders();
  EXPECT_CALL(filter_manager_callbacks_, disarmRequestTimeout());
  filter_manager_->decodeHeaders(*request_headers, true);

  filter_manager_->destroyFilters();
}

TEST_F(FilterManagerTest, GetRouteLevelFilterConfig) {
  initialize();

  std::shared_ptr<MockStreamDecoderFilter> decoder_filter(new NiceMock<MockStreamDecoderFilter>());

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto decoder_factory = createDecoderFilterFactoryCb(decoder_filter);
        callbacks.setFilterConfigName("custom-name");
        decoder_factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  std::shared_ptr<Router::MockRoute> route(new NiceMock<Router::MockRoute>());
  auto route_config = std::make_shared<Router::RouteSpecificFilterConfig>();

  NiceMock<MockDownstreamStreamFilterCallbacks> downstream_callbacks;
  ON_CALL(filter_manager_callbacks_, downstreamCallbacks)
      .WillByDefault(Return(OptRef<DownstreamStreamFilterCallbacks>{downstream_callbacks}));
  ON_CALL(downstream_callbacks, route(_))
      .WillByDefault(Return(makeOptRefFromPtr<const Router::Route>(route.get())));

  // Get a valid config by the custom filter name.
  EXPECT_CALL(*route, mostSpecificPerFilterConfig(testing::Eq("custom-name")))
      .WillOnce(Return(route_config.get()));
  EXPECT_EQ(route_config.get(), decoder_filter->callbacks_->mostSpecificPerFilterConfig());

  // Get nothing by the custom filter name.
  EXPECT_CALL(*route, mostSpecificPerFilterConfig(testing::Eq("custom-name")))
      .WillOnce(Return(nullptr));
  EXPECT_EQ(nullptr, decoder_filter->callbacks_->mostSpecificPerFilterConfig());

  // Get a valid config by the custom filter name.
  EXPECT_CALL(*route, perFilterConfigs(testing::Eq("custom-name")))
      .WillOnce([&](absl::string_view) -> Router::RouteSpecificFilterConfigs {
        return {route_config.get()};
      });
  auto route_config_result = decoder_filter->callbacks_->perFilterConfigs();
  EXPECT_EQ(route_config.get(), route_config_result[0]);

  // Get nothing by the custom filter name.
  EXPECT_CALL(*route, perFilterConfigs(testing::Eq("custom-name")))
      .WillOnce([](absl::string_view) -> Router::RouteSpecificFilterConfigs { return {}; });
  route_config_result = decoder_filter->callbacks_->perFilterConfigs();
  EXPECT_TRUE(route_config_result.empty());

  filter_manager_->destroyFilters();
};

TEST_F(FilterManagerTest, GetRouteLevelFilterConfigForNullRoute) {
  initialize();

  std::shared_ptr<MockStreamDecoderFilter> decoder_filter(new NiceMock<MockStreamDecoderFilter>());

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto decoder_factory = createDecoderFilterFactoryCb(decoder_filter);
        callbacks.setFilterConfigName("custom-name");
        decoder_factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  std::shared_ptr<Router::MockRoute> route(new NiceMock<Router::MockRoute>());
  auto route_config = std::make_shared<Router::RouteSpecificFilterConfig>();

  // Do nothing for no route.
  NiceMock<MockDownstreamStreamFilterCallbacks> downstream_callbacks;
  ON_CALL(filter_manager_callbacks_, downstreamCallbacks)
      .WillByDefault(Return(OptRef<DownstreamStreamFilterCallbacks>{downstream_callbacks}));
  EXPECT_CALL(downstream_callbacks, route(_)).WillOnce(Return(OptRef<const Router::Route>{}));
  decoder_filter->callbacks_->mostSpecificPerFilterConfig();

  EXPECT_CALL(downstream_callbacks, route(_)).WillOnce(Return(OptRef<const Router::Route>{}));
  decoder_filter->callbacks_->perFilterConfigs();

  filter_manager_->destroyFilters();
}

TEST_F(FilterManagerTest, MetadataContinueAll) {
  initialize();

  std::shared_ptr<MockStreamFilter> filter_1(new NiceMock<MockStreamFilter>());

  std::shared_ptr<MockStreamFilter> filter_2(new NiceMock<MockStreamFilter>());

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto decoder_factory = createStreamFilterFactoryCb(filter_1);
        callbacks.setFilterConfigName("configName1");
        decoder_factory(callbacks);
        decoder_factory = createStreamFilterFactoryCb(filter_2);
        callbacks.setFilterConfigName("configName2");
        decoder_factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  // Decode path:
  EXPECT_CALL(*filter_1, decodeHeaders(_, _)).WillOnce(Return(FilterHeadersStatus::StopIteration));
  RequestHeaderMapPtr basic_headers{
      new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "GET"}}};
  ON_CALL(filter_manager_callbacks_, requestHeaders())
      .WillByDefault(Return(makeOptRef(*basic_headers)));

  filter_manager_->requestHeadersInitialized();
  filter_manager_->decodeHeaders(*basic_headers, false);

  EXPECT_CALL(*filter_1, decodeMetadata(_)).WillOnce(Return(FilterMetadataStatus::ContinueAll));
  MetadataMap map1 = {{"a", "b"}};
  MetadataMap map2 = {{"c", "d"}};
  EXPECT_CALL(*filter_2, decodeHeaders(_, _)).WillOnce([&]() {
    filter_2->decoder_callbacks_->addDecodedMetadata().push_back(
        std::make_unique<MetadataMap>(map2));
    return FilterHeadersStatus::Continue;
  });
  {
    InSequence s;
    // Metadata added by filter_2.decodeHeaders(..) appears second, and goes through all filters.
    EXPECT_CALL(*filter_2, decodeMetadata(testing::Eq(map1)));
    EXPECT_CALL(*filter_1, decodeMetadata(testing::Eq(map2)));
    EXPECT_CALL(*filter_2, decodeMetadata(testing::Eq(map2)));
  }
  filter_manager_->decodeMetadata(map1);

  // Encode Path:
  ResponseHeaderMapPtr response_headers{new TestResponseHeaderMapImpl{{":status", "200"}}};
  ON_CALL(filter_manager_callbacks_, responseHeaders())
      .WillByDefault(Return(makeOptRef(*response_headers)));

  EXPECT_CALL(*filter_2, encodeHeaders(_, _)).WillOnce(Return(FilterHeadersStatus::StopIteration));
  EXPECT_CALL(*filter_1, encodeHeaders(_, _)).WillOnce([&]() {
    filter_2->encoder_callbacks_->addEncodedMetadata(std::make_unique<MetadataMap>(map2));
    return FilterHeadersStatus::Continue;
  });
  EXPECT_CALL(*filter_2, encodeMetadata(_)).WillOnce(Return(FilterMetadataStatus::ContinueAll));
  {
    InSequence s;
    // Metadata added by filter_1.decodeHeaders(..) appears second.
    EXPECT_CALL(*filter_1, encodeMetadata(testing::Eq(map1)));
    // The encode path for metadata is different (by design or coincidence) than the decode path.
    // On the encode path, calling addEncodedMetadata will only pass through this and later filters,
    // while on the decode path, calling addDecodedMetadata will pass metadata through all filters.
    EXPECT_CALL(*filter_2, encodeMetadata(testing::Eq(map2))).Times(0);
    EXPECT_CALL(*filter_1, encodeMetadata(testing::Eq(map2)));
  }

  filter_2->decoder_callbacks_->encodeHeaders(
      std::make_unique<TestResponseHeaderMapImpl>(*response_headers), false, "none");
  filter_2->decoder_callbacks_->encodeMetadata(std::make_unique<MetadataMap>(map1));

  filter_manager_->destroyFilters();
}

TEST_F(FilterManagerTest, DecodeMetadataSendsLocalReply) {
  initialize();

  std::shared_ptr<MockStreamFilter> filter_1(new NiceMock<MockStreamFilter>());

  std::shared_ptr<MockStreamFilter> filter_2(new NiceMock<MockStreamFilter>());
  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto factory = createStreamFilterFactoryCb(filter_1);
        callbacks.setFilterConfigName("configName1");
        factory(callbacks);
        factory = createStreamFilterFactoryCb(filter_2);
        callbacks.setFilterConfigName("configName2");
        factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  RequestHeaderMapPtr basic_headers{
      new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "GET"}}};
  ON_CALL(filter_manager_callbacks_, requestHeaders())
      .WillByDefault(Return(makeOptRef(*basic_headers)));

  EXPECT_CALL(*filter_1, decodeHeaders(_, _));
  EXPECT_CALL(*filter_2, decodeHeaders(_, _));
  filter_manager_->decodeHeaders(*basic_headers, false);

  EXPECT_CALL(*filter_1, decodeMetadata(_)).WillOnce([&]() {
    filter_1->decoder_callbacks_->sendLocalReply(Code::InternalServerError, "bad_metadata", nullptr,
                                                 std::nullopt, "bad_metadata");
    return FilterMetadataStatus::StopIterationForLocalReply;
  });

  // Metadata does not pass to the next filter due to local reply.
  EXPECT_CALL(*filter_2, decodeMetadata(_)).Times(0);
  // Triggered local reply should pass through encode headers for both filters.
  EXPECT_CALL(*filter_2, encodeHeaders(_, _));
  EXPECT_CALL(*filter_1, encodeHeaders(_, _));
  MetadataMap map = {{"a", "b"}};
  filter_manager_->decodeMetadata(map);

  EXPECT_THAT(*filter_manager_->streamInfo().responseCodeDetails(), "bad_metadata");

  validateFilterStateData("configName1");

  filter_manager_->destroyFilters();
}

TEST_F(FilterManagerTest, MetadataContinueAllFollowedByHeadersLocalReply) {
  initialize();

  std::shared_ptr<MockStreamFilter> filter_1(new NiceMock<MockStreamFilter>());

  std::shared_ptr<MockStreamFilter> filter_2(new NiceMock<MockStreamFilter>());

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto decoder_factory = createStreamFilterFactoryCb(filter_1);
        callbacks.setFilterConfigName("configName1");
        decoder_factory(callbacks);
        decoder_factory = createStreamFilterFactoryCb(filter_2);
        callbacks.setFilterConfigName("configName2");
        decoder_factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  // Decode path:
  EXPECT_CALL(*filter_1, decodeHeaders(_, _)).WillOnce(Return(FilterHeadersStatus::StopIteration));
  RequestHeaderMapPtr basic_headers{
      new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "GET"}}};
  ON_CALL(filter_manager_callbacks_, requestHeaders())
      .WillByDefault(Return(makeOptRef(*basic_headers)));

  filter_manager_->requestHeadersInitialized();
  filter_manager_->decodeHeaders(*basic_headers, false);

  EXPECT_CALL(*filter_1, decodeMetadata(_)).WillOnce(Return(FilterMetadataStatus::ContinueAll));
  MetadataMap map1 = {{"a", "b"}};
  MetadataMap map2 = {{"c", "d"}};
  EXPECT_CALL(*filter_2, decodeHeaders(_, _)).WillOnce([&]() {
    filter_2->decoder_callbacks_->sendLocalReply(Code::InternalServerError, "bad_headers", nullptr,
                                                 std::nullopt, "bad_headers");
    return FilterHeadersStatus::StopIteration;
  });
  // filter_2 should never decode metadata.
  EXPECT_CALL(*filter_2, decodeMetadata(_)).Times(0);
  filter_manager_->decodeMetadata(map1);
  filter_manager_->destroyFilters();
}

TEST_F(FilterManagerTest, EncodeMetadataSendsLocalReply) {
  initialize();

  std::shared_ptr<MockStreamFilter> filter_1(new NiceMock<MockStreamFilter>());

  std::shared_ptr<MockStreamFilter> filter_2(new NiceMock<MockStreamFilter>());
  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto factory = createStreamFilterFactoryCb(filter_1);
        callbacks.setFilterConfigName("configName1");
        factory(callbacks);
        factory = createStreamFilterFactoryCb(filter_2);
        callbacks.setFilterConfigName("configName2");
        factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  // Encode headers first, as metadata can't get ahead of headers.
  ResponseHeaderMapPtr response_headers{new TestResponseHeaderMapImpl{{":status", "200"}}};
  ON_CALL(filter_manager_callbacks_, responseHeaders())
      .WillByDefault(Return(makeOptRef(*response_headers)));

  EXPECT_CALL(*filter_2, encodeHeaders(_, _));
  EXPECT_CALL(*filter_1, encodeHeaders(_, _));
  filter_2->decoder_callbacks_->encodeHeaders(
      std::make_unique<TestResponseHeaderMapImpl>(*response_headers), false, "");

  EXPECT_CALL(*filter_2, encodeMetadata(_)).WillOnce([&]() {
    filter_2->encoder_callbacks_->sendLocalReply(Code::InternalServerError, "", nullptr,
                                                 std::nullopt, "bad_metadata");
    return FilterMetadataStatus::StopIterationForLocalReply;
  });
  // Headers have already passed through; we will reset the stream.
  EXPECT_CALL(filter_manager_callbacks_, resetStream(StreamResetReason::LocalReset, ""));
  MetadataMap map1 = {{"a", "b"}};
  filter_2->decoder_callbacks_->encodeMetadata(std::make_unique<MetadataMap>(map1));

  validateFilterStateData("configName2");

  filter_manager_->destroyFilters();
}

TEST_F(FilterManagerTest, RequestedApplicationProtocols) {
  initialize();

  const auto& protocols =
      filter_manager_->streamInfo().downstreamAddressProvider().requestedApplicationProtocols();
  EXPECT_TRUE(protocols.empty());

  filter_manager_->destroyFilters();
}

TEST_F(FilterManagerTest, IdleTimerResets) {
  initialize();

  std::shared_ptr<MockStreamFilter> filter_1(new NiceMock<MockStreamFilter>());
  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto factory = createStreamFilterFactoryCb(filter_1);
        callbacks.setFilterConfigName("configName1");
        factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  RequestHeaderMapPtr basic_headers{
      new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "GET"}}};
  ON_CALL(filter_manager_callbacks_, requestHeaders())
      .WillByDefault(Return(makeOptRef(*basic_headers)));
  filter_manager_->requestHeadersInitialized();

  filter_manager_->decodeHeaders(*basic_headers, false);

  Buffer::OwnedImpl data("absee");
  EXPECT_CALL(filter_manager_callbacks_, resetIdleTimer());
  filter_manager_->decodeData(data, false);

  MetadataMap map = {{"a", "b"}};
  EXPECT_CALL(filter_manager_callbacks_, resetIdleTimer());
  filter_manager_->decodeMetadata(map);

  RequestTrailerMapPtr basic_trailers{new TestRequestTrailerMapImpl{{"x", "y"}}};
  filter_manager_->decodeTrailers(*basic_trailers);

  ResponseHeaderMapPtr response_headers{new TestResponseHeaderMapImpl{{":status", "200"}}};
  ON_CALL(filter_manager_callbacks_, responseHeaders())
      .WillByDefault(Return(makeOptRef(*response_headers)));

  EXPECT_CALL(filter_manager_callbacks_, resetIdleTimer());
  filter_1->decoder_callbacks_->encodeHeaders(
      std::make_unique<TestResponseHeaderMapImpl>(*response_headers), false, "");

  EXPECT_CALL(filter_manager_callbacks_, resetIdleTimer());
  filter_1->decoder_callbacks_->encodeData(data, false);

  EXPECT_CALL(filter_manager_callbacks_, resetIdleTimer());
  filter_1->decoder_callbacks_->encodeMetadata(std::make_unique<MetadataMap>(map));

  ResponseTrailerMapPtr basic_resp_trailers{new TestResponseTrailerMapImpl{{"x", "y"}}};
  EXPECT_CALL(filter_manager_callbacks_, resetIdleTimer());
  filter_1->decoder_callbacks_->encodeTrailers(std::move(basic_resp_trailers));
  filter_manager_->destroyFilters();
}

// Verify that decodeData is not called on filters after the stream has been reset.
TEST_F(FilterManagerTest, DecodeDataNotCalledAfterDownstreamReset) {
  initialize();

  std::shared_ptr<MockStreamDecoderFilter> filter(new NiceMock<MockStreamDecoderFilter>());

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillOnce([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto factory = createDecoderFilterFactoryCb(filter);
        callbacks.setFilterConfigName("test_filter");
        factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  RequestHeaderMapPtr headers{
      new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "POST"}}};
  ON_CALL(filter_manager_callbacks_, requestHeaders()).WillByDefault(Return(makeOptRef(*headers)));

  EXPECT_CALL(*filter, decodeHeaders(_, false)).WillOnce(Return(FilterHeadersStatus::Continue));
  filter_manager_->requestHeadersInitialized();
  filter_manager_->decodeHeaders(*headers, false);

  // Simulate a downstream reset.
  filter_manager_->onDownstreamReset();

  // After reset, decodeData should not be called on the filter.
  EXPECT_CALL(*filter, decodeData(_, _)).Times(0);

  Buffer::OwnedImpl data("test_data");
  filter_manager_->decodeData(data, false);

  filter_manager_->destroyFilters();
}

// Verify that decodeHeaders is not called on filters after the stream has been reset.
TEST_F(FilterManagerTest, DecodeHeadersNotCalledAfterDownstreamReset) {
  initialize();

  std::shared_ptr<MockStreamDecoderFilter> filter(new NiceMock<MockStreamDecoderFilter>());

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillOnce([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto factory = createDecoderFilterFactoryCb(filter);
        callbacks.setFilterConfigName("test_filter");
        factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  // Simulate a downstream reset before headers are processed.
  filter_manager_->onDownstreamReset();

  // After reset, decodeHeaders should not be called on the filter.
  EXPECT_CALL(*filter, decodeHeaders(_, _)).Times(0);

  RequestHeaderMapPtr headers{
      new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "GET"}}};
  ON_CALL(filter_manager_callbacks_, requestHeaders()).WillByDefault(Return(makeOptRef(*headers)));

  filter_manager_->decodeHeaders(*headers, true);

  filter_manager_->destroyFilters();
}

// Verify that decodeTrailers is not called on filters after the stream has been reset.
TEST_F(FilterManagerTest, DecodeTrailersNotCalledAfterDownstreamReset) {
  initialize();

  std::shared_ptr<MockStreamDecoderFilter> filter(new NiceMock<MockStreamDecoderFilter>());

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillOnce([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto factory = createDecoderFilterFactoryCb(filter);
        callbacks.setFilterConfigName("test_filter");
        factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  RequestHeaderMapPtr headers{
      new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "POST"}}};
  ON_CALL(filter_manager_callbacks_, requestHeaders()).WillByDefault(Return(makeOptRef(*headers)));

  EXPECT_CALL(*filter, decodeHeaders(_, false)).WillOnce(Return(FilterHeadersStatus::Continue));
  filter_manager_->requestHeadersInitialized();
  filter_manager_->decodeHeaders(*headers, false);

  // Simulate a downstream reset.
  filter_manager_->onDownstreamReset();

  // After reset, decodeTrailers should not be called on the filter.
  EXPECT_CALL(*filter, decodeTrailers(_)).Times(0);

  RequestTrailerMapPtr trailers{new TestRequestTrailerMapImpl{{"foo", "bar"}}};
  ON_CALL(filter_manager_callbacks_, requestTrailers())
      .WillByDefault(Return(makeOptRef(*trailers)));

  filter_manager_->decodeTrailers(*trailers);

  filter_manager_->destroyFilters();
}

// Verify that decodeMetadata is not called on filters after the stream has been reset.
TEST_F(FilterManagerTest, DecodeMetadataNotCalledAfterDownstreamReset) {
  initialize();

  std::shared_ptr<MockStreamDecoderFilter> filter(new NiceMock<MockStreamDecoderFilter>());

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillOnce([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto factory = createDecoderFilterFactoryCb(filter);
        callbacks.setFilterConfigName("test_filter");
        factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  RequestHeaderMapPtr headers{
      new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "POST"}}};
  ON_CALL(filter_manager_callbacks_, requestHeaders()).WillByDefault(Return(makeOptRef(*headers)));

  EXPECT_CALL(*filter, decodeHeaders(_, false)).WillOnce(Return(FilterHeadersStatus::Continue));
  filter_manager_->requestHeadersInitialized();
  filter_manager_->decodeHeaders(*headers, false);

  // Simulate a downstream reset.
  filter_manager_->onDownstreamReset();

  // After reset, decodeMetadata should not be called on the filter.
  EXPECT_CALL(*filter, decodeMetadata(_)).Times(0);

  MetadataMap metadata_map{{"key", "value"}};
  filter_manager_->decodeMetadata(metadata_map);

  filter_manager_->destroyFilters();
}

// Verify that multiple decode operations are all blocked after downstream reset.
TEST_F(FilterManagerTest, AllDecodeOperationsBlockedAfterDownstreamReset) {
  initialize();

  std::shared_ptr<MockStreamDecoderFilter> filter(new NiceMock<MockStreamDecoderFilter>());

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillOnce([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto factory = createDecoderFilterFactoryCb(filter);
        callbacks.setFilterConfigName("test_filter");
        factory(callbacks);
        return true;
      });
  filter_manager_->createDownstreamFilterChain();

  RequestHeaderMapPtr headers{
      new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "POST"}}};
  ON_CALL(filter_manager_callbacks_, requestHeaders()).WillByDefault(Return(makeOptRef(*headers)));

  EXPECT_CALL(*filter, decodeHeaders(_, false)).WillOnce(Return(FilterHeadersStatus::Continue));
  filter_manager_->requestHeadersInitialized();
  filter_manager_->decodeHeaders(*headers, false);

  // Simulate a downstream reset.
  filter_manager_->onDownstreamReset();

  // After reset, none of the decode operations should call the filter.
  EXPECT_CALL(*filter, decodeData(_, _)).Times(0);
  EXPECT_CALL(*filter, decodeTrailers(_)).Times(0);
  EXPECT_CALL(*filter, decodeMetadata(_)).Times(0);

  // Try all decode operations. None of them should reach the filter.
  Buffer::OwnedImpl data("test_data");
  filter_manager_->decodeData(data, false);

  MetadataMap metadata_map{{"key", "value"}};
  filter_manager_->decodeMetadata(metadata_map);

  RequestTrailerMapPtr trailers{new TestRequestTrailerMapImpl{{"foo", "bar"}}};
  ON_CALL(filter_manager_callbacks_, requestTrailers())
      .WillByDefault(Return(makeOptRef(*trailers)));
  filter_manager_->decodeTrailers(*trailers);

  filter_manager_->destroyFilters();
}

// Reproduces the request-body frame loss reported in
// https://github.com/Kuadrant/wasm-shim/issues/388 (and Envoy #46841): a filter
// that returns StopIteration on headers (e.g. a wasm filter with
// allow_on_headers_stop_iteration, mapped to IterationState::StopSingleIteration)
// buffers a body chunk, continues asynchronously, and then on the next chunk
// drains the frame into the filter-manager buffer via addDecodedData() while
// returning Continue. Because the filter's IterationState is already Continue at
// that point, commonHandleAfterDataCallback() forwards the now-empty frame
// instead of the just-buffered data, so a downstream FULL_DUPLEX_STREAMED
// ext_proc filter never receives that chunk. Exactly one mid-stream frame is
// lost while the message count is unchanged.
//
// The `forward_data` parameter toggles the
// `filter_manager_forward_added_data_on_continue` runtime guard: when disabled
// this documents the pre-fix data loss; when enabled it verifies the fix.
void FilterManagerTest::runAddDecodedDataOnContinueTest(bool forward_data) {
  TestScopedRuntime scoped_runtime;
  scoped_runtime.mergeValues(
      {{"envoy.reloadable_features.filter_manager_forward_added_data_on_continue",
        forward_data ? "true" : "false"}});

  initialize();

  // filter_1 mimics the wasm filter (stops on headers, buffers, continues after
  // an async callout); filter_2 mimics a FULL_DUPLEX_STREAMED ext_proc filter
  // that streams (does not re-buffer) every request body byte it receives.
  std::shared_ptr<MockStreamDecoderFilter> filter_1(new NiceMock<MockStreamDecoderFilter>());
  std::shared_ptr<MockStreamDecoderFilter> filter_2(new NiceMock<MockStreamDecoderFilter>());

  EXPECT_CALL(filter_factory_, createFilterChain(_))
      .WillRepeatedly([&](FilterChainFactoryCallbacks& callbacks) -> bool {
        auto factory = createDecoderFilterFactoryCb(filter_1);
        callbacks.setFilterConfigName("filter_1");
        factory(callbacks);
        factory = createDecoderFilterFactoryCb(filter_2);
        callbacks.setFilterConfigName("filter_2");
        factory(callbacks);
        return true;
      });

  RequestHeaderMapPtr headers{
      new TestRequestHeaderMapImpl{{":authority", "host"}, {":path", "/"}, {":method", "POST"}}};
  ON_CALL(filter_manager_callbacks_, requestHeaders()).WillByDefault(Return(makeOptRef(*headers)));

  filter_manager_->createDownstreamFilterChain();
  filter_manager_->requestHeadersInitialized();

  // filter_2 accumulates and drains (streams) every request body byte it sees.
  std::string filter_2_received;
  ON_CALL(*filter_2, decodeData(_, _))
      .WillByDefault([&](Buffer::Instance& data, bool) -> FilterDataStatus {
        filter_2_received += data.toString();
        data.drain(data.length());
        return FilterDataStatus::StopIterationNoBuffer;
      });

  // filter_1 stops iteration on headers to await an async callout; filter_2 must
  // not see the headers yet.
  EXPECT_CALL(*filter_1, decodeHeaders(_, false))
      .WillOnce(Return(FilterHeadersStatus::StopIteration));
  filter_manager_->decodeHeaders(*headers, false);

  // Chunk A arrives while filter_1 is paused: buffer it in the filter manager.
  EXPECT_CALL(*filter_1, decodeData(_, false))
      .WillOnce(Return(FilterDataStatus::StopIterationAndBuffer));
  Buffer::OwnedImpl chunk_a("AAAA");
  filter_manager_->decodeData(chunk_a, false);

  // The async callout completes: filter_1 continues, which delivers the buffered
  // chunk A (and the headers) down to filter_2.
  EXPECT_CALL(*filter_2, decodeHeaders(_, false)).WillOnce(Return(FilterHeadersStatus::Continue));
  filter_1->callbacks_->continueDecoding();
  EXPECT_EQ("AAAA", filter_2_received);

  // Chunk B arrives right after the continue. filter_1, still in its buffering
  // mode, moves the frame into the filter-manager buffer via addDecodedData()
  // and then returns Continue. This frame must still reach filter_2.
  EXPECT_CALL(*filter_1, decodeData(_, false))
      .WillOnce([&](Buffer::Instance& data, bool) -> FilterDataStatus {
        filter_1->callbacks_->addDecodedData(data, false);
        return FilterDataStatus::Continue;
      });
  Buffer::OwnedImpl chunk_b("BBBB");
  filter_manager_->decodeData(chunk_b, false);

  // Chunk C (end of stream): filter_1 passes it straight through.
  EXPECT_CALL(*filter_1, decodeData(_, true)).WillOnce(Return(FilterDataStatus::Continue));
  Buffer::OwnedImpl chunk_c("CCCC");
  filter_manager_->decodeData(chunk_c, true);

  // With the fix (guard enabled) all three frames reach filter_2. Without it,
  // chunk B is dropped and filter_2 only sees "AAAACCCC".
  if (forward_data) {
    EXPECT_EQ("AAAABBBBCCCC", filter_2_received);
  } else {
    EXPECT_EQ("AAAACCCC", filter_2_received);
  }

  filter_manager_->destroyFilters();
}

TEST_F(FilterManagerTest, DecodeDataFrameLostAfterContinueWithoutGuard) {
  runAddDecodedDataOnContinueTest(/*forward_data=*/false);
}

TEST_F(FilterManagerTest, DecodeDataFrameNotLostAfterContinueWithAddDecodedData) {
  runAddDecodedDataOnContinueTest(/*forward_data=*/true);
}

} // namespace
} // namespace Http
} // namespace Envoy
