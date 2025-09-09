#include "source/server/admin/reverse_tunnels_handler.h"

#include "test/mocks/server/admin_stream.h"
#include "test/mocks/server/mocks.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;

namespace Envoy {
namespace Server {

class ReverseTunnelsHandlerTest : public testing::Test {
public:
  ReverseTunnelsHandlerTest() : handler_(server_) {}

protected:
  void SetUp() override {
    // Create default headers.
    headers_ = Http::TestRequestHeaderMapImpl{{":path", "/reverse_tunnels"}};
    ON_CALL(admin_stream_, getRequestHeaders()).WillByDefault(ReturnRef(headers_));

    // Create default empty query params.
    query_params_ = Http::Utility::QueryParamsMulti();
    ON_CALL(admin_stream_, queryParams()).WillByDefault(Return(query_params_));
  }

  void setQueryParam(const std::string& key, const std::string& value) {
    query_params_.overwrite(key, value);
  }

  NiceMock<Server::MockInstance> server_;
  ReverseTunnelsHandler handler_;
  NiceMock<Server::MockAdminStream> admin_stream_;
  Http::TestRequestHeaderMapImpl headers_;
  Http::Utility::QueryParamsMulti query_params_;
  Buffer::OwnedImpl response_buffer_;
  Http::TestResponseHeaderMapImpl response_headers_;
};

// Test basic functionality with no reverse tunnel interface (should return empty stats).
TEST_F(ReverseTunnelsHandlerTest, NoReverseConnectionInterface) {
  Http::Code result =
      handler_.handlerReverseTunnels(response_headers_, response_buffer_, admin_stream_);

  EXPECT_EQ(Http::Code::OK, result);
  EXPECT_THAT(response_headers_.getContentTypeValue(), testing::HasSubstr("application/json"));

  // Should return empty stats.
  std::string response = response_buffer_.toString();
  EXPECT_THAT(response, testing::HasSubstr("\"total_connections\": 0"));
  EXPECT_THAT(response, testing::HasSubstr("\"summary\""));
}

// Test JSON format response.
TEST_F(ReverseTunnelsHandlerTest, JsonFormat) {
  setQueryParam("format", "json");

  Http::Code result =
      handler_.handlerReverseTunnels(response_headers_, response_buffer_, admin_stream_);

  EXPECT_EQ(Http::Code::OK, result);
  EXPECT_THAT(response_headers_.getContentTypeValue(), testing::HasSubstr("application/json"));

  std::string response = response_buffer_.toString();
  EXPECT_THAT(response, testing::HasSubstr("\"timestamp\""));
  EXPECT_THAT(response, testing::HasSubstr("\"summary\""));
  EXPECT_THAT(response, testing::HasSubstr("\"aggregations\""));
}

// Test text format response.
TEST_F(ReverseTunnelsHandlerTest, TextFormat) {
  setQueryParam("format", "text");

  Http::Code result =
      handler_.handlerReverseTunnels(response_headers_, response_buffer_, admin_stream_);

  EXPECT_EQ(Http::Code::OK, result);
  EXPECT_THAT(response_headers_.getContentTypeValue(), testing::HasSubstr("text/plain"));

  std::string response = response_buffer_.toString();
  EXPECT_THAT(response, testing::HasSubstr("Reverse Tunnel Connections"));
  EXPECT_THAT(response, testing::HasSubstr("Summary:"));
  EXPECT_THAT(response, testing::HasSubstr("Total Connections: 0"));
}

// Test Prometheus format response.
TEST_F(ReverseTunnelsHandlerTest, PrometheusFormat) {
  setQueryParam("format", "prometheus");

  Http::Code result =
      handler_.handlerReverseTunnels(response_headers_, response_buffer_, admin_stream_);

  EXPECT_EQ(Http::Code::OK, result);
  EXPECT_THAT(response_headers_.getContentTypeValue(), testing::HasSubstr("text/plain"));

  std::string response = response_buffer_.toString();
  EXPECT_THAT(response, testing::HasSubstr("# HELP envoy_reverse_tunnels_total"));
  EXPECT_THAT(response, testing::HasSubstr("# TYPE envoy_reverse_tunnels_total gauge"));
  EXPECT_THAT(response, testing::HasSubstr("envoy_reverse_tunnels_total 0"));
}

// Test invalid format parameter.
TEST_F(ReverseTunnelsHandlerTest, InvalidFormat) {
  setQueryParam("format", "invalid");

  Http::Code result =
      handler_.handlerReverseTunnels(response_headers_, response_buffer_, admin_stream_);

  EXPECT_EQ(Http::Code::BadRequest, result);
  std::string response = response_buffer_.toString();
  EXPECT_THAT(response, testing::HasSubstr("Invalid format parameter"));
}

// Test aggregate_only parameter.
TEST_F(ReverseTunnelsHandlerTest, AggregateOnly) {
  setQueryParam("aggregate_only", "true");

  Http::Code result =
      handler_.handlerReverseTunnels(response_headers_, response_buffer_, admin_stream_);

  EXPECT_EQ(Http::Code::OK, result);
  std::string response = response_buffer_.toString();
  // Should not contain connections array in aggregate_only mode.
  EXPECT_THAT(response, testing::Not(testing::HasSubstr("\"connections\":")));
  EXPECT_THAT(response, testing::HasSubstr("\"summary\""));
}

// Test query parameter combinations.
TEST_F(ReverseTunnelsHandlerTest, QueryParameterCombinations) {
  // Test multiple parameters together.
  setQueryParam("node_id", "test");
  setQueryParam("cluster_id", "prod");
  setQueryParam("format", "text");
  setQueryParam("healthy_only", "true");
  setQueryParam("limit", "10");

  Http::Code result =
      handler_.handlerReverseTunnels(response_headers_, response_buffer_, admin_stream_);

  EXPECT_EQ(Http::Code::OK, result);
  EXPECT_THAT(response_headers_.getContentTypeValue(), testing::HasSubstr("text/plain"));
}

// Test makeRequest method.
TEST_F(ReverseTunnelsHandlerTest, MakeRequest) {
  auto request = handler_.makeRequest(admin_stream_);
  // Current implementation returns nullptr for streaming requests.
  EXPECT_EQ(request, nullptr);
}

} // namespace Server
} // namespace Envoy
