#include "contrib/mysql_proxy/filters/network/source/mysql_filter.h"

#include "envoy/config/core/v3/base.pb.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/hex.h"
#include "source/common/common/logger.h"
#include "source/extensions/filters/network/well_known_names.h"

#include "contrib/mysql_proxy/filters/network/source/mysql_codec.h"
#include "contrib/mysql_proxy/filters/network/source/mysql_codec_clogin_resp.h"
#include "contrib/mysql_proxy/filters/network/source/mysql_decoder_impl.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

MySQLFilterConfig::MySQLFilterConfig(const std::string& stat_prefix, Stats::Scope& scope)
    : scope_(scope), stats_(generateStats(stat_prefix, scope)) {}

MySQLFilter::MySQLFilter(MySQLFilterConfigSharedPtr config) : config_(std::move(config)) {}

void MySQLFilter::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;
}

void MySQLFilter::initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) {
  write_callbacks_ = &callbacks;
}

Network::FilterStatus MySQLFilter::onData(Buffer::Instance& data, bool) {
  //read_callbacks_->connection().readDisable(true);
  ENVOY_LOG(info, "mysql_proxy: onData() = {}", data.length());
  ENVOY_LOG(trace, "mysql_proxy: onData() buffer = {}",
            Hex::encode(static_cast<uint8_t*>(data.linearize(data.length())), data.length()));

  if (init_ == 0) {
    init_ = 1;
    data.drain(data.length());
    read_callbacks_->connection().readDisable(true);
  }

  return Network::FilterStatus::Continue;

  /*
  // Safety measure just to make sure that if we have a decoding error we keep going and lose stats.
  // This can be removed once we are more confident of this code.
  if (sniffing_) {
    read_buffer_.add(data);
    doDecode(read_buffer_);
  }
  //read_callbacks_->connection().readDisable(false);
  return Network::FilterStatus::Continue;
  */
}

Network::FilterStatus MySQLFilter::onWrite(Buffer::Instance& data, bool) {
  ENVOY_LOG(info, "mysql_proxy: onWrite() = {}", data.length());
  ENVOY_LOG(trace, "mysql_proxy: onWrite() buffer = {}",
            Hex::encode(static_cast<uint8_t*>(data.linearize(data.length())), data.length()));

  if (init_ == 1) {
    init_ = 2;
    data.drain(data.length());

    Buffer::OwnedImpl out_buffer_{};
    // 20 00 00 01 8d ae ff 19 00 00 00 01 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    const uint8_t buff_val_0[36]{32, 0, 0, 1, 141, 174, 255, 25, 0, 0, 0, 1, 255, 0, 0, 0, 0, 0,
                               0,  0, 0, 0, 0,   0,   0,   0,  0, 0, 0, 0, 0,   0, 0, 0, 0, 0};
    // 16 03 01 01 26 01 00 01 22 03 03 7e 22 94 97 72 be cb de 19 f0 7e 9d 30 15 1f c6 48 ba f3 3d 38 05 56 88 73 6f 7a aa c1 6e 00 86 20 9b 94 1e a9 9c 6a 47 68 4f 36 8f a5 75 a5 31 f5 f1 5c 8b 7f b6 00 26 d6 3e 47 15 26 65 59 64 24 00 48 13 02 13 03 13 01 c0 2b c0 2c c0 2f c0 23 c0 27 c0 30 c0 24 c0 28 00 9e 00 a2 00 67 00 40 00 a3 00 6b 00 6a 00 9f c0 13 c0 09 c0 14 c0 0a 00 32 00 33 00 38 00 39 00 35 00 84 00 41 00 9c 00 9d 00 3c 00 3d 00 2f 00 ff 01 00 00 91 00 0b 00 04 03 00 01 02 00 0a 00 0c 00 0a 00 1d 00 17 00 1e 00 19 00 18 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 30 00 2e 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 03 03 02 03 03 01 02 01 03 02 02 02 04 02 05 02 06 02 00 2b 00 05 04 03 04 03 03 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00 20 b6 c1 be b1 7a 6e 56 a1 60 73 bb ad 7e 07 aa a9 64 60 fc 22 3e 68 3e d8 bc f1 50 ad 41 5e 7b 4b
    const uint8_t buff_val_1[299]{22, 3, 1, 1, 38, 1, 0, 1, 34, 3, 3, 126, 34, 148, 151, 114, 190, 203, 222, 25, 240, 126, 157, 48, 21, 31, 198, 72, 186, 243, 61, 56, 5, 86, 136, 115, 111, 122, 170, 193, 110, 0, 134, 32, 155, 148, 30, 169, 156, 106, 71, 104, 79, 54, 143, 165, 117, 165, 49, 245, 241, 92, 139, 127, 182, 0, 38, 214, 62, 71, 21, 38, 101, 89, 100, 36, 0, 72, 19, 2, 19, 3, 19, 1, 192, 43, 192, 44, 192, 47, 192, 35, 192, 39, 192, 48, 192, 36, 192, 40, 0, 158, 0, 162, 0, 103, 0, 64, 0, 163, 0, 107, 0, 106, 0, 159, 192, 19, 192, 9, 192, 20, 192, 10, 0, 50, 0, 51, 0, 56, 0, 57, 0, 53, 0, 132, 0, 65, 0, 156, 0, 157, 0, 60, 0, 61, 0, 47, 0, 255, 1, 0, 0, 145, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 12, 0, 10, 0, 29, 0, 23, 0, 30, 0, 25, 0, 24, 0, 35, 0, 0, 0, 22, 0, 0, 0, 23, 0, 0, 0, 13, 0, 48, 0, 46, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10, 8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 3, 3, 2, 3, 3, 1, 2, 1, 3, 2, 2, 2, 4, 2, 5, 2, 6, 2, 0, 43, 0, 5, 4, 3, 4, 3, 3, 0, 45, 0, 2, 1, 1, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32, 182, 193, 190, 177, 122, 110, 86, 161, 96, 115, 187, 173, 126, 7, 170, 169, 100, 96, 252, 34, 62, 104, 62, 216, 188, 241, 80, 173, 65, 94, 123, 75};
    out_buffer_.add(buff_val_0, 36);
    out_buffer_.add(buff_val_1, 299);
    read_callbacks_->injectReadDataToFilterChain(out_buffer_, false);

    return Network::FilterStatus::StopIteration;
  }

  /*
  else if (init_ == 2) {
    init_ = 3;
    //data.drain(data.length());
    onSslState();
  }
  */

  return Network::FilterStatus::Continue;

  /*
  // Safety measure just to make sure that if we have a decoding error we keep going and lose stats.
  // This can be removed once we are more confident of this code.
  if (sniffing_) {
    write_buffer_.add(data);
    doDecode(write_buffer_);
  }
  return Network::FilterStatus::Continue;
  */
}

void MySQLFilter::onSslState() {
  // Try to switch upstream connection to use a secure channel.
  ENVOY_CONN_LOG(trace, "mysql_proxy: switching protocols.", read_callbacks_->connection());
  if (read_callbacks_->startUpstreamSecureTransport()) {
    ENVOY_CONN_LOG(trace, "mysql_proxy: onSslState()", read_callbacks_->connection());
    ENVOY_CONN_LOG(trace, "mysql_proxy: upstream SSL enabled.", read_callbacks_->connection());
  } else {
    ENVOY_CONN_LOG(info,
                   "mysql_proxy: cannot enable upstream secure transport. Check "
                   "configuration. Terminating.",
                   read_callbacks_->connection());
    read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
  }
}

void MySQLFilter::doDecode(Buffer::Instance& buffer) {
  ENVOY_LOG(info, "mysql_proxy: doDecode() = {}", buffer.length());
  ENVOY_LOG(trace, "mysql_proxy: doDecode() buffer = {}",
            Hex::encode(static_cast<uint8_t*>(buffer.linearize(buffer.length())), buffer.length()));
  // Clear dynamic metadata.
  envoy::config::core::v3::Metadata& dynamic_metadata =
      read_callbacks_->connection().streamInfo().dynamicMetadata();
  auto& metadata =
      (*dynamic_metadata.mutable_filter_metadata())[NetworkFilterNames::get().MySQLProxy];
  metadata.mutable_fields()->clear();

  if (!decoder_) {
    decoder_ = createDecoder(*this);
  }

  try {
    decoder_->onData(buffer);
  } catch (EnvoyException& e) {
    ENVOY_LOG(info, "mysql_proxy: decoding error: {}", e.what());
    config_->stats_.decoder_errors_.inc();
    sniffing_ = false;
    read_buffer_.drain(read_buffer_.length());
    write_buffer_.drain(write_buffer_.length());
  }
}

DecoderPtr MySQLFilter::createDecoder(DecoderCallbacks& callbacks) {
  return std::make_unique<DecoderImpl>(callbacks);
}

void MySQLFilter::onProtocolError() { config_->stats_.protocol_errors_.inc(); }

void MySQLFilter::onNewMessage(MySQLSession::State state) {
  if (state == MySQLSession::State::ChallengeReq) {
    config_->stats_.login_attempts_.inc();
  }
}

void MySQLFilter::onClientLogin(ClientLogin& client_login) {
  if (client_login.isSSLRequest()) {
    config_->stats_.upgraded_to_ssl_.inc();
    // author[agrawroh]: Switch protocols -> SSL
    if (!read_callbacks_->connection().startSecureTransport()) {
      ENVOY_CONN_LOG(
          info, "mysql_proxy: cannot enable downstream secure transport. Check configuration.",
          read_callbacks_->connection());
      read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
    } else {
      // Unsubscribe the callback.
      ENVOY_CONN_LOG(trace, "mysql_proxy: onClientLogin()", read_callbacks_->connection());
      // read_callbacks_->injectReadDataToFilterChain(data, false);
      ENVOY_CONN_LOG(trace, "mysql_proxy: enabled SSL termination.",
                     read_callbacks_->connection());
      // Switch to TLS has been completed.
      // Signal to the decoder to stop processing the current message (SSLRequest).
      // Because Envoy terminates SSL, the message was consumed and should not be
      // passed to other filters in the chain.
    }
  }
}

void MySQLFilter::onClientLoginResponse(ClientLoginResponse& client_login_resp) {
  if (client_login_resp.getRespCode() == MYSQL_RESP_AUTH_SWITCH) {
    config_->stats_.auth_switch_request_.inc();
  } else if (client_login_resp.getRespCode() == MYSQL_RESP_ERR) {
    config_->stats_.login_failures_.inc();
  }
}

void MySQLFilter::onMoreClientLoginResponse(ClientLoginResponse& client_login_resp) {
  if (client_login_resp.getRespCode() == MYSQL_RESP_ERR) {
    config_->stats_.login_failures_.inc();
  }
}

void MySQLFilter::onCommand(Command& command) {
  if (!command.isQuery()) {
    return;
  }

  // Parse a given query
  envoy::config::core::v3::Metadata& dynamic_metadata =
      read_callbacks_->connection().streamInfo().dynamicMetadata();
  ProtobufWkt::Struct metadata(
      (*dynamic_metadata.mutable_filter_metadata())[NetworkFilterNames::get().MySQLProxy]);

  auto result = Common::SQLUtils::SQLUtils::setMetadata(command.getData(),
                                                        decoder_->getAttributes(), metadata);

  ENVOY_CONN_LOG(trace, "mysql_proxy: query processed {}, result {}, cmd type {}",
                 read_callbacks_->connection(), command.getData(), result,
                 static_cast<int>(command.getCmd()));

  if (!result) {
    config_->stats_.queries_parse_error_.inc();
    return;
  }
  config_->stats_.queries_parsed_.inc();

  read_callbacks_->connection().streamInfo().setDynamicMetadata(
      NetworkFilterNames::get().MySQLProxy, metadata);
}

Network::FilterStatus MySQLFilter::onNewConnection() {
  config_->stats_.sessions_.inc();
  ENVOY_CONN_LOG(trace, "mysql_proxy: onNewConnection() called", read_callbacks_->connection());
  read_callbacks_->connection().readDisable(false);
  return Network::FilterStatus::StopIteration;
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
