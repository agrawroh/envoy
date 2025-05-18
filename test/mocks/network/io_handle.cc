#include "test/mocks/network/io_handle.h"

#include "envoy/network/address.h"

namespace Envoy {
namespace Network {

MockIoHandle::MockIoHandle() {
  ON_CALL(*this, supportsTls()).WillByDefault(testing::Return(false));
}
MockIoHandle::~MockIoHandle() = default;

} // namespace Network
} // namespace Envoy
