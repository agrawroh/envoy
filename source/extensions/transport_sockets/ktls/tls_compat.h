#pragma once

#include <cstdint>
#include <cstring>

// Platform compatibility header for kTLS support
// Provides defines and structs for kTLS configuration

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

// Common kTLS constants
#ifndef SOL_TLS
#define SOL_TLS 282
#endif

#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#ifdef __linux__
// Linux-specific definitions
#ifndef TLS_TX
#define TLS_TX 1
#endif

#ifndef TLS_RX
#define TLS_RX 2
#endif

#ifndef TLS_TX_ZEROCOPY_RO
#define TLS_TX_ZEROCOPY_RO 3
#endif

#ifndef TLS_RX_EXPECT_NO_PAD
#define TLS_RX_EXPECT_NO_PAD 4
#endif

#ifndef TLS_CIPHER_AES_GCM_128
#define TLS_CIPHER_AES_GCM_128 51
#endif

#ifndef TLS_CIPHER_AES_GCM_256
#define TLS_CIPHER_AES_GCM_256 52
#endif

#ifndef TLS_1_2_VERSION
#define TLS_1_2_VERSION 0x0303
#endif

#ifndef TLS_1_3_VERSION
#define TLS_1_3_VERSION 0x0304
#endif

// Linux kTLS crypto structure definitions
#pragma pack(push, 1)
struct tls12_crypto_info_aes_gcm_128 {
  uint16_t version;
  uint16_t cipher_type;
  uint8_t iv[8];
  uint8_t key[16];
  uint8_t salt[4];
  uint8_t rec_seq[8];
};

struct tls12_crypto_info_aes_gcm_256 {
  uint16_t version;
  uint16_t cipher_type;
  uint8_t iv[8];
  uint8_t key[32];
  uint8_t salt[4];
  uint8_t rec_seq[8];
};
#pragma pack(pop)

// Use AES-GCM-128 as default crypto info type
using tls_crypto_info_t = tls12_crypto_info_aes_gcm_128;

#else // Non-Linux platforms

// Define stubs for non-Linux platforms
struct tls12_crypto_info_aes_gcm_128 {
  uint16_t version;
  uint16_t cipher_type;
  uint8_t iv[8];
  uint8_t key[16];
  uint8_t salt[4];
  uint8_t rec_seq[8];
};

// Use AES-GCM-128 as default crypto info type
using tls_crypto_info_t = tls12_crypto_info_aes_gcm_128;

#endif

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 