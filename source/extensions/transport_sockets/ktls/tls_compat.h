#pragma once

// This header provides compatibility definitions for platforms without kernel TLS support

#ifdef __linux__
// Use the real linux/tls.h on Linux
#include <linux/tls.h>
#else
// Provide fallback definitions for other platforms

#include <cstdint>

// TLS protocol versions
#ifndef TLS_1_2_VERSION
#define TLS_1_2_VERSION 0x0303
#endif

#ifndef TLS_1_3_VERSION
#define TLS_1_3_VERSION 0x0304
#endif

// TLS cipher suites
#ifndef TLS_CIPHER_AES_GCM_128
#define TLS_CIPHER_AES_GCM_128 51
#endif

#ifndef TLS_CIPHER_AES_GCM_256
#define TLS_CIPHER_AES_GCM_256 52
#endif

// TLS socket options
#ifndef SOL_TLS
#define SOL_TLS 282
#endif

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

// TLS crypto info sizes
#define TLS_CIPHER_AES_GCM_128_IV_SIZE    8
#define TLS_CIPHER_AES_GCM_128_KEY_SIZE   16
#define TLS_CIPHER_AES_GCM_128_SALT_SIZE  4
#define TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE 8

// TLS crypto info structures
struct tls_crypto_info {
    uint16_t version;
    uint16_t cipher_type;
};

struct tls12_crypto_info_aes_gcm_128 {
    struct tls_crypto_info info;
    unsigned char iv[TLS_CIPHER_AES_GCM_128_IV_SIZE];
    unsigned char key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
    unsigned char salt[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
    unsigned char rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};

#endif // __linux__ 