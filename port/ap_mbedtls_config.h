/* mbedTLS build config for the AirPlay mirroring receiver.
 * Only the primitives UxPlay needs: AES-128 CTR/CBC/GCM, MD5, SHA-1/2, bignum (SRP-6a PIN pairing).
 * No TLS, no PSA, no entropy module (randomness comes from /dev/urandom in crypto_port.c). */
#ifndef AP_MBEDTLS_CONFIG_H
#define AP_MBEDTLS_CONFIG_H

#define MBEDTLS_AES_C
#define MBEDTLS_AES_ROM_TABLES          /* tables in .rodata instead of built at runtime */
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_GCM_C

#define MBEDTLS_MD5_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C

#define MBEDTLS_BIGNUM_C

/* mbedTLS insists on the platform layer for Windows builds (PC tests only) */
#if defined(_WIN32)
#define MBEDTLS_PLATFORM_C
#endif

#endif
