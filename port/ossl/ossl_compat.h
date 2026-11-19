/*
 * Minimal OpenSSL-compatible surface (BIGNUM, EVP digests, RAND, ERR) on top of mbedTLS, just
 * enough for UxPlay's srp.c and pairing.c to compile unchanged. Implemented in ossl_compat.c.
 * The openssl/*.h files in this directory all include this header.
 */
#ifndef AP_OSSL_COMPAT_H
#define AP_OSSL_COMPAT_H

#include <stddef.h>

#define SHA_DIGEST_LENGTH    20
#define SHA224_DIGEST_LENGTH 28
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64

/* ---- BIGNUM ---- */
typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;

BIGNUM *BN_new(void);
void BN_free(BIGNUM *a);
BN_CTX *BN_CTX_new(void);
void BN_CTX_free(BN_CTX *c);
int BN_num_bytes(const BIGNUM *a);
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_hex2bn(BIGNUM **a, const char *str);
int BN_is_zero(const BIGNUM *a);
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_mod(BIGNUM *rem, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx);
int BN_rand(BIGNUM *rnd, int bits, int top, int bottom);

/* ---- EVP message digests ---- */
typedef struct evp_md_st EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct engine_st ENGINE;

const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
int EVP_MD_CTX_reset(EVP_MD_CTX *ctx);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);

/* one-shot digests; return md like OpenSSL */
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *SHA224(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *SHA384(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md);

/* ---- RAND / ERR ---- */
void RAND_seed(const void *buf, int num);   /* no-op: randomness always comes from the OS */
int RAND_bytes(unsigned char *buf, int num);
unsigned long ERR_get_error(void);
char *ERR_error_string(unsigned long e, char *buf);

#endif
