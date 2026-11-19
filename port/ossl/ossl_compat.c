/*
 * OpenSSL-compatible BIGNUM / EVP digest / RAND / ERR subset on mbedTLS, for UxPlay's srp.c.
 * Return conventions follow OpenSSL: 1 = success, 0 = failure.
 * Linked with UxPlay (GPLv3), so distributed under GPLv3 as well.
 */
#include "ossl_compat.h"

#include <stdlib.h>
#include <string.h>

#include "mbedtls/bignum.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

int get_random_bytes(unsigned char *buf, int num);   /* crypto_port.c */

/* ---------------------------------------------------------------- BIGNUM */

struct bignum_st {
    mbedtls_mpi m;
};

struct bignum_ctx {
    int unused;
};

BIGNUM *BN_new(void)
{
    BIGNUM *a = calloc(1, sizeof(BIGNUM));
    if (a) {
        mbedtls_mpi_init(&a->m);
    }
    return a;
}

void BN_free(BIGNUM *a)
{
    if (a) {
        mbedtls_mpi_free(&a->m);
        free(a);
    }
}

BN_CTX *BN_CTX_new(void)
{
    return calloc(1, sizeof(BN_CTX));
}

void BN_CTX_free(BN_CTX *c)
{
    free(c);
}

int BN_num_bytes(const BIGNUM *a)
{
    return (int) mbedtls_mpi_size(&a->m);
}

int BN_bn2bin(const BIGNUM *a, unsigned char *to)
{
    size_t n = mbedtls_mpi_size(&a->m);
    if (n == 0) {
        return 0;
    }
    return mbedtls_mpi_write_binary(&a->m, to, n) == 0 ? (int) n : 0;
}

BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    BIGNUM *r = ret ? ret : BN_new();
    if (!r) {
        return NULL;
    }
    if (mbedtls_mpi_read_binary(&r->m, s, (size_t) (len > 0 ? len : 0)) != 0) {
        if (!ret) {
            BN_free(r);
        }
        return NULL;
    }
    return r;
}

int BN_hex2bn(BIGNUM **a, const char *str)
{
    if (!a || !str) {
        return 0;
    }
    if (!*a) {
        *a = BN_new();
        if (!*a) {
            return 0;
        }
    }
    if (mbedtls_mpi_read_string(&(*a)->m, 16, str) != 0) {
        return 0;
    }
    return (int) strlen(str);   /* OpenSSL returns the number of hex digits consumed */
}

int BN_is_zero(const BIGNUM *a)
{
    return mbedtls_mpi_cmp_int(&a->m, 0) == 0;
}

int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    return mbedtls_mpi_add_mpi(&r->m, &a->m, &b->m) == 0;
}

int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    return mbedtls_mpi_sub_mpi(&r->m, &a->m, &b->m) == 0;
}

int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    (void) ctx;
    return mbedtls_mpi_mul_mpi(&r->m, &a->m, &b->m) == 0;
}

int BN_mod(BIGNUM *rem, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
{
    (void) ctx;
    return mbedtls_mpi_mod_mpi(&rem->m, &a->m, &m->m) == 0;
}

/* r may alias a or b in OpenSSL; go through a temporary. */
int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
{
    mbedtls_mpi t;
    int ok;
    (void) ctx;
    mbedtls_mpi_init(&t);
    ok = mbedtls_mpi_add_mpi(&t, &a->m, &b->m) == 0 && mbedtls_mpi_mod_mpi(&r->m, &t, &m->m) == 0;
    mbedtls_mpi_free(&t);
    return ok;
}

int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
{
    mbedtls_mpi t;
    int ok;
    (void) ctx;
    mbedtls_mpi_init(&t);
    ok = mbedtls_mpi_mul_mpi(&t, &a->m, &b->m) == 0 && mbedtls_mpi_mod_mpi(&r->m, &t, &m->m) == 0;
    mbedtls_mpi_free(&t);
    return ok;
}

int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx)
{
    /* Reduce the base first and compute into a temporary (r may alias a). The SRP modulus is
     * an odd prime, which mbedtls_mpi_exp_mod requires. */
    mbedtls_mpi base, t;
    int ok;
    (void) ctx;
    mbedtls_mpi_init(&base);
    mbedtls_mpi_init(&t);
    ok = mbedtls_mpi_mod_mpi(&base, &a->m, &m->m) == 0 &&
         mbedtls_mpi_exp_mod(&t, &base, &p->m, &m->m, NULL) == 0 &&
         mbedtls_mpi_copy(&r->m, &t) == 0;
    mbedtls_mpi_free(&base);
    mbedtls_mpi_free(&t);
    return ok;
}

int BN_rand(BIGNUM *rnd, int bits, int top, int bottom)
{
    /* srp.c only uses top = -1, bottom = 0: any value below 2^bits. */
    unsigned char buf[512];
    int bytes = (bits + 7) / 8;
    (void) top;
    (void) bottom;
    if (bits <= 0 || bytes > (int) sizeof(buf) || get_random_bytes(buf, bytes) != 1) {
        return 0;
    }
    if (bits % 8) {
        buf[0] &= (unsigned char) ((1u << (bits % 8)) - 1);
    }
    int ok = mbedtls_mpi_read_binary(&rnd->m, buf, (size_t) bytes) == 0;
    memset(buf, 0, sizeof(buf));
    return ok;
}

/* ---------------------------------------------------------------- EVP digests */

enum { MD_SHA1 = 1, MD_SHA224, MD_SHA256, MD_SHA384, MD_SHA512 };

struct evp_md_st {
    int id;
};

static const EVP_MD md_sha1 = { MD_SHA1 }, md_sha224 = { MD_SHA224 }, md_sha256 = { MD_SHA256 },
                    md_sha384 = { MD_SHA384 }, md_sha512 = { MD_SHA512 };

const EVP_MD *EVP_sha1(void) { return &md_sha1; }
const EVP_MD *EVP_sha224(void) { return &md_sha224; }
const EVP_MD *EVP_sha256(void) { return &md_sha256; }
const EVP_MD *EVP_sha384(void) { return &md_sha384; }
const EVP_MD *EVP_sha512(void) { return &md_sha512; }

struct evp_md_ctx_st {
    int id;
    union {
        mbedtls_sha1_context s1;
        mbedtls_sha256_context s256;
        mbedtls_sha512_context s512;
    } u;
};

static void md_ctx_clear(EVP_MD_CTX *ctx)
{
    switch (ctx->id) {
    case MD_SHA1: mbedtls_sha1_free(&ctx->u.s1); break;
    case MD_SHA224:
    case MD_SHA256: mbedtls_sha256_free(&ctx->u.s256); break;
    case MD_SHA384:
    case MD_SHA512: mbedtls_sha512_free(&ctx->u.s512); break;
    default: break;
    }
    ctx->id = 0;
}

EVP_MD_CTX *EVP_MD_CTX_new(void)
{
    return calloc(1, sizeof(EVP_MD_CTX));
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    if (ctx) {
        md_ctx_clear(ctx);
        free(ctx);
    }
}

int EVP_MD_CTX_reset(EVP_MD_CTX *ctx)
{
    md_ctx_clear(ctx);
    return 1;
}

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
    (void) impl;
    md_ctx_clear(ctx);
    ctx->id = type->id;
    switch (ctx->id) {
    case MD_SHA1:
        mbedtls_sha1_init(&ctx->u.s1);
        return mbedtls_sha1_starts(&ctx->u.s1) == 0;
    case MD_SHA224:
    case MD_SHA256:
        mbedtls_sha256_init(&ctx->u.s256);
        return mbedtls_sha256_starts(&ctx->u.s256, ctx->id == MD_SHA224) == 0;
    case MD_SHA384:
    case MD_SHA512:
        mbedtls_sha512_init(&ctx->u.s512);
        return mbedtls_sha512_starts(&ctx->u.s512, ctx->id == MD_SHA384) == 0;
    default:
        ctx->id = 0;
        return 0;
    }
}

int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
    const unsigned char *p = d;
    switch (ctx->id) {
    case MD_SHA1: return mbedtls_sha1_update(&ctx->u.s1, p, cnt) == 0;
    case MD_SHA224:
    case MD_SHA256: return mbedtls_sha256_update(&ctx->u.s256, p, cnt) == 0;
    case MD_SHA384:
    case MD_SHA512: return mbedtls_sha512_update(&ctx->u.s512, p, cnt) == 0;
    default: return 0;
    }
}

int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
{
    int ok;
    unsigned int n;
    switch (ctx->id) {
    case MD_SHA1: ok = mbedtls_sha1_finish(&ctx->u.s1, md) == 0; n = SHA_DIGEST_LENGTH; break;
    case MD_SHA224: ok = mbedtls_sha256_finish(&ctx->u.s256, md) == 0; n = SHA224_DIGEST_LENGTH; break;
    case MD_SHA256: ok = mbedtls_sha256_finish(&ctx->u.s256, md) == 0; n = SHA256_DIGEST_LENGTH; break;
    case MD_SHA384: ok = mbedtls_sha512_finish(&ctx->u.s512, md) == 0; n = SHA384_DIGEST_LENGTH; break;
    case MD_SHA512: ok = mbedtls_sha512_finish(&ctx->u.s512, md) == 0; n = SHA512_DIGEST_LENGTH; break;
    default: return 0;
    }
    if (s) {
        *s = n;
    }
    return ok;
}

unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md)
{
    return mbedtls_sha1(d, n, md) == 0 ? md : NULL;
}

unsigned char *SHA224(const unsigned char *d, size_t n, unsigned char *md)
{
    return mbedtls_sha256(d, n, md, 1) == 0 ? md : NULL;
}

unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md)
{
    return mbedtls_sha256(d, n, md, 0) == 0 ? md : NULL;
}

unsigned char *SHA384(const unsigned char *d, size_t n, unsigned char *md)
{
    return mbedtls_sha512(d, n, md, 1) == 0 ? md : NULL;
}

unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md)
{
    return mbedtls_sha512(d, n, md, 0) == 0 ? md : NULL;
}

/* ---------------------------------------------------------------- RAND / ERR */

void RAND_seed(const void *buf, int num)
{
    (void) buf;
    (void) num;
}

int RAND_bytes(unsigned char *buf, int num)
{
    return get_random_bytes(buf, num);
}

unsigned long ERR_get_error(void)
{
    return 0;
}

char *ERR_error_string(unsigned long e, char *buf)
{
    static char msg[] = "mbedtls backend error";
    (void) e;
    return buf ? strcpy(buf, msg) : msg;
}
