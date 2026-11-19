/*
 * crypto.h backend for UxPlay without OpenSSL: mbedTLS (AES, GCM, SHA-512, MD5) + Monocypher
 * (X25519, Ed25519 with SHA-512). Replaces third_party/uxplay/lib/crypto.c; same API and semantics.
 *
 * This file is linked with UxPlay (GPLv3), so it is distributed under GPLv3 as well.
 */
#ifdef _WIN32
#define _CRT_RAND_S   /* rand_s() for PC test builds; must precede <stdlib.h> */
#endif
#include "crypto.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha512.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "utils.h"

#define SALT_PK "UxPlay-Persistent-Not-Secure-Public-Key"

static void crypto_fail(const char *where)
{
    /* Same policy as the OpenSSL version: a crypto primitive failing is a programming error. */
    fprintf(stderr, "Crypto error at %s\n", where);
    exit(EXIT_FAILURE);
}

/* ---------------------------------------------------------------- random */

#ifdef _WIN32
/* PC test builds only */
int get_random_bytes(unsigned char *buf, int num)
{
    for (int i = 0; i < num; i++) {
        unsigned int v;
        if (rand_s(&v) != 0) {
            return 0;
        }
        buf[i] = (unsigned char) v;
    }
    return 1;
}
#else
int get_random_bytes(unsigned char *buf, int num)
{
    /* Returns 1 on success like RAND_bytes. */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fd = open("/dev/random", O_RDONLY);
    }
    if (fd < 0) {
        return 0;
    }
    int got = 0;
    while (got < num) {
        ssize_t r = read(fd, buf + got, (size_t) (num - got));
        if (r <= 0) {
            close(fd);
            return 0;
        }
        got += (int) r;
    }
    close(fd);
    return 1;
}
#endif

static void random_or_die(unsigned char *buf, int num)
{
    if (get_random_bytes(buf, num) != 1) {
        crypto_fail("get_random_bytes");
    }
}

/* ---------------------------------------------------------------- AES */

typedef enum { AES_MODE_CTR, AES_MODE_CBC } aes_mode_t;

struct aes_ctx_s {
    mbedtls_aes_context aes;
    aes_mode_t mode;
    aes_direction_t direction;
    uint8_t key[AES_128_BLOCK_SIZE];
    uint8_t iv[AES_128_BLOCK_SIZE];
    /* running state, like an EVP_CIPHER_CTX */
    uint8_t counter[AES_128_BLOCK_SIZE];   /* CTR: nonce/counter; CBC: chaining IV */
    uint8_t stream_block[AES_128_BLOCK_SIZE];
    size_t nc_off;                          /* CTR: offset inside stream_block */
    uint8_t block_offset;                   /* UxPlay's own bookkeeping for start_fresh_block */
};

static void aes_setup(aes_ctx_t *ctx)
{
    int rc;
    mbedtls_aes_free(&ctx->aes);
    mbedtls_aes_init(&ctx->aes);
    /* CTR always uses the encrypt schedule; CBC decrypt needs the decrypt schedule. */
    if (ctx->mode == AES_MODE_CBC && ctx->direction == AES_DECRYPT) {
        rc = mbedtls_aes_setkey_dec(&ctx->aes, ctx->key, 128);
    } else {
        rc = mbedtls_aes_setkey_enc(&ctx->aes, ctx->key, 128);
    }
    if (rc != 0) {
        crypto_fail("aes_setkey");
    }
    memcpy(ctx->counter, ctx->iv, AES_128_BLOCK_SIZE);
    memset(ctx->stream_block, 0, sizeof(ctx->stream_block));
    ctx->nc_off = 0;
    ctx->block_offset = 0;
}

static aes_ctx_t *aes_new(const uint8_t *key, const uint8_t *iv, aes_mode_t mode, aes_direction_t direction)
{
    aes_ctx_t *ctx = calloc(1, sizeof(aes_ctx_t));
    assert(ctx != NULL);
    mbedtls_aes_init(&ctx->aes);
    ctx->mode = mode;
    ctx->direction = direction;
    memcpy(ctx->key, key, AES_128_BLOCK_SIZE);
    memcpy(ctx->iv, iv, AES_128_BLOCK_SIZE);
    aes_setup(ctx);
    return ctx;
}

static void aes_free_ctx(aes_ctx_t *ctx)
{
    if (ctx) {
        mbedtls_aes_free(&ctx->aes);
        free(ctx);
    }
}

aes_ctx_t *aes_ctr_init(const uint8_t *key, const uint8_t *iv)
{
    return aes_new(key, iv, AES_MODE_CTR, AES_ENCRYPT);
}

void aes_ctr_encrypt(aes_ctx_t *ctx, const uint8_t *in, uint8_t *out, int len)
{
    if (len <= 0) {
        return;
    }
    if (mbedtls_aes_crypt_ctr(&ctx->aes, (size_t) len, &ctx->nc_off, ctx->counter, ctx->stream_block, in, out) != 0) {
        crypto_fail(__func__);
    }
    ctx->block_offset = (uint8_t) ((ctx->block_offset + len) % AES_128_BLOCK_SIZE);
}

void aes_ctr_decrypt(aes_ctx_t *ctx, const uint8_t *in, uint8_t *out, int len)
{
    /* The OpenSSL version does not update block_offset here; keep that. */
    if (len <= 0) {
        return;
    }
    if (mbedtls_aes_crypt_ctr(&ctx->aes, (size_t) len, &ctx->nc_off, ctx->counter, ctx->stream_block, in, out) != 0) {
        crypto_fail(__func__);
    }
}

void aes_ctr_start_fresh_block(aes_ctx_t *ctx)
{
    uint8_t waste[AES_128_BLOCK_SIZE] = {0};
    if (ctx->block_offset == 0) {
        return;
    }
    aes_ctr_encrypt(ctx, waste, waste, AES_128_BLOCK_SIZE - ctx->block_offset);
}

void aes_ctr_reset(aes_ctx_t *ctx)
{
    aes_setup(ctx);
}

void aes_ctr_destroy(aes_ctx_t *ctx)
{
    aes_free_ctx(ctx);
}

aes_ctx_t *aes_cbc_init(const uint8_t *key, const uint8_t *iv, aes_direction_t direction)
{
    return aes_new(key, iv, AES_MODE_CBC, direction);
}

/* No padding: callers pass whole blocks (OpenSSL would abort on a partial block too).
 * A trailing partial block is ignored rather than aborting the process. */
static void aes_cbc_run(aes_ctx_t *ctx, int mode, const uint8_t *in, uint8_t *out, int len)
{
    size_t whole = (len > 0) ? ((size_t) len & ~(size_t) (AES_128_BLOCK_SIZE - 1)) : 0;
    if (whole == 0) {
        return;
    }
    if (mbedtls_aes_crypt_cbc(&ctx->aes, mode, whole, ctx->counter, in, out) != 0) {
        crypto_fail("aes_cbc");
    }
}

void aes_cbc_encrypt(aes_ctx_t *ctx, const uint8_t *in, uint8_t *out, int len)
{
    assert(ctx->direction == AES_ENCRYPT);
    aes_cbc_run(ctx, MBEDTLS_AES_ENCRYPT, in, out, len);
}

void aes_cbc_decrypt(aes_ctx_t *ctx, const uint8_t *in, uint8_t *out, int len)
{
    assert(ctx->direction == AES_DECRYPT);
    aes_cbc_run(ctx, MBEDTLS_AES_DECRYPT, in, out, len);
}

void aes_cbc_reset(aes_ctx_t *ctx)
{
    aes_setup(ctx);
}

void aes_cbc_destroy(aes_ctx_t *ctx)
{
    aes_free_ctx(ctx);
}

/* ---------------------------------------------------------------- GCM (16-byte IV, 16-byte tag) */

int gcm_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext,
                unsigned char *key, unsigned char *iv, unsigned char *tag)
{
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    if (mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 128) != 0 ||
        mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, (size_t) plaintext_len, iv, 16, NULL, 0,
                                  plaintext, ciphertext, 16, tag) != 0) {
        mbedtls_gcm_free(&g);
        crypto_fail(__func__);
    }
    mbedtls_gcm_free(&g);
    return plaintext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext,
                unsigned char *key, unsigned char *iv, unsigned char *tag)
{
    mbedtls_gcm_context g;
    int rc;
    mbedtls_gcm_init(&g);
    if (mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 128) != 0) {
        mbedtls_gcm_free(&g);
        crypto_fail(__func__);
    }
    rc = mbedtls_gcm_auth_decrypt(&g, (size_t) ciphertext_len, iv, 16, NULL, 0, tag, 16, ciphertext, plaintext);
    mbedtls_gcm_free(&g);
    return rc == 0 ? ciphertext_len : -1;
}

/* ---------------------------------------------------------------- X25519 */

struct x25519_key_s {
    int has_secret;
    uint8_t secret[X25519_KEY_SIZE];
    uint8_t pub[X25519_KEY_SIZE];
};

x25519_key_t *x25519_key_generate(void)
{
    x25519_key_t *key = calloc(1, sizeof(x25519_key_t));
    assert(key);
    random_or_die(key->secret, X25519_KEY_SIZE);
    crypto_x25519_public_key(key->pub, key->secret);
    key->has_secret = 1;
    return key;
}

x25519_key_t *x25519_key_from_raw(const unsigned char data[X25519_KEY_SIZE])
{
    x25519_key_t *key = calloc(1, sizeof(x25519_key_t));
    assert(key);
    memcpy(key->pub, data, X25519_KEY_SIZE);
    return key;
}

void x25519_key_get_raw(unsigned char data[X25519_KEY_SIZE], const x25519_key_t *key)
{
    assert(key);
    memcpy(data, key->pub, X25519_KEY_SIZE);
}

void x25519_key_destroy(x25519_key_t *key)
{
    if (key) {
        crypto_wipe(key, sizeof(*key));
        free(key);
    }
}

void x25519_derive_secret(unsigned char secret[X25519_KEY_SIZE], const x25519_key_t *ours, const x25519_key_t *theirs)
{
    assert(ours && theirs);
    if (!ours->has_secret) {
        crypto_fail(__func__);
    }
    crypto_x25519(secret, ours->secret, theirs->pub);
}

/* ---------------------------------------------------------------- Ed25519 (RFC 8032, SHA-512) */

struct ed25519_key_s {
    int refs;
    int has_secret;
    uint8_t secret[64];   /* Monocypher layout: seed(32) || public(32) */
    uint8_t pub[ED25519_KEY_SIZE];
};

static void ed25519_from_seed(ed25519_key_t *key, uint8_t seed[32])
{
    /* crypto_ed25519_key_pair wipes the seed it is given */
    crypto_ed25519_key_pair(key->secret, key->pub, seed);
    key->has_secret = 1;
}

/* Key file: the 32-byte seed as 64 hex characters plus newline. Not PEM like the OpenSSL
 * build, so a file written by desktop UxPlay is not reused; a bad or missing file makes a new key. */
static int ed25519_read_keyfile(const char *keyfile, uint8_t seed[32])
{
    char line[80];
    FILE *f = fopen(keyfile, "r");
    if (!f) {
        return 0;
    }
    int ok = fgets(line, sizeof(line), f) != NULL;
    fclose(f);
    if (!ok) {
        return 0;
    }
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(line + 2 * i, "%2x", &v) != 1) {
            return 0;
        }
        seed[i] = (uint8_t) v;
    }
    return 1;
}

static int ed25519_write_keyfile(const char *keyfile, const uint8_t seed[32])
{
    FILE *f = fopen(keyfile, "w");
    if (!f) {
        return 0;
    }
    for (int i = 0; i < 32; i++) {
        fprintf(f, "%02x", seed[i]);
    }
    fputc('\n', f);
    fclose(f);
    return 1;
}

ed25519_key_t *ed25519_key_generate(const char *device_id, const char *keyfile, int *result)
{
    uint8_t seed[32];
    int use_keyfile = keyfile && keyfile[0];
    *result = 0;
    ed25519_key_t *key = calloc(1, sizeof(ed25519_key_t));
    assert(key);
    key->refs = 1;

    if (use_keyfile) {
        if (!ed25519_read_keyfile(keyfile, seed)) {
            uint8_t keep[32];
            random_or_die(seed, 32);
            memcpy(keep, seed, 32);
            if (ed25519_write_keyfile(keyfile, keep)) {
                *result = 1;
            }
            crypto_wipe(keep, sizeof(keep));
        }
    } else {
        /* Same derivation as upstream: seed = first 32 bytes of SHA-512(salt || device_id). */
        unsigned char hash[64];
        sha_ctx_t *ctx = sha_init();
        sha_update(ctx, (const unsigned char *) SALT_PK, (int) strlen(SALT_PK));
        sha_update(ctx, (const unsigned char *) device_id, (int) strlen(device_id));
        sha_final(ctx, hash, NULL);
        sha_destroy(ctx);
        memcpy(seed, hash, 32);
        crypto_wipe(hash, sizeof(hash));
    }
    ed25519_from_seed(key, seed);
    return key;
}

ed25519_key_t *ed25519_key_from_raw(const unsigned char data[ED25519_KEY_SIZE])
{
    ed25519_key_t *key = calloc(1, sizeof(ed25519_key_t));
    assert(key);
    key->refs = 1;
    memcpy(key->pub, data, ED25519_KEY_SIZE);
    return key;
}

void ed25519_key_get_raw(unsigned char data[ED25519_KEY_SIZE], const ed25519_key_t *key)
{
    assert(key);
    memcpy(data, key->pub, ED25519_KEY_SIZE);
}

ed25519_key_t *ed25519_key_copy(const ed25519_key_t *key)
{
    /* Upstream shares the EVP_PKEY by refcount; a value copy is equivalent here. */
    assert(key);
    ed25519_key_t *copy = malloc(sizeof(ed25519_key_t));
    assert(copy);
    memcpy(copy, key, sizeof(*copy));
    copy->refs = 1;
    return copy;
}

void ed25519_sign(unsigned char *signature, size_t signature_len,
                  const unsigned char *data, size_t data_len, const ed25519_key_t *key)
{
    if (!key->has_secret || signature_len < 64) {
        crypto_fail(__func__);
    }
    crypto_ed25519_sign(signature, key->secret, data, data_len);
}

int ed25519_verify(const unsigned char *signature, size_t signature_len,
                   const unsigned char *data, size_t data_len, const ed25519_key_t *key)
{
    /* 1 = valid, 0 = invalid (EVP_DigestVerify convention) */
    if (signature_len != 64) {
        return 0;
    }
    return crypto_ed25519_check(signature, key->pub, data, data_len) == 0 ? 1 : 0;
}

void ed25519_key_destroy(ed25519_key_t *key)
{
    if (key) {
        crypto_wipe(key, sizeof(*key));
        free(key);
    }
}

/* ---------------------------------------------------------------- SHA-512 */

struct sha_ctx_s {
    mbedtls_sha512_context c;
};

sha_ctx_t *sha_init(void)
{
    sha_ctx_t *ctx = calloc(1, sizeof(sha_ctx_t));
    assert(ctx);
    mbedtls_sha512_init(&ctx->c);
    if (mbedtls_sha512_starts(&ctx->c, 0) != 0) {
        crypto_fail(__func__);
    }
    return ctx;
}

void sha_update(sha_ctx_t *ctx, const uint8_t *in, int len)
{
    if (len > 0 && mbedtls_sha512_update(&ctx->c, in, (size_t) len) != 0) {
        crypto_fail(__func__);
    }
}

void sha_final(sha_ctx_t *ctx, uint8_t *out, unsigned int *len)
{
    if (mbedtls_sha512_finish(&ctx->c, out) != 0) {
        crypto_fail(__func__);
    }
    if (len) {
        *len = 64;
    }
}

void sha_reset(sha_ctx_t *ctx)
{
    mbedtls_sha512_free(&ctx->c);
    mbedtls_sha512_init(&ctx->c);
    if (mbedtls_sha512_starts(&ctx->c, 0) != 0) {
        crypto_fail(__func__);
    }
}

void sha_destroy(sha_ctx_t *ctx)
{
    if (ctx) {
        mbedtls_sha512_free(&ctx->c);
        free(ctx);
    }
}

/* ---------------------------------------------------------------- MD5 */

struct md5_ctx_s {
    mbedtls_md5_context c;
};

md5_ctx_t *md5_init(void)
{
    md5_ctx_t *ctx = calloc(1, sizeof(md5_ctx_t));
    assert(ctx);
    mbedtls_md5_init(&ctx->c);
    if (mbedtls_md5_starts(&ctx->c) != 0) {
        crypto_fail(__func__);
    }
    return ctx;
}

void md5_update(md5_ctx_t *ctx, const uint8_t *in, int len)
{
    if (len > 0 && mbedtls_md5_update(&ctx->c, in, (size_t) len) != 0) {
        crypto_fail(__func__);
    }
}

void md5_final(md5_ctx_t *ctx, uint8_t *out, unsigned int *len)
{
    if (mbedtls_md5_finish(&ctx->c, out) != 0) {
        crypto_fail(__func__);
    }
    if (len) {
        *len = 16;
    }
}

void md5_reset(md5_ctx_t *ctx)
{
    mbedtls_md5_free(&ctx->c);
    mbedtls_md5_init(&ctx->c);
    if (mbedtls_md5_starts(&ctx->c) != 0) {
        crypto_fail(__func__);
    }
}

void md5_destroy(md5_ctx_t *ctx)
{
    if (ctx) {
        mbedtls_md5_free(&ctx->c);
        free(ctx);
    }
}

char *get_md5(char *string)
{
    unsigned char hash[16] = {0};
    md5_ctx_t *ctx = md5_init();
    md5_update(ctx, (const unsigned char *) string, (int) strlen(string));
    md5_final(ctx, hash, NULL);
    md5_destroy(ctx);
    return utils_hex_to_string(hash, 16);   /* caller frees */
}

/* ---------------------------------------------------------------- base64 (no newlines) */

void pk_to_base64(const unsigned char *pk, int pk_len, char *pk_base64, int len)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int len64 = (4 * (pk_len / 3)) + (pk_len % 3 ? 4 : 0);
    int o = 0;
    memset(pk_base64, 0, (size_t) len);
    assert(len > len64);
    for (int i = 0; i < pk_len; i += 3) {
        unsigned v = (unsigned) pk[i] << 16;
        int n = pk_len - i;
        if (n > 1) v |= (unsigned) pk[i + 1] << 8;
        if (n > 2) v |= pk[i + 2];
        pk_base64[o++] = tbl[(v >> 18) & 63];
        pk_base64[o++] = tbl[(v >> 12) & 63];
        pk_base64[o++] = n > 1 ? tbl[(v >> 6) & 63] : '=';
        pk_base64[o++] = n > 2 ? tbl[v & 63] : '=';
    }
}
