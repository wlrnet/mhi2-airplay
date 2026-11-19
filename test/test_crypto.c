/*
 * PC test for port/crypto_port.c and port/ossl/ossl_compat.c (digests).
 * Known-answer vectors: NIST SP 800-38A (AES CTR/CBC), FIPS 180 "abc" (SHA family), RFC 1321 (MD5),
 * RFC 7748 6.1 (X25519), RFC 8032 7.1 test 1 (Ed25519).
 * Build/run: sh airplay-mirror/test/run_tests.sh
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "monocypher.h"
#include "openssl/evp.h"
#include "openssl/sha.h"

static int g_fail, g_pass;

#define CHECK(cond, what) do { if (cond) g_pass++; else { g_fail++; printf("FAIL %s (line %d)\n", what, __LINE__); } } while (0)

static void unhex(const char *h, unsigned char *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (unsigned char) v;
    }
}

static int eqhex(const unsigned char *b, const char *h, size_t n)
{
    unsigned char t[256];
    unhex(h, t, n);
    return memcmp(b, t, n) == 0;
}

static const char *K_AES = "2b7e151628aed2a6abf7158809cf4f3c";
static const char *PT4 = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                         "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

static void test_aes_ctr(void)
{
    unsigned char key[16], iv[16], pt[64], ct[64], ct2[64];
    unhex(K_AES, key, 16);
    unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", iv, 16);
    unhex(PT4, pt, 64);
    const char *exp = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
                      "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee";

    aes_ctx_t *c = aes_ctr_init(key, iv);
    aes_ctr_encrypt(c, pt, ct, 64);
    CHECK(eqhex(ct, exp, 64), "AES-CTR one shot");

    /* streaming in odd pieces must equal one shot */
    aes_ctr_reset(c);
    aes_ctr_encrypt(c, pt, ct2, 5);
    aes_ctr_encrypt(c, pt + 5, ct2 + 5, 20);
    aes_ctr_encrypt(c, pt + 25, ct2 + 25, 39);
    CHECK(memcmp(ct, ct2, 64) == 0, "AES-CTR streaming == one shot");

    /* start_fresh_block: after 5 bytes, skip to block 2 */
    aes_ctr_reset(c);
    aes_ctr_encrypt(c, pt, ct2, 5);
    aes_ctr_start_fresh_block(c);
    aes_ctr_encrypt(c, pt + 16, ct2 + 16, 16);
    CHECK(memcmp(ct2 + 16, ct + 16, 16) == 0, "AES-CTR start_fresh_block");

    /* decrypt is the same keystream */
    aes_ctr_reset(c);
    aes_ctr_decrypt(c, ct, ct2, 64);
    CHECK(memcmp(ct2, pt, 64) == 0, "AES-CTR decrypt");
    aes_ctr_destroy(c);
}

static void test_aes_cbc(void)
{
    unsigned char key[16], iv[16], pt[64], ct[64], back[64];
    unhex(K_AES, key, 16);
    unhex("000102030405060708090a0b0c0d0e0f", iv, 16);
    unhex(PT4, pt, 64);
    const char *exp = "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
                      "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7";

    aes_ctx_t *e = aes_cbc_init(key, iv, AES_ENCRYPT);
    aes_cbc_encrypt(e, pt, ct, 32);           /* chaining must carry across calls */
    aes_cbc_encrypt(e, pt + 32, ct + 32, 32);
    CHECK(eqhex(ct, exp, 64), "AES-CBC encrypt (two calls)");
    aes_cbc_reset(e);
    aes_cbc_encrypt(e, pt, back, 16);
    CHECK(eqhex(back, exp, 16), "AES-CBC reset restores IV");
    aes_cbc_destroy(e);

    aes_ctx_t *d = aes_cbc_init(key, iv, AES_DECRYPT);
    aes_cbc_decrypt(d, ct, back, 64);
    CHECK(memcmp(back, pt, 64) == 0, "AES-CBC decrypt");
    aes_cbc_destroy(d);
}

static void test_gcm(void)
{
    unsigned char key[16], iv[16], pt[37], ct[37], back[37], tag[16];
    for (int i = 0; i < 16; i++) { key[i] = (unsigned char) i; iv[i] = (unsigned char) (0xa0 + i); }
    for (int i = 0; i < 37; i++) pt[i] = (unsigned char) (i * 7);
    CHECK(gcm_encrypt(pt, 37, ct, key, iv, tag) == 37, "GCM encrypt length");
    CHECK(gcm_decrypt(ct, 37, back, key, iv, tag) == 37 && memcmp(back, pt, 37) == 0, "GCM round trip");
    ct[3] ^= 1;
    CHECK(gcm_decrypt(ct, 37, back, key, iv, tag) == -1, "GCM rejects tampered data");
}

static void test_digests(void)
{
    unsigned char out[64];
    unsigned int n = 0;
    sha_ctx_t *s = sha_init();
    sha_update(s, (const unsigned char *) "a", 1);
    sha_update(s, (const unsigned char *) "bc", 2);
    sha_final(s, out, &n);
    CHECK(n == 64 && eqhex(out, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", 64), "SHA-512 abc");
    sha_reset(s);
    sha_update(s, (const unsigned char *) "abc", 3);
    sha_final(s, out, NULL);
    CHECK(eqhex(out, "ddaf35a193617aba", 8), "SHA-512 after reset");
    sha_destroy(s);

    char *m = get_md5("abc");
    CHECK(strcmp(m, "900150983cd24fb0d6963f7d28e17f72") == 0, "MD5 abc");
    free(m);

    struct { const EVP_MD *(*md)(void); unsigned len; const char *hex; } v[] = {
        { EVP_sha1, 20, "a9993e364706816aba3e25717850c26c9cd0d89d" },
        { EVP_sha224, 28, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
        { EVP_sha256, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { EVP_sha384, 48, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                          "8086072ba1e7cc2358baeca134c825a7" },
        { EVP_sha512, 64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
    };
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        n = 0;
        EVP_DigestInit_ex(c, v[i].md(), NULL);
        EVP_DigestUpdate(c, "ab", 2);
        EVP_DigestUpdate(c, "c", 1);
        EVP_DigestFinal_ex(c, out, &n);
        char what[40];
        snprintf(what, sizeof(what), "EVP digest #%u abc", (unsigned) i);
        CHECK(n == v[i].len && eqhex(out, v[i].hex, v[i].len), what);
        EVP_MD_CTX_reset(c);
    }
    EVP_MD_CTX_free(c);

    unsigned char *(*one[])(const unsigned char *, size_t, unsigned char *) = { SHA1, SHA224, SHA256, SHA384, SHA512 };
    for (size_t i = 0; i < 5; i++) {
        char what[40];
        snprintf(what, sizeof(what), "one-shot digest #%u abc", (unsigned) i);
        CHECK(one[i]((const unsigned char *) "abc", 3, out) == out && eqhex(out, v[i].hex, v[i].len), what);
    }
}

static void test_x25519(void)
{
    /* RFC 7748 6.1 through Monocypher directly (the API only takes random keys) */
    unsigned char a[32], bpub[32], apub[32], shared[32];
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a, 32);
    unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", bpub, 32);
    crypto_x25519_public_key(apub, a);
    CHECK(eqhex(apub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", 32), "X25519 RFC7748 public");
    crypto_x25519(shared, a, bpub);
    CHECK(eqhex(shared, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", 32), "X25519 RFC7748 shared");

    /* API: two random keys agree; raw round trip */
    x25519_key_t *k1 = x25519_key_generate(), *k2 = x25519_key_generate();
    unsigned char r1[32], r2[32], s1[32], s2[32];
    x25519_key_get_raw(r1, k1);
    x25519_key_get_raw(r2, k2);
    x25519_key_t *p1 = x25519_key_from_raw(r1), *p2 = x25519_key_from_raw(r2);
    x25519_derive_secret(s1, k1, p2);
    x25519_derive_secret(s2, k2, p1);
    CHECK(memcmp(s1, s2, 32) == 0 && memcmp(r1, r2, 32) != 0, "X25519 API agreement");
    x25519_key_destroy(k1); x25519_key_destroy(k2); x25519_key_destroy(p1); x25519_key_destroy(p2);
}

static void test_ed25519(const char *tmpdir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/ed25519_seed.txt", tmpdir);
    FILE *f = fopen(path, "w");
    fputs("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60\n", f);
    fclose(f);

    int result = -1;
    ed25519_key_t *k = ed25519_key_generate("AA:BB:CC:DD:EE:FF", path, &result);
    unsigned char pub[32], sig[64];
    ed25519_key_get_raw(pub, k);
    CHECK(result == 0, "Ed25519 existing key file is read, not rewritten");
    CHECK(eqhex(pub, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", 32), "Ed25519 RFC8032 public");
    ed25519_sign(sig, 64, (const unsigned char *) "", 0, k);
    CHECK(eqhex(sig, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bac"
                     "c61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", 64), "Ed25519 RFC8032 signature");

    ed25519_key_t *pk = ed25519_key_from_raw(pub);
    CHECK(ed25519_verify(sig, 64, (const unsigned char *) "", 0, pk) == 1, "Ed25519 verify ok");
    sig[10] ^= 4;
    CHECK(ed25519_verify(sig, 64, (const unsigned char *) "", 0, pk) == 0, "Ed25519 verify rejects bad sig");

    ed25519_key_t *cp = ed25519_key_copy(k);
    unsigned char pub2[32];
    ed25519_key_get_raw(pub2, cp);
    CHECK(memcmp(pub, pub2, 32) == 0, "Ed25519 copy");
    ed25519_key_destroy(cp); ed25519_key_destroy(pk); ed25519_key_destroy(k);

    /* missing key file: new key generated and saved, then reloaded identically */
    snprintf(path, sizeof(path), "%s/ed25519_new.txt", tmpdir);
    remove(path);
    k = ed25519_key_generate("x", path, &result);
    ed25519_key_get_raw(pub, k);
    CHECK(result == 1, "Ed25519 new key file written");
    ed25519_key_destroy(k);
    k = ed25519_key_generate("x", path, &result);
    ed25519_key_get_raw(pub2, k);
    CHECK(result == 0 && memcmp(pub, pub2, 32) == 0, "Ed25519 key file reload");
    ed25519_key_destroy(k);

    /* no key file: deterministic from device id */
    k = ed25519_key_generate("AA:BB", "", &result);
    ed25519_key_get_raw(pub, k);
    ed25519_key_destroy(k);
    k = ed25519_key_generate("AA:BB", "", &result);
    ed25519_key_get_raw(pub2, k);
    ed25519_key_destroy(k);
    CHECK(memcmp(pub, pub2, 32) == 0, "Ed25519 device-id key is stable");
}

static void test_base64(void)
{
    char out[16];
    pk_to_base64((const unsigned char *) "fooba", 5, out, sizeof(out));
    CHECK(strcmp(out, "Zm9vYmE=") == 0, "base64 5 bytes");
    pk_to_base64((const unsigned char *) "foobar", 6, out, sizeof(out));
    CHECK(strcmp(out, "Zm9vYmFy") == 0, "base64 6 bytes");
    pk_to_base64((const unsigned char *) "f", 1, out, sizeof(out));
    CHECK(strcmp(out, "Zg==") == 0, "base64 1 byte");
}

int main(int argc, char **argv)
{
    const char *tmpdir = argc > 1 ? argv[1] : ".";
    test_aes_ctr();
    test_aes_cbc();
    test_gcm();
    test_digests();
    test_x25519();
    test_ed25519(tmpdir);
    test_base64();
    printf("test_crypto: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
