/*
 * Helper for test_bn.py: evaluates BIGNUM operations through port/ossl/ossl_compat.c.
 * stdin lines: "<op> <hexA> <hexB> <hexM>" (unused operands are "0"); stdout: result in hex.
 * Operands go in through BN_hex2bn or BN_bin2bn alternately, and results come out through
 * BN_bn2bin, so the conversions are exercised too.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/bn.h"

static BIGNUM *in_bn(const char *hex, int via_bin)
{
    BIGNUM *r = NULL;
    if (!via_bin) {
        BN_hex2bn(&r, hex);
        return r;
    }
    size_t n = strlen(hex);
    unsigned char *buf = calloc(n / 2 + 2, 1);
    size_t len = 0;
    const char *p = hex;
    if (n % 2) {   /* odd number of digits: first nibble alone */
        unsigned v;
        sscanf(p, "%1x", &v);
        buf[len++] = (unsigned char) v;
        p++;
    }
    for (; *p; p += 2) {
        unsigned v;
        sscanf(p, "%2x", &v);
        buf[len++] = (unsigned char) v;
    }
    r = BN_bin2bn(buf, (int) len, NULL);
    free(buf);
    return r;
}

static void out_bn(const BIGNUM *a)
{
    int n = BN_num_bytes(a);
    if (n == 0 || BN_is_zero(a)) {
        printf("0\n");
        return;
    }
    unsigned char *buf = malloc((size_t) n);
    BN_bn2bin(a, buf);
    for (int i = 0; i < n; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
    free(buf);
}

int main(void)
{
    static char line[20000];
    char op[16];
    static char ha[6000], hb[6000], hm[6000];
    int k = 0;
    BN_CTX *ctx = BN_CTX_new();
    while (fgets(line, sizeof(line), stdin)) {
        if (sscanf(line, "%15s %5999s %5999s %5999s", op, ha, hb, hm) != 4) {
            continue;
        }
        BIGNUM *a = in_bn(ha, k & 1), *b = in_bn(hb, (k >> 1) & 1), *m = in_bn(hm, 0), *r = BN_new();
        int ok = 1;
        k++;
        if (!strcmp(op, "add")) ok = BN_add(r, a, b);
        else if (!strcmp(op, "sub")) ok = BN_sub(r, a, b);
        else if (!strcmp(op, "mul")) ok = BN_mul(r, a, b, ctx);
        else if (!strcmp(op, "mod")) ok = BN_mod(r, a, m, ctx);
        else if (!strcmp(op, "modadd")) ok = BN_mod_add(r, a, b, m, ctx);
        else if (!strcmp(op, "modmul")) ok = BN_mod_mul(r, a, b, m, ctx);
        else if (!strcmp(op, "modexp")) ok = BN_mod_exp(r, a, b, m, ctx);
        else if (!strcmp(op, "modexp_alias")) { ok = BN_mod_exp(a, a, b, m, ctx); BN_free(r); r = a; a = NULL; }
        else if (!strcmp(op, "rand")) {
            int bits = atoi(ha);
            ok = BN_rand(r, bits, -1, 0);
        }
        else ok = 0;
        if (!ok) printf("ERR\n");
        else out_bn(r);
        BN_free(a); BN_free(b); BN_free(m); BN_free(r);
        fflush(stdout);
    }
    BN_CTX_free(ctx);
    return 0;
}
