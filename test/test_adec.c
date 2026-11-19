/*
 * PC driver for src/ap_adec.c (FFmpeg AAC decoder subset).
 *   test_adec <asc-hex | ct8 | ct4> <in.pkt> <out.f32> <out.s16> [bench-repeats]
 *   test_adec --fuzz <n>        n random packets into the AirPlay ELD preset (must not crash)
 * in.pkt = [4-byte BE length][access unit]... (test/mp4_packets.py). Writes the decoder's raw
 * planar-float output interleaved (out.f32) and ap_adec_decode()'s S16 stereo (out.s16), and
 * prints "frames=<n> ch=<c> rate=<r> packets=<p> errors=<e>". With bench-repeats the packets are
 * decoded that many more times and the average time per packet is printed.
 * test/test_adec.py compares the outputs with the reference PCM.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ap_adec.h"

ap_adec_t *ap_adec_open_asc(const uint8_t *asc, int asc_len);
int ap_adec_decode_flt(ap_adec_t *d, const uint8_t *in, int len, const float **planes, int *nch, int *rate);

static ap_adec_t *open_spec(const char *spec)
{
    uint8_t asc[64];
    int n = 0;
    if (strcmp(spec, "ct8") == 0) return ap_adec_open(8);
    if (strcmp(spec, "ct4") == 0) return ap_adec_open(4);
    while (spec[0] && spec[1] && n < (int) sizeof(asc)) {
        unsigned v;
        if (sscanf(spec, "%2x", &v) != 1) return NULL;
        asc[n++] = (uint8_t) v;
        spec += 2;
    }
    return ap_adec_open_asc(asc, n);
}

int main(int argc, char **argv)
{
    FILE *f, *o32, *o16;
    uint8_t *data;
    long size;
    ap_adec_t *a, *b;
    long frames = 0, packets = 0, errors = 0;
    int ch = 0, rate = 0, reps = argc > 5 ? atoi(argv[5]) : 0;
    static int16_t s16[AP_ADEC_MAX_FRAMES * 2];

    if (argc == 3 && strcmp(argv[1], "--fuzz") == 0) {   /* robustness: random packets, must not crash */
        ap_adec_t *z = ap_adec_open(8);
        unsigned seed = 12345;
        long nf = atol(argv[2]), ok = 0, bad = 0;
        static uint8_t pk[1500];
        if (!z) return 1;
        for (long k = 0; k < nf; k++) {
            int len = 1 + (int) ((seed = seed * 1103515245u + 12345u) >> 16) % (int) sizeof(pk);
            for (int i = 0; i < len; i++) pk[i] = (uint8_t) ((seed = seed * 1103515245u + 12345u) >> 16);
            if (k % 3 == 0) pk[0] = 0x8c;                     /* looks like a real ELD frame start */
            if (ap_adec_decode(z, pk, len, s16, AP_ADEC_MAX_FRAMES, &rate, &ch) < 0) bad++; else ok++;
        }
        ap_adec_close(z);
        printf("fuzz: %ld packets, %ld rejected, %ld decoded, no crash\n", nf, bad, ok);
        return 0;
    }
    if (argc < 5) {
        fprintf(stderr, "usage: test_adec <asc-hex|ct8|ct4> <in.pkt> <out.f32> <out.s16> [bench-repeats]\n");
        return 2;
    }
    f = fopen(argv[2], "rb");
    if (!f) return 2;
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    data = malloc((size_t) size);
    if (!data || fread(data, 1, (size_t) size, f) != (size_t) size) return 2;
    fclose(f);
    a = open_spec(argv[1]);
    b = open_spec(argv[1]);
    if (!a || !b) {
        printf("open failed\n");
        return 1;
    }
    o32 = fopen(argv[3], "wb");
    o16 = fopen(argv[4], "wb");
    if (!o32 || !o16) return 2;
    for (long p = 0; p + 4 <= size;) {
        int len = (data[p] << 24) | (data[p + 1] << 16) | (data[p + 2] << 8) | data[p + 3];
        const float *pl[8];
        int n, n16, c2, r2;
        p += 4;
        if (len <= 0 || p + len > size) break;
        packets++;
        n = ap_adec_decode_flt(a, data + p, len, pl, &ch, &rate);
        n16 = ap_adec_decode(b, data + p, len, s16, AP_ADEC_MAX_FRAMES, &r2, &c2);
        if (n < 0 || n16 < 0 || n != n16) {
            errors++;
        } else if (n > 0) {
            for (int i = 0; i < n; i++)
                for (int c = 0; c < ch; c++) fwrite(&pl[c][i], 4, 1, o32);   /* little-endian host */
            fwrite(s16, 4, (size_t) n16, o16);
            frames += n;
        }
        p += len;
    }
    fclose(o32);
    fclose(o16);
    printf("frames=%ld ch=%d rate=%d packets=%ld errors=%ld\n", frames, ch, rate, packets, errors);
    if (reps > 0) {
        clock_t t0 = clock();
        long np = 0;
        for (int r = 0; r < reps; r++) {
            ap_adec_flush(a);
            for (long p = 0; p + 4 <= size;) {
                int len = (data[p] << 24) | (data[p + 1] << 16) | (data[p + 2] << 8) | data[p + 3];
                p += 4;
                if (len <= 0 || p + len > size) break;
                ap_adec_decode(a, data + p, len, s16, AP_ADEC_MAX_FRAMES, &rate, &ch);
                p += len;
                np++;
            }
        }
        printf("bench: %.2f us/packet over %ld packets\n", (double) (clock() - t0) * 1e6 / CLOCKS_PER_SEC / (double) np, np);
    }
    ap_adec_close(a);
    ap_adec_close(b);
    free(data);
    return errors ? 1 : 0;
}
