/* PC test for ap_split_au (src/ap_video_link.c): parameter sets vs slices, IDR flag, 3/4-byte start codes. */
#include <stdio.h>
#include <string.h>
#include "ap_video_link.h"

static int g_fail, g_pass;
#define CHECK(c, w) do { if (c) g_pass++; else { g_fail++; printf("FAIL %s (line %d)\n", w, __LINE__); } } while (0)

int main(void)
{
    uint8_t params[256], vcl[256];
    int pl, vl, f;
    /* SPS, PPS (4-byte codes) + IDR slice (3-byte code) */
    const uint8_t au1[] = { 0,0,0,1, 0x67,0xaa,0xbb, 0,0,0,1, 0x68,0xcc, 0,0,1, 0x65,1,2,3 };
    f = ap_split_au(au1, sizeof(au1), params, &pl, sizeof(params), vcl, &vl, sizeof(vcl));
    CHECK(f == 3, "IDR + params flags");
    const uint8_t p_exp[] = { 0,0,0,1, 0x67,0xaa,0xbb, 0,0,0,1, 0x68,0xcc };
    CHECK(pl == (int) sizeof(p_exp) && memcmp(params, p_exp, pl) == 0, "params bytes");
    const uint8_t v_exp[] = { 0,0,0,1, 0x65,1,2,3 };
    CHECK(vl == (int) sizeof(v_exp) && memcmp(vcl, v_exp, vl) == 0, "slice normalised to 4-byte code");

    /* P frame with SEI */
    const uint8_t au2[] = { 0,0,0,1, 0x06,9, 0,0,0,1, 0x41,7,7 };
    f = ap_split_au(au2, sizeof(au2), params, &pl, sizeof(params), vcl, &vl, sizeof(vcl));
    CHECK(f == 0 && pl == 0 && vl == (int) sizeof(au2), "P frame + SEI stay together");

    /* overflow */
    f = ap_split_au(au1, sizeof(au1), params, &pl, 8, vcl, &vl, sizeof(vcl));
    CHECK(f == -1, "params overflow reported");

    /* no start code at all */
    const uint8_t junk[] = { 1,2,3,4 };
    f = ap_split_au(junk, sizeof(junk), params, &pl, sizeof(params), vcl, &vl, sizeof(vcl));
    CHECK(f == 0 && pl == 0 && vl == 0, "garbage yields nothing");

    printf("test_split: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
