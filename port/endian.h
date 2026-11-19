/* QNX 6.5 has no <endian.h>; ARMv7 little endian only. */
#ifndef AP_ENDIAN_H
#define AP_ENDIAN_H
#include <stdint.h>
static inline uint64_t ap_bswap64(uint64_t x) {
    return ((x & 0x00000000000000FFULL) << 56) | ((x & 0x000000000000FF00ULL) << 40) |
           ((x & 0x0000000000FF0000ULL) << 24) | ((x & 0x00000000FF000000ULL) << 8)  |
           ((x & 0x000000FF00000000ULL) >> 8)  | ((x & 0x0000FF0000000000ULL) >> 24) |
           ((x & 0x00FF000000000000ULL) >> 40) | ((x & 0xFF00000000000000ULL) >> 56);
}
#define htobe64(x) ap_bswap64(x)
#define be64toh(x) ap_bswap64(x)
#endif
