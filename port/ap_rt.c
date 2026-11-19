/*
 * Runtime helpers that clang emits for ARM EABI (-mstrict-align, 64-bit to double) and that the
 * QNX 6.5 libc does not export, plus strndup() which that libc lacks (libplist needs it).
 * Note the EABI argument order: the memset helpers take (dest, n, c), not (dest, c, n).
 */
#include <stddef.h>
#include <string.h>

void __aeabi_memcpy(void *dest, const void *src, size_t n)  { memcpy(dest, src, n); }
void __aeabi_memcpy4(void *dest, const void *src, size_t n) { memcpy(dest, src, n); }
void __aeabi_memcpy8(void *dest, const void *src, size_t n) { memcpy(dest, src, n); }
void __aeabi_memclr(void *dest, size_t n)  { memset(dest, 0, n); }
void __aeabi_memclr4(void *dest, size_t n) { memset(dest, 0, n); }
void __aeabi_memclr8(void *dest, size_t n) { memset(dest, 0, n); }
void __aeabi_memset(void *dest, size_t n, int c)  { memset(dest, c, n); }
void __aeabi_memset4(void *dest, size_t n, int c) { memset(dest, c, n); }
void __aeabi_memset8(void *dest, size_t n, int c) { memset(dest, c, n); }
void __aeabi_memmove(void *dest, const void *src, size_t n)  { memmove(dest, src, n); }
void __aeabi_memmove4(void *dest, const void *src, size_t n) { memmove(dest, src, n); }
void __aeabi_memmove8(void *dest, const void *src, size_t n) { memmove(dest, src, n); }

/* QNX 6.5 libc has neither strndup nor strnlen (libplist needs strndup). */
#include <stdlib.h>

char *strndup(const char *s, size_t n)
{
    size_t len = 0;
    while (len < n && s[len]) {
        len++;
    }
    char *r = malloc(len + 1);
    if (r) {
        memcpy(r, s, len);
        r[len] = '\0';
    }
    return r;
}

/* 64-bit integer to double without calling ourselves: split into two 32-bit halves, which VFP
 * converts natively ((double)x on a 64-bit x would compile back into a call to this function). */
double __aeabi_ul2d(unsigned long long x)
{
    unsigned int hi = (unsigned int) (x >> 32);
    unsigned int lo = (unsigned int) x;
    return (double) hi * 4294967296.0 + (double) lo;
}

double __aeabi_l2d(long long x)
{
    return x < 0 ? -__aeabi_ul2d(0ULL - (unsigned long long) x) : __aeabi_ul2d((unsigned long long) x);
}
