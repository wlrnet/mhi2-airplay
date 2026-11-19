/* Force-included for libplist on QNX 6.5, whose libc has no strndup(). Defined in ap_rt.c. */
#ifndef AP_COMPAT_H
#define AP_COMPAT_H
#include <stddef.h>
char *strndup(const char *s, size_t n);
#endif
