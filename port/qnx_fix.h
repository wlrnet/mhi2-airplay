/* Force-included (-include) for UxPlay on QNX 6.5. No source changes in UxPlay itself. */
#ifndef AP_QNX_FIX_H
#define AP_QNX_FIX_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
/* QNX CMSG_SPACE calls a function -> not a constant expression; UxPlay sizes an array member with it. */
#undef CMSG_SPACE
#define CMSG_SPACE(l) ((((sizeof(struct cmsghdr)) + 3u) & ~3u) + (((l) + 3u) & ~3u))
/* Not available in this TCP stack: setsockopt fails and UxPlay only logs a warning. */
#ifndef TCP_KEEPINTVL
#define TCP_KEEPINTVL 0x7ff1
#endif
#ifndef TCP_KEEPCNT
#define TCP_KEEPCNT 0x7ff2
#endif
#endif
