/*
 * ap_video_link.c -- see ap_video_link.h. Our glue, linked into ap_receiver (GPLv3 as a whole).
 *
 * Rules (from the decoder process's behaviour):
 *   - parameter sets go as their own type-1 record, before the first frame of a connection and
 *     whenever they change (phone rotation changes the resolution; the decoder process reopens its decoder);
 *   - after (re)connecting, frames are held back until an IDR arrives, because AirPlay has no
 *     "send a key frame" request: a P frame without its reference only produces garbage;
 *     the last IDR is cached so a reconnect mid-session can restart from it at once;
 *   - a heartbeat record goes out every second while connected (a mirrored static screen may
 *     produce no frames for a long time, and the decoder process drops silent clients after 8 s);
 *   - 'K' (key frame request) from the decoder is logged and otherwise ignored.
 */
#include "ap_video_link.h"

#ifndef AP_SPLIT_ONLY   /* PC test builds only the Annex-B splitter (no POSIX sockets on Windows) */
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#else
#include <string.h>
#endif

#define PARAMS_MAX   1024
#define AU_MAX       (1024 * 1024)      /* the decoder accepts more; a mirrored AU is far smaller */
#define SEND_TIMEOUT_MS 500

#ifndef AP_SPLIT_ONLY
struct ap_video_link_s {
    int port;
    ap_log_fn log;
    pthread_mutex_t lock;
    pthread_t hb;
    int hb_run;
    int fd;                 /* -1 = not connected */
    int want_idr;           /* drop frames until an IDR (new connection) */
    uint8_t params[PARAMS_MAX];
    int plen;               /* current parameter sets (from the stream) */
    int params_sent;        /* sent on this connection */
    uint8_t *idr;           /* last IDR access unit (VCL part), for reconnects */
    int idr_len;
    uint8_t *vcl;           /* scratch */
    unsigned long frames, dropped, k_requests;
    int session;            /* a mirroring session is active */
};
#endif

/* ------------------------------------------------------------------ Annex-B */

static int next_start(const uint8_t *p, int len, int from, int *sc_len)
{
    for (int i = from; i + 3 <= len; i++) {
        if (p[i] == 0 && p[i + 1] == 0) {
            if (p[i + 2] == 1) { *sc_len = 3; return i; }
            if (i + 4 <= len && p[i + 2] == 0 && p[i + 3] == 1) { *sc_len = 4; return i; }
        }
    }
    return -1;
}

int ap_split_au(const uint8_t *au, int len, uint8_t *params, int *plen, int pcap,
                uint8_t *vcl, int *vlen, int vcap)
{
    static const uint8_t sc4[4] = { 0, 0, 0, 1 };
    int flags = 0, sc = 0;
    int pos = next_start(au, len, 0, &sc);
    *plen = 0;
    *vlen = 0;
    while (pos >= 0) {
        int start = pos + sc, sc2 = 0;
        int nxt = next_start(au, len, start, &sc2);
        int end = nxt >= 0 ? nxt : len;
        int nlen = end - start;
        if (nlen > 0) {
            int type = au[start] & 0x1f;
            uint8_t *dst;
            int *dlen, cap;
            if (type == 7 || type == 8) {
                dst = params; dlen = plen; cap = pcap;
                flags |= 2;
            } else {
                dst = vcl; dlen = vlen; cap = vcap;
                if (type == 5) flags |= 1;
            }
            if (*dlen + 4 + nlen > cap) return -1;
            memcpy(dst + *dlen, sc4, 4);
            memcpy(dst + *dlen + 4, au + start, (size_t) nlen);
            *dlen += 4 + nlen;
        }
        pos = nxt;
        sc = sc2;
    }
    return flags;
}

#ifndef AP_SPLIT_ONLY
/* ------------------------------------------------------------------ socket */

static int send_all(int fd, const uint8_t *p, int n)
{
    while (n > 0) {
        ssize_t r = send(fd, p, (size_t) n, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += r;
        n -= (int) r;
    }
    return 0;
}

static int send_rec(int fd, int type, int flags, const uint8_t *data, int len)
{
    uint8_t h[16];
    h[0] = 'W';
    h[1] = 'V';
    h[2] = (uint8_t) type;
    h[3] = (uint8_t) flags;
    h[4] = (uint8_t) (len >> 24);
    h[5] = (uint8_t) (len >> 16);
    h[6] = (uint8_t) (len >> 8);
    h[7] = (uint8_t) len;
    memset(h + 8, 0, 8);    /* ts 0: the decoder never drops pts==0 frames as late */
    if (send_all(fd, h, 16)) return -1;
    return len > 0 ? send_all(fd, data, len) : 0;
}

static void drop_conn_locked(ap_video_link_t *l, const char *why)
{
    if (l->fd >= 0) {
        close(l->fd);
        l->fd = -1;
        l->log("decoder link closed (%s)", why);
    }
    l->params_sent = 0;
    l->want_idr = 1;
}

static int connect_locked(ap_video_link_t *l)
{
    struct sockaddr_in a;
    struct timeval tv;
    int one = 1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t) l->port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *) &a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    tv.tv_sec = 0;
    tv.tv_usec = SEND_TIMEOUT_MS * 1000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    l->fd = fd;
    l->params_sent = 0;
    l->want_idr = 1;
    l->log("decoder link connected (127.0.0.1:%d)", l->port);
    return 0;
}

/* Read and log 'K' requests without blocking. */
static void drain_requests_locked(ap_video_link_t *l)
{
    uint8_t buf[32];
    for (;;) {
        ssize_t r = recv(l->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (r > 0) {
            for (ssize_t i = 0; i < r; i++) {
                if (buf[i] == 'K') l->k_requests++;
            }
            continue;
        }
        if (r == 0) {
            drop_conn_locked(l, "decoder closed it");
        }
        return;   /* EAGAIN or error: nothing more now */
    }
}

/* ------------------------------------------------------------------ heartbeat */

static void *hb_thread(void *arg)
{
    ap_video_link_t *l = arg;
    for (;;) {
        sleep(1);
        pthread_mutex_lock(&l->lock);
        if (!l->hb_run) {
            pthread_mutex_unlock(&l->lock);
            break;
        }
        if (l->fd >= 0) {
            drain_requests_locked(l);
            if (l->fd >= 0 && send_rec(l->fd, 0, 0, NULL, 0)) drop_conn_locked(l, "heartbeat send failed");
        }
        pthread_mutex_unlock(&l->lock);
    }
    return NULL;
}

/* ------------------------------------------------------------------ API */

ap_video_link_t *ap_video_link_create(int port, ap_log_fn log)
{
    ap_video_link_t *l = calloc(1, sizeof(*l));
    if (!l) return NULL;
    l->vcl = malloc(AU_MAX);
    l->idr = malloc(AU_MAX);
    if (!l->vcl || !l->idr) {
        free(l->vcl);
        free(l->idr);
        free(l);
        return NULL;
    }
    l->port = port;
    l->log = log;
    l->fd = -1;
    l->want_idr = 1;
    pthread_mutex_init(&l->lock, NULL);
    l->hb_run = 1;
    if (pthread_create(&l->hb, NULL, hb_thread, l) != 0) {
        l->hb_run = 0;
        log("heartbeat thread failed to start");
    }
    return l;
}

void ap_video_link_push(ap_video_link_t *l, const uint8_t *au, int len)
{
    uint8_t params[PARAMS_MAX];
    int plen = 0, vlen = 0, flags;
    if (!l || !au || len <= 0) return;
    flags = ap_split_au(au, len, params, &plen, sizeof(params), l->vcl, &vlen, AU_MAX);

    pthread_mutex_lock(&l->lock);
    if (flags < 0) {
        l->dropped++;
        l->log("access unit too large (%d bytes): dropped", len);
        pthread_mutex_unlock(&l->lock);
        return;
    }
    l->session = 1;
    if (flags & 2) {
        if (plen != l->plen || memcmp(params, l->params, (size_t) plen) != 0) {
            memcpy(l->params, params, (size_t) plen);
            l->plen = plen;
            l->params_sent = 0;          /* changed (rotation / new session): resend */
            l->log("parameter sets updated (%d bytes)", plen);
        }
    }
    if ((flags & 1) && vlen > 0) {
        memcpy(l->idr, l->vcl, (size_t) vlen);
        l->idr_len = vlen;
    }
    if (l->fd < 0 && connect_locked(l) != 0) {
        l->dropped++;
        if (l->dropped % 100 == 1) l->log("decoder (127.0.0.1:%d) not reachable: frames dropped (%lu)", l->port, l->dropped);
        pthread_mutex_unlock(&l->lock);
        return;
    }
    drain_requests_locked(l);
    if (l->fd < 0) {
        pthread_mutex_unlock(&l->lock);
        return;
    }
    if (!l->params_sent && l->plen > 0) {
        if (send_rec(l->fd, 1, 0, l->params, l->plen)) {
            drop_conn_locked(l, "send failed");
            pthread_mutex_unlock(&l->lock);
            return;
        }
        l->params_sent = 1;
    }
    if (l->want_idr) {
        if (!(flags & 1)) {
            /* restart from the cached IDR if we have one, then continue with this frame */
            if (l->idr_len > 0 && l->params_sent) {
                if (send_rec(l->fd, 2, 1, l->idr, l->idr_len)) {
                    drop_conn_locked(l, "send failed");
                    pthread_mutex_unlock(&l->lock);
                    return;
                }
                l->want_idr = 0;
            } else {
                l->dropped++;
                pthread_mutex_unlock(&l->lock);
                return;
            }
        } else {
            l->want_idr = 0;
        }
    }
    if (vlen > 0 && l->params_sent) {
        if (send_rec(l->fd, 2, flags & 1, l->vcl, vlen)) {
            drop_conn_locked(l, "send failed");
        } else {
            l->frames++;
        }
    }
    pthread_mutex_unlock(&l->lock);
}

void ap_video_link_end_session(ap_video_link_t *l)
{
    if (!l) return;
    pthread_mutex_lock(&l->lock);
    if (l->session || l->fd >= 0) {
        l->log("session end: frames %lu, dropped %lu, key frame requests %lu", l->frames, l->dropped, l->k_requests);
    }
    drop_conn_locked(l, "session end");
    l->session = 0;
    l->plen = 0;
    l->idr_len = 0;
    l->frames = l->dropped = l->k_requests = 0;
    pthread_mutex_unlock(&l->lock);
}

void ap_video_link_destroy(ap_video_link_t *l)
{
    if (!l) return;
    pthread_mutex_lock(&l->lock);
    int had = l->hb_run;
    l->hb_run = 0;
    pthread_mutex_unlock(&l->lock);
    if (had) pthread_join(l->hb, NULL);
    ap_video_link_end_session(l);
    pthread_mutex_destroy(&l->lock);
    free(l->vcl);
    free(l->idr);
    free(l);
}
#endif /* AP_SPLIT_ONLY */
