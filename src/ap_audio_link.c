/* ap_audio_link.c -- see ap_audio_link.h. Our glue, linked into ap_receiver (GPLv3 as a whole). */
#include "ap_audio_link.h"
#include "ap_audio_proto.h"

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

#define SEND_TIMEOUT_MS 200

struct ap_audio_link_s {
    int port;
    ap_alog_fn log;
    pthread_mutex_t lock;
    pthread_t hb;
    int hb_run;
    int fd;
    int rate, ch;           /* format sent on this connection (0 = none) */
    int session;
    unsigned long sent_frames, dropped_frames;
    time_t retry_at;        /* player not reachable: do not try to connect on every packet */
};

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

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) v;
}

static int send_rec(int fd, int type, const void *data, int len, int32_t due)
{
    uint8_t h[AP_AU_HDR];
    h[0] = 'A';
    h[1] = 'U';
    h[2] = (uint8_t) type;
    h[3] = 0;
    put32(h + 4, (uint32_t) len);
    put32(h + 8, (uint32_t) due);
    if (send_all(fd, h, AP_AU_HDR)) return -1;
    return len > 0 ? send_all(fd, (const uint8_t *) data, len) : 0;
}

static void drop_conn_locked(ap_audio_link_t *l, const char *why)
{
    if (l->fd >= 0) {
        close(l->fd);
        l->fd = -1;
        l->log("audio link closed (%s)", why);
    }
    l->rate = l->ch = 0;
}

static int connect_locked(ap_audio_link_t *l)
{
    struct sockaddr_in a;
    struct timeval tv;
    int one = 1;
    int fd;
    time_t now = time(NULL);
    if (now < l->retry_at) return -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t) l->port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *) &a, sizeof(a)) != 0) {
        close(fd);
        l->retry_at = now + 2;
        return -1;
    }
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    tv.tv_sec = 0;
    tv.tv_usec = SEND_TIMEOUT_MS * 1000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    l->fd = fd;
    l->rate = l->ch = 0;
    l->log("audio link connected (127.0.0.1:%d)", l->port);
    return 0;
}

static void *hb_thread(void *arg)
{
    ap_audio_link_t *l = (ap_audio_link_t *) arg;
    for (;;) {
        sleep(1);
        pthread_mutex_lock(&l->lock);
        if (!l->hb_run) {
            pthread_mutex_unlock(&l->lock);
            break;
        }
        if (l->fd >= 0 && send_rec(l->fd, AP_AU_HEARTBEAT, NULL, 0, 0)) drop_conn_locked(l, "heartbeat send failed");
        pthread_mutex_unlock(&l->lock);
    }
    return NULL;
}

ap_audio_link_t *ap_audio_link_create(int port, ap_alog_fn log)
{
    ap_audio_link_t *l = (ap_audio_link_t *) calloc(1, sizeof(*l));
    if (!l) return NULL;
    l->port = port;
    l->log = log;
    l->fd = -1;
    pthread_mutex_init(&l->lock, NULL);
    l->hb_run = 1;
    if (pthread_create(&l->hb, NULL, hb_thread, l) != 0) {
        l->hb_run = 0;
        log("audio heartbeat thread failed to start");
    }
    return l;
}

void ap_audio_link_pcm(ap_audio_link_t *l, const int16_t *pcm, int frames, int rate, int ch, int32_t due_ms)
{
    int bytes = frames * ch * 2;
    if (!l || frames <= 0 || bytes > AP_AU_MAX_LEN) return;
    pthread_mutex_lock(&l->lock);
    l->session = 1;
    if (l->fd < 0 && connect_locked(l) != 0) {
        l->dropped_frames += (unsigned long) frames;
        if (l->dropped_frames == (unsigned long) frames || l->dropped_frames % (44100ul * 60ul) < (unsigned long) frames)
            l->log("audio player (127.0.0.1:%d) not reachable: audio dropped", l->port);
        pthread_mutex_unlock(&l->lock);
        return;
    }
    if (l->rate != rate || l->ch != ch) {
        uint8_t f[5];
        put32(f, (uint32_t) rate);
        f[4] = (uint8_t) ch;
        if (send_rec(l->fd, AP_AU_FORMAT, f, 5, 0)) {
            drop_conn_locked(l, "send failed");
            pthread_mutex_unlock(&l->lock);
            return;
        }
        l->rate = rate;
        l->ch = ch;
    }
    if (send_rec(l->fd, AP_AU_PCM, pcm, bytes, due_ms)) {
        drop_conn_locked(l, "send failed");
        l->dropped_frames += (unsigned long) frames;
    } else {
        l->sent_frames += (unsigned long) frames;
    }
    pthread_mutex_unlock(&l->lock);
}

void ap_audio_link_flush(ap_audio_link_t *l)
{
    if (!l) return;
    pthread_mutex_lock(&l->lock);
    if (l->fd >= 0 && send_rec(l->fd, AP_AU_FLUSH, NULL, 0, 0)) drop_conn_locked(l, "send failed");
    pthread_mutex_unlock(&l->lock);
}

void ap_audio_link_end_session(ap_audio_link_t *l)
{
    if (!l) return;
    pthread_mutex_lock(&l->lock);
    if (l->session || l->fd >= 0) {
        l->log("audio session end: frames sent %lu, dropped %lu", l->sent_frames, l->dropped_frames);
    }
    drop_conn_locked(l, "session end");
    l->session = 0;
    l->sent_frames = l->dropped_frames = 0;
    l->retry_at = 0;
    pthread_mutex_unlock(&l->lock);
}

void ap_audio_link_destroy(ap_audio_link_t *l)
{
    int had;
    if (!l) return;
    pthread_mutex_lock(&l->lock);
    had = l->hb_run;
    l->hb_run = 0;
    pthread_mutex_unlock(&l->lock);
    if (had) pthread_join(l->hb, NULL);
    ap_audio_link_end_session(l);
    pthread_mutex_destroy(&l->lock);
    free(l);
}
