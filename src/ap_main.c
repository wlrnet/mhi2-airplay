/*
 * ap_receiver -- AirPlay screen mirroring receiver for MIB2 High (QNX 6.5).
 *
 * The protocol is UxPlay's lib/ (RAOP / AirPlay mirroring, pairing, FairPlay mirroring handshake,
 * built-in mDNS responder). This file is the glue:
 *   - announce "_airplay._tcp" / "_raop._tcp" on the head unit's hotspot address only,
 *   - forward the mirrored H.264 to the hardware decoder process (ap_video_link.h wire format, 127.0.0.1),
 *     which switches the main screen to the video layer on the first frame and gives it back to
 *     the head unit when we close the connection (mirroring stopped / receiver exit),
 *   - decode the phone's audio (mirroring: AAC-ELD; AAC-LC) with FFmpeg's AAC decoder
 *     (src/ap_adec.c) and send plain PCM to an external audio output process over 127.0.0.1
 *     (wire format: src/ap_audio_proto.h).
 *
 * Linked with UxPlay (GPLv3), so distributed under GPLv3 as well.
 *
 * Environment (all optional):
 *   AP_NAME          name shown in the iPhone's Screen Mirroring list (default: first line of
 *                    /mnt/persist/airplay_name, else "MIB")
 *   AP_IFNAME        interface to serve on (default uap0, the head-unit hotspot)
 *   AP_IFADDR        IPv4 to announce instead of looking up AP_IFNAME
 *   AP_DATA          persistent data dir (default /mnt/persist/airplay): device id + pairing key
 *   AP_VIDEO_PORT    video decoder process port on 127.0.0.1 (default 7111)
 *   AP_AUDIO_PORT    audio output process port on 127.0.0.1 (default 7112); AP_AUDIO=off drops audio
 *   AP_AUDIO_DELAY_MS added to the phone's presentation time before the late check (default 0)
 *   AP_WIDTH/HEIGHT  display size told to the phone (default 1280x640), AP_FPS (default 30)
 *   AP_PORT          RTSP port (default 7000); mirror data TCP 7100; UDP 7011/7012/7013
 *   AP_LOG_LEVEL     UxPlay log level (default 6 = info)
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "dnssd.h"
#include "raop.h"
#include "logger.h"
#include "ap_video_link.h"
#include "ap_audio_link.h"
#include "ap_adec.h"
#include "ap_audio_proto.h"


/* ------------------------------------------------------------------ log */

static void aplog(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "[ap %ld.%03ld] %s\n", (long) ts.tv_sec, ts.tv_nsec / 1000000, buf);
}

static int env_int(const char *name, int def)
{
    const char *v = getenv(name);
    return (v && *v) ? atoi(v) : def;
}

static const char *env_str(const char *name, const char *def)
{
    const char *v = getenv(name);
    return (v && *v) ? v : def;
}

/* ------------------------------------------------------------------ identity */

/* Device id = a locally administered MAC, generated once and kept in AP_DATA. The phone remembers
 * pairings by it, so it must survive restarts; it is not the real WLAN MAC (never logged in full). */
static void load_device_id(const char *dir, unsigned char mac[6])
{
    char path[256], line[64];
    FILE *f;
    snprintf(path, sizeof(path), "%s/deviceid", dir);
    f = fopen(path, "r");
    if (f) {
        unsigned v[6];
        int ok = fgets(line, sizeof(line), f) != NULL &&
                 sscanf(line, "%2x:%2x:%2x:%2x:%2x:%2x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) == 6;
        fclose(f);
        if (ok) {
            for (int i = 0; i < 6; i++) mac[i] = (unsigned char) v[i];
            return;
        }
    }
    extern int get_random_bytes(unsigned char *buf, int num);
    if (get_random_bytes(mac, 6) != 1) {
        unsigned seed = (unsigned) time(NULL) ^ (unsigned) getpid();
        for (int i = 0; i < 6; i++) mac[i] = (unsigned char) rand_r(&seed);
    }
    mac[0] = (unsigned char) ((mac[0] & 0xFC) | 0x02);   /* unicast, locally administered */
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        fclose(f);
    } else {
        aplog("cannot save %s (%s): the phone will see a new receiver after every restart", path, strerror(errno));
    }
}

static void load_name(char *out, size_t cap)
{
    const char *e = getenv("AP_NAME");
    if (e && *e) {
        snprintf(out, cap, "%s", e);
        return;
    }
    snprintf(out, cap, "MIB");
    FILE *f = fopen("/mnt/persist/airplay_name", "r");
    if (f) {
        char line[128];
        if (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = 0;
            if (line[0]) snprintf(out, cap, "%s", line);
        }
        fclose(f);
    }
}

/* IPv4 of the serving interface; 0 if it has none (yet). */
static uint32_t iface_addr(const char *ifname)
{
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    uint32_t a = 0;
    if (fd < 0) return 0;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0 && ifr.ifr_addr.sa_family == AF_INET) {
        a = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
    }
    close(fd);
    return a;
}

/* ------------------------------------------------------------------ state */

static volatile sig_atomic_t g_stop;
static ap_video_link_t *g_video;
static volatile int g_mirroring;
static volatile unsigned long g_audio_pkts;

/* audio: decoder for the current compression type (ct), touched only from UxPlay's audio thread
 * (audio_get_format runs before the stream starts, audio_process/flush on the RTP thread); g_alock
 * guards against the RTSP thread tearing it down at the same time. */
static ap_audio_link_t *g_audio;
static pthread_mutex_t g_alock = PTHREAD_MUTEX_INITIALIZER;
static ap_adec_t *g_adec;
static int g_adec_ct = -1;
static int g_audio_off;
static int32_t g_audio_delay_ms;
static volatile int g_gain_q15 = 32768;        /* phone volume, Q15 (32768 = 0 dB) */
static unsigned long g_audio_errs, g_audio_frames;
static int16_t g_pcm[AP_ADEC_MAX_FRAMES * 2];

static void on_signal(int sig)
{
    (void) sig;
    g_stop = 1;
}

/* ------------------------------------------------------------------ raop callbacks */

static void cb_video_process(void *cls, raop_ntp_t *ntp, video_decode_struct *data)
{
    (void) cls;
    (void) ntp;
    if (data->is_h265) {
        return;   /* never advertised; the hardware path is H.264 only */
    }
    if (!g_mirroring) {
        g_mirroring = 1;
        aplog("mirroring: first frame");
    }
    ap_video_link_push(g_video, data->data, data->data_len);
}

static const char *ct_name(int ct)
{
    return ct == 8 ? "AAC-ELD" : ct == 4 ? "AAC-LC" : ct == 2 ? "ALAC" : ct == 1 ? "PCM" : "?";
}

static void audio_close_locked(const char *why)
{
    if (g_adec) {
        aplog("audio: %s decoder closed (%s): %lu frames decoded, %lu errors, %lu packets",
              ct_name(g_adec_ct), why, g_audio_frames, g_audio_errs, (unsigned long) g_audio_pkts);
        ap_adec_close(g_adec);
        g_adec = NULL;
    }
    g_adec_ct = -1;
    g_audio_errs = g_audio_frames = 0;
}

static void cb_audio_process(void *cls, raop_ntp_t *ntp, audio_decode_struct *data)
{
    int frames, rate = 0, ch = 0;
    int32_t due = AP_DUE_UNKNOWN_MS;
    (void) cls;
    (void) ntp;
    g_audio_pkts++;
    if (g_audio_off || !data || !data->data || data->data_len <= 0) return;
    pthread_mutex_lock(&g_alock);
    if (!g_adec || g_adec_ct != data->ct) {
        /* normally opened by audio_get_format; covers a missed or changed format */
        if (g_adec) audio_close_locked("format changed");
        g_adec = ap_adec_open(data->ct);
        g_adec_ct = data->ct;
        if (!g_adec) {
            if (g_audio_errs++ == 0) aplog("audio: no decoder for ct=%d (%s): dropped", data->ct, ct_name(data->ct));
            pthread_mutex_unlock(&g_alock);
            return;
        }
    }
    frames = ap_adec_decode(g_adec, data->data, data->data_len, g_pcm, AP_ADEC_MAX_FRAMES, &rate, &ch);
    if (frames < 0) {
        if (g_audio_errs++ % 100 == 0) aplog("audio: decode error %d (#%lu, %d bytes)", frames, g_audio_errs, data->data_len);
        pthread_mutex_unlock(&g_alock);
        return;
    }
    g_audio_frames += (unsigned long) frames;
    if (frames > 0) {
        int g = g_gain_q15;
        if (g != 32768) {
            for (int i = 0; i < frames * ch; i++) g_pcm[i] = (int16_t) (((int32_t) g_pcm[i] * g) >> 15);
        }
        if (data->ntp_time_local) {
            /* ntp_time_local = when the phone wants this packet heard, on our CLOCK_REALTIME (ns) */
            struct timespec ts;
            int64_t now, d;
            clock_gettime(CLOCK_REALTIME, &ts);
            now = (int64_t) ts.tv_sec * 1000000000LL + ts.tv_nsec;
            d = ((int64_t) data->ntp_time_local - now) / 1000000LL + g_audio_delay_ms;
            due = d > 60000 ? 60000 : d < -60000 ? -60000 : (int32_t) d;
        }
        ap_audio_link_pcm(g_audio, g_pcm, frames, rate, ch, due);
    }
    pthread_mutex_unlock(&g_alock);
}

static void cb_audio_flush(void *cls)
{
    (void) cls;
    pthread_mutex_lock(&g_alock);
    if (g_adec) ap_adec_flush(g_adec);
    pthread_mutex_unlock(&g_alock);
    ap_audio_link_flush(g_audio);
}

static void audio_session_end(const char *why)
{
    pthread_mutex_lock(&g_alock);
    audio_close_locked(why);
    pthread_mutex_unlock(&g_alock);
    ap_audio_link_end_session(g_audio);   /* the audio output process releases its output */
}

static void mirroring_stopped(const char *why)
{
    if (g_mirroring) {
        aplog("mirroring: stopped (%s), audio packets dropped so far %lu", why, (unsigned long) g_audio_pkts);
    }
    g_mirroring = 0;
    ap_video_link_end_session(g_video);   /* closes the decoder link: the screen goes back to the head unit */
    audio_session_end(why);
}

static void cb_mirror_running(void *cls, bool running)
{
    (void) cls;
    aplog("mirroring: running=%d", (int) running);
    if (!running) mirroring_stopped("phone stopped");
}

static void cb_video_reset(void *cls, reset_type_t type)
{
    (void) cls;
    aplog("video reset type %d", (int) type);
    if (type != RESET_TYPE_ON_VIDEO_PLAY) mirroring_stopped("reset");
}

static int cb_codec_and_size(void *cls, video_codec_t codec, unsigned short ws, unsigned short hs,
                             unsigned short x, unsigned short y, unsigned short w, unsigned short h)
{
    (void) cls;
    aplog("video: codec=%s source %ux%u, picture %ux%u at %u,%u",
          codec == VIDEO_CODEC_H265 ? "h265" : codec == VIDEO_CODEC_H264 ? "h264" : "?",
          ws, hs, w, h, x, y);
    return 0;
}

static int g_conns;

static void cb_conn_init(void *cls)
{
    (void) cls;
    g_conns++;
    aplog("connections: %d", g_conns);
}

static void cb_conn_destroy(void *cls)
{
    (void) cls;
    if (g_conns > 0) g_conns--;
    aplog("connections: %d", g_conns);
    if (g_conns == 0) mirroring_stopped("phone disconnected");
}

static void cb_conn_reset(void *cls, int reason)
{
    (void) cls;
    aplog("connection reset (reason %d)", reason);
    mirroring_stopped("connection lost");
}

static void cb_noop(void *cls) { (void) cls; }
static void cb_conn_feedback(void *cls) { (void) cls; }
static double cb_client_volume(void *cls) { (void) cls; return 0.0; }
/* AirPlay volume: dB, -30..0, -144 = mute */
static void cb_set_volume(void *cls, float v)
{
    double g;
    (void) cls;
    if (v <= -144.0f) g = 0.0;
    else if (v >= 0.0f) g = 1.0;
    else g = pow(10.0, (double) v / 20.0);
    g_gain_q15 = (int) (g * 32768.0 + 0.5);
    aplog("audio: volume %.1f dB", (double) v);
}
static void cb_buf(void *cls, const void *b, int n) { (void) cls; (void) b; (void) n; }
static void cb_progress(void *cls, uint32_t *a, uint32_t *b, uint32_t *c) { (void) cls; (void) a; (void) b; (void) c; }
static void cb_dacp(void *cls, const char *a, const char *b) { (void) cls; (void) a; (void) b; }

static void cb_audio_get_format(void *cls, unsigned char *ct, unsigned short *spf, bool *screen, bool *media, uint64_t *fmt)
{
    (void) cls;
    aplog("audio: ct=%u (%s) spf=%u screen=%d media=%d", (unsigned) *ct, ct_name(*ct), (unsigned) *spf,
          (int) *screen, (int) *media);
    (void) fmt;
    if (g_audio_off) return;
    pthread_mutex_lock(&g_alock);
    if (g_adec && g_adec_ct != *ct) audio_close_locked("new stream format");
    if (!g_adec) {
        g_adec = ap_adec_open(*ct);
        g_adec_ct = *ct;
        if (g_adec) aplog("audio: %s decoder ready", ct_name(*ct));
        else aplog("audio: ct=%u not supported: this stream will be silent", (unsigned) *ct);
    }
    pthread_mutex_unlock(&g_alock);
}

static void cb_client_request(void *cls, char *deviceid, char *model, char *name, bool *admit)
{
    (void) cls;
    (void) deviceid;
    (void) name;   /* phone name is personal data: not logged */
    aplog("client request: model %s -> admitted", model ? model : "?");
    *admit = true;
}

static const char *cb_passwd(void *cls, int *len)
{
    (void) cls;
    *len = 0;   /* no password / PIN: anyone on the head unit's hotspot may mirror */
    return NULL;
}

static void uxplay_log(void *cls, int level, const char *msg)
{
    (void) cls;
    (void) level;
    aplog("raop: %s", msg);
}

/* ------------------------------------------------------------------ mDNS address */

/* Patched lib/mdnsd (see port/PATCHES.md) reads AP_MDNS_ADDR so that the responder answers with
 * the hotspot address and joins the multicast group on that interface only. */
static void set_mdns_addr(uint32_t a)
{
    char ip[INET_ADDRSTRLEN];
    struct in_addr in;
    in.s_addr = a;
    inet_ntop(AF_INET, &in, ip, sizeof(ip));
    setenv("AP_MDNS_ADDR", ip, 1);
    setenv("AP_MDNS_NO_IPV6", "1", 1);
}

/* ------------------------------------------------------------------ main */

int main(int argc, char **argv)
{
    char name[96], devid[24], data_dir[192];
    unsigned char mac[6];
    const char *ifname = env_str("AP_IFNAME", "uap0");
    unsigned short port = (unsigned short) env_int("AP_PORT", 7000);
    unsigned short tcp[2], udp[3];
    int err = 0;
    (void) argc;
    (void) argv;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    signal(SIGHUP, on_signal);

    aplog("ap_receiver start pid=%d", (int) getpid());

    snprintf(data_dir, sizeof(data_dir), "%s", env_str("AP_DATA", "/mnt/persist/airplay"));
    mkdir(data_dir, 0700);
    load_device_id(data_dir, mac);
    snprintf(devid, sizeof(devid), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    load_name(name, sizeof(name));
    aplog("name length %d, device id ..:%02X:%02X", (int) strlen(name), mac[4], mac[5]);

    /* wait for the hotspot address (the hotspot may come up after us) */
    uint32_t addr = 0;
    const char *fixed = getenv("AP_IFADDR");
    if (fixed && *fixed) {
        inet_pton(AF_INET, fixed, &addr);
    }
    for (int waited = 0; !addr && !g_stop; waited += 2) {
        addr = iface_addr(ifname);
        if (addr) break;
        if (waited % 60 == 0) aplog("waiting for %s to get an address (%ds)", ifname, waited);
        sleep(2);
    }
    if (g_stop) return 0;
    {
        struct in_addr in;
        in.s_addr = addr;
        aplog("serving on %s %s", ifname, inet_ntoa(in));
    }
    set_mdns_addr(addr);

    g_video = ap_video_link_create(env_int("AP_VIDEO_PORT", 7111), aplog);
    if (!g_video) {
        aplog("video link init failed");
        return 4;
    }

    g_audio_off = getenv("AP_AUDIO") && strcmp(getenv("AP_AUDIO"), "off") == 0;
    g_audio_delay_ms = env_int("AP_AUDIO_DELAY_MS", 0);
    g_audio = ap_audio_link_create(env_int("AP_AUDIO_PORT", AP_AU_DEFAULT_PORT), aplog);
    if (!g_audio) {
        aplog("audio link init failed");
        return 4;
    }
    if (g_audio_off) aplog("audio: off (AP_AUDIO=off)");

    ntp_global_init();

    raop_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.video_process = cb_video_process;
    cb.audio_process = cb_audio_process;
    cb.video_pause = cb_noop;
    cb.video_resume = cb_noop;
    cb.conn_feedback = cb_conn_feedback;
    cb.conn_reset = cb_conn_reset;
    cb.video_reset = cb_video_reset;
    cb.video_set_codec_and_size = cb_codec_and_size;
    cb.conn_init = cb_conn_init;
    cb.conn_destroy = cb_conn_destroy;
    cb.audio_flush = cb_audio_flush;
    cb.video_flush = cb_noop;
    cb.audio_set_client_volume = cb_client_volume;
    cb.audio_set_volume = cb_set_volume;
    cb.audio_set_metadata = cb_buf;
    cb.audio_set_coverart = cb_buf;
    cb.audio_stop_coverart_rendering = cb_noop;
    cb.audio_remote_control_id = cb_dacp;
    cb.audio_set_progress = cb_progress;
    cb.audio_get_format = cb_audio_get_format;
    cb.mirror_video_running = cb_mirror_running;
    cb.report_client_request = cb_client_request;
    cb.passwd = cb_passwd;
    cb.export_dacp = cb_dacp;

    raop_t *raop = raop_init(&cb);
    if (!raop) {
        aplog("raop_init failed");
        return 5;
    }
    raop_set_log_callback(raop, uxplay_log, NULL);
    raop_set_log_level(raop, env_int("AP_LOG_LEVEL", LOGGER_INFO));
    {
        char keyfile[256];
        snprintf(keyfile, sizeof(keyfile), "%s/pairing.key", data_dir);
        if (raop_init2(raop, 1 /* nohold: a new phone may take over */, devid, keyfile)) {
            aplog("raop_init2 failed");
            return 5;
        }
    }
    raop_set_plist(raop, "width", env_int("AP_WIDTH", 1280));
    raop_set_plist(raop, "height", env_int("AP_HEIGHT", 640));
    raop_set_plist(raop, "refreshRate", 60);
    raop_set_plist(raop, "maxFPS", env_int("AP_FPS", 30));
    raop_set_plist(raop, "overscanned", 0);

    tcp[0] = 7100;   /* mirror data */
    tcp[1] = port;   /* RTSP */
    udp[0] = 7011;   /* timing */
    udp[1] = 7012;   /* control */
    udp[2] = 7013;   /* audio data */
    raop_set_tcp_ports(raop, tcp);
    raop_set_udp_ports(raop, udp);
    if (raop_start_httpd(raop, &port) < 0) {
        aplog("cannot listen on TCP %u", (unsigned) port);
        return 6;
    }
    raop_set_port(raop, port);

    dnssd_t *dnssd = dnssd_init(name, (int) strlen(name), (const char *) mac, 6, 0, &err);
    if (err || !dnssd) {
        aplog("dnssd_init failed (%d)", err);
        return 7;
    }
    dnssd_set_airplay_features(dnssd, 0, 0);    /* no HLS video */
    dnssd_set_airplay_features(dnssd, 4, 0);
    dnssd_set_airplay_features(dnssd, 42, 0);   /* no H.265: the hardware path is H.264 */
    /* bit 27 ("supports legacy pairing") stays ON (UxPlay default): without it iOS 18 skips
     * pair-setup/pair-verify, completes SETUP/RECORD and then never sets up the mirror stream. */
    raop_set_dnssd(raop, dnssd);
    if ((err = dnssd_register_raop(dnssd, port)) != 0) aplog("register _raop failed (%d)", err);
    if ((err = dnssd_register_airplay(dnssd, port)) != 0) aplog("register _airplay failed (%d)", err);
    aplog("ready: RTSP %u, mirror 7100, UDP 7011-7013, decoder link 127.0.0.1:%d", (unsigned) port,
          env_int("AP_VIDEO_PORT", 7111));

    while (!g_stop) {
        sleep(1);
        /* the hotspot can be switched off/on; follow its address so discovery keeps working */
        uint32_t now = (fixed && *fixed) ? addr : iface_addr(ifname);
        if (now && now != addr) {
            aplog("%s address changed: restart to re-announce", ifname);
            break;
        }
    }

    aplog("stopping");
    mirroring_stopped("receiver exit");
    dnssd_unregister_raop(dnssd);
    dnssd_unregister_airplay(dnssd);
    raop_stop_httpd(raop);
    raop_destroy(raop);
    dnssd_destroy(dnssd);
    ap_video_link_destroy(g_video);
    ap_audio_link_destroy(g_audio);
    aplog("bye");
    return 0;
}
