/*
 * ap_ff_shim.c -- the few libavcodec/libavutil framework functions FFmpeg's AAC decoder calls,
 * replaced by minimal versions so that the decoder runs without the decode framework
 * (avcodec_open2/send_packet, AVBuffer pools, AVOptions, CPU detection). Used by src/ap_adec.c.
 * Part of the FFmpeg-derived subset: LGPL-2.1-or-later like the files it stands in for.
 *
 * Frame buffers: ff_get_buffer() hands out one 32-byte aligned planar block per frame (allocated
 * on first use, grown if needed); av_frame_unref() only clears the pointers. AVFrame.buf[] is not
 * used, so no other FFmpeg code may take references to these frames (the decoder does not).
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavcodec/decode.h"
#include "libavcodec/packet.h"
#include "libavutil/cpu.h"
#include "libavutil/frame.h"
#include "libavutil/internal.h"
#include "libavutil/log.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"

#define SHIM_MAX_CH 8

/* one buffer per AVFrame, keyed by the AVFrame address (ap_adec uses one frame per decoder) */
typedef struct {
    const AVFrame *owner;
    uint8_t *mem;
    size_t size;
} shim_buf_t;

#define SHIM_BUFS 8
static shim_buf_t g_bufs[SHIM_BUFS];

void ap_ff_shim_release(const AVFrame *f)
{
    for (int i = 0; i < SHIM_BUFS; i++) {
        if (g_bufs[i].owner == f) {
            av_freep(&g_bufs[i].mem);
            g_bufs[i].owner = NULL;
            g_bufs[i].size = 0;
        }
    }
}

int ff_get_buffer(AVCodecContext *avctx, AVFrame *frame, int flags)
{
    int ch = avctx->ch_layout.nb_channels, bps, i;
    size_t plane, need;
    shim_buf_t *b = NULL;
    (void) flags;
    if (ch < 1 || ch > SHIM_MAX_CH || frame->nb_samples <= 0 || frame->nb_samples > 16384) return AVERROR(EINVAL);
    if (avctx->sample_fmt != AV_SAMPLE_FMT_S32P && avctx->sample_fmt != AV_SAMPLE_FMT_FLTP) return AVERROR(EINVAL);
    bps = 4;
    plane = ((size_t) frame->nb_samples * (size_t) bps + 63) & ~(size_t) 63;
    need = plane * (size_t) ch;
    for (i = 0; i < SHIM_BUFS && !b; i++) if (g_bufs[i].owner == frame) b = &g_bufs[i];
    for (i = 0; i < SHIM_BUFS && !b; i++) if (!g_bufs[i].owner) { b = &g_bufs[i]; b->owner = frame; }
    if (!b) return AVERROR(ENOMEM);
    if (b->size < need) {
        av_freep(&b->mem);
        b->mem = (uint8_t *) av_mallocz(need);
        if (!b->mem) {
            b->owner = NULL;
            b->size = 0;
            return AVERROR(ENOMEM);
        }
        b->size = need;
    }
    frame->format = avctx->sample_fmt;
    frame->sample_rate = avctx->sample_rate;
    for (i = 0; i < ch; i++) frame->data[i] = b->mem + plane * (size_t) i;
    for (; i < AV_NUM_DATA_POINTERS; i++) frame->data[i] = NULL;
    frame->extended_data = frame->data;
    frame->linesize[0] = (int) plane;
    return 0;
}

void av_frame_unref(AVFrame *frame)
{
    if (!frame) return;
    for (int i = 0; i < AV_NUM_DATA_POINTERS; i++) frame->data[i] = NULL;
    frame->extended_data = NULL;
    frame->nb_samples = 0;
    frame->flags = 0;
    frame->linesize[0] = 0;
}

uint8_t *av_packet_get_side_data(const AVPacket *pkt, enum AVPacketSideDataType type, size_t *size)
{
    for (int i = 0; i < pkt->side_data_elems; i++) {
        if (pkt->side_data[i].type == type) {
            if (size) *size = pkt->side_data[i].size;
            return pkt->side_data[i].data;
        }
    }
    if (size) *size = 0;
    return NULL;
}

/* ---- logging: errors/warnings go to an optional callback (ap_receiver's log), the rest is dropped */

static void (*g_logcb)(int level, const char *msg);
static int g_loglevel = AV_LOG_WARNING;

void ap_ff_set_log(void (*cb)(int level, const char *msg), int level)
{
    g_logcb = cb;
    g_loglevel = level;
}

void av_vlog(void *avcl, int level, const char *fmt, va_list vl)
{
    char buf[256];
    (void) avcl;
    if (level > g_loglevel || !g_logcb) return;
    vsnprintf(buf, sizeof(buf), fmt, vl);
    buf[strcspn(buf, "\n")] = 0;
    g_logcb(level, buf);
}

void av_log(void *avcl, int level, const char *fmt, ...)
{
    va_list vl;
    va_start(vl, fmt);
    av_vlog(avcl, level, fmt, vl);
    va_end(vl);
}

const char *av_default_item_name(void *ctx)
{
    (void) ctx;
    return "aac";
}

void avpriv_report_missing_feature(void *avc, const char *msg, ...)
{
    va_list vl;
    va_start(vl, msg);
    av_vlog(avc, AV_LOG_WARNING, msg, vl);
    va_end(vl);
}

void avpriv_request_sample(void *avc, const char *msg, ...)
{
    va_list vl;
    va_start(vl, msg);
    av_vlog(avc, AV_LOG_WARNING, msg, vl);
    va_end(vl);
}

/* ---- USAC (xHE-AAC) is not part of the subset: AirPlay never sends it. The decoder calls these
 * only for audioObjectType 42; they reject the stream. */
#include "libavcodec/aac/aacdec.h"
#include "libavcodec/aac/aacdec_usac.h"

int ff_aac_usac_config_decode(AACDecContext *ac, AVCodecContext *avctx, GetBitContext *gb,
                              OutputConfiguration *oc, int channel_config)
{
    (void) ac; (void) gb; (void) oc; (void) channel_config;
    av_log(avctx, AV_LOG_ERROR, "USAC not supported in this build");
    return AVERROR_PATCHWELCOME;
}

int ff_aac_usac_reset_state(AACDecContext *ac, OutputConfiguration *oc)
{
    (void) ac; (void) oc;
    return 0;
}

int ff_aac_usac_decode_frame(AVCodecContext *avctx, AACDecContext *ac, GetBitContext *gb, int *got_frame_ptr)
{
    (void) avctx; (void) ac; (void) gb;
    *got_frame_ptr = 0;
    return AVERROR_PATCHWELCOME;
}

/* ---- no CPU-specific code is built (no asm/SIMD in this subset) */
int av_get_cpu_flags(void)
{
    return 0;
}

/* ---- channel_layout.c parses layout strings with these; the decoder never uses strings */
int av_opt_get_key_value(const char **ropts, const char *key_val_sep, const char *pairs_sep,
                         unsigned flags, char **rkey, char **rval)
{
    (void) ropts; (void) key_val_sep; (void) pairs_sep; (void) flags;
    *rkey = *rval = NULL;
    return AVERROR(EINVAL);
}

int av_sscanf(const char *string, const char *format, ...)
{
    va_list vl;
    int r;
    va_start(vl, format);
    r = vsscanf(string, format, vl);
    va_end(vl);
    return r;
}
