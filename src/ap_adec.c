/*
 * ap_adec.c -- see ap_adec.h. Drives FFmpeg's AAC decoder (third_party/ffmpeg, LGPL-2.1+)
 * through its FFCodec callbacks, without avcodec_open2()/the decode framework: the few framework
 * functions the decoder calls (ff_get_buffer, av_frame_unref, av_packet_get_side_data, av_log)
 * are provided by port/ffmpeg/ap_ff_shim.c. Linked into ap_receiver (GPLv3 as a whole).
 *
 * The floating-point decoder is used: FFmpeg 9.0.1's fixed-point one decodes 480-sample AAC-ELD
 * (exactly AirPlay's mirroring format) wrongly -- on the ISO conformance stream er_eld2100np_48 it
 * is at -2 dB SNR while the float decoder is within 1 LSB (test/test_adec.py). Output is planar
 * float (AV_SAMPLE_FMT_FLTP, full scale +-1.0); it is interleaved here and rounded/saturated to S16.
 */
#include "ap_adec.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavcodec/codec_internal.h"
#include "libavcodec/internal.h"
#include "libavcodec/aac/aacdec.h"
#include "libavutil/channel_layout.h"
#include "libavutil/frame.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"

extern const FFCodec ff_aac_decoder;
void ap_ff_shim_release(const AVFrame *f);   /* port/ffmpeg/ap_ff_shim.c */

struct ap_adec_s {
    AVCodecContext *avctx;
    AVCodecInternal *internal;
    AVFrame frame;
    AVPacket pkt;
    uint8_t *inbuf;          /* packet copy with AV_INPUT_BUFFER_PADDING_SIZE zero bytes */
    int inbuf_cap;
};

/* AudioSpecificConfig as UxPlay gives it to GStreamer for each AirPlay compression type */
static const uint8_t ASC_ELD[] = { 0xf8, 0xe8, 0x50, 0x00 };   /* AOT 39 (ER AAC-ELD), 44.1 kHz, 2 ch, 480 */
static const uint8_t ASC_LC[]  = { 0x12, 0x10 };               /* AOT 2 (AAC-LC), 44.1 kHz, 2 ch */

void ap_adec_close(ap_adec_t *d)
{
    if (!d) return;
    if (d->avctx) {
        if (d->avctx->priv_data && ff_aac_decoder.close) ff_aac_decoder.close(d->avctx);
        av_freep(&d->avctx->priv_data);
        av_freep(&d->avctx->extradata);
        av_channel_layout_uninit(&d->avctx->ch_layout);
        av_freep(&d->avctx);
    }
    av_frame_unref(&d->frame);
    ap_ff_shim_release(&d->frame);
    av_freep(&d->internal);
    av_freep(&d->inbuf);
    free(d);
}

static ap_adec_t *open_asc(const uint8_t *asc, int asc_len)
{
    ap_adec_t *d = (ap_adec_t *) calloc(1, sizeof(*d));
    AVCodecContext *c;
    if (!d) return NULL;
    c = d->avctx = (AVCodecContext *) av_mallocz(sizeof(AVCodecContext));
    d->internal = (AVCodecInternal *) av_mallocz(sizeof(AVCodecInternal));
    if (!c || !d->internal) goto fail;
    c->internal = d->internal;
    c->codec_type = AVMEDIA_TYPE_AUDIO;
    c->codec_id = AV_CODEC_ID_AAC;
    av_channel_layout_default(&c->ch_layout, 2);
    c->extradata = (uint8_t *) av_mallocz((size_t) asc_len + AV_INPUT_BUFFER_PADDING_SIZE);
    if (!c->extradata) goto fail;
    memcpy(c->extradata, asc, (size_t) asc_len);
    c->extradata_size = asc_len;
    c->priv_data = av_mallocz((size_t) ff_aac_decoder.priv_data_size);
    if (!c->priv_data) goto fail;
    /* AVOption defaults (what av_opt_set_defaults would set; see the options table in aacdec.c):
     * dual_mono_mode = -1 (auto), channel_order = default (0), target_level = 0 */
    {
        const AVOption *o;
        for (o = ff_aac_decoder.p.priv_class->option; o && o->name; o++) {
            if (o->type == AV_OPT_TYPE_INT) *(int *) ((uint8_t *) c->priv_data + o->offset) = (int) o->default_val.i64;
        }
    }
    if (ff_aac_decoder.init(c) < 0) goto fail;
    /* without a demuxer nothing sets avctx->sample_rate for the ER (ELD) path: take it from the
     * parsed AudioSpecificConfig (SBR output rate if SBR is signalled) */
    {
        const AACDecContext *ac = (const AACDecContext *) c->priv_data;
        int sr = ac->oc[1].m4ac.sample_rate;
        if (ac->oc[1].m4ac.sbr == 1 && ac->oc[1].m4ac.ext_sample_rate > sr) sr = ac->oc[1].m4ac.ext_sample_rate;
        if (sr <= 0) goto fail;
        c->sample_rate = sr;
    }
    return d;
fail:
    ap_adec_close(d);
    return NULL;
}

ap_adec_t *ap_adec_open(int ct)
{
    if (ct == 8) return open_asc(ASC_ELD, sizeof(ASC_ELD));
    if (ct == 4) return open_asc(ASC_LC, sizeof(ASC_LC));
    return NULL;
}

/* Also used by the PC test with a container's AudioSpecificConfig. */
ap_adec_t *ap_adec_open_asc(const uint8_t *asc, int asc_len)
{
    if (!asc || asc_len <= 0 || asc_len > 64) return NULL;
    return open_asc(asc, asc_len);
}

/* Decodes one access unit; on success *planes points at nch planar float channels. */
int ap_adec_decode_flt(ap_adec_t *d, const uint8_t *in, int len, const float **planes, int *nch, int *rate)
{
    int got = 0, ret;
    if (!d || !in || len <= 0 || len > 1 << 20) return AVERROR(EINVAL);
    if (len + AV_INPUT_BUFFER_PADDING_SIZE > d->inbuf_cap) {
        av_freep(&d->inbuf);
        d->inbuf_cap = len + AV_INPUT_BUFFER_PADDING_SIZE + 1024;
        d->inbuf = (uint8_t *) av_malloc((size_t) d->inbuf_cap);
        if (!d->inbuf) {
            d->inbuf_cap = 0;
            return AVERROR(ENOMEM);
        }
    }
    memcpy(d->inbuf, in, (size_t) len);
    memset(d->inbuf + len, 0, AV_INPUT_BUFFER_PADDING_SIZE);
    memset(&d->pkt, 0, sizeof(d->pkt));
    d->pkt.data = d->inbuf;
    d->pkt.size = len;
    av_frame_unref(&d->frame);
    ret = ff_aac_decoder.cb.decode(d->avctx, &d->frame, &got, &d->pkt);
    if (ret < 0) return ret;
    if (!got || d->frame.nb_samples <= 0) return 0;
    for (int c = 0; c < d->avctx->ch_layout.nb_channels && c < 8; c++) planes[c] = (const float *) d->frame.extended_data[c];
    *nch = d->avctx->ch_layout.nb_channels;
    *rate = d->avctx->sample_rate;
    return d->frame.nb_samples;
}

static inline int16_t flt_to_s16(float v)
{
    /* same conversion as libswresample's flt -> s16: round to nearest, saturate */
    long r = lrintf(v * 32768.0f);
    return (int16_t) (r > 32767 ? 32767 : r < -32768 ? -32768 : r);
}

int ap_adec_decode(ap_adec_t *d, const uint8_t *in, int len, int16_t *out, int max_frames, int *rate, int *ch)
{
    const float *pl[8];
    int nch = 0, r = 0, n, i;
    n = ap_adec_decode_flt(d, in, len, pl, &nch, &r);
    if (n <= 0) return n;
    if (nch < 1) return AVERROR_INVALIDDATA;
    if (n > max_frames) n = max_frames;
    if (nch == 1) {                          /* mono stream: duplicate to stereo */
        for (i = 0; i < n; i++) out[2 * i] = out[2 * i + 1] = flt_to_s16(pl[0][i]);
    } else {                                 /* first two channels (AirPlay is stereo) */
        for (i = 0; i < n; i++) {
            out[2 * i] = flt_to_s16(pl[0][i]);
            out[2 * i + 1] = flt_to_s16(pl[1][i]);
        }
    }
    *rate = r;
    *ch = 2;
    return n;
}

void ap_adec_flush(ap_adec_t *d)
{
    if (d && d->avctx && ff_aac_decoder.flush) ff_aac_decoder.flush(d->avctx);
}
