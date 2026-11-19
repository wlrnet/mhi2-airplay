/*
 * AirPlay audio decoder for ap_receiver: wraps FFmpeg's (floating-point) AAC decoder (LGPL-2.1+,
 * vendored subset in third_party/ffmpeg) without the libavcodec framework.
 *
 * AirPlay compression types (ct, from the RTSP SETUP; codec config as UxPlay feeds GStreamer):
 *   ct = 8  AAC-ELD 44100 Hz stereo, 480 samples/frame (screen mirroring), ASC f8 e8 50 00
 *   ct = 4  AAC-LC  44100 Hz stereo, 1024 samples/frame, ASC 12 10
 *   ct = 2  ALAC (audio-only AirPlay): not supported, ap_adec_open returns NULL
 */
#ifndef AP_ADEC_H
#define AP_ADEC_H

#include <stdint.h>

#define AP_ADEC_MAX_FRAMES 2048   /* per decoded packet (AAC-LC 1024, ELD 480) */

typedef struct ap_adec_s ap_adec_t;

/* NULL if ct is not supported or the decoder fails to initialise. */
ap_adec_t *ap_adec_open(int ct);

/* Decodes one raw access unit (no ADTS/LATM framing) into interleaved S16 (at most max_frames,
 * at most 2 channels). Returns frames (0 = nothing output yet), or a negative error. */
int ap_adec_decode(ap_adec_t *d, const uint8_t *in, int len, int16_t *out, int max_frames, int *rate, int *ch);

/* Forget overlap/history (after a flush or a gap). */
void ap_adec_flush(ap_adec_t *d);

void ap_adec_close(ap_adec_t *d);

#endif
