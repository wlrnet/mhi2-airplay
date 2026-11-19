/*
 * Link from ap_receiver to an external hardware video decoder process, over
 * 127.0.0.1 TCP, with this wire format:
 *   'W' 'V' type(1) flags(1) len(4, BE) ts_us(8, BE) + payload
 *   type 0 = heartbeat (no payload; the decoder drops a client after 8 s of silence),
 *   type 1 = parameter sets (SPS+PPS, Annex-B), type 2 = one access unit, flags bit0 = IDR.
 * The decoder switches the main screen to the video layer on its first decoded frame and gives
 * it back to the head unit when this connection closes.
 */
#ifndef AP_VIDEO_LINK_H
#define AP_VIDEO_LINK_H

#include <stddef.h>
#include <stdint.h>

typedef struct ap_video_link_s ap_video_link_t;
typedef void (*ap_log_fn)(const char *fmt, ...);

ap_video_link_t *ap_video_link_create(int port, ap_log_fn log);

/* One Annex-B access unit as delivered by UxPlay (SPS/PPS may be prepended). Connects on demand.
 * Called from UxPlay's mirroring thread; never blocks longer than the socket send timeout. */
void ap_video_link_push(ap_video_link_t *l, const uint8_t *au, int len);

/* Mirroring stopped: close the decoder connection (the screen goes back to the head unit). */
void ap_video_link_end_session(ap_video_link_t *l);

void ap_video_link_destroy(ap_video_link_t *l);

/* ---- exposed for the PC unit test ---- */

/* Split an Annex-B access unit: copies SPS/PPS NALs (with 4-byte start codes) to params, the rest
 * to vcl. Returns bit0 = contains IDR slice, bit1 = contains parameter sets. -1 on overflow. */
int ap_split_au(const uint8_t *au, int len, uint8_t *params, int *plen, int pcap,
                uint8_t *vcl, int *vlen, int vcap);

#endif
