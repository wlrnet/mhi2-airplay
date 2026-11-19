/*
 * Wire format between ap_receiver (decodes AirPlay audio) and an external audio output process
 * (plays the PCM), over 127.0.0.1 TCP (default port 7112). Only plain PCM crosses this boundary.
 *
 * Record: 'A' 'U' type(1) flags(1) len(4, BE) due_ms(4, BE, signed) + payload(len)
 *   type 0  heartbeat, no payload (sent every second; the output process may drop a client after 8 s of silence,
 *           because io-pkt does not always close a loopback connection of a crashed process)
 *   type 1  format: rate(4, BE) channels(1); must come before the first PCM record
 *   type 2  PCM: interleaved signed 16-bit little-endian frames; due_ms = milliseconds until the
 *           first frame should be heard (negative = late), 0x7fffffff = unknown (no clock sync yet)
 *   type 3  flush: drop what is buffered (phone flushed / paused)
 * Closing the connection ends the audio session: the output process releases its output.
 */
#ifndef AP_AUDIO_PROTO_H
#define AP_AUDIO_PROTO_H

#define AP_AU_HDR        12
#define AP_AU_HEARTBEAT  0
#define AP_AU_FORMAT     1
#define AP_AU_PCM        2
#define AP_AU_FLUSH      3
#define AP_AU_MAX_LEN    65536
#define AP_AU_DEFAULT_PORT 7112
#define AP_DUE_UNKNOWN_MS  0x7fffffff   /* due_ms when the sender has no clock sync yet (= AP_DUE_UNKNOWN) */

#endif
