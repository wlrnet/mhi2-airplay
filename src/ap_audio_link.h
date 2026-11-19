/*
 * Link from ap_receiver to the external audio output process over 127.0.0.1 TCP
 * (wire format: ap_audio_proto.h). Only decoded PCM crosses it. Connects on demand, sends a
 * heartbeat every second while connected, never blocks the caller longer than the send timeout.
 */
#ifndef AP_AUDIO_LINK_H
#define AP_AUDIO_LINK_H

#include <stdint.h>

typedef struct ap_audio_link_s ap_audio_link_t;
typedef void (*ap_alog_fn)(const char *fmt, ...);

ap_audio_link_t *ap_audio_link_create(int port, ap_alog_fn log);

/* Interleaved S16 frames; due_ms as in ap_audio_proto.h. A format record is sent first on each
 * connection and whenever rate/channels change. */
void ap_audio_link_pcm(ap_audio_link_t *l, const int16_t *pcm, int frames, int rate, int ch, int32_t due_ms);

/* Ask the player to drop what it has buffered. */
void ap_audio_link_flush(ap_audio_link_t *l);

/* Audio session over: close the connection (the output process releases its output). */
void ap_audio_link_end_session(ap_audio_link_t *l);

void ap_audio_link_destroy(ap_audio_link_t *l);

#endif
