#ifndef WW_RTMP_SESSION_H
#define WW_RTMP_SESSION_H

#include "rtmp_wire.h"

enum
{
    RTMP_SESSION_APP_MAX    = 127,
    RTMP_SESSION_STREAM_MAX = 255,
    RTMP_SESSION_URL_MAX    = 255,
    RTMP_SESSION_WIRE_MAX   = 4114,
    RTMP_SESSION_DATA_MAX   = RTMP_WIRE_DATA_MAX,
    RTMP_SESSION_HIGH_WATER = 512 * 1024,
    RTMP_SESSION_LOW_WATER  = 256 * 1024,
};

typedef struct rtmp_session rtmp_session_t;

/* One session per connection, operated by a single worker. The session invokes
 * no application callbacks. Invalid configuration returns NULL. Any failed
 * start, acceptance, enqueue or step requires the caller to close the stream. */
rtmp_session_t *rtmpSessionCreate(bool server, const char *app, const char *stream, const char *tc_url,
                                  size_t block_size);
void            rtmpSessionDestroy(rtmp_session_t *session);

bool rtmpSessionStart(rtmp_session_t *session);
bool rtmpSessionAccept(rtmp_session_t *session);
bool rtmpSessionQueuePlain(rtmp_session_t *session, const uint8_t *bytes, size_t size);
bool rtmpSessionQueueCarrier(rtmp_session_t *session, const uint8_t *bytes, size_t size);
/* Performs bounded protocol work without handing off any output. */
bool rtmpSessionStep(rtmp_session_t *session, uint32_t elapsed_ms, bool *progress);

bool   rtmpSessionPublishPending(const rtmp_session_t *session);
bool   rtmpSessionIsActive(const rtmp_session_t *session);
bool   rtmpSessionPeerClosed(const rtmp_session_t *session);
bool   rtmpSessionHasTxTail(const rtmp_session_t *session);
bool   rtmpSessionNeedsSendCredit(const rtmp_session_t *session);
size_t rtmpSessionPendingRx(const rtmp_session_t *session);

size_t rtmpSessionPeekWire(const rtmp_session_t *session);
size_t rtmpSessionPeekPlain(const rtmp_session_t *session);
/* TakeWire requires room for the complete eligible chunk. It commits protocol
 * credit as it removes the chunk, before the caller hands off the bytes.
 * If supplied, is_data reports whether application wire bytes were taken. */
size_t rtmpSessionTakeWire(rtmp_session_t *session, uint8_t *dst, size_t capacity, bool *is_data);
size_t rtmpSessionTakePlain(rtmp_session_t *session, uint8_t *dst, size_t capacity);

#endif
