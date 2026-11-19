#ifndef WW_RTMP_ENGINE_H
#define WW_RTMP_ENGINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum
{
    kRtmpMaxAppLength         = 127,
    kRtmpMaxStreamLength      = 255,
    kRtmpMaxUrlLength         = 255,
    kRtmpMaxMessageSize       = 65552,
    kRtmpOutChunkSize         = 4096,
    kRtmpMaxInChunkSize       = 65536,
    kRtmpMaxChunkHeaderSize   = 18,
    kRtmpMaxHandshakeOutput   = 3073,
    kRtmpMaxReassemblyBytes   = 3 * kRtmpMaxMessageSize,
    kRtmpInitialAckWindow     = 32768,
    kRtmpInitialPeerBandwidth = 262144,
    kRtmpDataChunkStream      = 6,
};

typedef struct ww_rtmp_engine ww_rtmp_engine_t;

typedef enum
{
    kRtmpOutputHandshake,
    kRtmpOutputOrdered,
    kRtmpOutputData,
    kRtmpOutputUrgent,
} ww_rtmp_output_e;

typedef enum
{
    kRtmpEventPublish,
    kRtmpEventReady,
    kRtmpEventAck,
    kRtmpEventBandwidth,
} ww_rtmp_event_e;

typedef struct
{
    /* All spans are borrowed until the callback returns. Callback success is 0. */
    int (*send)(void *context, const void *header, size_t header_size, const void *payload, size_t payload_size,
                ww_rtmp_output_e kind);
    int (*data)(void *context, const void *data, size_t size, uint32_t timestamp, uint32_t chunk_stream_id,
                uint32_t message_stream_id);
    int (*event)(void *context, ww_rtmp_event_e event, uint32_t value, uint8_t detail);
    int (*received)(void *context, size_t bytes);
} ww_rtmp_engine_callbacks_t;

ww_rtmp_engine_t *wwRtmpEngineCreate(bool server, const char *app, const char *stream, const char *tc_url,
                                     const ww_rtmp_engine_callbacks_t *callbacks, void *context);
void              wwRtmpEngineDestroy(ww_rtmp_engine_t *engine);

/* Start is only used on the client. Accept is only used after a server Publish event. */
int wwRtmpEngineStart(ww_rtmp_engine_t *engine);
/* Input returns zero on success, kRtmpInputClosed on an orderly peer close, or a negative error. */
enum
{
    kRtmpInputClosed = 1
};
int wwRtmpEngineInput(ww_rtmp_engine_t *engine, const void *data, size_t size);
int wwRtmpEngineAccept(ww_rtmp_engine_t *engine);
int wwRtmpEngineSendData(ww_rtmp_engine_t *engine, const void *data, size_t size, uint32_t timestamp);
int wwRtmpEngineAdvertiseWindow(ww_rtmp_engine_t *engine, uint32_t window);

#endif
