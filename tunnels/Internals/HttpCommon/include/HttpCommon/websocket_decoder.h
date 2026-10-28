#pragma once

#include "buffer_stream.h"

enum
{
    kHttpWebSocketBodySliceBytes = 16 * 1024
};

typedef struct http_websocket_decoder_s
{
    uint32_t remaining;
    uint8_t  mask_key[4];
    uint8_t  mask_offset;
    uint8_t  opcode;
    bool     active;
    bool     masked;
} http_websocket_decoder_t;

typedef enum http_websocket_result_e
{
    kHttpWebSocketNeedMore,
    kHttpWebSocketData,
    kHttpWebSocketPing,
    kHttpWebSocketPong,
    kHttpWebSocketClose,
    kHttpWebSocketError
} http_websocket_result_t;

/* Zero-initialize state for a new connection. The stream contains ordinary
 * buffers and owns its input. One call consumes framing and returns at most one
 * caller-owned output; Data is nonempty and at most BodySliceBytes, while empty
 * control events return NULL. NeedMore/Error also return NULL. Invalid framing
 * requires the caller to close; this helper has no callbacks or line ownership.
 *
 * Headers are validated before waiting for payload. Data frames may declare up
 * to UINT32_MAX bytes, but are delivered incrementally. Control frames remain
 * whole and at most 125 bytes. State is advanced before returning an output, so
 * the caller can safely invoke another tunnel after serializing input admission.
 * Masking continues across body slices. Text/binary/continuation payloads remain
 * a byte stream; message sequencing, text validation and extensions are unchanged.
 */
http_websocket_result_t httpWebSocketDecoderStep(http_websocket_decoder_t *state, buffer_stream_t *stream,
                                                 bool expect_masked, sbuf_t **out);
