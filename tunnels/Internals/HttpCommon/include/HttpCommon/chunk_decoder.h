#pragma once

#include "buffer_stream.h"

enum
{
    kHttpChunkMaxSizeLineBytes = 1024,
    kHttpChunkMaxTrailerBytes  = 16384,
    kHttpChunkMaxOutputBytes   = 16384
};

typedef enum http_chunk_phase_e
{
    kHttpChunkSize,
    kHttpChunkBody,
    kHttpChunkTail,
    kHttpChunkTrailers,
    kHttpChunkComplete,
    kHttpChunkInvalid
} http_chunk_phase_t;

/* Zero initialization starts a new message. No buffers or callbacks are owned.
 * Metadata is consumed incrementally, so partial lines retain only this state. */
typedef struct http_chunk_decoder_s
{
    uint64_t           remaining;
    http_chunk_phase_t phase;
    uint16_t           metadata_bytes;
    uint16_t           line_bytes;
    bool               size_digits : 1;
    bool               size_padding : 1;
    bool               size_extension : 1;
    bool               saw_cr : 1;
} http_chunk_decoder_t;

typedef enum http_chunk_result_e
{
    kHttpChunkNeedMore,
    kHttpChunkData,
    kHttpChunkDone,
    kHttpChunkError
} http_chunk_result_t;

/* Consume ordinary HTTP/1 chunk framing and return at most 16 KiB of body.
 * Data transfers one buffer to the caller; every other result sets *out to NULL.
 * All parser progress is published before Data returns. Callers may deliver it
 * immediately, but must serialize nested input and validate their own lifetime.
 * Chunk sizes are bounded by INT64_MAX. Size lines include extensions and CRLF
 * in their 1 KiB bound; discarded trailers include the final CRLF in 16 KiB.
 * Extensions remain opaque after ';', apart from rejecting control bytes.
 * Done leaves bytes following this message in the stream. Error is terminal.
 * Invalid chunk terminators may be detected after body bytes were returned. */
http_chunk_result_t httpChunkDecoderStep(http_chunk_decoder_t *decoder, buffer_stream_t *stream, sbuf_t **out);
