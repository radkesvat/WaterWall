#pragma once

#include "buffer_pool.h"
#include "buffer_queue.h"

/* Staged ordinary/splice input on the pool's owner worker. Owns its active
 * buffer and unbound FIFO; borrows caller-owned header storage through Destroy.
 * Keep the reader and header storage at stable addresses. Fields are private.
 * Protocol validation, admission limits, reentry guards, callbacks and line
 * lifetime remain with the caller. No operation invokes callbacks. */
typedef struct buffer_reader_s
{
    buffer_pool_t *pool;
    buffer_queue_t pending;
    sbuf_t        *head;
    uint8_t       *header;
    size_t         bytes;
    uint16_t       header_capacity;
    uint16_t       header_filled;
} buffer_reader_t;

void bufferreaderInit(buffer_reader_t *reader, buffer_pool_t *pool, uint8_t *header, uint16_t header_capacity);
/* Clear releases input but preserves the pool/header binding. Destroy also
 * zeroes the reader. Neither wipes the caller-owned header storage. */
void bufferreaderClear(buffer_reader_t *reader);
void bufferreaderDestroy(buffer_reader_t *reader);

/* Inclusive logical-byte admission, including cached header bytes. On success
 * input ownership transfers, including empty input; on false input remains
 * caller-owned and all reader state is unchanged. Empty-input policy is local. */
bool bufferreaderTryPush(buffer_reader_t *reader, sbuf_t **input, size_t max_bytes);
/* Gather only the requested prefix. needed <= header_capacity is a precondition.
 * False retains partial progress; cached bytes remain logically charged. */
bool bufferreaderGather(buffer_reader_t *reader, uint16_t needed);
/* Consume validated metadata without taking body bytes. */
void bufferreaderConsumeHeader(buffer_reader_t *reader);
/* Requires complete body availability and representable ordinary output geometry.
 * Transfers one body with full pool large-buffer padding, then consumes the cached
 * header. A suitable whole head transfers directly; otherwise any contributing
 * splice wrapper selects pipe assembly, even for resident-only prefix bytes.
 * Pipe refusal falls back to complete ordinary output, retaining partial progress.
 * Zero bytes returns an empty ordinary buffer without consuming source body bytes.
 * Unrequested suffix bytes stay in the reader. */
sbuf_t *bufferreaderTakeBody(buffer_reader_t *reader, uint32_t bytes);
/* Requires no cached header. Transfers the next owned storage chunk, or NULL
 * when absent; storage boundaries need not coincide with original admissions. */
sbuf_t *bufferreaderTakeChunk(buffer_reader_t *reader);
/* Settle after incomplete parsing or nested admission. Within the inclusive
 * charge bound this is a no-op; otherwise coalesce unread sources in FIFO
 * order, reusing append room and growing assembly geometrically within max_charge.
 * Preserves feasible splice representation with complete ordinary fallback.
 * False means ordinary fallback cannot fit max_charge, leaves input unchanged,
 * and requires caller cleanup. Cached metadata and
 * logical-byte accounting stay intact; charge excludes the fixed header cache. */
bool bufferreaderSettle(buffer_reader_t *reader, size_t max_charge);

/* Transfer to an initialized empty unbound queue before output-budget attachment
 * or fallback replay. restore_header prepends the inspected prefix; otherwise
 * the caller must already have consumed it. Success empties the reader. False
 * leaves destination unchanged and all input owned by reader, though its head
 * may have moved into its FIFO. The caller must close/clean up on refusal. */
bool bufferreaderMoveToQueue(buffer_reader_t *reader, buffer_queue_t *destination, bool restore_header);

static inline size_t bufferreaderLength(const buffer_reader_t *reader)
{
    return reader->bytes;
}

static inline uint16_t bufferreaderHeaderLength(const buffer_reader_t *reader)
{
    return reader->header_filled;
}

/* Borrowed caller-owned cache; decode before another gather or cache reuse. */
static inline const uint8_t *bufferreaderHeader(const buffer_reader_t *reader)
{
    return reader->header;
}

static inline size_t bufferreaderBodyBytes(const buffer_reader_t *reader)
{
    assert(reader->bytes >= reader->header_filled);
    return reader->bytes - reader->header_filled;
}

static inline bool bufferreaderBodyReady(const buffer_reader_t *reader, uint32_t bytes)
{
    return bufferreaderBodyBytes(reader) >= bytes;
}

static inline size_t bufferreaderEntryCount(buffer_reader_t *reader)
{
    return bufferqueueGetBufCount(&reader->pending) + (reader->head != NULL);
}

static inline uint32_t bufferreaderHeadLength(const buffer_reader_t *reader)
{
    return reader->head == NULL ? 0 : sbufGetLength(reader->head);
}

size_t bufferreaderCharge(const buffer_reader_t *reader);
