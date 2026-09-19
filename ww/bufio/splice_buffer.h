#pragma once

#include "buffer_pool.h"
#include "shiftbuffer.h"

/* Metadata is private to one splice allocation, including while its flags are reset
 * in a pool. Delivered payload is already in this allocation's pipe. */
typedef struct splice_buffer_metadata_s
{
    int      pipefd[2];
    uint32_t pipe_capacity;        // Last known kernel capacity; zero means not yet known.
    uint64_t capacity_retry_at_us; // Monotonic deadline after a failed query/growth; survives pooling.
} splice_buffer_metadata_t;
static_assert(sizeof(splice_buffer_metadata_t) <= SPLICE_BUFFER_STORAGE_SIZE,
              "splice metadata must fit control storage");

static inline splice_buffer_metadata_t sbufSpliceMetadata(const sbuf_t *buf)
{
    splice_buffer_metadata_t metadata;
    sbufByteCopy(&metadata, buf->buf + buf->l_pad, sizeof(metadata));
    return metadata;
}
static inline void sbufSpliceSetMetadata(sbuf_t *buf, splice_buffer_metadata_t metadata)
{
    sbufByteCopy(buf->buf + buf->l_pad, &metadata, sizeof(metadata));
}

/** Proven addressable prefix of a valid buffer; never reads or materializes a pipe. */
static inline uint32_t sbufGetResidentPrefixLength(const sbuf_t *buf)
{
    assert(buf != NULL);
    if (! sbufIsSplice(buf))
        return sbufGetLength(buf);
    assert(buf->curpos <= buf->l_pad && (uint32_t) (buf->l_pad - buf->curpos) <= sbufGetLength(buf));
    return (uint32_t) buf->l_pad - buf->curpos;
}

/** Account for body bytes already removed from the private pipe by successful I/O.
 * Performs no I/O; reduces length and logical capacity without moving the cursor
 * into metadata or consuming any resident prefix. */
static inline void sbufSpliceConsumeBody(sbuf_t *buf, uint32_t bytes)
{
    assert(sbufIsSplice(buf));
    assert(bytes <= sbufGetLength(buf) - sbufGetResidentPrefixLength(buf));
    sbufConsume(buf, bytes);
    buf->capacity -= bytes;
}

/**
 * Replace an ordinary destination payload with the complete resident contents
 * of a splice wrapper. Real prefix bytes are copied before the private-pipe body.
 * The source must be exclusively owned, have no lifetime metadata, and is recycled
 * through pool on success. Destination allocation geometry and lifetime metadata
 * remain caller-owned. Invalid representation, bounds, pipe state, or incomplete
 * pipe contents are fatal invariants. Unsupported builds abort.
 */
sbuf_t *sbufSpliceMaterializeToBuffer(sbuf_t *buf, sbuf_t *dest, buffer_pool_t *pool);

/**
 * Append exactly bytes from a splice wrapper's logical front into ordinary dest.
 * Real prefix bytes are copied first, followed by body bytes from the private pipe.
 * Source length decreases by bytes; only consumed real prefix advances curpos,
 * while consumed pipe body reduces logical capacity so metadata remains fixed at
 * buf + l_pad. Both buffers stay caller-owned. Invalid representation, bounds,
 * destination space, pipe state, or incomplete pipe contents are fatal invariants.
 * Unsupported builds abort.
 */
sbuf_t *sbufSpliceReadToBuffer(sbuf_t *buf, sbuf_t *dest, uint32_t bytes);

/** Append exactly bytes from owned source into destination, replacing destination
 * with complete ordinary storage on pipe pressure/unsupported destination. The
 * caller retains source (possibly empty) and owns only the returned destination;
 * a replaced destination is recycled. final_size is the total planned assembly
 * size and padding is required onward headroom, also when destination is NULL.
 * Both ordinary and splice sources are accepted; no lifetime is transferred here.
 * Source range and destination geometry are preconditions. No callbacks occur. */
sbuf_t *sbufMoveRangeTo(buffer_pool_t *pool, sbuf_t *source, sbuf_t *destination, uint32_t bytes, uint32_t final_size,
                        uint16_t padding);

/** Consume exactly bytes into sufficient resident memory. Source remains owned
 * by the caller and its lifetime association is unchanged. */
void sbufReadRangeToMemory(sbuf_t *source, void *destination, uint32_t bytes);
