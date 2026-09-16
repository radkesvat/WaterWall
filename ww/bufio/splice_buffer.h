#pragma once
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
