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
/* Create the private pipe if needed. For empty buffers, try to grow its capacity
 * to preferred_capacity (at most INT_MAX); zero skips capacity negotiation.
 * Query/growth failure is nonfatal and retains the usable pipe. Undersized or
 * unknown-capacity pairs retry on later empty initialization at most once per
 * second per pair, including after pool reuse. Never shrinks a pipe or resizes
 * a buffer with payload. Returns -1 only when creation fails or splice is unsupported. */
int  sbufSpliceInitPipe(sbuf_t *buf, uint32_t preferred_capacity);
void sbufSpliceClosePipe(sbuf_t *buf);
/* Discard an exclusively owned splice payload before recycling. Drains the private
 * pipe, or closes it on error; clears length/cursor without freeing the wrapper.
 * Empty unused wrappers are valid. No lifetime metadata is allowed. */
void sbufSpliceDiscard(sbuf_t *buf);
/* Checks kernel emptiness as well as logical settlement; reset never drains. */
bool sbufSpliceIsReusable(const sbuf_t *buf);
/* Type-specific destruction also accepts cached wrappers with reset flags. */
void sbufDestroySplice(sbuf_t *buf);
