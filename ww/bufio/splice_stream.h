#pragma once

#include "buffer_queue.h"
#include "splice_buffer.h"

/* Fixed-header FIFO, serialized on the pool's owner worker. Fields are private
 * implementation state; queued buffers must never be mutated through aliases. */
typedef struct splice_stream_s
{
    buffer_pool_t *pool;
    buffer_queue_t pending;
    sbuf_t        *head;
    size_t         head_charge;
    size_t         total;
    size_t         charge;
    uint32_t       header_size;
    uint32_t       header_filled;
    uint8_t        header[];
} splice_stream_t;

/* Checked object/header allocation. Zero header size is valid.
 * The borrowed owner-worker pool must outlive destroy. */
splice_stream_t *splicestreamCreate(buffer_pool_t *pool, uint32_t header_size);
void             splicestreamDestroy(splice_stream_t *stream);

/* Takes input on every result. False recycles only this input and leaves existing
 * bytes/costs intact. Reserve precedes header consumption. Empty inputs recycle.
 * No callback or representation conversion occurs. */
bool splicestreamPush(splice_stream_t *stream, sbuf_t *input);

/* Non-consuming, no I/O/allocation. NULL until complete; borrowed until mutation. */
const uint8_t *splicestreamPeekHeader(const splice_stream_t *stream);
size_t         splicestreamBodyBytes(const splice_stream_t *stream);
size_t         splicestreamLength(const splice_stream_t *stream);
size_t         splicestreamCharge(const splice_stream_t *stream);

/* Explicit pressure relief. Combine remaining sources into one ordinary buffer
 * only if predicted charge is strictly smaller. Preserve cached header and total;
 * no callback or lifetime propagation. False leaves bytes and ownership intact. */
bool splicestreamCompact(splice_stream_t *stream);

/* Consume the cached header AND exactly bytes body bytes (bytes excludes header).
 * Caller guarantees a complete header/body and an empty destination (Debug asserts).
 * The destination transfers ownership;
 * NULL requests ordinary fallback. Return is the sole owned result, which may
 * replace/recycle destination. Full pool onward padding is preserved. Next
 * header refills only after the body completes. bytes=0 still consumes a frame.
 */
sbuf_t *splicestreamMoveFrame(splice_stream_t *stream, sbuf_t *destination, uint32_t bytes);

/* Same caller preconditions, into caller-owned sufficient empty ordinary storage.
 * Destination representation/space is checked fatally before consumption;
 * never grows/replaces destination.
 */
void splicestreamMoveFrameToOrdinary(splice_stream_t *stream, sbuf_t *destination, uint32_t bytes);
