#pragma once

#include "splice_stream.h"

/* Complete-frame reader, serialized on the borrowed pool's owner worker.
 * Fields are private. The caller owns protocol validation, delivery, lifetime
 * protection and closure; no operation invokes callbacks or takes line refs. */
typedef struct splice_frame_reader_s
{
    splice_stream_t *stream;
    size_t           nested_bytes;
    size_t           retained_charge;
    bool             splice_output : 1;
    bool             draining : 1;
} splice_frame_reader_t;

typedef enum splice_frame_admit_e
{
    kSpliceFrameDrain,
    kSpliceFrameQueued,
    kSpliceFrameEmpty,
    kSpliceFrameByteLimit,
    kSpliceFrameChargeLimit,
    kSpliceFramePushFailed
} splice_frame_admit_t;

/* Initialize fresh storage with a nonzero, representable fixed header size.
 * The pool must outlive Destroy. Limits are literal bounds, including zero;
 * splice_output is an immutable capability, with ordinary fallback on refusal. */
void spliceframereaderInit(splice_frame_reader_t *reader, buffer_pool_t *pool, uint32_t header_size,
                           size_t nested_bytes, size_t retained_charge, bool splice_output);
/* Releases all retained input and zeroes the reader, including during a drain. */
void spliceframereaderDestroy(splice_frame_reader_t *reader);

/* Takes input on every result. Empty recycles without starting a drain.
 * Drain starts the guard: the caller must drain complete frames then EndDrain.
 * Queued means an existing drain owns delivery; return without recursing.
 * Nested input checks logical bytes before Push, then settles source charge
 * before returning Queued. Top-level complete batches have no such precheck.
 * ByteLimit/PushFailed recycle only input, preserving previously held bytes.
 * ChargeLimit has already admitted input and may have compacted the stream.
 * On any refusal the caller must close and Destroy; none releases older input.
 */
splice_frame_admit_t spliceframereaderAdmit(splice_frame_reader_t *reader, sbuf_t *input);

/* Settle incomplete retention and clear the guard on success. False requires
 * closure/Destroy. Call only on a live reader after rechecking caller state;
 * never after a callback retired it. Compaction may materialize pipe bytes. */
bool spliceframereaderEndDrain(splice_frame_reader_t *reader);

/* Complete header/body and active drain are caller preconditions. Take returns
 * the sole owned body with full pool padding, preserving feasible pipe ranges.
 * Discard consumes the frame without allocating an output buffer. Both mutate
 * the header cache; decode header fields before calling either operation. */
sbuf_t *spliceframereaderTakeFrame(splice_frame_reader_t *reader, uint32_t body_bytes);
void    spliceframereaderDiscardFrame(splice_frame_reader_t *reader, uint32_t body_bytes);

/* IsAttached is only a state-retirement sentinel, not a lifetime guard. The
 * caller must first establish that the containing allocation is still alive. */
static inline bool spliceframereaderIsAttached(const splice_frame_reader_t *reader)
{
    return reader->stream != NULL;
}

/* Borrowed until any mutation; NULL while the header is incomplete. */
static inline const uint8_t *spliceframereaderPeekHeader(const splice_frame_reader_t *reader)
{
    return splicestreamPeekHeader(reader->stream);
}

static inline bool spliceframereaderBodyReady(const splice_frame_reader_t *reader, uint32_t body_bytes)
{
    return spliceframereaderPeekHeader(reader) != NULL && splicestreamBodyBytes(reader->stream) >= body_bytes;
}

static inline size_t spliceframereaderLength(const splice_frame_reader_t *reader)
{
    return splicestreamLength(reader->stream);
}

static inline size_t spliceframereaderCharge(const splice_frame_reader_t *reader)
{
    return splicestreamCharge(reader->stream);
}
