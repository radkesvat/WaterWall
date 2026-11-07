#include "splice_frame_reader.h"

void spliceframereaderInit(splice_frame_reader_t *r, buffer_pool_t *pool, uint32_t header_size,
                           size_t nested_byte_limit, size_t retained_charge_limit, bool splice_output)
{
    assert(header_size != 0 && (uint64_t) header_size + sizeof(splice_stream_t) <= SIZE_MAX);
    *r = (splice_frame_reader_t) {.stream                = splicestreamCreate(pool, header_size),
                                  .nested_byte_limit     = nested_byte_limit,
                                  .retained_charge_limit = retained_charge_limit,
                                  .splice_output         = splice_output};
}

void spliceframereaderDestroy(splice_frame_reader_t *r)
{
    splicestreamDestroy(r->stream);
    *r = (splice_frame_reader_t) {0};
}

splice_frame_admit_t spliceframereaderAdmit(splice_frame_reader_t *r, sbuf_t *input)
{
    assert(spliceframereaderIsAttached(r));
    const size_t length = sbufGetLength(input);
    if (length == 0)
    {
        bufferpoolReuseBuffer(splicestreamGetPool(r->stream), input);
        return kSpliceFrameEmpty;
    }
    if (r->draining)
    {
        const size_t bytes = spliceframereaderLength(r);
        if (bytes > r->nested_byte_limit || length > r->nested_byte_limit - bytes)
        {
            bufferpoolReuseBuffer(splicestreamGetPool(r->stream), input);
            return kSpliceFrameByteLimit;
        }
    }
    if (! splicestreamPush(r->stream, input))
        return kSpliceFramePushFailed;
    if (r->draining)
        return splicestreamSettleCharge(r->stream, r->retained_charge_limit) ? kSpliceFrameQueued
                                                                             : kSpliceFrameChargeLimit;
    r->draining = true;
    return kSpliceFrameDrain;
}

bool spliceframereaderEndDrain(splice_frame_reader_t *r)
{
    assert(r->draining);
    if (! splicestreamSettleCharge(r->stream, r->retained_charge_limit))
        return false;
    r->draining = false;
    return true;
}

sbuf_t *spliceframereaderTakeFrame(splice_frame_reader_t *r, uint32_t body_bytes)
{
    assert(r->draining && ! r->frame_active);
    sbuf_t *destination =
        r->splice_output && body_bytes != 0 ? bufferpoolGetSpliceBuffer(splicestreamGetPool(r->stream)) : NULL;
    return splicestreamMoveFrame(r->stream, destination, body_bytes);
}

void spliceframereaderDiscardFrame(splice_frame_reader_t *r, uint32_t body_bytes)
{
    assert(r->draining && ! r->frame_active);
    splicestreamDiscardFrame(r->stream, body_bytes);
}

void spliceframereaderBeginFrame(splice_frame_reader_t *r, uint32_t body_bytes)
{
    assert(r->draining && ! r->frame_active && spliceframereaderPeekHeader(r) != NULL);
    r->frame_remaining = body_bytes;
    r->frame_active    = true;
}

static bool frameReaderConsumeChunk(splice_frame_reader_t *r, uint32_t bytes)
{
    assert(r->draining && r->frame_active && bytes <= spliceframereaderFrameAvailable(r));
    r->frame_remaining -= bytes;
    r->frame_active = r->frame_remaining != 0;
    return ! r->frame_active;
}

sbuf_t *spliceframereaderTakeChunk(splice_frame_reader_t *r, uint32_t bytes)
{
    const bool finish_frame = frameReaderConsumeChunk(r, bytes);
    sbuf_t    *destination =
        r->splice_output && bytes != 0 ? bufferpoolGetSpliceBuffer(splicestreamGetPool(r->stream)) : NULL;
    return splicestreamMoveFrameChunk(r->stream, destination, bytes, finish_frame);
}

void spliceframereaderDiscardChunk(splice_frame_reader_t *r, uint32_t bytes)
{
    const bool finish_frame = frameReaderConsumeChunk(r, bytes);
    splicestreamDiscardFrameChunk(r->stream, bytes, finish_frame);
}
