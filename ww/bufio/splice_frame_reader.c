#include "splice_frame_reader.h"

void spliceframereaderInit(splice_frame_reader_t *r, buffer_pool_t *pool, uint32_t header_size, size_t nested_bytes,
                           size_t retained_charge, bool splice_output)
{
    assert(header_size != 0 && (uint64_t) header_size + sizeof(splice_stream_t) <= SIZE_MAX);
    *r = (splice_frame_reader_t) {.stream          = splicestreamCreate(pool, header_size),
                                  .nested_bytes    = nested_bytes,
                                  .retained_charge = retained_charge,
                                  .splice_output   = splice_output};
}

void spliceframereaderDestroy(splice_frame_reader_t *r)
{
    splicestreamDestroy(r->stream);
    *r = (splice_frame_reader_t) {0};
}

splice_frame_admit_t spliceframereaderAdmit(splice_frame_reader_t *r, sbuf_t *input)
{
    assert(spliceframereaderIsAttached(r));
    const uint32_t length = sbufGetLength(input);
    if (length == 0)
    {
        bufferpoolReuseBuffer(splicestreamGetPool(r->stream), input);
        return kSpliceFrameEmpty;
    }
    if (r->draining)
    {
        const size_t bytes = spliceframereaderLength(r);
        if (bytes > r->nested_bytes || length > r->nested_bytes - bytes)
        {
            bufferpoolReuseBuffer(splicestreamGetPool(r->stream), input);
            return kSpliceFrameByteLimit;
        }
    }
    if (! splicestreamPush(r->stream, input))
        return kSpliceFramePushFailed;
    if (r->draining)
        return splicestreamSettleCharge(r->stream, r->retained_charge) ? kSpliceFrameQueued : kSpliceFrameChargeLimit;
    r->draining = true;
    return kSpliceFrameDrain;
}

bool spliceframereaderEndDrain(splice_frame_reader_t *r)
{
    assert(r->draining);
    if (! splicestreamSettleCharge(r->stream, r->retained_charge))
        return false;
    r->draining = false;
    return true;
}

sbuf_t *spliceframereaderTakeFrame(splice_frame_reader_t *r, uint32_t body_bytes)
{
    assert(r->draining);
    sbuf_t *destination =
        r->splice_output && body_bytes != 0 ? bufferpoolGetSpliceBuffer(splicestreamGetPool(r->stream)) : NULL;
    return splicestreamMoveFrame(r->stream, destination, body_bytes);
}

void spliceframereaderDiscardFrame(splice_frame_reader_t *r, uint32_t body_bytes)
{
    assert(r->draining);
    splicestreamDiscardFrame(r->stream, body_bytes);
}
