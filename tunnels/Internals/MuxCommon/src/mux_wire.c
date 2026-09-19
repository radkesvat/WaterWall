#include "MuxCommon/mux_wire.h"
#include "MuxCommon/mux_limits.h"

void muxSetMuxFrameHeader(mux_wire_header_t *frame, mux_length_t length, mux_cid_t cid, uint8_t flag)
{
    assert(length <= kMuxMaxDataFrameLength);
    *frame = (mux_wire_header_t) {.bytes = {(uint8_t) (length >> 16),
                                            (uint8_t) (length >> 8),
                                            (uint8_t) length,
                                            flag,
                                            (uint8_t) (cid >> 24),
                                            (uint8_t) (cid >> 16),
                                            (uint8_t) (cid >> 8),
                                            (uint8_t) cid}};
}

void muxDecodeFrameHeader(const void *wire, mux_frame_t *frame)
{
    const uint8_t *bytes = wire;
    *frame               = (mux_frame_t) {.length = ((uint32_t) bytes[0] << 16) | ((uint32_t) bytes[1] << 8) | bytes[2],
                                          .flags  = bytes[3],
                                          .cid    = ((uint32_t) bytes[4] << 24) | ((uint32_t) bytes[5] << 16) |
                                                 ((uint32_t) bytes[6] << 8) | bytes[7]};
}

void muxMakeMuxFrame(sbuf_t *buf, mux_cid_t cid, uint8_t flag)
{
    assert(sbufGetLength(buf) <= kMuxMaxDataFrameLength);

    mux_wire_header_t frame;
    muxSetMuxFrameHeader(&frame, sbufGetLength(buf), cid, flag);
    sbufShiftLeft(buf, kMuxFrameLength);
    sbufWrite(buf, &frame, kMuxFrameLength);
}

void muxMakeMuxOpenDataFrames(sbuf_t *buf, mux_cid_t cid)
{
    uint32_t payload_length = sbufGetLength(buf);
    assert(payload_length <= kMuxMaxDataFrameLength);

    mux_wire_header_t open_frame;
    mux_wire_header_t data_frame;
    muxSetMuxFrameHeader(&open_frame, 0, cid, kMuxFlagOpen);
    muxSetMuxFrameHeader(&data_frame, payload_length, cid, kMuxFlagData);

    sbufShiftLeft(buf, kMuxFrameLength * 2);
    sbufWrite(buf, &open_frame, kMuxFrameLength);
    memoryCopy(sbufGetMutablePtr(buf) + kMuxFrameLength, &data_frame, kMuxFrameLength);
}

void muxMakeMuxOpenCloseFrames(sbuf_t *buf, mux_cid_t cid)
{
    mux_wire_header_t open_frame;
    mux_wire_header_t close_frame;
    muxSetMuxFrameHeader(&open_frame, 0, cid, kMuxFlagOpen);
    muxSetMuxFrameHeader(&close_frame, 0, cid, kMuxFlagClose);

    sbufShiftLeft(buf, kMuxFrameLength * 2);
    sbufWrite(buf, &open_frame, kMuxFrameLength);
    memoryCopy(sbufGetMutablePtr(buf) + kMuxFrameLength, &close_frame, kMuxFrameLength);
}

bool muxTryComputeEncodedLength(uint32_t payload_length, bool prepend_open, uint32_t *encoded_length)
{
    assert(encoded_length != NULL);

    uint64_t data_frames =
        ((uint64_t) payload_length + (uint64_t) kMuxMaxDataFrameLength - 1U) / (uint64_t) kMuxMaxDataFrameLength;
    if (data_frames == 0)
    {
        data_frames = 1;
    }

    const uint64_t header_count = data_frames + (prepend_open ? UINT64_C(1) : UINT64_C(0));
    const uint64_t total_length = (uint64_t) payload_length + (header_count * (uint64_t) kMuxFrameLength);
    if (UNLIKELY(total_length > UINT32_MAX))
    {
        return false;
    }

    *encoded_length = (uint32_t) total_length;
    return true;
}

mux_peek_result_t muxPeekCompleteFrame(const splice_stream_t *stream, mux_frame_t *frame)
{
    const uint8_t *header = splicestreamPeekHeader(stream);
    if (header == NULL)
        return kMuxPeekNeedMore;
    muxDecodeFrameHeader(header, frame);
    if (UNLIKELY(frame->length > kMuxMaxDataFrameLength))
        return kMuxPeekInvalidLength;
    return splicestreamBodyBytes(stream) >= frame->length ? kMuxPeekReady : kMuxPeekNeedMore;
}

sbuf_t *muxReadFrameBody(splice_stream_t *stream, const mux_frame_t *frame, bool prefer_splice)
{
    if (prefer_splice)
        return splicestreamMoveFrame(
            stream, frame->length ? bufferpoolGetSpliceBuffer(stream->pool) : NULL, frame->length);
    sbuf_t *dest = bufferpoolGetBestFit(stream->pool, frame->length, bufferpoolGetLargeBufferPadding(stream->pool));
    splicestreamMoveFrameToOrdinary(stream, dest, frame->length);
    return dest;
}

mux_encode_result_t muxEncodeChildPayload(buffer_pool_t *pool, sbuf_t *input, mux_cid_t cid, bool prepend_open,
                                          sbuf_t **encoded_out)
{
    assert(pool != NULL);
    assert(input != NULL);
    assert(encoded_out != NULL);

    *encoded_out                  = NULL;
    const uint32_t payload_length = sbufGetLength(input);

    if (LIKELY(payload_length <= kMuxMaxDataFrameLength))
    {
        if (prepend_open)
        {
            muxMakeMuxOpenDataFrames(input, cid);
        }
        else
        {
            muxMakeMuxFrame(input, cid, kMuxFlagData);
        }
        *encoded_out = input;
        return kMuxEncodeSuccess;
    }

    assert(! sbufIsSplice(input)); // Large splice inputs use atomic batches.
    uint32_t encoded_length = 0;
    if (UNLIKELY(! muxTryComputeEncodedLength(payload_length, prepend_open, &encoded_length)))
    {
        bufferpoolReuseBuffer(pool, input);
        return kMuxEncodeLengthOverflow;
    }

    sbuf_t  *encoded           = bufferpoolGetLargeBuffer(pool);
    uint32_t required_capacity = 0;
    if (UNLIKELY(! sbufTryComputeCapacity(encoded_length, sbufGetLeftPadding(encoded), &required_capacity)))
    {
        bufferpoolReuseBuffer(pool, encoded);
        bufferpoolReuseBuffer(pool, input);
        return kMuxEncodeLengthOverflow;
    }

    encoded = sbufReserveSpace(encoded, encoded_length);
    sbufSetLength(encoded, 0);
    sbufTransferLifetime(input, encoded);

    if (prepend_open)
    {
        mux_wire_header_t open_frame;
        muxSetMuxFrameHeader(&open_frame, 0, cid, kMuxFlagOpen);
        const uint32_t offset = sbufGetLength(encoded);
        memoryCopy(sbufGetMutablePtr(encoded) + offset, &open_frame, kMuxFrameLength);
        sbufSetLength(encoded, offset + kMuxFrameLength);
    }

    uint32_t remaining = payload_length;
    while (remaining != 0)
    {
        const uint32_t chunk = min(remaining, (uint32_t) kMuxMaxDataFrameLength);

        mux_wire_header_t data_frame;
        muxSetMuxFrameHeader(&data_frame, chunk, cid, kMuxFlagData);
        const uint32_t offset = sbufGetLength(encoded);
        memoryCopy(sbufGetMutablePtr(encoded) + offset, &data_frame, kMuxFrameLength);
        sbufSetLength(encoded, offset + kMuxFrameLength);
        sbufMoveTo(encoded, input, chunk);
        remaining -= chunk;
    }

    assert(sbufGetLength(input) == 0);
    bufferpoolReuseBuffer(pool, input);
    assert(sbufGetLength(encoded) == encoded_length);

    *encoded_out = encoded;
    return kMuxEncodeSuccess;
}

bool muxEncodeSpliceBatch(buffer_pool_t *pool, sbuf_t *input, mux_cid_t cid, bool prepend_open,
                          mux_parent_output_t *output, size_t limit)
{
    assert(sbufIsSplice(input) && sbufGetLength(input) > kMuxMaxDataFrameLength);
    buffer_queue_t batch;
    bufferqueueInitEmpty(&batch);
    const uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
    uint32_t       encoded_length;
    const uint32_t length = sbufGetLength(input);
    const size_t   frames = (size_t) (length / kMuxMaxDataFrameLength) + (length % kMuxMaxDataFrameLength != 0);
    if (! muxTryComputeEncodedLength(length, prepend_open, &encoded_length) || output->charge > limit ||
        ! bufferqueueReserveExtra(&batch, frames))
        goto refused;
    discard encoded_length;

    // Every body is a full frame except the optional final short frame.
    buffer_pool_fit_t full_frame_fit, tail_fit;
    if (! bufferpoolQueryBestFit(pool, kMuxMaxDataFrameLength, padding, &full_frame_fit) ||
        ! bufferpoolQueryBestFit(pool, length % kMuxMaxDataFrameLength, padding, &tail_fit))
        goto refused;

    size_t ordinary_remaining = 0;
    for (uint32_t remaining = length; remaining != 0;)
    {
        const uint32_t count = min(remaining, (uint32_t) kMuxMaxDataFrameLength);
        const size_t   charge =
            count == kMuxMaxDataFrameLength ? full_frame_fit.allocation_charge : tail_fit.allocation_charge;
        if (charge > limit - output->charge - ordinary_remaining)
            goto refused;
        ordinary_remaining += charge;
        remaining -= count;
    }

    size_t staged_charge = 0;
    bool   first         = true;
    while (sbufGetLength(input) != 0)
    {
        const uint32_t count = min(sbufGetLength(input), (uint32_t) kMuxMaxDataFrameLength);
        ordinary_remaining -=
            count == kMuxMaxDataFrameLength ? full_frame_fit.allocation_charge : tail_fit.allocation_charge;
        const size_t allowance = limit - output->charge - staged_charge - ordinary_remaining;
        sbuf_t      *candidate = bufferpoolGetSpliceBuffer(pool);
        if (candidate != NULL)
        {
            const uint32_t capacity = sbufSpliceMetadata(candidate).pipe_capacity;
            size_t         cost;
            if (capacity < count || sbufGetLeftCapacity(candidate) < padding ||
                ! sbufTryComputeQueueCharge((uint32_t) candidate->l_pad + count, &cost) || cost > allowance)
            {
                bufferpoolReuseBuffer(pool, candidate);
                candidate = NULL;
            }
        }
        candidate = sbufMoveRangeTo(pool, input, candidate, count, count, padding);
        if (first && prepend_open)
            muxMakeMuxOpenDataFrames(candidate, cid);
        else
            muxMakeMuxFrame(candidate, cid, kMuxFlagData);
        first             = false;
        candidate         = bufferqueuePushBack(&batch, candidate);
        const size_t cost = sbufGetQueueCharge(candidate);
        assert(cost <= allowance);
        staged_charge += cost;
    }
    if (! bufferqueueReserveExtra(&output->pending, frames))
        goto refused;
    /* All fallible admission is complete. Debug replacements retain geometry.
     * No external callback can observe a partly committed batch. */
    sbuf_t *frame;
    while ((frame = bufferqueuePopFront(&batch)) != NULL)
    {
        const bool inserted = muxParentOutputEnqueue(output, &frame, limit);
        if (UNLIKELY(! inserted))
        {
            printError("Mux: reserved batch admission failed");
            abortProgramNow(1);
        }
    }
    bufferqueueDestroy(&batch);
    bufferpoolReuseBuffer(pool, input);
    return true;

refused: {
    sbuf_t *discarded;
    while ((discarded = bufferqueuePopFront(&batch)) != NULL)
        bufferpoolReuseBuffer(pool, discarded);
    bufferqueueDestroy(&batch);
    bufferpoolReuseBuffer(pool, input);
    return false;
}
}
