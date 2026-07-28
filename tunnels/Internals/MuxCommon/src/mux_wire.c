#include "MuxCommon/mux_wire.h"

void muxSetMuxFrameHeader(mux_frame_t *frame, mux_length_t length, mux_cid_t cid, uint8_t flag)
{
    *frame = (mux_frame_t) {.length = htobe16(length), .flags = flag, ._pad1 = 0, .cid = htobe32(cid)};
}

void muxMakeMuxFrame(sbuf_t *buf, mux_cid_t cid, uint8_t flag)
{
    assert(sbufGetLength(buf) <= kMuxMaxDataFrameLength);

    mux_frame_t frame;
    muxSetMuxFrameHeader(&frame, (mux_length_t) sbufGetLength(buf), cid, flag);
    sbufShiftLeft(buf, kMuxFrameLength);
    sbufWrite(buf, &frame, kMuxFrameLength);
}

void muxMakeMuxOpenDataFrames(sbuf_t *buf, mux_cid_t cid)
{
    uint32_t payload_length = sbufGetLength(buf);
    assert(payload_length <= kMuxMaxDataFrameLength);

    mux_frame_t open_frame;
    mux_frame_t data_frame;
    muxSetMuxFrameHeader(&open_frame, 0, cid, kMuxFlagOpen);
    muxSetMuxFrameHeader(&data_frame, (mux_length_t) payload_length, cid, kMuxFlagData);

    sbufShiftLeft(buf, kMuxFrameLength * 2);
    sbufWrite(buf, &open_frame, kMuxFrameLength);
    memoryCopy(sbufGetMutablePtr(buf) + kMuxFrameLength, &data_frame, kMuxFrameLength);
}

void muxMakeMuxOpenCloseFrames(sbuf_t *buf, mux_cid_t cid)
{
    mux_frame_t open_frame;
    mux_frame_t close_frame;
    muxSetMuxFrameHeader(&open_frame, 0, cid, kMuxFlagOpen);
    muxSetMuxFrameHeader(&close_frame, 0, cid, kMuxFlagClose);

    sbufShiftLeft(buf, kMuxFrameLength * 2);
    sbufWrite(buf, &open_frame, kMuxFrameLength);
    memoryCopy(sbufGetMutablePtr(buf) + kMuxFrameLength, &close_frame, kMuxFrameLength);
}

bool muxTryComputeEncodedLength(uint32_t payload_length, bool prepend_open, uint32_t *encoded_length)
{
    if (encoded_length == NULL)
    {
        return false;
    }

    uint64_t data_frames =
        ((uint64_t) payload_length + (uint64_t) kMuxMaxDataFrameLength - 1U) / (uint64_t) kMuxMaxDataFrameLength;
    if (data_frames == 0)
    {
        data_frames = 1;
    }

    const uint64_t header_count = data_frames + (prepend_open ? UINT64_C(1) : UINT64_C(0));
    const uint64_t total_length = (uint64_t) payload_length + (header_count * (uint64_t) kMuxFrameLength);
    if (total_length > UINT32_MAX)
    {
        return false;
    }

    *encoded_length = (uint32_t) total_length;
    return true;
}

sbuf_t *muxReadCompleteFrame(buffer_stream_t *stream, mux_frame_t *frame)
{
    assert(stream != NULL);
    assert(frame != NULL);

    if (bufferstreamGetBufLen(stream) < kMuxFrameLength)
    {
        return NULL;
    }

    bufferstreamViewBytesAt(stream, 0, (uint8_t *) frame, kMuxFrameLength);

    const mux_length_t payload_length = be16toh(frame->length);
    const mux_cid_t    cid            = be32toh(frame->cid);
    const size_t       total_length   = (size_t) payload_length + (size_t) kMuxFrameLength;

    if (bufferstreamGetBufLen(stream) < total_length)
    {
        return NULL;
    }

    frame->length = payload_length;
    frame->cid    = cid;
    return bufferstreamReadExact(stream, total_length);
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
    sbufSetLength(encoded, encoded_length);

    uint8_t       *out    = sbufGetMutablePtr(encoded);
    const uint8_t *in     = (const uint8_t *) sbufGetRawPtr(input);
    uint32_t       offset = 0;

    if (prepend_open)
    {
        mux_frame_t open_frame;
        muxSetMuxFrameHeader(&open_frame, 0, cid, kMuxFlagOpen);
        memoryCopy(out + offset, &open_frame, kMuxFrameLength);
        offset += kMuxFrameLength;
    }

    for (uint32_t consumed = 0; consumed < payload_length;)
    {
        const uint32_t chunk = min(payload_length - consumed, (uint32_t) kMuxMaxDataFrameLength);

        mux_frame_t data_frame;
        muxSetMuxFrameHeader(&data_frame, (mux_length_t) chunk, cid, kMuxFlagData);
        memoryCopy(out + offset, &data_frame, kMuxFrameLength);
        offset += kMuxFrameLength;

        memoryCopyLarge(out + offset, in + consumed, chunk);
        offset += chunk;
        consumed += chunk;
    }

    assert(offset == encoded_length);

    bufferpoolReuseBuffer(pool, input);
    *encoded_out = encoded;
    return kMuxEncodeSuccess;
}
