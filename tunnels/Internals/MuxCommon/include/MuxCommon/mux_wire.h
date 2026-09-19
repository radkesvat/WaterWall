#ifndef MUX_COMMON_MUX_WIRE_H_
#define MUX_COMMON_MUX_WIRE_H_

#include "MuxCommon/mux_parent_output.h"
#include "splice_stream.h"
#include "wwapi.h"

typedef uint32_t mux_length_t;
typedef uint32_t mux_cid_t;
#define kMuxCidMax UINT32_MAX

/* Network bytes: 24-bit payload length, 8-bit flags, 32-bit CID. */
typedef struct
{
    uint8_t bytes[8];
} mux_wire_header_t;

/* Decoded host values; never copy this structure to or from wire storage. */
typedef struct
{
    mux_length_t length;
    mux_cid_t    cid;
    uint8_t      flags;
} mux_frame_t;

_Static_assert(sizeof(mux_wire_header_t) == 8, "MUX wire header must be exactly eight bytes");
_Static_assert(sizeof(mux_length_t) >= 4, "MUX decoded length must hold 24 bits");

enum
{
    kMuxFlagOpen               = 0,
    kMuxFlagClose              = 1,
    kMuxFlagFlowPause          = 2,
    kMuxFlagFlowResume         = 3,
    kMuxFlagData               = 4,
    kMuxFrameLength            = sizeof(mux_wire_header_t),
    kMuxMaxDataFrameLength     = 1024U * 1024U, // Payload only; independent of pool and pipe geometry.
    kMuxMaxBufferedFrameLength = kMuxMaxDataFrameLength + kMuxFrameLength,
};

typedef enum mux_encode_result_e
{
    kMuxEncodeSuccess,
    kMuxEncodeLengthOverflow
} mux_encode_result_t;

/** Serialize a valid payload length (0 through kMuxMaxDataFrameLength inclusive). */
WW_EXPORT void muxSetMuxFrameHeader(mux_wire_header_t *frame, mux_length_t length, mux_cid_t cid, uint8_t flag);

WW_EXPORT void muxMakeMuxFrame(sbuf_t *buf, mux_cid_t cid, uint8_t flag);

WW_EXPORT void muxMakeMuxOpenDataFrames(sbuf_t *buf, mux_cid_t cid);

WW_EXPORT void muxMakeMuxOpenCloseFrames(sbuf_t *buf, mux_cid_t cid);

/**
 * Compute the size of a DATA-framed payload, optionally preceded by OPEN.
 * Caller supplies a non-NULL encoded_length output.
 *
 * @return true when the encoded stream fits in uint32_t; false otherwise,
 *         leaving @p encoded_length unchanged.
 */
WW_EXPORT bool muxTryComputeEncodedLength(uint32_t payload_length, bool prepend_open, uint32_t *encoded_length);

/** Decode eight bytes, including unaligned storage, without validating the length. */
WW_EXPORT void muxDecodeFrameHeader(const void *wire, mux_frame_t *frame);

typedef enum mux_peek_result_e
{
    kMuxPeekNeedMore,
    kMuxPeekReady,
    kMuxPeekInvalidLength
} mux_peek_result_t;

/** No I/O or consumption. Reject an oversized length as soon as the header is
 * complete, for every frame type, before waiting for the body. */
WW_EXPORT mux_peek_result_t muxPeekCompleteFrame(const splice_stream_t *stream, mux_frame_t *frame);
/** Consume header and exact body. Returns only the owned body with onward
 * padding; optional splice assembly may return a complete ordinary fallback. */
WW_EXPORT sbuf_t *muxReadFrameBody(splice_stream_t *stream, const mux_frame_t *frame, bool prefer_splice);

/**
 * Consume one child payload and encode it as one or more MUX DATA frames.
 * An empty payload produces one zero-length DATA frame. Payloads larger than
 * kMuxMaxDataFrameLength are split; decoding does not restore their original
 * callback boundary. MUX framing is not a general datagram-framing contract.
 *
 * Large splice inputs must use muxEncodeSpliceBatch instead.
 * The input buffer is consumed on every result. On in-place success,
 * @p encoded_out receives @p input. On expanded success it receives a new
 * buffer and @p input has been returned to @p pool exactly once. On failure,
 * every owned buffer is returned to @p pool and @p encoded_out is NULL.
 */
WW_EXPORT mux_encode_result_t muxEncodeChildPayload(buffer_pool_t *pool, sbuf_t *input, mux_cid_t cid,
                                                    bool prepend_open, sbuf_t **encoded_out);

/** Consume large splice input on every result. Stage the complete ordered batch
 * and transactionally append to output under limit, including writable parents.
 * No callback or wire-state publication occurs here. False leaves output unchanged; caller closes the affected parent.
 */
WW_EXPORT bool muxEncodeSpliceBatch(buffer_pool_t *pool, sbuf_t *input, mux_cid_t cid, bool prepend_open,
                                    mux_parent_output_t *output, size_t limit);

#endif // MUX_COMMON_MUX_WIRE_H_
