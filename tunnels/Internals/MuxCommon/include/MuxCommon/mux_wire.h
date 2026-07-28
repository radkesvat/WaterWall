#ifndef MUX_COMMON_MUX_WIRE_H_
#define MUX_COMMON_MUX_WIRE_H_

#include "wwapi.h"

typedef uint16_t mux_length_t;
typedef uint32_t mux_cid_t;
#define kMuxCidMax UINT32_MAX

#ifdef COMPILER_MSVC
#pragma pack(push, 1)
#define MUX_WIRE_PACKED
#else
#define MUX_WIRE_PACKED __attribute__((__packed__))
#endif

typedef struct
{
    mux_length_t length;
    uint8_t      flags;
    uint8_t      _pad1;
    mux_cid_t    cid;

    char data[];
} MUX_WIRE_PACKED mux_frame_t;

#ifdef COMPILER_MSVC
#pragma pack(pop)
#endif

#undef MUX_WIRE_PACKED

_Static_assert(sizeof(mux_frame_t) == 8, "MUX wire header must be exactly eight bytes");

enum
{
    kMuxFlagOpen           = 0,
    kMuxFlagClose          = 1,
    kMuxFlagFlowPause      = 2,
    kMuxFlagFlowResume     = 3,
    kMuxFlagData           = 4,
    kMuxFrameLength        = sizeof(mux_frame_t),
    kMuxMaxDataFrameLength = 0xFFFF - kMuxFrameLength,
};

typedef enum mux_encode_result_e
{
    kMuxEncodeSuccess,
    kMuxEncodeLengthOverflow
} mux_encode_result_t;

WW_EXPORT void muxSetMuxFrameHeader(mux_frame_t *frame, mux_length_t length, mux_cid_t cid, uint8_t flag);

WW_EXPORT void muxMakeMuxFrame(sbuf_t *buf, mux_cid_t cid, uint8_t flag);

WW_EXPORT void muxMakeMuxOpenDataFrames(sbuf_t *buf, mux_cid_t cid);

WW_EXPORT void muxMakeMuxOpenCloseFrames(sbuf_t *buf, mux_cid_t cid);

/**
 * Compute the size of a DATA-framed payload, optionally preceded by OPEN.
 *
 * @return true when the encoded stream fits in uint32_t; false otherwise,
 *         leaving @p encoded_length unchanged.
 */
WW_EXPORT bool muxTryComputeEncodedLength(uint32_t payload_length, bool prepend_open, uint32_t *encoded_length);

/**
 * Read and decode one complete frame without consuming an incomplete frame.
 *
 * @return a pooled buffer containing the complete wire frame, or NULL when the
 *         stream does not yet hold the complete header and payload.
 */
WW_EXPORT sbuf_t *muxReadCompleteFrame(buffer_stream_t *stream, mux_frame_t *frame);

/**
 * Consume one child payload and encode it as one or more MUX DATA frames.
 *
 * The input buffer is consumed on every result. On in-place success,
 * @p encoded_out receives @p input. On expanded success it receives a new
 * buffer and @p input has been returned to @p pool exactly once. On failure,
 * every owned buffer is returned to @p pool and @p encoded_out is NULL.
 */
WW_EXPORT mux_encode_result_t muxEncodeChildPayload(buffer_pool_t *pool, sbuf_t *input, mux_cid_t cid,
                                                    bool prepend_open, sbuf_t **encoded_out);

#endif // MUX_COMMON_MUX_WIRE_H_
