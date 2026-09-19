/* Preparation preserves splice identity regardless of cached pipe capacity. */
#pragma once

static void testRetainedCandidatePreparation(buffer_pool_t *pool)
{
    sbuf_t *ordinary = makePayload(pool, 1);
    require(muxPrepareRetainedCandidate(pool, ordinary, false) == ordinary, "output preparation copied ordinary input");
    bufferpoolReuseBuffer(pool, ordinary);
#if WW_HAVE_SPLICE
    for (unsigned unknown = 0; unknown < 2; ++unknown)
    {
        sbuf_t *source = makeSplicePattern(pool, 32);
        if (unknown)
        {
            splice_buffer_metadata_t metadata = sbufSpliceMetadata(source);
            metadata.pipe_capacity            = 0;
            sbufSpliceSetMetadata(source, metadata);
        }
        const size_t charge = sbufGetQueueCharge(source);
        sbuf_t      *result = muxPrepareRetainedCandidate(pool, source, true);
        require(result == source && sbufGetQueueCharge(result) == charge,
                "preparation materialized a valid splice source");
        requireSpliceBody(pool, result, 32, "retained candidate changed bytes");
    }
    sbuf_t *empty = makeSplicePattern(pool, 0);
    require(muxPrepareRetainedCandidate(pool, empty, true) == empty, "empty splice geometry forced conversion");
    bufferpoolReuseBuffer(pool, empty);
#endif
}
