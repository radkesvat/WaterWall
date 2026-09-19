/* Included only by the two existing Mux frame fixtures. These wrappers observe
 * the real production representation helpers, not an alternative pipe reader. */
#pragma once

static uint64_t pqMaterializedBodyBytes;

sbuf_t *__real_sbufSpliceReadToBuffer(sbuf_t *buf, sbuf_t *dest, uint32_t bytes);
sbuf_t *__wrap_sbufSpliceReadToBuffer(sbuf_t *buf, sbuf_t *dest, uint32_t bytes);
sbuf_t *__real_sbufSpliceMaterializeToBuffer(sbuf_t *buf, sbuf_t *dest, buffer_pool_t *pool);
sbuf_t *__wrap_sbufSpliceMaterializeToBuffer(sbuf_t *buf, sbuf_t *dest, buffer_pool_t *pool);

sbuf_t *__wrap_sbufSpliceReadToBuffer(sbuf_t *buf, sbuf_t *dest, uint32_t bytes)
{
    const uint32_t prefix = sbufGetResidentPrefixLength(buf);
    pqMaterializedBodyBytes += bytes > prefix ? bytes - prefix : 0;
    return __real_sbufSpliceReadToBuffer(buf, dest, bytes);
}

sbuf_t *__wrap_sbufSpliceMaterializeToBuffer(sbuf_t *buf, sbuf_t *dest, buffer_pool_t *pool)
{
    pqMaterializedBodyBytes += sbufGetLength(buf) - sbufGetResidentPrefixLength(buf);
    return __real_sbufSpliceMaterializeToBuffer(buf, dest, pool);
}

void __real_sbufReadRangeToMemory(sbuf_t *buf, void *dest, uint32_t bytes);
void __wrap_sbufReadRangeToMemory(sbuf_t *buf, void *dest, uint32_t bytes);
void __wrap_sbufReadRangeToMemory(sbuf_t *buf, void *dest, uint32_t bytes)
{
    const uint32_t prefix = sbufGetResidentPrefixLength(buf);
    pqMaterializedBodyBytes += bytes > prefix ? bytes - prefix : 0;
    __real_sbufReadRangeToMemory(buf, dest, bytes);
}
