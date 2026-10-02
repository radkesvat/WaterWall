#pragma once

/* Opt-in GNU buffer wrappers and the existing per-translation-unit ledger. Link every __wrap symbol listed here. */
#include "fixtures/assertions.h"
#include "wevent.h"
#include "wwapi.h"

// ---------------------------------------------------------------------------
// buffer accounting
// ---------------------------------------------------------------------------

enum
{
    kTwfMaxTrackedBuffers = 8192
};

typedef struct twf_buffer_ledger_s
{
    sbuf_t        *live[kTwfMaxTrackedBuffers];
    uint32_t       live_count;
    sbuf_t        *recycled[kTwfMaxTrackedBuffers];
    uint32_t       recycled_count;
    uint32_t       total_acquired;
    uint32_t       total_recycled;
    sbuf_t        *last_recycled_buffer;
    buffer_pool_t *last_recycle_pool;
} twf_buffer_ledger_t;

static twf_buffer_ledger_t g_twf_buffers;

void __real_sbufDestroy(sbuf_t *b);
void __wrap_sbufDestroy(sbuf_t *b);

sbuf_t *__real_bufferpoolGetLargeBuffer(buffer_pool_t *pool);
sbuf_t *__real_bufferpoolGetSmallBuffer(buffer_pool_t *pool);
sbuf_t *__real_bufferpoolGetMediumBuffer(buffer_pool_t *pool);
sbuf_t *__real_bufferpoolGetBestFit(buffer_pool_t *pool, uint32_t size, uint16_t padding);
sbuf_t *__wrap_bufferpoolGetBestFit(buffer_pool_t *pool, uint32_t size, uint16_t padding);
sbuf_t *__real_bufferpoolGetSpliceBuffer(buffer_pool_t *pool);
sbuf_t *__wrap_bufferpoolGetSpliceBuffer(buffer_pool_t *pool);
sbuf_t *__real_bufferpoolTryGetBestFit(buffer_pool_t *pool, uint64_t size, uint16_t padding);
void    __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *b);

sbuf_t *__wrap_bufferpoolGetLargeBuffer(buffer_pool_t *pool);
sbuf_t *__wrap_bufferpoolGetSmallBuffer(buffer_pool_t *pool);
sbuf_t *__wrap_bufferpoolGetMediumBuffer(buffer_pool_t *pool);
sbuf_t *__wrap_bufferpoolTryGetBestFit(buffer_pool_t *pool, uint64_t size, uint16_t padding);
void    __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *b);

static void twfLedgerForget(sbuf_t **table, uint32_t *count, sbuf_t *b)
{
    for (uint32_t i = 0; i < *count; ++i)
    {
        if (table[i] == b)
        {
            table[i] = table[*count - 1U];
            --(*count);
            return;
        }
    }
}

static bool twfLedgerContains(sbuf_t *const *table, uint32_t count, const sbuf_t *b)
{
    for (uint32_t i = 0; i < count; ++i)
    {
        if (table[i] == b)
        {
            return true;
        }
    }
    return false;
}

static void twfLedgerRemember(sbuf_t **table, uint32_t *count, sbuf_t *b, const char *overflow_message)
{
    twfRequire(*count < kTwfMaxTrackedBuffers, overflow_message);
    table[(*count)++] = b;
}

static sbuf_t *twfTrackAcquired(sbuf_t *b)
{
    if (b == NULL)
    {
        return NULL;
    }

    // The pool may legitimately hand back a buffer that was recycled earlier, so it stops being a double-recycle
    // candidate the moment it is owned again.
    twfLedgerForget(g_twf_buffers.recycled, &g_twf_buffers.recycled_count, b);
    twfLedgerRemember(g_twf_buffers.live, &g_twf_buffers.live_count, b, "too many live buffers to track");
    ++g_twf_buffers.total_acquired;
    return b;
}

sbuf_t *__wrap_bufferpoolGetLargeBuffer(buffer_pool_t *pool)
{
    return twfTrackAcquired(__real_bufferpoolGetLargeBuffer(pool));
}

sbuf_t *__wrap_bufferpoolGetSmallBuffer(buffer_pool_t *pool)
{
    return twfTrackAcquired(__real_bufferpoolGetSmallBuffer(pool));
}

sbuf_t *__wrap_bufferpoolGetMediumBuffer(buffer_pool_t *pool)
{
    return twfTrackAcquired(__real_bufferpoolGetMediumBuffer(pool));
}

sbuf_t *__wrap_bufferpoolTryGetBestFit(buffer_pool_t *pool, uint64_t size, uint16_t padding)
{
    return twfTrackAcquired(__real_bufferpoolTryGetBestFit(pool, size, padding));
}

sbuf_t *__wrap_bufferpoolGetBestFit(buffer_pool_t *pool, uint32_t size, uint16_t padding)
{
    return twfTrackAcquired(__real_bufferpoolGetBestFit(pool, size, padding));
}

sbuf_t *__wrap_bufferpoolGetSpliceBuffer(buffer_pool_t *pool)
{
    return twfTrackAcquired(__real_bufferpoolGetSpliceBuffer(pool));
}

void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *b)
{
    twfRequire(b != NULL, "a NULL buffer was recycled");

    if (twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, b))
    {
        twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, b);
        twfLedgerRemember(
            g_twf_buffers.recycled, &g_twf_buffers.recycled_count, b, "too many recycled buffers to track");
    }
    else
    {
        // Buffers produced by sbufSlice()/sbufReserveSpace() never came from the pool, so they are only checked
        // for a second recycle of the same pointer.
        twfRequire(! twfLedgerContains(g_twf_buffers.recycled, g_twf_buffers.recycled_count, b),
                   "a buffer was recycled twice");
        twfLedgerRemember(
            g_twf_buffers.recycled, &g_twf_buffers.recycled_count, b, "too many recycled buffers to track");
    }

    ++g_twf_buffers.total_recycled;
    g_twf_buffers.last_recycled_buffer = b;
    g_twf_buffers.last_recycle_pool    = pool;
    __real_bufferpoolReuseBuffer(pool, b);
}

/*
 * Debug builds replace a buffer whenever ownership moves into a queue (BUFFER_WONT_BE_REUSED) and whenever
 * sbufReserveSpace() has to grow one. Both dispose of the previous allocation through sbufDestroy() rather than
 * the pool, so that is a legitimate end of life and not a leak.
 */
void __wrap_sbufDestroy(sbuf_t *b)
{
    if (b != NULL)
    {
        twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, b);
        twfLedgerForget(g_twf_buffers.recycled, &g_twf_buffers.recycled_count, b);
    }
    __real_sbufDestroy(b);
}

static void twfBufferLedgerReset(void)
{
    memoryZero(&g_twf_buffers, sizeof(g_twf_buffers));
}

static void twfRequireNoLeakedBuffers(void)
{
    twfRequireEqualU32(g_twf_buffers.live_count, 0, "pooled buffers were leaked by the failure path");
}

static uint32_t twfRecycleCount(void)
{
    return g_twf_buffers.total_recycled;
}

static void twfRequireLastRecycle(const sbuf_t *buffer, const buffer_pool_t *pool, const char *message)
{
    twfRequire(g_twf_buffers.last_recycled_buffer == buffer && g_twf_buffers.last_recycle_pool == pool, message);
}
