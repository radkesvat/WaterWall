#pragma once

#include "global_state.h"
#include "shiftbuffer.h"
#include "splice_buffer.h"
#include "test_assert.h"

/* The fixture inventory is shared by every worker/pool in this process. Large
 * pipes preserve framing cases that populate a complete body before consuming
 * it; its lifetime also permits overlapping worker environments. */
static inline void testSpliceInventoryInitialize(uint16_t padding)
{
#if WW_HAVE_SPLICE
    static bool cleanup_registered;
    padding = sbufAlignLeftPadding(padding);
    if (GSTATE.splice_inventory != NULL && sbufSplicePoolPadding() != padding)
        sbufSplicePoolDestroy();
    if (GSTATE.splice_inventory == NULL)
    {
        TEST_REQUIRE(TEST_FAILURE_EXIT,
                     sbufSplicePoolInitialize(UINT64_C(32) * SPLICE_PAYLOAD_LIMIT, SPLICE_PAYLOAD_LIMIT, 32, padding) >
                         0,
                     "could not initialize test splice inventory");
    }
    if (! cleanup_registered)
    {
        TEST_REQUIRE(
            TEST_FAILURE_EXIT, atexit(sbufSplicePoolDestroy) == 0, "could not register test splice inventory cleanup");
        cleanup_registered = true;
    }
#else
    discard padding;
#endif
}

/* Retain the requesting worker cache and all reachable master entries to force fallback. */
typedef struct test_splice_inventory_hold_s
{
    sbuf_t **buffers;
    uint32_t count;
} test_splice_inventory_hold_t;

static inline test_splice_inventory_hold_t testSpliceInventoryHoldAvailable(buffer_pool_t *pool)
{
    test_splice_inventory_hold_t held = {0};
#if WW_HAVE_SPLICE
    const uint32_t capacity = sbufSplicePoolCount();
    held.buffers            = memoryAllocate((size_t) capacity * sizeof(*held.buffers));
    TEST_REQUIRE(TEST_FAILURE_EXIT, capacity == 0 || held.buffers != NULL, "inventory hold allocation failed");
    while (held.count < capacity)
    {
        sbuf_t *buffer = bufferpoolGetSpliceBuffer(pool);
        if (buffer == NULL)
            break;
        held.buffers[held.count++] = buffer;
    }
#endif
    discard pool;
    return held;
}

static inline void testSpliceInventoryReleaseHeld(test_splice_inventory_hold_t *held)
{
    for (uint32_t i = 0; i < held->count; ++i)
        sbufDestroy(held->buffers[i]);
    memoryFree(held->buffers);
    *held = (test_splice_inventory_hold_t) {0};
}
