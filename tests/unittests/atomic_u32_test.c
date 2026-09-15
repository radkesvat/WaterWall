#include "wlibc.h"
#include "wthread.h"

typedef struct guarded_counter_s
{
    uint32_t     before;
    atomic_u32_t count;
    uint32_t     after;
} guarded_counter_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void testUnsignedBoundaries(void)
{
    guarded_counter_t counter = {.before = UINT32_C(0x12345678), .count = 0, .after = UINT32_C(0xABCDEF01)};
    require(sizeof(counter.count) == 4 && offsetof(guarded_counter_t, after) == 8,
            "counter does not occupy exactly four bytes");
    atomicStoreU32(&counter.count, UINT32_MAX);
    require(atomicLoadU32(&counter.count) == UINT32_MAX, "maximum value was truncated or sign-extended");
    require(atomicIncU32Relaxed(&counter.count) == UINT32_MAX && atomicLoadU32Relaxed(&counter.count) == 0,
            "increment did not return the previous unsigned value and wrap");
    require(atomicDecU32Explicit(&counter.count, memory_order_acq_rel) == 0 &&
                atomicLoadU32Relaxed(&counter.count) == UINT32_MAX,
            "decrement did not wrap from zero");
    atomicStoreU32Relaxed(&counter.count, UINT32_C(0x80000000));
    require(atomicSubU32(&counter.count, UINT32_C(0x80000000)) == UINT32_C(0x80000000) &&
                atomicLoadU32Relaxed(&counter.count) == 0,
            "subtraction of the high bit overflowed signed arithmetic");
    require(atomicAddU32(&counter.count, UINT32_C(0x80000000)) == 0 &&
                atomicLoadU32Relaxed(&counter.count) == UINT32_C(0x80000000),
            "addition did not preserve the high bit");
    require(counter.before == UINT32_C(0x12345678) && counter.after == UINT32_C(0xABCDEF01),
            "32-bit operations changed adjacent fields");
}

enum
{
    kThreadCount = 4,
    kIncrements  = 10000
};

static WTHREAD_ROUTINE(incrementCounter)
{
    guarded_counter_t *counter = userdata;
    for (unsigned int i = 0; i < kIncrements; ++i)
    {
        atomicIncU32Relaxed(&counter->count);
    }
    return 0;
}

static void testConcurrentIncrements(void)
{
    guarded_counter_t counter = {.count = 0};
    wthread_t         threads[kThreadCount];
    for (size_t i = 0; i < ARRAY_SIZE(threads); ++i)
    {
        require(threadCreate(&threads[i], incrementCounter, &counter) == kWThreadErrorNone,
                "failed to create increment thread");
    }
    for (size_t i = 0; i < ARRAY_SIZE(threads); ++i)
    {
        require(threadJoin(threads[i]) == 0, "failed to join increment thread");
    }
    require(atomicLoadU32(&counter.count) == kThreadCount * kIncrements, "concurrent increments lost updates");
}

int main(void)
{
    testUnsignedBoundaries();
    testConcurrentIncrements();
    return 0;
}
