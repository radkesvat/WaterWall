/* Unsigned 32-bit atomic boundaries, strong compare-exchange and four threads performing 10000 increments each.
 * Joined threads precede the final count check; exit(1) failures.
 * CTest: waterwall.atomic_u32_unit and Windows waterwall.atomic_u32_fallback_unit. */

#include "wlibc.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "wthread.h"

typedef struct guarded_counter_s
{
    uint32_t     before;
    atomic_u32_t count;
    uint32_t     after;
} guarded_counter_t;


static void testUnsignedBoundaries(void)
{
    guarded_counter_t counter = {.before = UINT32_C(0x12345678), .count = 0, .after = UINT32_C(0xABCDEF01)};
    require(sizeof(counter.count) == 4 && offsetof(guarded_counter_t, after) == 8,
            "counter does not occupy exactly four bytes");
    atomicStoreU32(&counter.count, UINT32_MAX);
    TEST_EQUAL_UINT(
        TEST_FAILURE_EXIT, atomicLoadU32(&counter.count), UINT32_MAX, "maximum value was truncated or sign-extended");
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

static void testCompareExchangeBoundaries(void)
{
    guarded_counter_t counter = {
        .before = UINT32_C(0x12345678), .count = UINT32_C(0x80000000), .after = UINT32_C(0xABCDEF01)};
    uint32_t expected = UINT32_C(0x80000000);
    require(atomicCompareExchangeU32Explicit(
                &counter.count, &expected, UINT32_MAX, memory_order_acq_rel, memory_order_acquire),
            "matching compare-exchange spuriously failed or lost the high bit");
    require(expected == UINT32_C(0x80000000) && atomicLoadU32Relaxed(&counter.count) == UINT32_MAX,
            "successful compare-exchange changed expected or truncated the maximum value");

    expected = 0;
    require(
        ! atomicCompareExchangeU32Explicit(&counter.count, &expected, 1U, memory_order_release, memory_order_relaxed),
        "mismatched compare-exchange succeeded");
    require(expected == UINT32_MAX && atomicLoadU32Relaxed(&counter.count) == UINT32_MAX,
            "failed compare-exchange did not publish the observed unsigned value");
    require(atomicCompareExchangeU32Explicit(&counter.count, &expected, 0U, memory_order_relaxed, memory_order_relaxed),
            "compare-exchange retry did not use the failure-updated expected value");
    require(expected == UINT32_MAX && atomicLoadU32Relaxed(&counter.count) == 0,
            "compare-exchange did not preserve expected while replacing the maximum value");
    require(! atomicCompareExchangeU32Explicit(
                &counter.count, &expected, UINT32_C(0x80000000), memory_order_seq_cst, memory_order_seq_cst),
            "mismatched maximum compare-exchange succeeded");
    require(expected == 0 && atomicLoadU32Relaxed(&counter.count) == 0,
            "failed compare-exchange changed the object or did not update expected to zero");
    require(counter.before == UINT32_C(0x12345678) && counter.after == UINT32_C(0xABCDEF01),
            "32-bit compare-exchange changed adjacent fields");
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
        TEST_EQUAL_INT(TEST_FAILURE_EXIT,
                       threadCreate(&threads[i], incrementCounter, &counter),
                       kWThreadErrorNone,
                       "failed to create increment thread");
    }
    for (size_t i = 0; i < ARRAY_SIZE(threads); ++i)
    {
        TEST_EQUAL_INT(TEST_FAILURE_EXIT, threadJoin(threads[i]), 0, "failed to join increment thread");
    }
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT,
                    atomicLoadU32(&counter.count),
                    kThreadCount * kIncrements,
                    "concurrent increments lost updates");
}

static WTHREAD_ROUTINE(compareExchangeCounter)
{
    guarded_counter_t *counter = userdata;
    for (unsigned int i = 0; i < kIncrements; ++i)
    {
        uint32_t expected = atomicLoadU32Relaxed(&counter->count);
        while (! atomicCompareExchangeU32Explicit(
            &counter->count, &expected, expected + UINT32_C(1), memory_order_relaxed, memory_order_relaxed))
        {
            /* Failure updates expected for the next attempt. */
        }
    }
    return 0;
}

static void testConcurrentCompareExchange(void)
{
    const uint32_t    initial = UINT32_MAX - (kThreadCount * kIncrements / 2U);
    guarded_counter_t counter = {.before = UINT32_C(0x12345678), .count = initial, .after = UINT32_C(0xABCDEF01)};
    wthread_t         threads[kThreadCount];
    for (size_t i = 0; i < ARRAY_SIZE(threads); ++i)
    {
        TEST_EQUAL_INT(TEST_FAILURE_EXIT,
                       threadCreate(&threads[i], compareExchangeCounter, &counter),
                       kWThreadErrorNone,
                       "failed to create compare-exchange thread");
    }
    for (size_t i = 0; i < ARRAY_SIZE(threads); ++i)
    {
        TEST_EQUAL_INT(TEST_FAILURE_EXIT, threadJoin(threads[i]), 0, "failed to join compare-exchange thread");
    }
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT,
                    atomicLoadU32Relaxed(&counter.count),
                    initial + (uint32_t) (kThreadCount * kIncrements),
                    "concurrent compare-exchange lost updates or failed unsigned wrap");
    require(counter.before == UINT32_C(0x12345678) && counter.after == UINT32_C(0xABCDEF01),
            "concurrent 32-bit compare-exchange changed adjacent fields");
}

int main(void)
{
    TEST_RUN_CASE(testUnsignedBoundaries);
    TEST_RUN_CASE(testCompareExchangeBoundaries);
    TEST_RUN_CASE(testConcurrentIncrements);
    TEST_RUN_CASE(testConcurrentCompareExchange);
    return 0;
}
