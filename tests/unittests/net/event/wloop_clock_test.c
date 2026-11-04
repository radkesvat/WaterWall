/*
 * Covers: wloopUpdateTime and cached wall-clock/monotonic values.
 * Setup: Isolated wloop with linker-wrapped clocks on Linux; real-clock smoke elsewhere.
 * Cases: Ordinary second crossing, positive/negative drift thresholds, genuine clock jumps,
 * seconds/milliseconds/microseconds consistency and independent monotonic progress.
 * Limits: Exact boundary coverage requires linker wrapping. No system clock is changed.
 * CTest: waterwall.wloop_clock_unit
 */
#include "ev_memory.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include "fixtures/worker_registry_fixture.h"
#include "wevent.h"
#include "wloop_internal.h"

#include <stdint.h>
#include <stdio.h>

#ifdef WATERWALL_CLOCK_TEST_WRAPPERS
#include <sys/time.h>
#include <time.h>

static uint64_t clock_monotonic_us;
static uint64_t clock_wall_ms;

unsigned long long __wrap_getHRTimeUs(void);
int                __wrap_gettimeofday(struct timeval *value, void *zone);
time_t             __wrap_time(time_t *value);

unsigned long long __wrap_getHRTimeUs(void)
{
    return clock_monotonic_us;
}

int __wrap_gettimeofday(struct timeval *value, void *zone)
{
    discard zone;
    value->tv_sec  = (time_t) (clock_wall_ms / 1000U);
    value->tv_usec = (suseconds_t) ((clock_wall_ms % 1000U) * 1000U);
    return 0;
}

time_t __wrap_time(time_t *value)
{
    time_t seconds = (time_t) (clock_wall_ms / 1000U);
    if (value != NULL)
    {
        *value = seconds;
    }
    return seconds;
}

static void requireCachedTime(wloop_t *loop, uint64_t expected_us)
{
    require(wloopNowUS(loop) == expected_us, "cached microseconds disagree with expected time");
    require(wloopNowMS(loop) == expected_us / 1000U, "cached milliseconds disagree with microseconds");
    require(wloopNow(loop) == expected_us / 1000000U, "cached seconds disagree with microseconds");
    require(wloopNowLoopRunTime(loop) == clock_monotonic_us, "wall-clock correction changed monotonic microseconds");
    require(wloopNowMonotonicMS(loop) == clock_monotonic_us / 1000U,
            "wall-clock correction changed monotonic milliseconds");
}

static wloop_t *createClockLoop(void)
{
    clock_monotonic_us = UINT64_C(10000000);
    clock_wall_ms      = UINT64_C(1700000000900);
    wloop_t *loop      = wloopCreate(0, NULL, 0);
    require(loop != NULL, "loop creation failed");
    requireCachedTime(loop, clock_wall_ms * 1000U);
    return loop;
}

static void testOrdinarySecondBoundary(void)
{
    wloop_t       *loop     = createClockLoop();
    const uint64_t start_ms = loop->start_ms;

    /* 00.900 + 0.200123 seconds must become 01.100123, without changing the origin. */
    clock_monotonic_us += 200123;
    clock_wall_ms += 200;
    wloopUpdateTime(loop);
    require(loop->start_ms == start_ms, "ordinary second crossing changed the wall-clock origin");
    requireCachedTime(loop, start_ms * 1000U + 200123);

    clock_monotonic_us += 999999;
    clock_wall_ms += 1000;
    wloopUpdateTime(loop);
    require(loop->start_ms == start_ms, "ordinary elapsed time changed the wall-clock origin");
    requireCachedTime(loop, start_ms * 1000U + 1200122);
    wloopDestroy(&loop);
}

static void testDriftThresholds(void)
{
    static const struct
    {
        const char *name;
        int64_t     drift_ms;
        bool        adjusts;
    } cases[] = {
        {"positive subthreshold drift", 999, false},
        {"negative subthreshold drift", -999, false},
        {"positive threshold drift", 1000, true},
        {"negative threshold drift", -1000, true},
    };

    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        testCaseSet(cases[i].name);
        wloop_t       *loop         = createClockLoop();
        const uint64_t start_ms     = loop->start_ms;
        const uint64_t start_hrtime = loop->start_hrtime;
        clock_monotonic_us += 1234567;
        clock_wall_ms = (uint64_t) ((int64_t) start_ms + 1234 + cases[i].drift_ms);

        wloopUpdateTime(loop);
        uint64_t expected_start_ms = cases[i].adjusts ? (uint64_t) ((int64_t) start_ms + cases[i].drift_ms) : start_ms;
        require(loop->start_ms == expected_start_ms, "wall-clock adjustment did not respect the one-second threshold");
        require(loop->start_hrtime == start_hrtime, "wall-clock adjustment changed the monotonic origin");
        requireCachedTime(loop, expected_start_ms * 1000U + 1234567);
        wloopDestroy(&loop);
    }
}

static void testWallClockJumps(void)
{
    wloop_t       *loop         = createClockLoop();
    const uint64_t start_hrtime = loop->start_hrtime;
    const uint64_t start_ms     = loop->start_ms;

    clock_monotonic_us += 250125;
    clock_wall_ms += 250;
    wloopUpdateTime(loop);
    uint64_t previous_wall_ms = wloopNowMS(loop);

    clock_monotonic_us += 100000;
    clock_wall_ms += 5100;
    wloopUpdateTime(loop);
    require(wloopNowMS(loop) == previous_wall_ms + 5100,
            "cached wall clock did not follow a forward system-clock jump");
    require(loop->start_ms == start_ms + 5000, "forward system-clock jump changed the wrong origin");
    requireCachedTime(loop, (start_ms + 5000) * 1000U + 350125);
    previous_wall_ms = wloopNowMS(loop);

    clock_monotonic_us += 100000;
    clock_wall_ms -= 9900;
    wloopUpdateTime(loop);
    require(wloopNowMS(loop) == previous_wall_ms - 9900,
            "cached wall clock did not follow a backward system-clock jump");
    require(loop->start_ms == start_ms - 5000, "backward system-clock jump changed the wrong origin");
    require(loop->start_hrtime == start_hrtime, "system-clock jumps changed the monotonic origin");
    requireCachedTime(loop, (start_ms - 5000) * 1000U + 450125);
    wloopDestroy(&loop);
}
#else
enum
{
    kRunMs = 1200
};

/* Whole seconds of the system clock and of start + elapsed differ for most of a second when the start time sits near
 * the end of its own second, and that is no reason to read the clocks again: each new reading can move the loop's clock
 * back by a millisecond, and elapsed-time checks then underflow. */
static void testNoSpuriousSystemTimeChange(void)
{
    wloop_t *loop = wloopCreate(0, NULL, 0);
    require(loop != NULL, "loop creation failed");
    wloopUpdateTime(loop);
    loop->start_ms          = loop->start_ms - (loop->start_ms % 1000) + 999;
    const uint64_t start_ms = loop->start_ms;
    uint64_t       previous = 0;
    const uint64_t end      = getHRTimeUs() + (uint64_t) kRunMs * 1000U;
    while (getHRTimeUs() < end)
    {
        wloopUpdateTime(loop);
        require(loop->start_ms == start_ms, "start time changed without a system time change");
        require(wloopNowMS(loop) >= previous, "clock moved back");
        previous = wloopNowMS(loop);
    }
    wloopDestroy(&loop);
}

static void testSystemTimeChange(void)
{
    wloop_t *loop = wloopCreate(0, NULL, 0);
    require(loop != NULL, "loop creation failed");
    wloopUpdateTime(loop);
    loop->start_ms -= 5000;
    wloopUpdateTime(loop);
    const uint64_t system_ms = getTimeOfDayMS();
    const uint64_t clock_ms  = wloopNowMS(loop);
    require(clock_ms + 100 >= system_ms && system_ms + 100 >= clock_ms, "clock did not follow a system time change");
    wloopDestroy(&loop);
}
#endif

int main(void)
{
    testCaseSet("wloop_clock_test");
    test_worker_registry_t registry = {0};
    GSTATE.workers_count            = 1;
    testWorkerRegistryInstall(&registry);
    testWorkerBindWID(0);
#ifdef WATERWALL_CLOCK_TEST_WRAPPERS
    TEST_RUN_CASE(testOrdinarySecondBoundary);
    TEST_RUN_CASE(testDriftThresholds);
    TEST_RUN_CASE(testWallClockJumps);
#else
    TEST_RUN_CASE(testNoSpuriousSystemTimeChange);
    TEST_RUN_CASE(testSystemTimeChange);
#endif
    testWorkerUnbindWID();
    testWorkerRegistryRestore(&registry);
    puts("wloop_clock_test: all cases passed");
    return 0;
}
