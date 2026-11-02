/*
 * Covers: wloopUpdateTime and the loop's cached wall-clock milliseconds.
 * Setup: Isolated wloop whose start time is moved within the current second.
 * Cases: testNoSpuriousSystemTimeChange, testSystemTimeChange.
 * Checks: Assertion labels include: clock moved back; start time changed without a system time change;
 * clock did not follow a system time change.
 * Limits: Component fixtures do not establish host-network or application-throughput behavior.
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

int main(void)
{
    testCaseSet("wloop_clock_test");
    test_worker_registry_t registry = {0};
    GSTATE.workers_count            = 1;
    testWorkerRegistryInstall(&registry);
    testWorkerBindWID(0);
    testNoSpuriousSystemTimeChange();
    testSystemTimeChange();
    testWorkerUnbindWID();
    testWorkerRegistryRestore(&registry);
    puts("wloop_clock_test: all cases passed");
    return 0;
}
