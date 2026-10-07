/*
 * Covers: getHRTimeUs arithmetic with signed 32-bit POSIX clock fields.
 * Setup: The actual wtime.c implementation, with deterministic clock calls and
 * int32_t timespec/timeval fields matching 32-bit Android's arithmetic widths.
 * Cases: Fractional seconds, the signed microsecond-overflow boundary, one-day
 * uptime and INT32_MAX seconds, under both clock_gettime and fallback builds.
 * Checks: Exact 64-bit microsecond results; CLOCK_MONOTONIC is requested.
 * Limits: This host fixture checks arithmetic, not Android ABI or OS execution.
 * CTest: waterwall.wtime_monotonic32_unit; waterwall.wtime_fallback32_unit
 */
#include "wdef.h"
#include "wtime.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

struct test_timespec32
{
    int32_t tv_sec;
    int32_t tv_nsec;
};

struct test_timeval32
{
    int32_t tv_sec;
    int32_t tv_usec;
};

static int32_t clock_seconds;
static int32_t clock_fraction_us;

#if WW_TEST_CLOCK_GETTIME
static int testClockGetTime(clockid_t clock_id, struct test_timespec32 *ts)
{
    require(clock_id == CLOCK_MONOTONIC, "high-resolution clock must request CLOCK_MONOTONIC");
    ts->tv_sec  = clock_seconds;
    ts->tv_nsec = clock_fraction_us * 1000 + 999;
    return 0;
}
#endif

static int testGetTimeOfDay(struct test_timeval32 *tv, void *timezone)
{
    require(timezone == NULL, "clock must not request a timezone");
    tv->tv_sec  = clock_seconds;
    tv->tv_usec = clock_fraction_us;
    return 0;
}

/* System headers have already been parsed. Only the production source's clock
 * boundary and field widths change; its conversion expressions stay intact. */
#undef HAVE_CLOCK_GETTIME
#define HAVE_CLOCK_GETTIME WW_TEST_CLOCK_GETTIME
#define timespec           test_timespec32
#define timeval            test_timeval32
#define clock_gettime      testClockGetTime
#define gettimeofday       testGetTimeOfDay
#include "../../../ww/libc/wtime.c"
#undef gettimeofday
#undef clock_gettime
#undef timeval
#undef timespec

int main(void)
{
    static const struct
    {
        int32_t            seconds;
        int32_t            fraction_us;
        unsigned long long expected_us;
    } cases[] = {
        {0, 0, 0ULL},
        {1, 123456, 1123456ULL},
        {2147, 483647, 2147483647ULL},
        {2147, 483648, 2147483648ULL},
        {2148, 123456, 2148123456ULL},
        {86400, 999999, 86400999999ULL},
        {INT32_MAX, 999999, 2147483647999999ULL},
    };

#if WW_TEST_CLOCK_GETTIME
    testCaseSet("wtime_monotonic32_test");
#else
    testCaseSet("wtime_fallback32_test");
#endif
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        clock_seconds     = cases[i].seconds;
        clock_fraction_us = cases[i].fraction_us;
        TEST_EQUAL_UINT(TEST_FAILURE_EXIT,
                        getHRTimeUs(),
                        cases[i].expected_us,
                        "clock conversion must widen before microsecond arithmetic");
    }
    return 0;
}
