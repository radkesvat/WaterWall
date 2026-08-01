#include "wwapi.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static bool secondsAreClose(unsigned long long actual, time_t expected)
{
    if (expected < 0)
    {
        return false;
    }

    const unsigned long long expected_seconds = (unsigned long long) expected;
    const unsigned long long difference =
        actual >= expected_seconds ? actual - expected_seconds : expected_seconds - actual;
    return difference <= 5ULL;
}

static void testCurrentEpochTime(void)
{
    const unsigned long long now_ms  = getTimeOfDayMS();
    const unsigned long long now_us  = getTimeOfDayUS();
    const time_t             now_sec = time(NULL);

    require(secondsAreClose(now_ms / 1000ULL, now_sec), "millisecond wall clock is not the current Unix epoch");
    require(secondsAreClose(now_us / 1000000ULL, now_sec), "microsecond wall clock is not the current Unix epoch");
}

#if defined(OS_WIN)
static void testWindowsFileTimeConversionBeyond2038(void)
{
    const unsigned long long windows_to_unix_epoch_100ns = 116444736000000000ULL;
    const unsigned long long unix_seconds                = 2208988800ULL; // 2040-01-01 00:00:00 UTC
    const unsigned long long fractional_100ns            = 1234567ULL;
    ULARGE_INTEGER           raw;
    FILETIME                 ft;

    raw.QuadPart      = windows_to_unix_epoch_100ns + (unix_seconds * 10000000ULL) + fractional_100ns;
    ft.dwLowDateTime  = raw.LowPart;
    ft.dwHighDateTime = raw.HighPart;

    require(wwWindowsFileTimeToUnix100ns(&ft) == (unix_seconds * 10000000ULL) + fractional_100ns,
            "Windows FILETIME conversion narrowed or corrupted a post-2038 epoch");
}
#endif

int main(void)
{
    testCurrentEpochTime();
#if defined(OS_WIN)
    testWindowsFileTimeConversionBeyond2038();
#endif
    return 0;
}
