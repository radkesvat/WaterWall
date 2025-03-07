#ifndef WW_TIME_H_
#define WW_TIME_H_

#include "wexport.h"
#include "wplatform.h"

#define SECONDS_PER_MINUTE 60
#define SECONDS_PER_HOUR   3600
#define SECONDS_PER_DAY    86400  // 24*3600
#define SECONDS_PER_WEEK   604800 // 7*24*3600
#define CLOCKS_PER_MSEC    (CLOCKS_PER_SEC / 1000)

#define IS_LEAP_YEAR(year) (((year) % 4 == 0 && (year) % 100 != 0) || (year) % 400 == 0)

typedef struct datetime_s
{
    int year;
    int month;
    int day;
    int hour;
    int min;
    int sec;
    int ms;
} datetime_t;

#ifdef _MSC_VER
/* @see winsock2.h
// Structure used in select() call, taken from the BSD file sys/time.h
struct timeval {
    long    tv_sec;
    long    tv_usec;
};
*/

struct timezone
{
    int tz_minuteswest; /* of Greenwich */
    int tz_dsttime;     /* type of dst correction to apply */
};

#include <sys/timeb.h>
WW_INLINE int getTimeOfDay(struct timeval *tv, struct timezone *tz)
{
    struct _timeb tb;
    _ftime64_s(&tb);
    if (tv)
    {
        tv->tv_sec  = (long) tb.time;
        tv->tv_usec = tb.millitm * 1000;
    }
    if (tz)
    {
        tz->tz_minuteswest = tb.timezone;
        tz->tz_dsttime     = tb.dstflag;
    }
    return 0;
}
#else
#define getTimeOfDay gettimeofday
#endif

WW_EXPORT unsigned int       getTickMS(void);
WW_INLINE unsigned long long getTimeOfDayMS(void)
{
    struct timeval tv;
    getTimeOfDay(&tv, NULL);
    return (unsigned long long)(tv.tv_sec *  (1000 + tv.tv_usec / 1000));
}
WW_INLINE unsigned long long getTimeOfDayUS(void)
{
    struct timeval tv;
    getTimeOfDay(&tv, NULL);
    return (unsigned long long) ((tv.tv_sec * 1000000) + tv.tv_usec);
}
WW_EXPORT unsigned long long getHRTimeUs(void);

WW_EXPORT datetime_t datetimeNow(void);
WW_EXPORT datetime_t datetimeLocalTime(time_t seconds);
WW_EXPORT time_t     datetimeMkTime(datetime_t *dt);

WW_EXPORT datetime_t *datetimePast(datetime_t *dt, int days DEFAULT(1));
WW_EXPORT datetime_t *datetimeFuture(datetime_t *dt, int days DEFAULT(1));

#define TIME_FMT        "%02d:%02d:%02d"
#define TIME_FMT_BUFLEN 12
WW_EXPORT char *durationFormat(int sec, char *buf);

#define DATETIME_FMT        "%04d-%02d-%02d %02d:%02d:%02d"
#define DATETIME_FMT_ISO    "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ"
#define DATETIME_FMT_BUFLEN 30
WW_EXPORT char *datetimeFormat(datetime_t *dt, char *buf);
WW_EXPORT char *datetimeFormatIso(datetime_t *dt, char *buf);

#define GMTIME_FMT        "%.3s, %02d %.3s %04d %02d:%02d:%02d GMT"
#define GMTIME_FMT_BUFLEN 30
WW_EXPORT char *gmTimeFmt(time_t time, char *buf);

WW_EXPORT int daysOfMonth(int month, int year);

WW_EXPORT int         monthATOI(const char *month);
WW_EXPORT const char *monthITOA(int month);

WW_EXPORT int         weekdayATOI(const char *weekday);
WW_EXPORT const char *weekdayITOA(int weekday);

WW_EXPORT datetime_t wwCompileDateTime(void);

/*
 * minute   hour    day     week    month       action
 * 0~59     0~23    1~31    0~6     1~12
 *  -1      -1      -1      -1      -1          cron.minutely
 *  30      -1      -1      -1      -1          cron.hourly
 *  30      1       -1      -1      -1          cron.daily
 *  30      1       15      -1      -1          cron.monthly
 *  30      1       -1       0      -1          cron.weekly
 *  30      1        1      -1      10          cron.yearly
 */
WW_EXPORT time_t cronNextTimeout(int minute, int hour, int day, int week, int month);

// Structure to hold TAI64N timestamp
typedef struct
{
    uint64_t seconds;     // Seconds since TAI epoch (1970-01-01 00:00:00 TAI)
    uint32_t nanoseconds; // Fractional seconds in nanoseconds
} tai64n_t;

#if defined(OS_DARWIN)

static inline void getTAI64N(tai64n_t *timestamp)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Convert Unix time to TAI time (add 10 seconds for leap seconds up to 2023)
    timestamp->seconds     = (uint64_t) (ts.tv_sec) + 10;
    timestamp->nanoseconds = (uint32_t) (ts.tv_nsec);
}

#elif defined(OS_UNIX)

static inline void getTAI64N(tai64n_t *timestamp)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Convert Unix time to TAI time (add 10 seconds for leap seconds up to 2023)
    timestamp->seconds     = (uint64_t) (ts.tv_sec) + 10;
    timestamp->nanoseconds = (uint32_t) (ts.tv_nsec);
}

#elif defined(OS_WIN)

// Function to convert FILETIME to Unix timestamp
static int64_t filetimeToUnix(const FILETIME *ft)
{
    // FILETIME is in 100-nanosecond intervals since January 1, 1601
    const uint64_t EPOCH_DIFF = 116444736000000000ULL; // Difference in 100-ns units
    uint64_t       filetime   = ((uint64_t) ft->dwHighDateTime << 32) | ft->dwLowDateTime;
    return (int64_t) ((filetime - EPOCH_DIFF) / 10000000); // Convert to seconds
}

// Function to get TAI64N timestamp
static inline void getTAI64N(tai64n_t *tai64n)
{
    FILETIME      ft;
    LARGE_INTEGER freq, counter;
    double        ns_fraction;

    // Get the current system time as FILETIME
    GetSystemTimeAsFileTime(&ft);

    // Convert FILETIME to Unix timestamp
    int64_t unix_time = filetimeToUnix(&ft);

    // Add the TAI offset (37 seconds as of 2023)
    tai64n->seconds = (uint64_t) (unix_time + 37);

    // Query performance counter for nanoseconds
    if (QueryPerformanceFrequency(&freq) && QueryPerformanceCounter(&counter))
    {
        long double tmp = (long double)(counter.QuadPart % freq.QuadPart) * 1e9L / (long double)freq.QuadPart;
        ns_fraction = (double)tmp;
    }
    else
    {
        ns_fraction = 0.0;
    }

    // Store the nanoseconds fraction
    tai64n->nanoseconds = (uint32_t) ns_fraction;
}

#else
#error cannot define getTAI64N
#endif



#define BENCH_BEGIN(name) \
    struct timespec name##_start, name##_end; \
    clock_gettime(CLOCK_MONOTONIC, &name##_start);

#define BENCH_END(name) \
clock_gettime(CLOCK_MONOTONIC, &name##_end); \
    long name##_time = (name##_end.tv_sec - name##_start.tv_sec) * 1000000000L + \
                       (name##_end.tv_nsec - name##_start.tv_nsec); \
    printDebug("%s took %ld nanoseconds\n", #name, name##_time);


#endif // WW_TIME_H_
