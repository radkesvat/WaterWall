#include "wtime.h"
#include "wdef.h"
#define __STDC_WANT_LIB_EXT1__ 1
#include <time.h>

static const char* s_weekdays[] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};

static const char* s_months[] = {"January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"};

static const uint8_t s_days[] = \
//   1       3       5       7   8       10      12
    {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

unsigned int getTickMS(void) {
#ifdef OS_WIN
    return GetTickCount();
#elif HAVE_CLOCK_GETTIME
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

unsigned long long getHRTimeUs(void) {
#ifdef OS_WIN
    static LONGLONG s_freq = 0;
    if (s_freq == 0) {
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        s_freq = freq.QuadPart;
    }
    if (s_freq != 0) {
        LARGE_INTEGER count;
        QueryPerformanceCounter(&count);
        return (unsigned long long)(count.QuadPart / (double)s_freq * 1000000);
    }
    return 0;
#elif defined(OS_SOLARIS)
    return gethrtime() / 1000;
#elif HAVE_CLOCK_GETTIME
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec*(unsigned long long)1000000 + ts.tv_nsec / 1000;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec*(unsigned long long)1000000 + tv.tv_usec;
#endif
}

datetime_t datetimeNow(void) {
#ifdef OS_WIN
    SYSTEMTIME tm;
    GetLocalTime(&tm);
    datetime_t dt;
    dt.year  = tm.wYear;
    dt.month = tm.wMonth;
    dt.day   = tm.wDay;
    dt.hour  = tm.wHour;
    dt.min   = tm.wMinute;
    dt.sec   = tm.wSecond;
    dt.ms    = tm.wMilliseconds;
    return dt;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    datetime_t dt = datetime_localtime(tv.tv_sec);
    dt.ms = tv.tv_usec / 1000;
    return dt;
#endif
}

datetime_t datetimeLocalTime(time_t seconds) {
    static _Thread_local  struct tm tm;
#ifdef OS_UNIX
    localtime_r(&seconds,&tm);
#else
    localtime_s(&tm,&seconds);
#endif
    datetime_t dt;
    dt.year  = tm.tm_year + 1900;
    dt.month = tm.tm_mon  + 1;
    dt.day   = tm.tm_mday;
    dt.hour  = tm.tm_hour;
    dt.min   = tm.tm_min;
    dt.sec   = tm.tm_sec;
    return dt;
}

time_t datetimeMkTime(datetime_t* dt) {
    struct tm tm;
    time_t ts;
    time(&ts);
    static _Thread_local  struct tm ptm;
#ifdef OS_UNIX
    localtime_r(&ts,&ptm);
#else
    localtime_s(&ptm,&ts);
#endif
    memoryCopy(&tm, &ptm, sizeof(struct tm));
    tm.tm_year = dt->year  - 1900;
    tm.tm_mon  = dt->month - 1;
    tm.tm_mday = dt->day;
    tm.tm_hour = dt->hour;
    tm.tm_min  = dt->min;
    tm.tm_sec  = dt->sec;
    return mktime(&tm);
}

int daysOfMonth(int month, int year) {
    if (month < 1 || month > 12) {
        return 0;
    }
    int days = s_days[month-1];
    return (month == 2 && IS_LEAP_YEAR(year)) ? ++days : days;
}

datetime_t* datetimePast(datetime_t* dt, int days) {
    assert(days >= 0);
    int sub = days;
    while (sub) {
        if (dt->day > sub) {
            dt->day -= sub;
            break;
        }
        sub -= dt->day;
        if (--dt->month == 0) {
            dt->month = 12;
            --dt->year;
        }
        dt->day = daysOfMonth(dt->month, dt->year);
    }
    return dt;
}

datetime_t* datetimeFuture(datetime_t* dt, int days) {
    assert(days >= 0);
    int sub = days;
    int mdays;
    while (sub) {
        mdays = daysOfMonth(dt->month, dt->year);
        if (dt->day + sub <= mdays) {
            dt->day += sub;
            break;
        }
        sub -= (mdays - dt->day + 1);
        if (++dt->month > 12) {
            dt->month = 1;
            ++dt->year;
        }
        dt->day = 1;
    }
    return dt;
}

char* durationFormat(int sec, char* buf) {
    int h, m, s;
    m = sec / 60;
    s = sec % 60;
    h = m / 60;
    m = m % 60;
    sprintf(buf, TIME_FMT, h, m, s);
    return buf;
}

char* datetimeFormat(datetime_t* dt, char* buf) {
    sprintf(buf, DATETIME_FMT,
        dt->year, dt->month, dt->day,
        dt->hour, dt->min, dt->sec);
    return buf;
}

char* datetimeFormatIso(datetime_t* dt, char* buf) {
    sprintf(buf, DATETIME_FMT_ISO,
        dt->year, dt->month, dt->day,
        dt->hour, dt->min, dt->sec,
        dt->ms);
    return buf;
}

char* gmTimeFmt(time_t time, char* buf) {

#ifdef OS_UNIX
    struct tm* tm = gmtime(&time);
#else
    struct tm gmt_tm_buf;
    struct tm* tm = &gmt_tm_buf;
    gmtime_s(tm, &time);
#endif

    //strftime(buf, GMTIME_FMT_BUFLEN, "%a, %d %b %Y %H:%M:%S GMT", tm);
    sprintf(buf, GMTIME_FMT,
        s_weekdays[tm->tm_wday],
        tm->tm_mday, s_months[tm->tm_mon], tm->tm_year + 1900,
        tm->tm_hour, tm->tm_min, tm->tm_sec);
    return buf;
}

int monthATOI(const char* month) {
    for (size_t i = 0; i < 12; ++i) {
        if (strnicmp(month, s_months[i], strlen(month)) == 0)
            return i+1;
    }
    return 0;
}

const char* monthITOA(int month) {
    assert(month >= 1 && month <= 12);
    return s_months[month-1];
}

int weekdayATOI(const char* weekday) {
    for (size_t i = 0; i < 7; ++i) {
        if (strnicmp(weekday, s_weekdays[i], strlen(weekday)) == 0)
            return i;
    }
    return 0;
}

const char* weekdayITOA(int weekday) {
    assert(weekday >= 0 && weekday <= 7);
    if (weekday == 7) weekday = 0;
    return s_weekdays[weekday];
}

datetime_t wwCompileDateTime(void) {
    datetime_t dt;
    char month[32];
    sscanf(__DATE__, "%s %d %d", month, &dt.day, &dt.year);
    sscanf(__TIME__, "%d:%d:%d", &dt.hour, &dt.min, &dt.sec);
    dt.month = monthATOI(month);
    return dt;
}

time_t cronNextTimeout(int minute, int hour, int day, int week, int month) {
    enum {
        MINUTELY,
        HOURLY,
        DAILY,
        WEEKLY,
        MONTHLY,
        YEARLY,
    } period_type = MINUTELY;
    time_t tt;
    time(&tt);
    static _Thread_local  struct tm tm;
#ifdef OS_UNIX
    localtime_r(&tt,&tm);
#else
    localtime_s(&tm,&tt);
#endif
    time_t tt_round = 0;

    tm.tm_sec = 0;
    if (minute >= 0) {
        period_type = HOURLY;
        tm.tm_min = minute;
    }
    if (hour >= 0) {
        period_type = DAILY;
        tm.tm_hour = hour;
    }
    if (week >= 0) {
        period_type = WEEKLY;
    }
    else if (day > 0) {
        period_type = MONTHLY;
        tm.tm_mday = day;
        if (month > 0) {
            period_type = YEARLY;
            tm.tm_mon = month - 1;
        }
    }

    tt_round = mktime(&tm);
    if (week >= 0) {
        tt_round += (week-tm.tm_wday)*SECONDS_PER_DAY;
    }
    if (tt_round > tt) {
        return tt_round;
    }

    switch(period_type) {
    case MINUTELY:
        tt_round += SECONDS_PER_MINUTE;
        return tt_round;
    case HOURLY:
        tt_round += SECONDS_PER_HOUR;
        return tt_round;
    case DAILY:
        tt_round += SECONDS_PER_DAY;
        return tt_round;
    case WEEKLY:
        tt_round += SECONDS_PER_WEEK;
        return tt_round;
    case MONTHLY:
        if (++tm.tm_mon == 12) {
            tm.tm_mon = 0;
            ++tm.tm_year;
        }
        break;
    case YEARLY:
        ++tm.tm_year;
        break;
    default:
        return -1;
    }

    return mktime(&tm);
}
