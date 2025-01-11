#ifndef WW_TIME_H_
#define WW_TIME_H_

#include "wexport.h"
#include "wplatform.h"



#define SECONDS_PER_MINUTE  60
#define SECONDS_PER_HOUR    3600
#define SECONDS_PER_DAY     86400   // 24*3600
#define SECONDS_PER_WEEK    604800  // 7*24*3600

#define IS_LEAP_YEAR(year) (((year)%4 == 0 && (year)%100 != 0) || (year)%400 == 0)

typedef struct datetime_s {
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

struct timezone {
    int tz_minuteswest; /* of Greenwich */
    int tz_dsttime;     /* type of dst correction to apply */
};

#include <sys/timeb.h>
WW_INLINE int getTimeOfDay(struct timeval *tv, struct timezone *tz) {
    struct _timeb tb;
    _ftime64_s(&tb);
    if (tv) {
        tv->tv_sec =  (long)tb.time;
        tv->tv_usec = tb.millitm * 1000;
    }
    if (tz) {
        tz->tz_minuteswest = tb.timezone;
        tz->tz_dsttime = tb.dstflag;
    }
    return 0;
}
#endif

WW_EXPORT unsigned int getTickMS(void);
WW_INLINE unsigned long long getTimeOfDayMS(void) {
    struct timeval tv;
    getTimeOfDay(&tv, NULL);
    return tv.tv_sec * (unsigned long long)1000 + tv.tv_usec/1000;
}
WW_INLINE unsigned long long getTimeOfDayUS(void) {
    struct timeval tv;
    getTimeOfDay(&tv, NULL);
    return tv.tv_sec * (unsigned long long)1000000 + tv.tv_usec;
}
WW_EXPORT unsigned long long getHRTimeUs(void);

WW_EXPORT datetime_t datetimeNow(void);
WW_EXPORT datetime_t datetimeLocalTime(time_t seconds);
WW_EXPORT time_t     datetimeMkTime(datetime_t* dt);

WW_EXPORT datetime_t* datetimePast(datetime_t* dt, int days DEFAULT(1));
WW_EXPORT datetime_t* datetimeFuture(datetime_t* dt, int days DEFAULT(1));

#define TIME_FMT            "%02d:%02d:%02d"
#define TIME_FMT_BUFLEN     12
WW_EXPORT char* durationFormat(int sec, char* buf);

#define DATETIME_FMT        "%04d-%02d-%02d %02d:%02d:%02d"
#define DATETIME_FMT_ISO    "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ"
#define DATETIME_FMT_BUFLEN 30
WW_EXPORT char* datetimeFormat(datetime_t* dt, char* buf);
WW_EXPORT char* datetimeFormatIso(datetime_t* dt, char* buf);

#define GMTIME_FMT          "%.3s, %02d %.3s %04d %02d:%02d:%02d GMT"
#define GMTIME_FMT_BUFLEN   30
WW_EXPORT char* gmTimeFmt(time_t time, char* buf);

WW_EXPORT int daysOfMonth(int month, int year);

WW_EXPORT int monthATOI(const char* month);
WW_EXPORT const char* monthITOA(int month);

WW_EXPORT int weekdayATOI(const char* weekday);
WW_EXPORT const char* weekdayITOA(int weekday);

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



#endif // WW_TIME_H_
