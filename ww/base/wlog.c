#include "wlog.h"
#include "wmutex.h"

// #include "wtime.h"
#define SECONDS_PER_HOUR 3600
#define SECONDS_PER_DAY  86400  // 24*3600
#define SECONDS_PER_WEEK 604800 // 7*24*3600;

static int s_gmtoff = 28800; // 8*3600

struct logger_s
{
    logger_handler handler;
    unsigned int   bufsize;
    char          *buf;

    int  level;
    int  enable_color;
    char format[64];

    // for file logger
    char               filepath[256];
    unsigned long long max_filesize;
    int                remain_days;
    int                enable_fsync;
    FILE              *fp_;
    char               cur_logfile[256];
    time_t             last_logfile_ts;
    int                can_write_cnt;

    wmutex_t mutex_; // thread-safe
};

static void initLogger(logger_t *logger)
{
    logger->handler = NULL;
    logger->bufsize = DEFAULT_LOG_MAX_BUFSIZE;
    logger->buf     = (char *) memoryAllocate(logger->bufsize);

    logger->level        = DEFAULT_LOG_LEVEL;
    logger->enable_color = 0;
    // NOTE: format is faster 6% than snprintf
    // logger->format[0] = '\0';
#if defined(OS_UNIX)
    strncpy(logger->format, DEFAULT_LOG_FORMAT, sizeof(logger->format) - 1);
#else
    strncpy_s(logger->format, sizeof(logger->format), DEFAULT_LOG_FORMAT, sizeof(logger->format) - 1);
#endif

    logger->fp_          = NULL;
    logger->max_filesize = DEFAULT_LOG_MAX_FILESIZE;
    logger->remain_days  = DEFAULT_LOG_REMAIN_DAYS;
    logger->enable_fsync = 1;
    loggerSetFile(logger, DEFAULT_LOG_FILE);
    logger->last_logfile_ts = 0;
    logger->can_write_cnt   = -1;
    mutexInit(&logger->mutex_);
}

logger_t *loggerCreate(void)
{
    // init gmtoff here
    time_t                        ts = time(NULL);
    static thread_local struct tm local_tm;
#ifdef OS_UNIX
    localtime_r(&ts, &local_tm);
#else
    localtime_s(&local_tm, &ts);
#endif
    int local_hour = local_tm.tm_hour;

#ifdef OS_UNIX
    struct tm *gmt_tm = gmtime(&ts);
#else
    struct tm  gmt_tm_buf;
    struct tm *gmt_tm = &gmt_tm_buf;
    gmtime_s(gmt_tm, &ts);
#endif

    int gmt_hour = gmt_tm->tm_hour;
    s_gmtoff     = (local_hour - gmt_hour) * SECONDS_PER_HOUR;

    logger_t *logger = (logger_t *) memoryAllocate(sizeof(logger_t));
    initLogger(logger);
    return logger;
}

void loggerDestroy(logger_t *logger)
{
    if (logger)
    {
        if (logger->buf)
        {
            memoryFree(logger->buf);
            logger->buf = NULL;
        }
        if (logger->fp_)
        {
            fclose(logger->fp_);
            logger->fp_ = NULL;
        }
        mutexDestroy(&logger->mutex_);
        memoryFree(logger);
    }
}

void loggerSetHandler(logger_t *logger, logger_handler fn)
{
    logger->handler = fn;
}

void loggerSetLevel(logger_t *logger, int level)
{
    logger->level = level;
}

void loggerSetLevelByString(logger_t *logger, const char *szLoglevel)
{
    int loglevel = DEFAULT_LOG_LEVEL;
    if (strcmp(szLoglevel, "VERBOSE") == 0)
    {
        loglevel = LOG_LEVEL_VERBOSE;
    }
    else if (strcmp(szLoglevel, "DEBUG") == 0)
    {
        loglevel = LOG_LEVEL_DEBUG;
    }
    else if (strcmp(szLoglevel, "INFO") == 0)
    {
        loglevel = LOG_LEVEL_INFO;
    }
    else if (strcmp(szLoglevel, "WARN") == 0)
    {
        loglevel = LOG_LEVEL_WARN;
    }
    else if (strcmp(szLoglevel, "ERROR") == 0)
    {
        loglevel = LOG_LEVEL_ERROR;
    }
    else if (strcmp(szLoglevel, "FATAL") == 0)
    {
        loglevel = LOG_LEVEL_FATAL;
    }
    else if (strcmp(szLoglevel, "SILENT") == 0)
    {
        loglevel = LOG_LEVEL_SILENT;
    }
    else
    {
        loglevel = DEFAULT_LOG_LEVEL;
    }
    logger->level = loglevel;
}

int loggerCheckWriteLevel(logger_t *logger, log_level_e level)
{
    return (logger->level) <= (int) level;
}

logger_handler loggerGetHandle(logger_t *logger)
{
    return logger->handler;
}

void loggerSetFormat(logger_t *logger, const char *format)
{
    if (format)
    {
#if defined(OS_UNIX)
        strncpy(logger->format, format, sizeof(logger->format) - 1);
#else
        strncpy_s(logger->format, sizeof(logger->format), format, sizeof(logger->format) - 1);
#endif
    }
    else
    {
        logger->format[0] = '\0';
    }
}

void loggerSetRemainDays(logger_t *logger, int days)
{
    logger->remain_days = days;
}

void loggerSetMaxBufSIze(logger_t *logger, unsigned int bufsize)
{
    logger->bufsize = bufsize;
    logger->buf     = (char *) realloc(logger->buf, bufsize);
}

void loggerEnableColor(logger_t *logger, int on)
{
    logger->enable_color = on;
}

bool loggerSetFile(logger_t *logger, const char *filepath)
{
    // when path ends with / means no log file

    if (strrchr(filepath, '/') == filepath + stringLength(filepath) - 1 || stringLength(filepath) == 0)
    {
        if (logger->fp_)
        {
            fclose(logger->fp_);
            logger->fp_ = NULL;
        }
        logger->filepath[0] = 0X0;
        return;
    }

#if defined(OS_UNIX)
    strncpy(logger->filepath, filepath, sizeof(logger->filepath) - 1);
#else
    strncpy_s(logger->filepath, sizeof(logger->filepath), filepath, sizeof(logger->filepath) - 1);
#endif

    // remove suffix .log
    char *suffix = strrchr(logger->filepath, '.');
    if (suffix && strcmp(suffix, ".log") == 0)
    {
        *suffix = '\0';
    }
}

void loggerSetMaxFileSize(logger_t *logger, unsigned long long filesize)
{
    logger->max_filesize = filesize;
}

void loggerSetMaxFileSizeByStr(logger_t *logger, const char *str)
{
    int num = atoi(str);
    if (num <= 0)
        return;
    // 16 16M 16MB
    const char *e = str;
    while (*e != '\0')
        ++e;
    --e;
    char unit;
    if (*e >= '0' && *e <= '9')
        unit = 'M';
    else if (*e == 'B')
        unit = *(e - 1);
    else
        unit = *e;
    unsigned long long filesize = (unsigned long long) num;
    switch (unit)
    {
    case 'K':
        filesize <<= 10;
        break;
    case 'M':
        filesize <<= 20;
        break;
    case 'G':
        filesize <<= 30;
        break;
    default:
        filesize <<= 20;
        break;
    }
    logger->max_filesize = filesize;
}

void loggerEnableFileSync(logger_t *logger, int on)
{
    logger->enable_fsync = on;
}

void loggerSyncFile(logger_t *logger)
{
    mutexLock(&logger->mutex_);
    if (logger->fp_)
    {
        fflush(logger->fp_);
    }
    mutexUnlock(&logger->mutex_);
}

const char *loggerSetCurrentFile(logger_t *logger)
{
    return logger->cur_logfile;
}

#if defined(__GNUC__) && ! defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

static void logfile_name(const char *filepath, time_t ts, char *buf, int len)
{
    static thread_local struct tm tm;
#ifdef OS_UNIX
    localtime_r(&ts, &tm);
#else
    localtime_s(&tm, &ts);
#endif
    snprintf(buf, (size_t) len, "%s.%04d%02d%02d.log", filepath, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
}
#if defined(__GNUC__) && ! defined(__clang__)
#pragma GCC diagnostic pop
#endif

static FILE *shiftLogFile(logger_t *logger)
{
    time_t ts_now = time(NULL);
    int    interval_days =
        logger->last_logfile_ts == 0
               ? 0
               : (int) ((ts_now + s_gmtoff) / SECONDS_PER_DAY - (logger->last_logfile_ts + s_gmtoff) / SECONDS_PER_DAY);
    if (logger->fp_ == NULL || interval_days > 0)
    {
        // close old logfile
        if (logger->fp_)
        {
            fclose(logger->fp_);
            logger->fp_ = NULL;
        }
        else
        {
            interval_days = 30;
        }

        if (logger->remain_days >= 0)
        {
            char rm_logfile[256] = {0};
            if (interval_days >= logger->remain_days)
            {
                // remove [today-interval_days, today-remain_days] logfile
                for (int i = interval_days; i >= logger->remain_days; --i)
                {
                    time_t ts_rm = ts_now - i * SECONDS_PER_DAY;
                    logfile_name(logger->filepath, ts_rm, rm_logfile, sizeof(rm_logfile));
                    remove(rm_logfile);
                }
            }
            else
            {
                // remove today-remain_days logfile
                time_t ts_rm = ts_now - logger->remain_days * SECONDS_PER_DAY;
                logfile_name(logger->filepath, ts_rm, rm_logfile, sizeof(rm_logfile));
                remove(rm_logfile);
            }
        }
    }

    // open today logfile
    if (logger->fp_ == NULL)
    {
        logfile_name(logger->filepath, ts_now, logger->cur_logfile, sizeof(logger->cur_logfile));

#if defined(OS_UNIX)
        logger->fp_ = fopen(logger->cur_logfile, "a");
#else
        fopen_s(&(logger->fp_), logger->cur_logfile, "a");
#endif
        logger->last_logfile_ts = ts_now;
    }

    // NOTE: estimate can_write_cnt to avoid frequent fseek/ftell
    if (logger->fp_ && --logger->can_write_cnt < 0)
    {
        fseek(logger->fp_, 0, SEEK_END);
        unsigned long long filesize = (unsigned long long) ftell(logger->fp_);
        if (filesize > logger->max_filesize)
        {
            fclose(logger->fp_);
            logger->fp_ = NULL;
            // ftruncate
#if defined(OS_UNIX)
            logger->fp_ = fopen(logger->cur_logfile, "w");
#else
            fopen_s(&(logger->fp_), logger->cur_logfile, "w");
#endif

            // reopen with O_APPEND for multi-processes
            if (logger->fp_)
            {
                fclose(logger->fp_);
#if defined(OS_UNIX)
                logger->fp_ = fopen(logger->cur_logfile, "a");
#else
                fopen_s(&(logger->fp_), logger->cur_logfile, "a");
#endif
            }
        }
        else
        {
            logger->can_write_cnt = (int) ((logger->max_filesize - filesize) / logger->bufsize);
        }
    }

    return logger->fp_;
}

void loggerWrite(logger_t *logger, const char *buf, int len)
{
    FILE *fp = shiftLogFile(logger);
    if (fp)
    {
        fwrite(buf, 1, (size_t) len, fp);
        if (logger->enable_fsync)
        {
            fflush(fp);
        }
    }
}

static int i2a(int i, char *buf, int len)
{
    for (int l = len - 1; l >= 0; --l)
    {
        if (i == 0)
        {
            buf[l] = '0';
        }
        else
        {
            buf[l] = (char) (i % 10) + '0';
            i /= 10;
        }
    }
    return len;
}

int loggerPrintVA(logger_t *logger, int level, const char *fmt, va_list ap)
{
    if (level < logger->level)
        return -10;

    int year, month, day, hour, min, sec, us;
#ifdef _WIN32
    SYSTEMTIME tm;
    GetLocalTime(&tm);
    year  = tm.wYear;
    month = tm.wMonth;
    day   = tm.wDay;
    hour  = tm.wHour;
    min   = tm.wMinute;
    sec   = tm.wSecond;
    us    = tm.wMilliseconds * 1000;
#else
    struct timeval                tv;
    static thread_local struct tm tm;
    getTimeOfDay(&tv, NULL);
    time_t tt = tv.tv_sec;
    localtime_r(&tt, &tm);
    year  = tm.tm_year + 1900;
    month = tm.tm_mon + 1;
    day   = tm.tm_mday;
    hour  = tm.tm_hour;
    min   = tm.tm_min;
    sec   = tm.tm_sec;
    us    = (int) tv.tv_usec;
#endif

    const char *pcolor = "";
    const char *plevel = "";
#define XXX(id, str, clr)                                                                                              \
    case id:                                                                                                           \
        plevel = str;                                                                                                  \
        pcolor = clr;                                                                                                  \
        break;

    switch (level)
    {
        LOG_LEVEL_MAP(XXX)
    }
#undef XXX

    // lock logger->buf
    mutexLock(&logger->mutex_);

    char *buf     = logger->buf;
    int   bufsize = (int)logger->bufsize;
    int   len     = 0;

    if (logger->enable_color)
    {
        len = snprintf(buf, (size_t) bufsize, "%s", pcolor);
    }

    const char *p = logger->format;
    if (*p)
    {
        while (*p)
        {
            if (*p == '%')
            {
                switch (*++p)
                {
                case 'y':
                    len += i2a(year, buf + len, 4);
                    break;
                case 'm':
                    len += i2a(month, buf + len, 2);
                    break;
                case 'd':
                    len += i2a(day, buf + len, 2);
                    break;
                case 'H':
                    len += i2a(hour, buf + len, 2);
                    break;
                case 'M':
                    len += i2a(min, buf + len, 2);
                    break;
                case 'S':
                    len += i2a(sec, buf + len, 2);
                    break;
                case 'z':
                    len += i2a(us / 1000, buf + len, 3);
                    break;
                case 'Z':
                    len += i2a(us, buf + len, 6);
                    break;
                case 'l':
                    buf[len++] = *plevel;
                    break;
                case 'L':
                    for (int i = 0; i < 5; ++i)
                    {
                        buf[len++] = plevel[i];
                    }
                    break;
                case 's': {
                    len += vsnprintf(buf + len, (size_t)(bufsize - len), fmt, ap);
                }
                break;
                case '%':
                    buf[len++] = '%';
                    break;
                default:
                    break;
                }
            }
            else
            {
                buf[len++] = *p;
            }
            ++p;
        }
    }
    else
    {
        len += snprintf(buf + len, (size_t)(bufsize - len), "%04d-%02d-%02d %02d:%02d:%02d.%03d %s ", year, month, day, hour, min,
                        sec, us / 1000, plevel);

        len += vsnprintf(buf + len, (size_t) (bufsize - len), fmt, ap);
    }

    if (logger->enable_color)
    {
        len += snprintf(buf + len, (size_t) (bufsize - len), "%s", CLR_CLR);
    }

    if (len < bufsize)
    {
        buf[len++] = '\n';
    }

    if (logger->handler)
    {
        logger->handler(level, buf, len);
    }
    // else
    // {
    //     loggerWrite(logger, buf, len);
    // }

    mutexUnlock(&logger->mutex_);
    return len;
}



void stdoutLogger(int loglevel, const char *buf, int len)
{
    discard loglevel;
    ssize_t count = write(fileno(stdout), buf,  len);
    discard count;
}

void stderrLogger(int loglevel, const char *buf, int len)
{
    discard loglevel;
    ssize_t count = write(fileno(stderr), buf, len);
    discard count;
}

void fileLogger(int loglevel, const char *buf, int len)
{
    discard loglevel;
    loggerWrite(loggerGetDefaultLogger(), buf, len);
}
