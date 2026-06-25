/**
 * @file wlog.c
 * @brief Implementation of thread-safe logging, formatting, and file rotation.
 */

#include "wlog.h"
#include "wmutex.h"

#include <limits.h>

// #include "wtime.h"
#define SECONDS_PER_HOUR 3600
#define SECONDS_PER_DAY  86400  // 24*3600
#define SECONDS_PER_WEEK 604800 // 7*24*3600;

static int s_gmtoff = 28800; // 8*3600

#if defined(va_copy)
#define LOGGER_VA_COPY(dst, src) va_copy(dst, src)
#elif defined(__va_copy)
#define LOGGER_VA_COPY(dst, src) __va_copy(dst, src)
#else
#define LOGGER_VA_COPY(dst, src) ((dst) = (src))
#endif

struct logger_s
{
    logger_handler handler;
    unsigned int   bufsize;

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

    wmutex_t mutex_;         // protects logger settings (level/format/color/handler/bufsize)
    wmutex_t handler_mutex_; // serializes sink/handler calls without blocking config or formatting
    wmutex_t write_mutex_;   // protects file state
};

static bool loggerFilePathDisablesFile(const char *filepath)
{
    if (filepath == NULL)
    {
        return true;
    }

    size_t path_len = stringLength(filepath);
    if (path_len == 0)
    {
        return true;
    }

    char last = filepath[path_len - 1];
#ifdef OS_WIN
    return last == '/' || last == '\\';
#else
    return last == '/';
#endif
}

/**
 * @brief Initialize a logger object with default settings.
 *
 * @param logger Logger instance to initialize.
 */
static void initLogger(logger_t *logger)
{
    logger->handler = NULL;
    logger->bufsize = DEFAULT_LOG_MAX_BUFSIZE;

    logger->level        = DEFAULT_LOG_LEVEL;
    logger->enable_color = 0;
    // NOTE: format is faster 6% than snprintf
    // logger->format[0] = '\0';
    stringCopyN(logger->format, DEFAULT_LOG_FORMAT, sizeof(logger->format));

    logger->fp_          = NULL;
    logger->max_filesize = DEFAULT_LOG_MAX_FILESIZE;
    logger->remain_days  = DEFAULT_LOG_REMAIN_DAYS;
    logger->enable_fsync = 1;
    logger->filepath[0]  = '\0';
    logger->cur_logfile[0] = '\0';
    logger->last_logfile_ts = 0;
    logger->can_write_cnt   = -1;
    mutexInit(&logger->mutex_);
    mutexInit(&logger->handler_mutex_);
    mutexInit(&logger->write_mutex_);
    loggerSetFile(logger, DEFAULT_LOG_FILE);
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
    if (logger == NULL)
    {
        return NULL;
    }
    initLogger(logger);
    return logger;
}

void loggerDestroy(logger_t *logger)
{
    if (logger)
    {
        mutexLock(&logger->mutex_);
        mutexLock(&logger->write_mutex_);
        if (logger->fp_)
        {
            fclose(logger->fp_);
            logger->fp_ = NULL;
        }
        mutexUnlock(&logger->write_mutex_);
        mutexUnlock(&logger->mutex_);
        mutexDestroy(&logger->write_mutex_);
        mutexDestroy(&logger->handler_mutex_);
        mutexDestroy(&logger->mutex_);
        memoryFree(logger);
    }
}

void loggerSetHandler(logger_t *logger, logger_handler fn)
{
    if (logger == NULL)
    {
        return;
    }
    mutexLock(&logger->mutex_);
    logger->handler = fn;
    mutexUnlock(&logger->mutex_);
}

void loggerSetLevel(logger_t *logger, int level)
{
    if (logger == NULL)
    {
        return;
    }
    mutexLock(&logger->mutex_);
    logger->level = level;
    mutexUnlock(&logger->mutex_);
}

void loggerSetLevelByString(logger_t *logger, const char *szLoglevel)
{
    if (logger == NULL)
    {
        return;
    }

    int loglevel = DEFAULT_LOG_LEVEL;
    if (szLoglevel == NULL)
    {
        loglevel = DEFAULT_LOG_LEVEL;
    }
    else if (strcmp(szLoglevel, "VERBOSE") == 0)
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
    mutexLock(&logger->mutex_);
    logger->level = loglevel;
    mutexUnlock(&logger->mutex_);
}

int loggerCheckWriteLevel(logger_t *logger, log_level_e level)
{
    if (logger == NULL)
    {
        return 0;
    }
    mutexLock(&logger->mutex_);
    int can_write = (logger->level) <= (int) level;
    mutexUnlock(&logger->mutex_);
    return can_write;
}

logger_handler loggerGetHandle(logger_t *logger)
{
    if (logger == NULL)
    {
        return NULL;
    }
    mutexLock(&logger->mutex_);
    logger_handler handler = logger->handler;
    mutexUnlock(&logger->mutex_);
    return handler;
}

void loggerSetFormat(logger_t *logger, const char *format)
{
    if (logger == NULL)
    {
        return;
    }

    mutexLock(&logger->mutex_);
    if (format)
    {
        stringCopyN(logger->format, format, sizeof(logger->format));
    }
    else
    {
        logger->format[0] = '\0';
    }
    mutexUnlock(&logger->mutex_);
}

void loggerSetRemainDays(logger_t *logger, int days)
{
    if (logger == NULL)
    {
        return;
    }
    mutexLock(&logger->write_mutex_);
    logger->remain_days = days;
    mutexUnlock(&logger->write_mutex_);
}

void loggerSetMaxBufSIze(logger_t *logger, unsigned int bufsize)
{
    if (logger == NULL || bufsize < 2 || bufsize > (unsigned int) INT_MAX)
    {
        return;
    }

    // loggerPrintVA() now renders into a per-call stack/heap buffer, so there is
    // no shared render buffer to reallocate here; just record the new maximum.
    mutexLock(&logger->mutex_);
    logger->bufsize = bufsize;
    mutexUnlock(&logger->mutex_);
}

void loggerEnableColor(logger_t *logger, int on)
{
    if (logger == NULL)
    {
        return;
    }
    mutexLock(&logger->mutex_);
    logger->enable_color = on;
    mutexUnlock(&logger->mutex_);
}

bool loggerSetFile(logger_t *logger, const char *filepath)
{
    if (logger == NULL)
    {
        return false;
    }

    // when path ends with / means no log file
    mutexLock(&logger->write_mutex_);
    if (loggerFilePathDisablesFile(filepath))
    {
        if (logger->fp_)
        {
            fclose(logger->fp_);
            logger->fp_ = NULL;
        }
        logger->filepath[0] = 0X0;
        logger->cur_logfile[0] = '\0';
        logger->last_logfile_ts = 0;
        logger->can_write_cnt = -1;
        mutexUnlock(&logger->write_mutex_);
        return false;
    }

    if (logger->fp_)
    {
        fclose(logger->fp_);
        logger->fp_ = NULL;
    }

    stringCopyN(logger->filepath, filepath, sizeof(logger->filepath));

    // remove suffix .log
    char *suffix = strrchr(logger->filepath, '.');
    if (suffix && strcmp(suffix, ".log") == 0)
    {
        *suffix = '\0';
    }
    logger->cur_logfile[0] = '\0';
    logger->last_logfile_ts = 0;
    logger->can_write_cnt = -1;
    mutexUnlock(&logger->write_mutex_);
    return true;
}

void loggerSetMaxFileSize(logger_t *logger, unsigned long long filesize)
{
    if (logger == NULL)
    {
        return;
    }
    mutexLock(&logger->write_mutex_);
    logger->max_filesize = filesize;
    mutexUnlock(&logger->write_mutex_);
}

void loggerSetMaxFileSizeByStr(logger_t *logger, const char *str)
{
    if (logger == NULL || str == NULL)
    {
        return;
    }

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
    mutexLock(&logger->write_mutex_);
    logger->max_filesize = filesize;
    mutexUnlock(&logger->write_mutex_);
}

void loggerEnableFileSync(logger_t *logger, int on)
{
    if (logger == NULL)
    {
        return;
    }
    mutexLock(&logger->write_mutex_);
    logger->enable_fsync = on;
    mutexUnlock(&logger->write_mutex_);
}

void loggerSyncFile(logger_t *logger)
{
    if (logger == NULL)
    {
        return;
    }
    mutexLock(&logger->write_mutex_);
    if (logger->fp_)
    {
        fflush(logger->fp_);
    }
    mutexUnlock(&logger->write_mutex_);
}

const char *loggerSetCurrentFile(logger_t *logger)
{
    if (logger == NULL)
    {
        return "";
    }
    return logger->cur_logfile;
}

#if defined(__GNUC__) && ! defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

/**
 * @brief Build daily rotated logfile name from base path and timestamp.
 *
 * @param filepath Base file path.
 * @param ts Timestamp used for date suffix.
 * @param buf Output buffer.
 * @param len Output buffer size.
 */
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

/**
 * @brief Rotate/open current logfile and enforce retention/size rules.
 *
 * @param logger Logger instance.
 * @return Writable FILE handle, or NULL on failure.
 */
static FILE *shiftLogFile(logger_t *logger)
{
    if (logger->filepath[0] == '\0')
    {
        return NULL;
    }

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
        if (fseek(logger->fp_, 0, SEEK_END) != 0)
        {
            logger->can_write_cnt = 0;
            return logger->fp_;
        }

        long file_pos = ftell(logger->fp_);
        if (file_pos < 0)
        {
            logger->can_write_cnt = 0;
            return logger->fp_;
        }

        unsigned long long filesize = (unsigned long long) file_pos;
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
    if (logger == NULL || buf == NULL || len <= 0)
    {
        return;
    }

    mutexLock(&logger->write_mutex_);
    FILE *fp = shiftLogFile(logger);
    if (fp)
    {
        fwrite(buf, 1, (size_t) len, fp);
        if (logger->enable_fsync)
        {
            fflush(fp);
        }
    }
    mutexUnlock(&logger->write_mutex_);
}

/**
 * @brief Convert integer to zero-padded decimal text.
 *
 * @param i Value to convert.
 * @param buf Output buffer.
 * @param len Fixed output width.
 * @return Number of written chars.
 */
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

/**
 * @brief Append one character to bounded output buffer.
 *
 * @param buf Output buffer.
 * @param bufsize Buffer capacity.
 * @param len Current length (in/out).
 * @param c Character to append.
 */
static inline void loggerAppendChar(char *buf, int bufsize, int *len, char c)
{
    if (*len < bufsize - 1)
    {
        buf[(*len)++] = c;
    }
}

/**
 * @brief Append fixed-width zero-padded integer.
 *
 * @param buf Output buffer.
 * @param bufsize Buffer capacity.
 * @param len Current length (in/out).
 * @param value Integer value.
 * @param width Printed width.
 */
static inline void loggerAppendFixedInt(char *buf, int bufsize, int *len, int value, int width)
{
    char num_buf[8] = {0};
    i2a(value, num_buf, width);

    for (int i = 0; i < width; ++i)
    {
        loggerAppendChar(buf, bufsize, len, num_buf[i]);
    }
}

/**
 * @brief Append formatted text from `va_list` with bounds checking.
 *
 * @param buf Output buffer.
 * @param bufsize Buffer capacity.
 * @param len Current length (in/out).
 * @param fmt Format string.
 * @param ap Variadic arguments.
 */
static inline void loggerAppendVFormat(char *buf, int bufsize, int *len, const char *fmt, va_list ap)
{
    int avail = bufsize - *len;
    if (avail <= 0)
    {
        return;
    }

    int wrote = vsnprintf(buf + *len, (size_t) avail, fmt, ap);
    if (wrote <= 0)
    {
        return;
    }

    if (wrote >= avail)
    {
        *len = bufsize - 1;
    }
    else
    {
        *len += wrote;
    }
}

/**
 * @brief Variadic wrapper for `loggerAppendVFormat`.
 *
 * @param buf Output buffer.
 * @param bufsize Buffer capacity.
 * @param len Current length (in/out).
 * @param fmt Format string.
 */
static inline void loggerAppendFormat(char *buf, int bufsize, int *len, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    loggerAppendVFormat(buf, bufsize, len, fmt, ap);
    va_end(ap);
}

static inline void loggerAppendMessageFormat(char *buf, int bufsize, int *len, const char *fmt, va_list ap)
{
    va_list ap_copy;
    LOGGER_VA_COPY(ap_copy, ap);
    loggerAppendVFormat(buf, bufsize, len, fmt, ap_copy);
    va_end(ap_copy);
}

/**
 * @brief Pick a render buffer for one log line.
 *
 * Returns @p stack_buf (capacity DEFAULT_LOG_MAX_BUFSIZE) for the common case;
 * heap-allocates only when a larger maximum line length is configured. On a
 * failed heap allocation the size is clamped back to the stack capacity so the
 * line is truncated rather than dropped.
 *
 * @param stack_buf Caller-owned stack buffer of DEFAULT_LOG_MAX_BUFSIZE bytes.
 * @param bufsize In: configured max size. Out: effective buffer capacity.
 * @param heap_out Out: heap pointer the caller must free, or NULL.
 * @return Buffer to render into.
 */
static char *loggerAcquireRenderBuffer(char *stack_buf, int *bufsize, char **heap_out)
{
    *heap_out = NULL;
    if (*bufsize > DEFAULT_LOG_MAX_BUFSIZE)
    {
        char *heap_buf = (char *) memoryAllocate((size_t) *bufsize);
        if (heap_buf != NULL)
        {
            *heap_out = heap_buf;
            return heap_buf;
        }
        // allocation failed: emit a truncated line from the stack buffer
        *bufsize = DEFAULT_LOG_MAX_BUFSIZE;
    }
    return stack_buf;
}

int loggerPrintVA(logger_t *logger, int level, const char *fmt, va_list ap)
{
    if (logger == NULL || fmt == NULL)
    {
        return -1;
    }

    // Snapshot logger settings under mutex_, then render and emit the line
    // outside of it so stdout/stderr/file writes never hold mutex_.
    mutexLock(&logger->mutex_);

    if (level < logger->level)
    {
        mutexUnlock(&logger->mutex_);
        return -10;
    }

    logger_handler handler      = logger->handler;
    int            bufsize      = (int) logger->bufsize;
    int            enable_color = logger->enable_color;
    char           format[64];
    stringCopyN(format, logger->format, sizeof(format));
    mutexUnlock(&logger->mutex_);

    if (bufsize < 2)
    {
        return -1;
    }

    char  stack_buf[DEFAULT_LOG_MAX_BUFSIZE];
    char *heap_buf = NULL;
    char *buf      = loggerAcquireRenderBuffer(stack_buf, &bufsize, &heap_buf);

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
    const char *plevel = "UNKWN";
#define XXX(id, str, clr)                                                                                              \
    case id:                                                                                                           \
        plevel = str;                                                                                                  \
        pcolor = clr;                                                                                                  \
        break;

    switch (level)
    {
    case LOG_LEVEL_VERBOSE:
        plevel = "VERBO";
        pcolor = CLR_WHITE;
        break;
    case LOG_LEVEL_SILENT:
        plevel = "SILEN";
        pcolor = CLR_WHITE;
        break;
        LOG_LEVEL_MAP(XXX)
    }
#undef XXX

    int len = 0;

    if (enable_color)
    {
        loggerAppendFormat(buf, bufsize, &len, "%s", pcolor);
    }

    const char *p = format;
    if (*p)
    {
        while (*p)
        {
            if (*p == '%')
            {
                ++p;
                if (*p == '\0')
                {
                    break;
                }

                switch (*p)
                {
                case 'y':
                    loggerAppendFixedInt(buf, bufsize, &len, year, 4);
                    break;
                case 'm':
                    loggerAppendFixedInt(buf, bufsize, &len, month, 2);
                    break;
                case 'd':
                    loggerAppendFixedInt(buf, bufsize, &len, day, 2);
                    break;
                case 'H':
                    loggerAppendFixedInt(buf, bufsize, &len, hour, 2);
                    break;
                case 'M':
                    loggerAppendFixedInt(buf, bufsize, &len, min, 2);
                    break;
                case 'S':
                    loggerAppendFixedInt(buf, bufsize, &len, sec, 2);
                    break;
                case 'z':
                    loggerAppendFixedInt(buf, bufsize, &len, us / 1000, 3);
                    break;
                case 'Z':
                    loggerAppendFixedInt(buf, bufsize, &len, us, 6);
                    break;
                case 'l':
                    loggerAppendChar(buf, bufsize, &len, *plevel);
                    break;
                case 'L':
                    for (int i = 0; i < 5; ++i)
                    {
                        loggerAppendChar(buf, bufsize, &len, plevel[i]);
                    }
                    break;
                case 's': {
                    loggerAppendMessageFormat(buf, bufsize, &len, fmt, ap);
                }
                break;
                case '%':
                    loggerAppendChar(buf, bufsize, &len, '%');
                    break;
                default:
                    break;
                }
            }
            else
            {
                loggerAppendChar(buf, bufsize, &len, *p);
            }
            ++p;
            if (len >= bufsize - 1)
                break;
        }
    }
    else
    {
        loggerAppendFormat(buf, bufsize, &len, "%04d-%02d-%02d %02d:%02d:%02d.%03d %s ", year, month, day, hour,
                           min, sec, us / 1000, plevel);

        loggerAppendMessageFormat(buf, bufsize, &len, fmt, ap);
    }

    if (enable_color && len < bufsize)
    {
        loggerAppendFormat(buf, bufsize, &len, "%s", CLR_CLR);
    }

    loggerAppendChar(buf, bufsize, &len, '\n');

    if (handler)
    {
        // serialize sink calls so concurrent log lines are not interleaved,
        // without blocking logger configuration or formatting on mutex_.
        mutexLock(&logger->handler_mutex_);
        handler(level, buf, len);
        mutexUnlock(&logger->handler_mutex_);
    }

    if (heap_buf != NULL)
    {
        memoryFree(heap_buf);
    }
    return len;
}



void stdoutLogger(int loglevel, const char *buf, int len)
{
    discard loglevel;
    if (buf == NULL || len <= 0)
    {
        return;
    }
    ssize_t count = write(fileno(stdout), buf,  (size_t) len);
    discard count;
}

void stderrLogger(int loglevel, const char *buf, int len)
{
    discard loglevel;
    if (buf == NULL || len <= 0)
    {
        return;
    }
    ssize_t count = write(fileno(stderr), buf, (size_t) len);
    discard count;
}

void fileLogger(int loglevel, const char *buf, int len)
{
    discard loglevel;
    loggerWrite(loggerGetDefaultLogger(), buf, len);
}
