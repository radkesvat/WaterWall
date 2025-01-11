#ifndef WW_LOG_H_
#define WW_LOG_H_

/*
 * wlog is thread-safe
 */

#include <stdarg.h>
#include <string.h>

#ifdef _WIN32
#define DIR_SEPARATOR     '\\'
#define DIR_SEPARATOR_STR "\\"
#else
#define DIR_SEPARATOR     '/'
#define DIR_SEPARATOR_STR "/"
#endif

#ifndef __FILENAME__
// #define __FILENAME__  (strrchr(__FILE__, DIR_SEPARATOR) ? strrchr(__FILE__, DIR_SEPARATOR) + 1 : __FILE__)
#define __FILENAME__ (strrchr(DIR_SEPARATOR_STR __FILE__, DIR_SEPARATOR) + 1)
#endif

#include "wexport.h"

#define CLR_CLR     "\033[0m"  /* 恢复颜色 */
#define CLR_BLACK   "\033[30m" /* 黑色字 */
#define CLR_RED     "\033[31m" /* 红色字 */
#define CLR_GREEN   "\033[32m" /* 绿色字 */
#define CLR_YELLOW  "\033[33m" /* 黄色字 */
#define CLR_BLUE    "\033[34m" /* 蓝色字 */
#define CLR_PURPLE  "\033[35m" /* 紫色字 */
#define CLR_SKYBLUE "\033[36m" /* 天蓝字 */
#define CLR_WHITE   "\033[37m" /* 白色字 */

#define CLR_BLK_WHT     "\033[40;37m" /* 黑底白字 */
#define CLR_RED_WHT     "\033[41;37m" /* 红底白字 */
#define CLR_GREEN_WHT   "\033[42;37m" /* 绿底白字 */
#define CLR_YELLOW_WHT  "\033[43;37m" /* 黄底白字 */
#define CLR_BLUE_WHT    "\033[44;37m" /* 蓝底白字 */
#define CLR_PURPLE_WHT  "\033[45;37m" /* 紫底白字 */
#define CLR_SKYBLUE_WHT "\033[46;37m" /* 天蓝底白字 */
#define CLR_WHT_BLK     "\033[47;30m" /* 白底黑字 */

// XXX(id, str, clr)
#define LOG_LEVEL_MAP(XXX)                                                                                             \
    XXX(LOG_LEVEL_DEBUG, "DEBUG", CLR_WHITE)                                                                           \
    XXX(LOG_LEVEL_INFO, "INFO ", CLR_GREEN)                                                                            \
    XXX(LOG_LEVEL_WARN, "WARN ", CLR_YELLOW)                                                                           \
    XXX(LOG_LEVEL_ERROR, "ERROR", CLR_RED)                                                                             \
    XXX(LOG_LEVEL_FATAL, "FATAL", CLR_RED_WHT)

typedef enum
{
    LOG_LEVEL_VERBOSE = 0,
#define XXX(id, str, clr) id,
    LOG_LEVEL_MAP(XXX)
#undef XXX
    LOG_LEVEL_SILENT
} log_level_e;

#define DEFAULT_LOG_FILE         "libhv"
#define DEFAULT_LOG_LEVEL        LOG_LEVEL_INFO
#define DEFAULT_LOG_FORMAT       "%y-%m-%d %H:%M:%S.%z %L %s"
#define DEFAULT_LOG_REMAIN_DAYS  1
#define DEFAULT_LOG_MAX_BUFSIZE  (1 << 14) // 16k
#define DEFAULT_LOG_MAX_FILESIZE (1 << 24) // 16M

// logger: default fileLogger
// network_logger() see event/nlog.h
typedef void (*logger_handler)(int loglevel, const char *buf, int len);
typedef struct logger_s logger_t;

WW_EXPORT void writeLogFile(logger_t *logger, const char *buf, int len);
WW_EXPORT void stdoutLogger(int loglevel, const char *buf, int len);
WW_EXPORT void stderrLogger(int loglevel, const char *buf, int len);
WW_EXPORT void fileLogger(int loglevel, const char *buf, int len);
// network_logger implement see event/nlog.h
// WW_EXPORT void network_logger(int loglevel, const char* buf, int len);

WW_EXPORT logger_t *createLogger(void);
WW_EXPORT void      destroyLogger(logger_t *logger);

WW_EXPORT void setLoggerHandler(logger_t *logger, logger_handler fn);
WW_EXPORT void setLoggerLevel(logger_t *logger, int level);
// level = [VERBOSE,DEBUG,INFO,WARN,ERROR,FATAL,SILENT]
WW_EXPORT void           setLoggerLevelByStr(logger_t *logger, const char *level);
WW_EXPORT int            checkLoggerWriteLevel(logger_t *logger, log_level_e level);
WW_EXPORT logger_handler getLoggerHandle(logger_t *logger);
/*
 * format  = "%y-%m-%d %H:%M:%S.%z %L %s"
 * message = "2020-01-02 03:04:05.067 DEBUG message"
 * %y year
 * %m month
 * %d day
 * %H hour
 * %M min
 * %S sec
 * %z ms
 * %Z us
 * %l First character of level
 * %L All characters of level
 * %s message
 * %% %
 */
WW_EXPORT void setLoggerFormat(logger_t *logger, const char *format);
WW_EXPORT void setLoggerMaxBufSIze(logger_t *logger, unsigned int bufsize);
WW_EXPORT void enableLoggerColor(logger_t *logger, int on);
WW_EXPORT int  printLoggerVA(logger_t *logger, int level, const char *fmt, va_list ap);

static inline int printLogger(logger_t *logger, int level, const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    int ret = printLoggerVA(logger, level, fmt, myargs);
    va_end(myargs);
    return ret;
}

// below for file logger
WW_EXPORT void setLoggerFile(logger_t *logger, const char *filepath);
WW_EXPORT void setLoggerMaxFileSize(logger_t *logger, unsigned long long filesize);
// 16, 16M, 16MB
WW_EXPORT void        setLoggerMaxFileSizeByStr(logger_t *logger, const char *filesize);
WW_EXPORT void        setLoggerRemainDays(logger_t *logger, int days);
WW_EXPORT void        enableLoggerFSync(logger_t *logger, int on);
WW_EXPORT void        syncLoggerFile(logger_t *logger);
WW_EXPORT const char *setLoggerCurrentFile(logger_t *logger);

// wlog: default logger instance
WW_EXPORT logger_t *getDefaultWWLogger(void);
WW_EXPORT void      destroyDefaultWWLogger(void);

// macro wlog*
#ifndef wlog
#define wlog getDefaultWWLogger()
#endif
#define destroyWLog()                     destroyDefaultWWLogger()
#define setWLogLevel()                    setLoggerLevel(wlog, LOG_LEVEL_SILENT)
#define setWLogFile(filepath)             setLoggerFile(wlog, filepath)
#define setWLogLevel(level)               setLoggerLevel(wlog, level)
#define setWLogLevelByStr(level)          setLoggerLevelByStr(wlog, level)
#define setWLogHandler(fn)                setLoggerHandler(wlog, fn)
#define setWLogFormat(format)             setLoggerFormat(wlog, format)
#define setWLogMaxFileSize(filesize)      setLoggerMaxFileSize(wlog, filesize)
#define setWLogMaxFileSizeByStr(filesize) setLoggerMaxFileSizeByStr(wlog, filesize)
#define setWLogRemainDays(days)           setLoggerRemainDays(wlog, days)
#define enableWLogFSync()                 enableLoggerFSync(wlog, 1)
#define enableWLogFSync()                 enableLoggerFSync(wlog, 0)
#define syncWLogFile()                    syncLoggerFile(wlog)
#define setWLogCurrentFile()              setLoggerCurrentFile(wlog)
#define checkWLogWriteLevel(level)        checkLoggerWriteLevel(wlog, level)

// below for android
#if defined(ANDROID) || defined(__ANDROID__)
#include <android/log.h>
#define LOG_TAG "JNI"
static inline void wlogd(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    __android_log_vprint(ANDROID_LOG_DEBUG, LOG_TAG, fmt, myargs);
    va_end(myargs);
}

static inline void wlogi(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, fmt, myargs);
    va_end(myargs);
}

static inline void wlogw(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    __android_log_vprint(ANDROID_LOG_WARN, LOG_TAG, fmt, myargs);
    va_end(myargs);
}

static inline void wloge(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    __android_log_vprint(ANDROID_LOG_ERROR, LOG_TAG, fmt, myargs);
    va_end(myargs);
}
static inline void wlogf(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    __android_log_vprint(ANDROID_LOG_FATAL, LOG_TAG, fmt, myargs);
    va_end(myargs);
}
#else

static inline void wlogd(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    printLoggerVA(wlog, LOG_LEVEL_DEBUG, fmt, myargs);
    va_end(myargs);
}

static inline void wlogi(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    printLoggerVA(wlog, LOG_LEVEL_INFO, fmt, myargs);
    va_end(myargs);
}

static inline void wlogw(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    printLoggerVA(wlog, LOG_LEVEL_WARN, fmt, myargs);
    va_end(myargs);
}

static inline void wloge(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    printLoggerVA(wlog, LOG_LEVEL_ERROR, fmt, myargs);
    va_end(myargs);
}
static inline void wlogf(const char *fmt, ...)
{
    va_list myargs;
    va_start(myargs, fmt);
    printLoggerVA(wlog, LOG_LEVEL_FATAL, fmt, myargs);
    va_end(myargs);
}
#endif

// macro alias
#if ! defined(LOGD) && ! defined(LOGI) && ! defined(LOGW) && ! defined(LOGE) && ! defined(LOGF)
#define LOGD wlogd
#define LOGI wlogi
#define LOGW wlogw
#define LOGE wloge
#define LOGF wlogf
#endif

#endif // WW_LOG_H_
