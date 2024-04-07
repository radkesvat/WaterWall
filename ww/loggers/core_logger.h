#pragma once
#include "hv/hlog.h"
#include <stdbool.h>

#if !defined(ANDROID) || !defined(__ANDROID__)
#undef hlog
#define hlog getCoreLogger()

// FUCK ISO C99 WARNING
#ifdef DEBUG
#undef hlogd
#undef hlogi
#undef hlogw
#undef hloge
#undef hlogf
#define hlogd(...) logger_print(hlog, LOG_LEVEL_DEBUG, ##__VA_ARGS__)
#define hlogi(...) logger_print(hlog, LOG_LEVEL_INFO, ##__VA_ARGS__)
#define hlogw(...) logger_print(hlog, LOG_LEVEL_WARN, ##__VA_ARGS__)
#define hloge(...) logger_print(hlog, LOG_LEVEL_ERROR, ##__VA_ARGS__)
#define hlogf(...) logger_print(hlog, LOG_LEVEL_FATAL, ##__VA_ARGS__)
#endif
#endif // android

typedef void (*core_logger_handle_t)(int, const char *, int);
core_logger_handle_t getCoreLoggerHandle(bool console);


logger_t *getCoreLogger();
void setCoreLogger(logger_t * newlogger);

logger_t * createCoreLogger(const char * log_file,const char* log_level, bool console);
