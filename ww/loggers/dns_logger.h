#pragma once
#include "hv/hlog.h"
#include <stdbool.h>

#if !defined(ANDROID) || !defined(__ANDROID__)
#undef hlog
#define hlog getDnsLogger() // NOLINT

// GET RID OF ISO C99 WARNING IN DEBUG MODE
#ifdef DEBUG
#undef  hlogd
#undef  hlogi
#undef  hlogw
#undef  hloge
#undef  hlogf
#define hlogd(...) logger_print(hlog, LOG_LEVEL_DEBUG, ## __VA_ARGS__) // NOLINT
#define hlogi(...) logger_print(hlog, LOG_LEVEL_INFO,  ## __VA_ARGS__) // NOLINT
#define hlogw(...) logger_print(hlog, LOG_LEVEL_WARN,  ## __VA_ARGS__) // NOLINT
#define hloge(...) logger_print(hlog, LOG_LEVEL_ERROR, ## __VA_ARGS__) // NOLINT
#define hlogf(...) logger_print(hlog, LOG_LEVEL_FATAL, ## __VA_ARGS__) // NOLINT
#endif
#endif // android

logger_t *getDnsLogger();
void setDnsLogger(logger_t * newlogger);
logger_t *createDnsLogger(const char *log_file, bool console);


static inline void setDnsLoggerLevelByStr(const char *log_level){
    logger_set_level_by_str(getDnsLogger(), log_level);
}
