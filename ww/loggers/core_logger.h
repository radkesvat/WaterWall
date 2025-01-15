#pragma once

#include "wlibc.h"

#if (defined(WW_LOG_H_) || defined(wlog)) && ! defined(LOGGER_CHOSEN)
#error "CoreLogger must be included before wlog.h"
#elif defined(LOGGER_CHOSEN)
// previews logger will have the hooks
#else

#define LOGGER_CHOSEN CoreLogger
#define wlog          getCoreLogger() // NOLINT

#endif

struct logger_s;
typedef struct logger_s logger_t;
logger_t               *getCoreLogger(void);

#include "wlog.h"

void      setCoreLogger(logger_t *newlogger);
logger_t *createCoreLogger(const char *log_file, bool console);

static inline void setCoreLoggerLevelByStr(const char *log_level)
{
    loggerSetLevelByString(getCoreLogger(), log_level);
}

logger_handler getCoreLoggerHandle(void);
