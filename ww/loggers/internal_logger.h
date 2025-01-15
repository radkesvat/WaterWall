#pragma once
#include "wlibc.h"

#if (defined(WW_LOG_H_) || defined(wlog)) && ! defined(LOGGER_CHOSEN)
#error "InternalLogger must be included before wlog.h"
#elif defined(LOGGER_CHOSEN)
// previews logger will have the hooks
#else

#define LOGGER_CHOSEN InternalLogger
#define wlog          getInternalLogger() // NOLINT

#endif


struct logger_s;
typedef struct logger_s logger_t;
logger_t               *getInternalLogger(void);

#include "wlog.h"

void      setInternalLogger(logger_t *newlogger);
logger_t *createInternalLogger(const char *log_file, bool console);

static inline void setInternalLoggerLevelByStr(const char *log_level)
{
    loggerSetLevelByString(getInternalLogger(), log_level);
}

logger_handler getInternalLoggerHandle(void);
