#pragma once

#include "wlibc.h"


#if (defined(WW_LOG_H_) || defined(wlog)) && ! defined(LOGGER_CHOSEN)
#error "NetworkLogger must be included before wlog.h"
#elif defined(LOGGER_CHOSEN)
// previews logger will have the hooks
#else

#define LOGGER_CHOSEN NetworkLogger
#define wlog          getNetworkLogger() // NOLINT

#endif


struct logger_s;
typedef struct logger_s logger_t;
logger_t               *getNetworkLogger(void);

#include "wlog.h"

void      setNetworkLogger(logger_t *newlogger);
logger_t *createNetworkLogger(const char *log_file, bool console);

static inline void setNetworkLoggerLevelByStr(const char *log_level)
{
    loggerSetLevelByString(getNetworkLogger(), log_level);
}

logger_handler getNetworkLoggerHandle(void);

void networkloggerDestroy(void);
