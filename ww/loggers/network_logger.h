#pragma once

#if (defined(HV_LOG_H_) || defined(hlog)) && ! defined(LOGGER_CHOSEN)
#error "NetworkLogger must be included before hlog.h"
#elif defined(LOGGER_CHOSEN)
// previews logger will have the hooks
#else

#define LOGGER_CHOSEN NetworkLogger
#define hlog          getNetworkLogger() // NOLINT

#endif

#include <stdbool.h>

struct logger_s;
typedef struct logger_s logger_t;
logger_t               *getNetworkLogger(void);

#include "hlog.h"

void      setNetworkLogger(logger_t *newlogger);
logger_t *createNetworkLogger(const char *log_file, bool console);

static inline void setNetworkLoggerLevelByStr(const char *log_level)
{
    logger_set_level_by_str(getNetworkLogger(), log_level);
}

logger_handler getNetworkLoggerHandle(void);
