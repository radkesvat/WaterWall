#pragma once

#if (defined(HV_LOG_H_) || defined(hlog)) && ! defined(LOGGER_CHOSEN)
#error "WWLogger must be included before hlog.h"
#elif defined(LOGGER_CHOSEN)
// previews logger will have the hooks
#else

#define LOGGER_CHOSEN WWLogger
#define hlog          getWWLogger() // NOLINT

#endif

#include <stdbool.h>

struct logger_s;
typedef struct logger_s logger_t;
logger_t               *getWWLogger(void);

#include "hlog.h"

void      setWWLogger(logger_t *newlogger);
logger_t *createWWLogger(const char *log_file, bool console);

static inline void setWWLoggerLevelByStr(const char *log_level)
{
    logger_set_level_by_str(getWWLogger(), log_level);
}

logger_handler getWWLoggerHandle(void);
