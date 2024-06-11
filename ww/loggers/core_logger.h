#pragma once


#if (defined(HV_LOG_H_) || defined(hlog)) && ! defined(LOGGER_CHOSEN)
#error "CoreLogger must be included before hlog.h"
#elif defined(LOGGER_CHOSEN)
// previews logger will have the hooks
#else

#define LOGGER_CHOSEN CoreLogger
#define hlog getCoreLogger() // NOLINT

#endif
#include <stdbool.h>

struct logger_s;
typedef struct logger_s logger_t;
logger_t          *getCoreLogger(void);
#include "hlog.h"


void               setCoreLogger(logger_t *newlogger);
logger_t          *createCoreLogger(const char *log_file, bool console);

static inline void setCoreLoggerLevelByStr(const char *log_level)
{
    logger_set_level_by_str(getCoreLogger(), log_level);
}

logger_handler getCoreLoggerHandle(void);

