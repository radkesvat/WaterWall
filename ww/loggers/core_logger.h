#pragma once
#include "hlog.h"
#include <stdbool.h>

#undef hlog
#define hlog getCoreLogger()  //NOLINT


logger_t          *getCoreLogger(void);
void               setCoreLogger(logger_t *newlogger);
logger_t          *createCoreLogger(const char *log_file, bool console);

static inline void setCoreLoggerLevelByStr(const char *log_level)
{
    logger_set_level_by_str(getCoreLogger(), log_level);
}

logger_handler getCoreLoggerHandle(void);
