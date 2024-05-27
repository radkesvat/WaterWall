#pragma once
#include "hlog.h"
#include <stdbool.h>

#undef hlog
#define hlog getDnsLogger()  //NOLINT

logger_t          *getDnsLogger(void);
void               setDnsLogger(logger_t *newlogger);
logger_t          *createDnsLogger(const char *log_file, bool console);

static inline void setDnsLoggerLevelByStr(const char *log_level)
{
    logger_set_level_by_str(getDnsLogger(), log_level);
}

logger_handler getDnsLoggerHandle(void);
