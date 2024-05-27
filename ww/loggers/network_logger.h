#pragma once
#include "hlog.h"
#include <stdbool.h>

#undef hlog
#define hlog getNetworkLogger()  //NOLINT

logger_t          *getNetworkLogger(void);
void               setNetworkLogger(logger_t *newlogger);
logger_t          *createNetworkLogger(const char *log_file, bool console);

static inline void setNetworkLoggerLevelByStr(const char *log_level)
{
    logger_set_level_by_str(getNetworkLogger(), log_level);
}

logger_handler getNetworkLoggerHandle(void);
