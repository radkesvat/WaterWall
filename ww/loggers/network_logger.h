#pragma once
#include "hlog.h"
#include <stdbool.h>

#undef hlog
#undef HLOG
#define HLOG getNetworkLogger() 

#undef   LOGD
#undef   LOGI
#undef   LOGW
#undef   LOGE
#undef   LOGF
#define  LOGD    hlogd
#define  LOGI    hlogi
#define  LOGW    hlogw
#define  LOGE    hloge
#define  LOGF    hlogf


logger_t          *getNetworkLogger(void);
void               setNetworkLogger(logger_t *newlogger);
logger_t          *createNetworkLogger(const char *log_file, bool console);

static inline void setNetworkLoggerLevelByStr(const char *log_level)
{
    logger_set_level_by_str(getNetworkLogger(), log_level);
}

logger_handler getNetworkLoggerHandle(void);
