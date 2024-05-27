#pragma once
#include "hlog.h"
#include <stdbool.h>

#undef hlog
#undef HLOG
#define HLOG getDnsLogger() 

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



logger_t          *getDnsLogger(void);
void               setDnsLogger(logger_t *newlogger);
logger_t          *createDnsLogger(const char *log_file, bool console);

static inline void setDnsLoggerLevelByStr(const char *log_level)
{
    logger_set_level_by_str(getDnsLogger(), log_level);
}

logger_handler getDnsLoggerHandle(void);
