#pragma once
#include "hlog.h"
#include <stdbool.h>

#undef hlog
#undef HLOG
#define HLOG getCoreLogger() 

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



logger_t          *getCoreLogger(void);
void               setCoreLogger(logger_t *newlogger);
logger_t          *createCoreLogger(const char *log_file, bool console);

static inline void setCoreLoggerLevelByStr(const char *log_level)
{
    logger_set_level_by_str(getCoreLogger(), log_level);
}

logger_handler getCoreLoggerHandle(void);
