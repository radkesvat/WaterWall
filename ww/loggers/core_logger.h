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
#define  LOGD    HLOGD
#define  LOGI    HLOGI
#define  LOGW    HLOGW
#define  LOGE    HLOGE
#define  LOGF    HLOGF

#if defined(ANDROID) || defined(__ANDROID__)
#define LOG_TAG "JNI"

#define HLOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define HLOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define HLOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define HLOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define HLOGF(...) __android_log_print(ANDROID_LOG_FATAL, LOG_TAG, __VA_ARGS__)
#else
#define HLOGD(...) logger_print(HLOG, LOG_LEVEL_DEBUG, ## __VA_ARGS__) 
#define HLOGI(...) logger_print(HLOG, LOG_LEVEL_INFO,  ## __VA_ARGS__) 
#define HLOGW(...) logger_print(HLOG, LOG_LEVEL_WARN,  ## __VA_ARGS__) 
#define HLOGE(...) logger_print(HLOG, LOG_LEVEL_ERROR, ## __VA_ARGS__) 
#define HLOGF(...) logger_print(HLOG, LOG_LEVEL_FATAL, ## __VA_ARGS__) 
#endif


logger_t          *getCoreLogger();
void               setCoreLogger(logger_t *newlogger);
logger_t          *createCoreLogger(const char *log_file, bool console);

static inline void setCoreLoggerLevelByStr(const char *log_level)
{
    logger_set_level_by_str(getCoreLogger(), log_level);
}

typedef void (*core_logger_handle_t)(int, const char *, int);
core_logger_handle_t getCoreLoggerHandle();