#pragma once

#include "wlibc.h"

#if (defined(WW_LOG_H_) || defined(wlog)) && ! defined(LOGGER_CHOSEN)
#error "DnsLogger must be included before wlog.h"
#elif defined(LOGGER_CHOSEN)
// previews logger will have the hooks
#else

#define LOGGER_CHOSEN DnsLogger
#define wlog          getDnsLogger() // NOLINT

#endif

struct logger_s;
typedef struct logger_s logger_t;
logger_t               *getDnsLogger(void);

#include "wlog.h"

void      setDnsLogger(logger_t *newlogger);
logger_t *createDnsLogger(const char *log_file, bool console);

static inline void setDnsLoggerLevelByStr(const char *log_level)
{
    loggerSetLevelByString(getDnsLogger(), log_level);
}

logger_handler getDnsLoggerHandle(void);

void dnsloggerDestroy(void);
