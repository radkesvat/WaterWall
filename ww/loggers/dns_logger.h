#pragma once


#if (defined(HV_LOG_H_) || defined(hlog)) && ! defined(LOGGER_CHOSEN)
#error "DnsLogger must be included before hlog.h"
#elif defined(LOGGER_CHOSEN)
// previews logger will have the hooks
#else

#define LOGGER_CHOSEN DnsLogger
#define hlog getDnsLogger() // NOLINT

#endif
#include <stdbool.h>

struct logger_s;
typedef struct logger_s logger_t;
logger_t          *getDnsLogger(void);
#include "hlog.h"


void               setDnsLogger(logger_t *newlogger);
logger_t          *createDnsLogger(const char *log_file, bool console);

static inline void setDnsLoggerLevelByStr(const char *log_level)
{
    logger_set_level_by_str(getDnsLogger(), log_level);
}

logger_handler getDnsLoggerHandle(void);

