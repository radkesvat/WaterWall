#pragma once
#include "hv/hlog.h"
#ifdef hlog
#undef hlog
#define hlog dns_logger()
#endif

logger_t *dns_logger();

void initDnsLogger(const char * log_file,const char* log_level);
