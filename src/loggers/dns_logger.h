#pragma once
#include "hv/hlog.h"

#ifdef hlog
#undef hlog
#endif
#define hlog dns_logger()

logger_t *dns_logger();

void initDnsLogger(char * log_file);
