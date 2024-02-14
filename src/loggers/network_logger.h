#pragma once
#include "hv/hlog.h"

#ifdef hlog
#undef hlog
#endif
#define hlog network_logger()

logger_t *network_logger();

void initNetworkLogger(char * log_file);
