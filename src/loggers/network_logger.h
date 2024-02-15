#pragma once
#include "hv/hlog.h"


#ifdef hlog
#undef hlog
#define hlog network_logger()
#endif


logger_t *network_logger();

void initNetworkLogger(const char * log_file,const char* log_level);
