#pragma once
#include "hv/hlog.h"



#ifdef hlog
#undef hlog
#endif
#define hlog core_logger()


logger_t *core_logger();

void initCoreLogger(char * log_file);
