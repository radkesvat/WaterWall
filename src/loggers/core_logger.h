#pragma once
#include "hv/hlog.h"

#ifdef hlog
#undef hlog
#define hlog core_logger()
#endif


logger_t *core_logger();

void initCoreLogger(char *log_file);
