#pragma once
#include "hv/hlog.h"



#if !defined(ANDROID) || !defined(__ANDROID__)
#undef hlog
#define hlog dns_logger()


// FUCK ISO C99 WARNING 
#ifdef DEBUG
#undef  hlogd
#undef  hlogi
#undef  hlogw
#undef  hloge
#undef  hlogf
#define hlogd(...) logger_print(hlog, LOG_LEVEL_DEBUG, ## __VA_ARGS__)
#define hlogi(...) logger_print(hlog, LOG_LEVEL_INFO,  ## __VA_ARGS__)
#define hlogw(...) logger_print(hlog, LOG_LEVEL_WARN,  ## __VA_ARGS__)
#define hloge(...) logger_print(hlog, LOG_LEVEL_ERROR, ## __VA_ARGS__)
#define hlogf(...) logger_print(hlog, LOG_LEVEL_FATAL, ## __VA_ARGS__)
#endif


#endif // android




logger_t *dns_logger();

void initDnsLogger(const char * log_file,const char* log_level);
