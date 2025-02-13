#include "wthread.h"



#ifdef __CYGWIN__
#include <windows.h>

long gettid(void){
    return (long)GetCurrentThreadId();
}

#endif
