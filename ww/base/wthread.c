#include "wthread.h"



#ifdef __CYGWIN__
#include <windows.h>

long getTID(void){
    return (long)GetCurrentThreadId();
}

#endif
