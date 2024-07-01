#include "frand.h"

_Thread_local bool     frand_initialized = 0;
_Thread_local uint32_t frand_seed32      = 0;
_Thread_local uint64_t frand_seed64      = 0;
