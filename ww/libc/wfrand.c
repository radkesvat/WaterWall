#include "wfrand.h"
#include "wlibc.h"

thread_local uint32_t frand_seed32      = 0;
thread_local uint64_t frand_seed64      = 0;
