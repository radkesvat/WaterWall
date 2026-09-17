/* Exercise the CRT bypass backend with the same public allocation contract. */
#include "wlibc.h"

#undef ALLOCATOR_BYPASS
#define ALLOCATOR_BYPASS 1

#include "../../ww/managers/memory_manager.c"
#include "memory_allocation_test.c"
