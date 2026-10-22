/* Exercise the production memory manager's bypass backend without changing the
 * native tree's generated configuration. The default C++ test uses ww directly. */
#include "wlibc.h"

#undef ALLOCATOR_BYPASS
#define ALLOCATOR_BYPASS 1
#include "../../../ww/managers/memory_manager.c"
