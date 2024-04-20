#pragma once
#include <stdlib.h>
#undef max
#undef min
static inline size_t min(size_t x, size_t y) { return (((x) < (y)) ? (x) : (y)); }
static inline size_t max(size_t x, size_t y) { return (((x) < (y)) ? (y) : (x)); }
