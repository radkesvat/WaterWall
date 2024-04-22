#pragma once
#include <stdlib.h>
#undef max
#undef min
static inline size_t min(ssize_t x, ssize_t y) { return (((x) < (y)) ? (x) : (y)); }
static inline size_t max(ssize_t x, ssize_t y) { return (((x) < (y)) ? (y) : (x)); }
