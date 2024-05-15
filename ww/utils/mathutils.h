#pragma once
#include <stdlib.h>
#include <sys/types.h>
#undef max
#undef min
static inline ssize_t min(ssize_t x, ssize_t y) { return (((x) < (y)) ? (x) : (y)); }
static inline ssize_t max(ssize_t x, ssize_t y) { return (((x) < (y)) ? (y) : (x)); }
