#pragma once

#include "wlibc.h"

/* The user indexes use STC's default 0.80 load factor. Validate its floating
 * conversion, power-of-two bucket rounding and signed byte arithmetic before
 * reserving. Both arrays must fit; heap exhaustion itself is fatal. */
static inline bool userIndexHashCapacityIsRepresentable(size_t count, size_t value_size, size_t metadata_size)
{
    assert(value_size >= 4 && metadata_size != 0);
    if (count > (size_t) PTRDIFF_MAX / 4U)
        return false;
    const size_t requested_buckets = (size_t) ((float) count / 0.80f) + 4U;
    size_t       buckets           = 1;
    while (buckets < requested_buckets)
        buckets *= 2U;
    return buckets <= (size_t) PTRDIFF_MAX / value_size && buckets < (size_t) PTRDIFF_MAX / metadata_size;
}
