#pragma once

#include "wlibc.h"

/* Called only after the signed geometry bound has admitted count. */
static inline size_t userIndexHashBucketCount(size_t count)
{
    const size_t requested = (size_t) ((float) count / 0.80f) + 4U;
    size_t       buckets   = 1;
    while (buckets < requested)
        buckets *= 2U;
    return buckets;
}

/* The user indexes use STC's default 0.80 load factor. Validate its floating
 * conversion, power-of-two bucket rounding and signed byte arithmetic before
 * reserving. Both arrays must fit; heap exhaustion itself is fatal. */
static inline bool userIndexHashCapacityIsRepresentable(size_t count, size_t value_size, size_t metadata_size)
{
    assert(value_size >= 4 && metadata_size != 0);
    if (count > (size_t) PTRDIFF_MAX / 4U)
        return false;
    const size_t buckets = userIndexHashBucketCount(count);
    return buckets <= (size_t) PTRDIFF_MAX / value_size && buckets < (size_t) PTRDIFF_MAX / metadata_size;
}

/* Match hmap reserve exactly, including its early exit against current capacity.
 * The extent counts both new arrays in full while the old arrays still exist. */
static inline bool userIndexHashGrowthGeometry(size_t count, size_t current_buckets, size_t value_size,
                                               size_t metadata_size, size_t *buckets_out, size_t *extent_out)
{
    assert(buckets_out != NULL && extent_out != NULL);
    *buckets_out = current_buckets;
    *extent_out  = 0;
    if (count <= (size_t) ((float) current_buckets * 0.80f))
        return true;
    if (! userIndexHashCapacityIsRepresentable(count, value_size, metadata_size))
        return false;
    size_t buckets = userIndexHashBucketCount(count);
    if (buckets == current_buckets)
        return true;
    size_t values   = buckets * value_size;
    size_t metadata = (buckets + 1U) * metadata_size;
    if (values > SIZE_MAX - metadata)
        return false;
    *buckets_out = buckets;
    *extent_out  = values + metadata;
    return true;
}
