#pragma once

#include "wlibc.h"

/* Heap entries can all move into the staging deque. Its power-of-two ring has
 * one empty slot and uses signed byte arithmetic, so it sets the tighter bound. */
static inline size_t idleTableMaximumEntries(void)
{
    return (size_t) PTRDIFF_MAX / (2U * sizeof(void *));
}

static inline bool idleTableCanAddEntry(size_t heap_entries, size_t posted_entries)
{
    const size_t maximum = idleTableMaximumEntries();
    return heap_entries < maximum && posted_entries < maximum - heap_entries;
}

/* STC's default hash load factor, power-of-two rounding and signed array sizes.
 * Call before a growing reserve; actual heap allocation failure is fatal. */
static inline bool idleTableHashCapacityIsRepresentable(size_t count, size_t value_size, size_t metadata_size)
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
