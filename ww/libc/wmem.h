#pragma once

#include <stdbool.h>
#include <stddef.h> /* for size_t */
#include <stdint.h>

static inline bool memoryTryComputeArraySizeForLimit(uint64_t count, uint64_t item_size, uint64_t size_limit,
                                                     uint64_t *size_out)
{
    if (size_out == NULL || item_size == 0 || count > UINT64_MAX / item_size)
    {
        return false;
    }
    const uint64_t size = count * item_size;
    if (size > size_limit)
    {
        return false;
    }
    *size_out = size;
    return true;
}

static inline bool memoryTryComputeArraySize(size_t count, size_t item_size, size_t *size_out)
{
    uint64_t size;
    if (size_out == NULL ||
        ! memoryTryComputeArraySizeForLimit((uint64_t) count, (uint64_t) item_size, (uint64_t) SIZE_MAX, &size))
    {
        return false;
    }
    *size_out = (size_t) size;
    return true;
}

struct dedicated_memory_s;
typedef struct dedicated_memory_s dedicated_memory_t;

void *memoryAllocate(size_t size);
void *memoryAllocateZero(size_t size);
bool  memoryAlignedAllocationSizeIsRepresentableForLimit(uint64_t size, size_t alignment, uint64_t size_limit);
void *memoryAllocateAligned(size_t size, size_t alignment);
void *memoryAllocateAlignedZero(size_t size, size_t alignment);
void *memoryAllocateCacheAligned(size_t size);
void *memoryAllocateCacheAlignedZero(size_t size);
void *memoryReAllocate(void *ptr, size_t size);
void *memoryCalloc(size_t n, size_t size);
void  memoryFree(void *ptr);
void  memoryFreeAligned(void *ptr);

void *memoryDedicatedAllocate(dedicated_memory_t *dm, size_t size);
void *memoryDedicatedReallocate(dedicated_memory_t *dm, void *ptr, size_t size);
void  memoryDedicatedFree(dedicated_memory_t *dm, void *ptr);
