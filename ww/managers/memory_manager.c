/*
 * Memory allocation backend bindings and dedicated-memory compatibility layer.
 */

#include "memory_manager.h"
#include "mimalloc.h"
#include "wmutex.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool memoryAlignmentIsValid(size_t alignment)
{
    return alignment != 0 && (alignment & (alignment - 1)) == 0;
}

void *memoryAllocateAligned(size_t size, size_t alignment)
{
    if (! memoryAlignmentIsValid(alignment))
    {
        return NULL;
    }

    // promote so the padding gap below is always at least one pointer wide
    alignment = max(alignment, sizeof(void *));

    if (size > SIZE_MAX - alignment)
    {
        return NULL;
    }

    // over-allocate by exactly `alignment` (1 + (alignment - 1)): aligning
    // (base + 1) up lands a non-zero multiple of sizeof(void *) past base,
    // since the allocator returns pointer-aligned memory, so the padding
    // itself has room for the back-pointer
    void *base = memoryAllocate(size + alignment);
    if (base == NULL)
    {
        return NULL;
    }

    uintptr_t aligned = ALIGN2((uintptr_t) base + 1, alignment);
    assert(aligned - (uintptr_t) base >= sizeof(void *));
    ((void **) aligned)[-1] = base;
    return (void *) aligned;
}

void *memoryAllocateAlignedZero(size_t size, size_t alignment)
{
    void *ptr = memoryAllocateAligned(size, alignment);
    if (ptr != NULL)
    {
        memorySet(ptr, 0, size);
    }
    return ptr;
}

void *memoryAllocateCacheAligned(size_t size)
{
    return memoryAllocateAligned(size, kCpuLineCacheSize);
}

void *memoryAllocateCacheAlignedZero(size_t size)
{
    return memoryAllocateAlignedZero(size, kCpuLineCacheSize);
}

void memoryFreeAligned(void *ptr)
{
    if (ptr == NULL)
    {
        return;
    }

    memoryFree(((void **) ptr)[-1]);
}

#if ! ALLOCATOR_BYPASS

/**
 * @brief Initialize mimalloc runtime options.
 */
void memorymanagerInit(void)
{
    // assert(state == NULL);
    // state = memorymanagerCreateDedicatedMemory();
    // return state;

    mi_option_enable(mi_option_allow_large_os_pages);
    mi_option_enable(mi_option_eager_commit);
    mi_option_enable(mi_option_large_os_pages);
    // mi_option_set(mi_option_reserve_huge_os_pages, 1);
}

struct dedicated_memory_s
{
    wmutex_t     mut;
    mi_heap_t   *mi_heap;
    unsigned int free_counter;
};

enum
{
    kFreeThreShouldCounter = 64
};

void memorymanagerSetState(dedicated_memory_t *new_state)
{
    discard new_state;

    // assert(state == NULL);
    // state = new_state;
}

dedicated_memory_t *memorymanagerCreateDedicatedMemory(void)
{
    return NULL;

    // dedicated_memory_t *dm = malloc(sizeof(dedicated_memory_t));
    // *dm                    = (struct dedicated_memory_s) {.free_counter = 0, .mi_heap = mi_heap_new()};
    // mutexInit(&dm->mut);
    // return dm;
}

/*

    Note: mimalloc has its own thred local heaps, makes no sense if we uses dedicated mem and mutex for it.

*/
void *memoryAllocate(size_t size)
{
    void *ptr = mi_malloc(size);
#ifdef DEBUG
    memorySet(ptr, 0XBE, size);
#endif
    return ptr;
}
void *memoryReAllocate(void *ptr, size_t size)
{
    return mi_realloc(ptr, size);
}

void *memoryCalloc(size_t n, size_t size)
{
    return mi_calloc(n, size);
}

void memoryFree(void *ptr)
{
    mi_free(ptr);
}

/*

    Note: temporarily map to default allocators since mimalloc has no api for dedicated memory pools

*/

void *memoryDedicatedAllocate(dedicated_memory_t *dm, size_t size)
{
    discard dm;

    return memoryAllocate(size);
    // mutexLock(&dm->mut);
    // void *ptr = mi_heap_malloc(dm->mi_heap, size);
    // mutexUnlock(&dm->mut);
    // return ptr;
}
void *memoryDedicatedReallocate(dedicated_memory_t *dm, void *ptr, size_t size)
{
    discard dm;

    return memoryReAllocate(ptr, size);

    // mutexLock(&dm->mut);
    // void *newptr = mi_heap_realloc(dm->mi_heap, ptr, size);
    // mutexUnlock(&dm->mut);
    // return newptr;
}
void memoryDedicatedFree(dedicated_memory_t *dm, void *ptr)
{
    discard dm;

    memoryFree(ptr);

    // mutexLock(&dm->mut);
    // wof_free(dm->mi_heap, ptr);
    // if (dm->free_counter++ > kFreeThreShouldCounter)
    // {
    //     wof_gc(dm->mi_heap);
    //     dm->free_counter = 0;
    // }
    // mutexUnlock(&dm->mut);
}

#else

/**
 * @brief Initialize allocator in bypass mode (no-op).
 */
void memorymanagerInit(void)
{
}

void *memoryAllocate(size_t size)
{
    void *ptr = malloc(size);
#ifdef DEBUG
    memorySet(ptr, 0XBE, size);
#endif
    return ptr;
}

void *memoryReAllocate(void *ptr, size_t size)
{
    return realloc(ptr, size);
}

void *memoryCalloc(size_t n, size_t size)
{
    return calloc(n, size);
}

void memoryFree(void *ptr)
{
    free(ptr);
}

dedicated_memory_t *memorymanagerCreateDedicatedMemory(void)
{
    return NULL;
}

void *memoryDedicatedAllocate(dedicated_memory_t *dm, size_t size)
{
    discard dm;

    return memoryAllocate(size);
}

void *memoryDedicatedReallocate(dedicated_memory_t *dm, void *ptr, size_t size)
{
    discard dm;

    return memoryReAllocate(ptr, size);
}

void memoryDedicatedFree(dedicated_memory_t *dm, void *ptr)
{
    discard dm;

    memoryFree(ptr);
}

#endif

/**
 * @brief Allocate memory and zero-initialize it.
 *
 * @param size Allocation size.
 * @return void* Zeroed allocation.
 */
void *memoryAllocateZero(size_t size)
{
    void *ptr = memoryAllocate(size);
    memorySet(ptr, 0, size);
    return ptr;
}
