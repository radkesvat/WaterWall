#pragma once

#define ALLOCATOR_BYPASS // switch to stdlib allocators

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct dedicated_memory_s;
typedef struct dedicated_memory_s dedicated_memory_t;

/// opens global memory manager (call this once before first usage of global ww_mem functions below)
dedicated_memory_t *createWWMemoryManager(void);

/// get the memory manager global state
dedicated_memory_t *getWWMemoryManager(void);

/// set the memory manager global state
void setWWMemoryManager(dedicated_memory_t *new_state);

dedicated_memory_t *createWWDedicatedMemory(void);

/// malloc, free and realloc (thread-safe).

#ifdef ALLOCATOR_BYPASS
#include <stdlib.h>

static inline void *wwmGlobalMalloc(size_t size)
{
    return malloc(size);
}
static inline void *wwmGlobalRealloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}
static inline void wwmGlobalFree(void *ptr)
{
    free(ptr);
}

static inline void *wwmDedicatedMalloc(dedicated_memory_t *dm, size_t size)
{
    (void) dm;
    return malloc(size);
}
static inline void *wwmDedicatedRealloc(dedicated_memory_t *dm, void *ptr, size_t size)
{
    (void) dm;
    return realloc(ptr, size);
}
static inline void wwmDedicatedFree(dedicated_memory_t *dm, void *ptr)
{
    (void) dm;
    free(ptr);
}

#else

void *wwmGlobalMalloc(size_t size);
void *wwmGlobalRealloc(void *ptr, size_t size);
void  wwmGlobalFree(void *ptr);

void *wwmDedicatedMalloc(dedicated_memory_t *dm, size_t size);
void *wwmDedicatedRealloc(dedicated_memory_t *dm, void *ptr, size_t size);
void  wwmDedicatedFree(dedicated_memory_t *dm, void *ptr);

#endif
