#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


// #define ALLOCATOR_BYPASS // switch to stdlib allocators




struct dedicated_memory_s;
typedef struct dedicated_memory_s dedicated_memory_t;

/// opens global memory manager (call this once before first usage of global ww_mem functions below)
void initMemoryManager(void);


/// set the memory manager global state
void setMemoryManager(dedicated_memory_t *new_state);

dedicated_memory_t *createWWDedicatedMemory(void);

/// malloc, free and realloc (thread-safe).

#ifdef ALLOCATOR_BYPASS
#include <stdlib.h>

static inline void *globalMalloc(size_t size)
{
    return malloc(size);
}
static inline void *globalRealloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}
static inline void globalFree(void *ptr)
{
    free(ptr);
}

static inline void *dedicatedMalloc(dedicated_memory_t *dm, size_t size)
{
    (void) dm;
    return malloc(size);
}
static inline void *dedicatedRealloc(dedicated_memory_t *dm, void *ptr, size_t size)
{
    (void) dm;
    return realloc(ptr, size);
}
static inline void dedicatedFree(dedicated_memory_t *dm, void *ptr)
{
    (void) dm;
    free(ptr);
}

#else

void *globalMalloc(size_t size);
void *globalRealloc(void *ptr, size_t size);
void  globalFree(void *ptr);

void *dedicatedMalloc(dedicated_memory_t *dm, size_t size);
void *dedicatedRealloc(dedicated_memory_t *dm, void *ptr, size_t size);
void  dedicatedFree(dedicated_memory_t *dm, void *ptr);

#endif
