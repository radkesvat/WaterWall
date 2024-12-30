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

static inline void *memoryAllocate(size_t size)
{
    return malloc(size);
}
static inline void *memoryReAllocate(void *ptr, size_t size)
{
    return realloc(ptr, size);
}
static inline void memoryFree(void *ptr)
{
    free(ptr);
}

static inline void *memoryDedicatedAllocate(dedicated_memory_t *dm, size_t size)
{
    (void) dm;
    return malloc(size);
}
static inline void *memoryDedicatedReallocate(dedicated_memory_t *dm, void *ptr, size_t size)
{
    (void) dm;
    return realloc(ptr, size);
}
static inline void memoryDedicatedFree(dedicated_memory_t *dm, void *ptr)
{
    (void) dm;
    free(ptr);
}

#else

void *memoryAllocate(size_t size);
void *memoryReAllocate(void *ptr, size_t size);
void  memoryFree(void *ptr);

void *memoryDedicatedAllocate(dedicated_memory_t *dm, size_t size);
void *memoryDedicatedReallocate(dedicated_memory_t *dm, void *ptr, size_t size);
void  memoryDedicatedFree(dedicated_memory_t *dm, void *ptr);

#endif




static inline void memoryCopy(void *Dst, void const *Src, size_t Size)
{
    memcpy(Dst, Src, Size);
}

static inline void memoryMove(void *Dst, void const *Src, size_t Size)
{
    memmove(Dst, Src, Size);
}



