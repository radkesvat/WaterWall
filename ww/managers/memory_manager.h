#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// #define ALLOCATOR_BYPASS // switch to stdlib allocators

struct dedicated_memory_s;
typedef struct dedicated_memory_s dedicated_memory_t;

/// opens global memory manager (call this once before first usage of global functions below)
void initMemoryManager(void);


/// set the memory manager global state
void setMemoryManager(dedicated_memory_t *new_state);

dedicated_memory_t *createGlobalStateDedicatedMemory(void);

/// malloc, free and realloc (thread-safe).

void *memoryAllocate(size_t size);
void *memoryReAllocate(void *ptr, size_t size);
void  memoryFree(void *ptr);

void *memoryDedicatedAllocate(dedicated_memory_t *dm, size_t size);
void *memoryDedicatedReallocate(dedicated_memory_t *dm, void *ptr, size_t size);
void  memoryDedicatedFree(dedicated_memory_t *dm, void *ptr);




