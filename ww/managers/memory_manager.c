#include "memory_manager.h"
#include "mimalloc.h"
#include "wmutex.h"


#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void memorymanagerInit(void)
{
    // assert(state == NULL);
    // state = memorymanagerCreateDedicatedMemory();
    // return state;
}

#ifndef ALLOCATOR_BYPASS

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
    (void) new_state;

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
    return mi_malloc(size);
}
void *memoryReAllocate(void *ptr, size_t size)
{
    return mi_realloc(ptr, size);
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
    (void) dm;

    return memoryAllocate(size);
    // mutexLock(&dm->mut);
    // void *ptr = mi_heap_malloc(dm->mi_heap, size);
    // mutexUnlock(&dm->mut);
    // return ptr;
}
void *memoryDedicatedReallocate(dedicated_memory_t *dm, void *ptr, size_t size)
{
    (void) dm;

    return memoryReAllocate(ptr, size);

    // mutexLock(&dm->mut);
    // void *newptr = mi_heap_realloc(dm->mi_heap, ptr, size);
    // mutexUnlock(&dm->mut);
    // return newptr;
}
void memoryDedicatedFree(dedicated_memory_t *dm, void *ptr)
{
    (void) dm;

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

void *memoryAllocate(size_t size)
{
    void* ptr = malloc(size);
#ifdef DEBUG
    memorySet(ptr, 0XBE, size);
#endif
    return ptr;
}

void *memoryReAllocate(void *ptr, size_t size)
{
    return realloc(ptr, size);
}

void memoryFree(void *ptr)
{
    free(ptr);
}

dedicated_memory_t *memorymanagerCreateDedicatedMemory(void){
    return NULL;
}

void *memoryDedicatedAllocate(dedicated_memory_t *dm, size_t size)
{
    (void) dm;

    return memoryAllocate(size);
}

void *memoryDedicatedReallocate(dedicated_memory_t *dm, void *ptr, size_t size)
{
    (void) dm;

    return memoryReAllocate(ptr, size);
}

void memoryDedicatedFree(dedicated_memory_t *dm, void *ptr)
{
    (void) dm;

    memoryFree(ptr);
}

#endif
