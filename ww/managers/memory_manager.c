#include "memory_manager.h"
#include "hmutex.h"
#include "mimalloc.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct dedicated_memory_s
{
    hhybridmutex_t mut;
    mi_heap_t     *mi_heap;
    unsigned int   free_counter;
};
enum
{
    kFreeThreShouldCounter = 64
};

#ifdef ALLOCATOR_BYPASS

dedicated_memory_t *createWWMemoryManager(void)
{
    return NULL;
}

dedicated_memory_t *getWWMemoryManager(void)
{
    return NULL;
}

void setWWMemoryManager(dedicated_memory_t *new_state)
{
    (void) new_state;
}

dedicated_memory_t *createWWDedicatedMemory(void)
{
    return NULL;
}

#else

static dedicated_memory_t *state;

dedicated_memory_t *createWWMemoryManager(void)
{

    return NULL;
    // assert(state == NULL);
    // state = createWWDedicatedMemory();
    // return state;
}

dedicated_memory_t *getWWMemoryManager(void)
{
    return state;
}

void setWWMemoryManager(dedicated_memory_t *new_state)
{
    (void) new_state;
    
    // assert(state == NULL);
    // state = new_state;
}

dedicated_memory_t *createWWDedicatedMemory(void)
{
    return NULL;

    // dedicated_memory_t *dm = malloc(sizeof(dedicated_memory_t));
    // *dm                    = (struct dedicated_memory_s) {.free_counter = 0, .mi_heap = mi_heap_new()};
    // hhybridmutex_init(&dm->mut);
    // return dm;
}

/*

    Note: mimalloc has its own thred local heaps, makes no sense if we uses dedicated mem and mutex for it.

*/
void *wwmGlobalMalloc(size_t size)
{
    return mi_malloc(size);
}
void *wwmGlobalRealloc(void *ptr, size_t size)
{
    return mi_realloc(ptr, size);
}
void wwmGlobalFree(void *ptr)
{
    mi_free(ptr);
}


/*

    Note: temporarily map to default allocators since mimalloc has no api for dedicated memory pools

*/

void *wwmDedicatedMalloc(dedicated_memory_t *dm, size_t size)
{
    (void) dm;

    return wwmGlobalMalloc(size);
    // hhybridmutex_lock(&dm->mut);
    // void *ptr = mi_heap_malloc(dm->mi_heap, size);
    // hhybridmutex_unlock(&dm->mut);
    // return ptr;
}
void *wwmDedicatedRealloc(dedicated_memory_t *dm, void *ptr, size_t size)
{
    (void) dm;

    return wwmGlobalRealloc(ptr,size);

    // hhybridmutex_lock(&dm->mut);
    // void *newptr = mi_heap_realloc(dm->mi_heap, ptr, size);
    // hhybridmutex_unlock(&dm->mut);
    // return newptr;
}
void wwmDedicatedFree(dedicated_memory_t *dm, void *ptr)
{
    (void) dm;

    wwmGlobalFree(ptr);

    // hhybridmutex_lock(&dm->mut);
    // wof_free(dm->mi_heap, ptr);
    // if (dm->free_counter++ > kFreeThreShouldCounter)
    // {
    //     wof_gc(dm->mi_heap);
    //     dm->free_counter = 0;
    // }
    // hhybridmutex_unlock(&dm->mut);
}

#endif
