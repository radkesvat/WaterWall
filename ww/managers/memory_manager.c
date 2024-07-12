#include "memory_manager.h"
#include "alloc-engine/wof_allocator.h"
#include "hmutex.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct dedicated_memory_s
{
    hhybridmutex_t   mut;
    wof_allocator_t *wof_state;
    unsigned int     free_counter;
};

static dedicated_memory_t *state;

enum
{
    kFreeThreShouldCounter = 64
};

#ifdef ALLOCATOR_BYPASS

dedicated_memory_t *createWWMemoryManager()
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

dedicated_memory_t *createWWDedicatedMemory()
{
    return NULL;
}

#else

dedicated_memory_t *createWWMemoryManager(void)
{
    assert(state == NULL);
    state = createWWDedicatedMemory();
    return state;
}

dedicated_memory_t *getWWMemoryManager(void)
{
    return state;
}

void setWWMemoryManager(dedicated_memory_t *new_state)
{
    assert(state == NULL);
    state = new_state;
}

dedicated_memory_t *createWWDedicatedMemory(void)
{
    dedicated_memory_t *dm = malloc(sizeof(dedicated_memory_t));
    *dm                    = (struct dedicated_memory_s) {.free_counter = 0, .wof_state = wof_allocator_new()};
    hhybridmutex_init(&dm->mut);
    return dm;
}

void *wwmGlobalMalloc(size_t size)
{
    return wwmDedicatedMalloc(state, size);
}
void *wwmGlobalRealloc(void *ptr, size_t size)
{
    return wwmDedicatedRealloc(state, ptr, size);
}
void wwmGlobalFree(void *ptr)
{
    wwmDedicatedFree(state, ptr);
}

void *wwmDedicatedMalloc(dedicated_memory_t *dm, size_t size)
{
    hhybridmutex_lock(&dm->mut);
    void *ptr = wof_alloc(dm->wof_state, size);
    hhybridmutex_unlock(&dm->mut);
    return ptr;
}
void *wwmDedicatedRealloc(dedicated_memory_t *dm, void *ptr, size_t size)
{
    hhybridmutex_lock(&dm->mut);
    void *newptr = wof_realloc(dm->wof_state, ptr, size);
    hhybridmutex_unlock(&dm->mut);
    return newptr;
}
void wwmDedicatedFree(dedicated_memory_t *dm, void *ptr)
{
    hhybridmutex_lock(&dm->mut);
    wof_free(dm->wof_state, ptr);
    if (state->free_counter++ > kFreeThreShouldCounter)
    {
        wof_gc(state->wof_state);
        state->free_counter = 0;
    }
    hhybridmutex_unlock(&dm->mut);
}

#endif
