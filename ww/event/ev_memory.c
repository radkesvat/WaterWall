#include "ev_memory.h"

#ifdef OS_DARWIN
#include <mach-o/dyld.h> // for _NSGetExecutablePath
#endif

#include "watomic.h"

#ifndef RAND_MAX
#define RAND_MAX 2147483647
#endif

static atomic_long s_alloc_cnt = (0);
static atomic_long s_free_cnt  = (0);

#ifdef WW_EVENT_MEMORY_TEST_SEAM
static atomic_bool s_fail_next_try_zalloc;

void eventloopTestFailNextTryZalloc(void)
{
    atomicStoreExplicit(&s_fail_next_try_zalloc, true, memory_order_release);
}
#endif

long eventloopAllocCount(void)
{
    return (long) s_alloc_cnt;
}

long eventloopFreeCount(void)
{
    return (long) s_free_cnt;
}

static void *eventloopCountAllocation(void *ptr)
{
    if (ptr != NULL)
    {
        atomicIncRelaxed(&s_alloc_cnt);
    }
    return ptr;
}

void *eventloopMalloc(size_t size)
{
    return eventloopCountAllocation(memoryAllocate(size));
}

void *eventloopRealloc(void *oldptr, size_t newsize, size_t oldsize)
{
    if (oldptr)
        atomicIncRelaxed(&s_free_cnt);
    void *ptr = memoryReAllocate(oldptr, newsize);
    if (newsize > oldsize)
    {
        memoryZero((char *) ptr + oldsize, newsize - oldsize);
    }
    return eventloopCountAllocation(ptr);
}

void *eventloopCalloc(size_t nmemb, size_t size)
{
    return eventloopCountAllocation(memoryCalloc(nmemb, size));
}

void *eventloopZalloc(size_t size)
{
    return eventloopCountAllocation(memoryAllocateZero(size));
}

void *eventloopTryZalloc(size_t size)
{
#ifdef WW_EVENT_MEMORY_TEST_SEAM
    if (atomicExchangeExplicit(&s_fail_next_try_zalloc, false, memory_order_acq_rel))
    {
        return NULL;
    }
#endif

    return eventloopCountAllocation(memoryTryAllocateZero(size));
}

void eventloopFree(void *ptr)
{
    if (ptr)
    {
        memoryFree(ptr);
        atomicIncRelaxed(&s_free_cnt);
    }
}
