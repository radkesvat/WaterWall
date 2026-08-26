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

void *eventloopMalloc(size_t size)
{
    atomicIncRelaxed(&s_alloc_cnt);
    void *ptr = memoryAllocate(size);
    if (! ptr)
    {
        printError("malloc failed!\n");
        exit(-1);
    }
    return ptr;
}

void *eventloopRealloc(void *oldptr, size_t newsize, size_t oldsize)
{
    atomicIncRelaxed(&s_alloc_cnt);
    if (oldptr)
        atomicIncRelaxed(&s_free_cnt);
    void *ptr = memoryReAllocate(oldptr, newsize);
    if (! ptr)
    {
        printError("realloc failed!\n");
        exit(-1);
    }
    if (newsize > oldsize)
    {
        memoryZero((char *) ptr + oldsize, newsize - oldsize);
    }
    return ptr;
}

void *eventloopCalloc(size_t nmemb, size_t size)
{
    atomicIncRelaxed(&s_alloc_cnt);
    void *ptr = memoryAllocateZero(nmemb * size);
    if (! ptr)
    {
        printError("calloc failed!\n");
        exit(-1);
    }

    return ptr;
}

void *eventloopZalloc(size_t size)
{
    atomicIncRelaxed(&s_alloc_cnt);
    void *ptr = memoryAllocateZero(size);
    if (! ptr)
    {
        printError("malloc failed!\n");
        exit(-1);
    }
    return ptr;
}

void *eventloopTryZalloc(size_t size)
{
#ifdef WW_EVENT_MEMORY_TEST_SEAM
    if (atomicExchangeExplicit(&s_fail_next_try_zalloc, false, memory_order_acq_rel))
    {
        return NULL;
    }
#endif

    /* MI_XMALLOC makes the ordinary memoryAllocate() family fail-fast. Use
     * the unoverridden CRT family for this deliberately recoverable boundary;
     * MI_OVERRIDE is disabled by the build. */
    void *ptr = calloc(1, size);
    if (ptr != NULL)
    {
        atomicIncRelaxed(&s_alloc_cnt);
    }
    return ptr;
}

void eventloopFree(void *ptr)
{
    if (ptr)
    {
        memoryFree(ptr);
        ptr = NULL;
        atomicIncRelaxed(&s_free_cnt);
    }
}

void eventloopTryFree(void *ptr)
{
    if (ptr != NULL)
    {
        free(ptr);
        atomicIncRelaxed(&s_free_cnt);
    }
}
