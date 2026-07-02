#include "ev_memory.h"

#ifdef OS_DARWIN
#include <mach-o/dyld.h> // for _NSGetExecutablePath
#endif

#include "watomic.h"


#ifndef RAND_MAX
#define RAND_MAX 2147483647
#endif

static atomic_long s_alloc_cnt = (0);
static atomic_long s_free_cnt = (0);

long eventloopAllocCount(void) {
    return (long) s_alloc_cnt;
}

long eventloopFreeCount(void) {
    return (long) s_free_cnt;
}


void* eventloopMalloc(size_t size) {
    atomicIncRelaxed(&s_alloc_cnt);
    void* ptr = memoryAllocate(size);
    if (!ptr) {
        printError("malloc failed!\n");
        exit(-1);
    }
    return ptr;
}

void* eventloopRealloc(void* oldptr, size_t newsize, size_t oldsize) {
    atomicIncRelaxed(&s_alloc_cnt);
    if (oldptr) atomicIncRelaxed(&s_free_cnt);
    void* ptr = memoryReAllocate(oldptr, newsize);
    if (!ptr) {
        printError("realloc failed!\n");
        exit(-1);
    }
    if (newsize > oldsize) {
        memoryZero((char*)ptr + oldsize, newsize - oldsize);
    }
    return ptr;
}

void* eventloopCalloc(size_t nmemb, size_t size) {
    atomicIncRelaxed(&s_alloc_cnt);
    void* ptr = memoryAllocateZero(nmemb* size);
    if (!ptr) {
        printError("calloc failed!\n");
        exit(-1);
    }

    return ptr;
}

void* eventloopZalloc(size_t size) {
    atomicIncRelaxed(&s_alloc_cnt);
    void* ptr = memoryAllocateZero(size);
    if (!ptr) {
        printError("malloc failed!\n");
        exit(-1);
    }
    return ptr;
}

void eventloopFree(void* ptr) {
    if (ptr) {
        memoryFree(ptr);
        ptr = NULL;
        atomicIncRelaxed(&s_free_cnt);
    }
}
