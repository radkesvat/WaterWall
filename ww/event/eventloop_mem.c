#include "eventloop_mem.h"

#ifdef OS_DARWIN
#include <mach-o/dyld.h> // for _NSGetExecutablePath
#endif

#include "watomic.h"
#include "managers/memory_manager.h"

#ifndef RAND_MAX
#define RAND_MAX 2147483647
#endif

static atomic_long s_alloc_cnt = (0);
static atomic_long s_free_cnt = (0);

long eventloopAllocCount(void) {
    return s_alloc_cnt;
}

long eventloopFreeCount(void) {
    return s_free_cnt;
}


void* eventloopMalloc(size_t size) {
    atomicInc(&s_alloc_cnt);
    void* ptr = memoryAllocate(size);
    if (!ptr) {
        fprintf(stderr, "malloc failed!\n");
        exit(-1);
    }
    return ptr;
}

void* eventloopRealloc(void* oldptr, size_t newsize, size_t oldsize) {
    atomicInc(&s_alloc_cnt);
    if (oldptr) atomicInc(&s_free_cnt);
    void* ptr = memoryReAllocate(oldptr, newsize);
    if (!ptr) {
        fprintf(stderr, "realloc failed!\n");
        exit(-1);
    }
    if (newsize > oldsize) {
        memorySet((char*)ptr + oldsize, 0, newsize - oldsize);
    }
    return ptr;
}

void* eventloopCalloc(size_t nmemb, size_t size) {
    atomicInc(&s_alloc_cnt);
    void* ptr = memoryAllocate(nmemb* size);
    if (!ptr) {
        fprintf(stderr, "calloc failed!\n");
        exit(-1);
    }
    memorySet(ptr, 0,nmemb* size);

    return ptr;
}

void* eventloopZalloc(size_t size) {
    atomicInc(&s_alloc_cnt);
    void* ptr = memoryAllocate(size);
    if (!ptr) {
        fprintf(stderr, "malloc failed!\n");
        exit(-1);
    }
    memorySet(ptr, 0, size);
    return ptr;
}

void eventloopFree(void* ptr) {
    if (ptr) {
        memoryFree(ptr);
        ptr = NULL;
        atomicInc(&s_free_cnt);
    }
}
