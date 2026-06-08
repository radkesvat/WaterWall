/*
 * Implements mutex-based master pool operations shared across worker pools.
 */

#include "master_pool.h"

/**
 * Default create handler for the master pool.
 * @param pool The master pool.
 * @param userdata User data passed to the create handler.
 * @return A pointer to the created pool item.
 */
static master_pool_item_t *defaultCreateHandle(void *userdata)
{
    discard userdata;
    printError("MasterPool CallBack is not set. this is a bug");
    terminateProgram(1);
}

/**
 * Default destroy handler for the master pool.
 * @param pool The master pool.
 * @param item The pool item to destroy.
 * @param userdata User data passed to the destroy handler.
 */
static void defaultDestroyHandle(master_pool_item_t *item)
{
    discard item;
    printError("MasterPool CallBack is not set. this is a bug");
    terminateProgram(1);
}

master_pool_t *masterpoolCreateWithCapacity(uint32_t pool_width)
{

    pool_width = max((uint32_t) 1, pool_width);
    // half of the pool is used, other half is free at startup
    pool_width = 2 * pool_width;

    // Calculate all sizes in size_t.
    const uint64_t container_len64 = ((uint64_t) pool_width) * ((uint64_t) sizeof(master_pool_item_t *));
    if (container_len64 > ((uint64_t) SIZE_MAX))
    {
        printError("buffer size out of range");
        terminateProgram(1);
    }
    const size_t container_len = (size_t) container_len64;

    if (container_len > (SIZE_MAX - sizeof(master_pool_t)))
    {
        printError("buffer size out of range");
        terminateProgram(1);
    }
    const size_t required_size = sizeof(master_pool_t) + container_len;

    // allocate memory, placing master_pool_t at a line cache address boundary
    master_pool_t *pool_ptr = memoryAllocateCacheAligned(required_size);
    if (pool_ptr == NULL)
    {
        printError("buffer size out of range");
        terminateProgram(1);
    }

#ifdef DEBUG
    memorySet(pool_ptr, 0xEB, required_size);
#endif

    master_pool_t pool = {.memptr              = pool_ptr,
                          .cap                 = pool_width,
                          .len                 = 0,
                          .create_item_handle  = defaultCreateHandle,
                          .destroy_item_handle = defaultDestroyHandle};

    memoryCopy(pool_ptr, &pool, sizeof(master_pool_t));
    mutexInit(&(pool_ptr->mutex));
    atomicStoreExplicit(&(pool_ptr->len), 0, memory_order_relaxed);

    return pool_ptr;
}

void masterpoolInstallCallBacks(master_pool_t *pool, MasterPoolItemCreateHandle create_h,
                                MasterPoolItemDestroyHandle destroy_h)
{
    mutexLock(&(pool->mutex));
    pool->create_item_handle  = create_h;
    pool->destroy_item_handle = destroy_h;
    mutexUnlock(&(pool->mutex));
}

void masterpoolMakeEmpty(master_pool_t *pool)
{
    mutexLock(&(pool->mutex));
    const uint32_t current_len = (uint32_t) atomicLoadExplicit(&(pool->len), memory_order_relaxed);
    for (uint32_t i = 0; i < current_len; i++)
    {
        pool->destroy_item_handle(pool->available[i]);
    }
    atomicStoreExplicit(&(pool->len), 0, memory_order_relaxed);
    mutexUnlock(&(pool->mutex));
}

void masterpoolDestroy(master_pool_t *pool)
{
    mutexLock(&(pool->mutex));
    if (pool->len != 0)
    {
        // wmutex_t* wbs = NULL; some bullshit code that was used to debug
        // mutexUnlock(wbs);
        printError("MasterPool: Destroying pool with items in it, this is a bug");
        terminateProgram(1);
    }
    mutexUnlock(&(pool->mutex));

    mutexDestroy(&pool->mutex);
    memoryFreeAligned(pool->memptr);
}
