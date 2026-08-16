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
    abortProgramNow(1);
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
    abortProgramNow(1);
}

static bool masterpoolTryComputeGeometry(uint32_t pool_width, uint32_t *capacity_out, size_t *allocation_size_out)
{
    if (capacity_out == NULL || allocation_size_out == NULL)
    {
        return false;
    }

    pool_width = max((uint32_t) 1, pool_width);
    // half of the pool is used, other half is free at startup
    if (pool_width > UINT32_MAX / 2U)
    {
        return false;
    }
    const uint32_t capacity = pool_width * 2U;

    size_t container_len;
    if (! memoryTryComputeArraySize(capacity, sizeof(master_pool_item_t *), &container_len) ||
        container_len > SIZE_MAX - sizeof(master_pool_t))
    {
        return false;
    }
    const size_t required_size = sizeof(master_pool_t) + container_len;
    if (! memoryAlignedAllocationSizeIsRepresentable(required_size, kCpuLineCacheSize))
    {
        return false;
    }

    *capacity_out        = capacity;
    *allocation_size_out = required_size;
    return true;
}

master_pool_item_t *masterpoolRequireCreatedItem(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    if (UNLIKELY(item == NULL))
    {
        printError("MasterPool: item creation returned NULL (pool=%p, userdata=%p)", (void *) pool, userdata);
        abortProgramNow(1);
    }
    return item;
}

master_pool_t *masterpoolCreateWithCapacity(uint32_t pool_width)
{
    uint32_t capacity;
    size_t   required_size;
    if (! masterpoolTryComputeGeometry(pool_width, &capacity, &required_size))
    {
        return NULL;
    }
    // allocate memory, placing master_pool_t at a line cache address boundary
    master_pool_t *pool_ptr = memoryAllocateCacheAligned(required_size);
    if (pool_ptr == NULL)
    {
        return NULL;
    }

#ifdef DEBUG
    memorySet(pool_ptr, 0xEB, required_size);
#endif

    master_pool_t pool = {.cap                 = capacity,
                          .len                 = 0,
                          .checked_out         = 0,
                          .create_item_handle  = defaultCreateHandle,
                          .destroy_item_handle = defaultDestroyHandle};

    memoryCopy(pool_ptr, &pool, sizeof(master_pool_t));
    if (UNLIKELY(! mutexTryInit(&pool_ptr->mutex)))
    {
        memoryFreeAligned(pool_ptr);
        return NULL;
    }
    atomicStoreExplicit(&(pool_ptr->len), 0, memory_order_relaxed);
    atomicStoreExplicit(&(pool_ptr->checked_out), 0, memory_order_relaxed);

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
    if (pool == NULL)
    {
        return;
    }
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
    if (pool == NULL)
    {
        return;
    }
    mutexLock(&(pool->mutex));
    if (masterpoolGetCheckedOut(pool) != 0)
    {
        printError("MasterPool: destroying a pool with %zu checked-out item(s)", masterpoolGetCheckedOut(pool));
        abortProgramNow(1);
    }
    if (pool->len != 0)
    {
        // wmutex_t* wbs = NULL; some bullshit code that was used to debug
        // mutexUnlock(wbs);
        printError("MasterPool: Destroying pool with items in it, this is a bug");
        abortProgramNow(1);
    }
    mutexUnlock(&(pool->mutex));

    mutexDestroy(&pool->mutex);
    memoryFreeAligned(pool);
}
