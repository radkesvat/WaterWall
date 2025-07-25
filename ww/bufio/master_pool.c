#include "master_pool.h"

/**
 * Default create handler for the master pool.
 * @param pool The master pool.
 * @param userdata User data passed to the create handler.
 * @return A pointer to the created pool item.
 */
static master_pool_item_t *defaultCreateHandle(master_pool_t *pool, void *userdata)
{
    discard pool;
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
static void defaultDestroyHandle(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    discard pool;
    discard userdata;
    discard item;
    printError("MasterPool CallBack is not set. this is a bug");
    terminateProgram(1);
}

/**
 * Creates a master pool with a specified capacity.
 * @param pool_width The width of the pool.
 * @return A pointer to the created master pool.
 */
master_pool_t *masterpoolCreateWithCapacity(uint32_t pool_width)
{

    pool_width = max((uint32_t) 1, pool_width);
    // half of the pool is used, other half is free at startup
    pool_width = 2 * pool_width;

    const unsigned long container_len = pool_width * sizeof(master_pool_item_t *);

    size_t memsize = (sizeof(master_pool_t) + container_len);
    // ensure we have enough space to offset the allocation by line cache (for alignment)
    memsize = ALIGN2(memsize + ((kCpuLineCacheSize + 1) / 2), kCpuLineCacheSize);

    // check for overflow
    if (memsize < sizeof(master_pool_t))
    {
        printError("buffer size out of range");
        terminateProgram(1);
    }

    // allocate memory, placing master_pool_t at a line cache address boundary
    uintptr_t ptr = (uintptr_t) memoryAllocate(memsize);


    // align pointer to line cache boundary
    master_pool_t *pool_ptr = (master_pool_t *) ALIGN2(ptr, kCpuLineCacheSize); // NOLINT

#ifdef DEBUG
    memorySet(pool_ptr, 0xEB, sizeof(master_pool_t) + container_len);
#endif

    master_pool_t pool = {.memptr              = (void *) ptr,
                          .cap                 = pool_width,
                          .len                 = 0,
                          .create_item_handle  = defaultCreateHandle,
                          .destroy_item_handle = defaultDestroyHandle};

    memoryCopy(pool_ptr, &pool, sizeof(master_pool_t));
    mutexInit(&(pool_ptr->mutex));
    atomicStoreExplicit(&(pool_ptr->len), 0, memory_order_relaxed);

    return pool_ptr;
}

/**
 * Installs create and destroy callbacks for the master pool.
 * @param pool The master pool.
 * @param create_h The handler to create pool items.
 * @param destroy_h The handler to destroy pool items.
 */
void masterpoolInstallCallBacks(master_pool_t *pool, MasterPoolItemCreateHandle create_h,
                                MasterPoolItemDestroyHandle destroy_h)
{
    mutexLock(&(pool->mutex));
    pool->create_item_handle  = create_h;
    pool->destroy_item_handle = destroy_h;
    mutexUnlock(&(pool->mutex));
}

/**
 * Makes the master pool empty without destroying it.
 * @param pool The master pool to make empty.
 * @param userdata User data passed to the destroy handler.
 */
void masterpoolMakeEmpty(master_pool_t *pool, void *userdata)
{
    mutexLock(&(pool->mutex));
    const uint32_t current_len = (uint32_t) atomicLoadExplicit(&(pool->len), memory_order_relaxed);
    for (uint32_t i = 0; i < current_len; i++)
    {
        pool->destroy_item_handle(pool, pool->available[i], userdata);
    }
    atomicStoreExplicit(&(pool->len), 0, memory_order_relaxed);
    mutexUnlock(&(pool->mutex));
}

/**
 * Destroys the master pool and frees its resources.
 * @param pool The master pool to destroy.
 */
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
    memoryFree(pool->memptr);
}
