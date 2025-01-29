#pragma once

#include "wlibc.h"
#include "wmutex.h"
#include "worker.h"

/*
    Master Pool

    In some cases, workers need to send data/buffers to each other, while each have a thread local pool

    therefore, thread local pools may keep running out of items, and there is a need for a thread-safe-pool

    thread local pools will fall back to the master pool instead of allocating more memory or freeing it and
    interacting with os, malloc,free; in a single batch allocation for a full charge with only 1 mutex lock


                                |-----------|
                                |           |
                                |           |
                                |           | -------------> |----------------|
                                |           |                | Worker 1 pools |
                                |           | <------------- |----------------|
                                |           |
                                |           |
                                |           |
                                |           |
                                |           | -------------> |----------------|
                                |           |                | Worker 2 pools |
                                |           | <------------- |----------------|
     |-----------|              |           |
     |  Malloc   | -----------> |  MASTER   |
     | --------  |              |           |
     |   Free    | <----------- |   POOL    |
     |-----------|              |           |
                                |           | -------------> |----------------|
                                |           |                | Worker 3 pools |
                                |           | <------------- |----------------|
                                |           |
                                |           |
                                |           |
                                |           |
                                |           | -------------> |----------------|
                                |           |                | Worker 4 pools |
                                |           | <------------- |----------------|
                                |           |
                                |           |
                                |-----------|


*/

struct master_pool_s;
typedef void master_pool_item_t;

// pool handles are assumed to be thread safe
typedef master_pool_item_t *(*MasterPoolItemCreateHandle)(struct master_pool_s *pool, void *userdata);
typedef void (*MasterPoolItemDestroyHandle)(struct master_pool_s *pool, master_pool_item_t *item, void *userdata);

/*
    do not read this pool properties from the struct, its a multi-threaded object
*/

typedef struct master_pool_s
{
    void                       *memptr;
    wmutex_t                    mutex;
    MasterPoolItemCreateHandle  create_item_handle;
    MasterPoolItemDestroyHandle destroy_item_handle;
    atomic_uint                 len;
    const uint32_t              cap;
    void                       *available[];
} ATTR_ALIGNED_LINE_CACHE master_pool_t;

/**
 * Retrieves a specified number of items from the master pool.
 * @param pool The master pool.
 * @param iptr Pointer to the array where the items will be stored.
 * @param count The number of items to retrieve.
 * @param userdata User data passed to the create handler.
 */
static inline void masterpoolGetItems(master_pool_t *const pool, master_pool_item_t const **const iptr,
                                      const uint32_t count, void *userdata)
{
    // for (uint32_t i = 0; i < count; i++)
    // {
    //     iptr[i] = pool->create_item_handle(pool, userdata);
    // }
    // return;
    uint32_t i = 0;

    if (atomicLoadExplicit(&(pool->len), memory_order_relaxed) > 0)
    {
        mutexLock(&(pool->mutex));
        const uint32_t tmp_len  = atomicLoadExplicit(&(pool->len), memory_order_relaxed);
        const uint32_t consumed = min(tmp_len, count);

        if (consumed > 0)
        {
            atomicAddExplicit(&(pool->len), -consumed, memory_order_relaxed);
            const uint32_t pbase = (tmp_len - consumed);
            for (; i < consumed; i++)
            {
                iptr[i] = pool->available[pbase + i];
            }
        }
        mutexUnlock(&(pool->mutex));
    }

    for (; i < count; i++)
    {
        iptr[i] = pool->create_item_handle(pool, userdata);
    }
}

/**
 * Reuses a specified number of items by returning them to the master pool.
 * @param pool The master pool.
 * @param iptr Pointer to the array of items to be reused.
 * @param count The number of items to reuse.
 * @param userdata User data passed to the destroy handler.
 */
static inline void masterpoolReuseItems(master_pool_t *const pool, master_pool_item_t **const iptr,
                                        const uint32_t count, void *userdata)
{
    // for (uint32_t i = 0; i < count; i++)
    // {
    //     pool->destroy_item_handle(pool, iptr[i], userdata);
    // }
    // return;

    if (pool->cap == atomicLoadExplicit(&(pool->len), memory_order_relaxed))
    {
        for (uint32_t i = 0; i < count; i++)
        {
            pool->destroy_item_handle(pool, iptr[i], userdata);
        }
        return;
    }

    uint32_t i = 0;

    mutexLock(&(pool->mutex));

    const uint32_t tmp_len  = atomicLoadExplicit(&(pool->len), memory_order_relaxed);
    const uint32_t consumed = min(pool->cap - tmp_len, count);

    atomicAddExplicit(&(pool->len), consumed, memory_order_relaxed);

    for (; i < consumed; i++)
    {
        pool->available[i + tmp_len] = iptr[i];
    }

    mutexUnlock(&(pool->mutex));

    for (; i < count; i++)
    {
        pool->destroy_item_handle(pool, iptr[i], userdata);
    }
}

/**
 * Installs create and destroy callbacks for the master pool.
 * @param pool The master pool.
 * @param create_h The handler to create pool items.
 * @param destroy_h The handler to destroy pool items.
 */
void masterpoolInstallCallBacks(master_pool_t *pool, MasterPoolItemCreateHandle create_h,
                                MasterPoolItemDestroyHandle destroy_h);

/**
 * Creates a master pool with a specified capacity.
 * @param pool_width The width of the pool.
 * @return A pointer to the created master pool.
 */
master_pool_t *masterpoolCreateWithCapacity(uint32_t pool_width);

/**
 * Destroys the master pool and frees its resources.
 * @param pool The master pool to destroy.
 */
void masterpoolDestroy(master_pool_t *pool);
