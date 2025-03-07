#pragma once

#include "wlibc.h"

/**
 * @file master_pool.h
 * @brief Lock-free implementation of a master object pool for sharing resources across worker threads.
 * 
 * The master pool provides a thread-safe way to allocate and recycle objects without
 * repeatedly calling malloc/free. Worker pools can retrieve objects from or return objects
 * to the master pool when their local pools are depleted or have excess items.
 */

/*
    Master Pool (Lock-Free Implementation)

    In some cases, workers need to send data/buffers to each other, while each have a thread local pool

    therefore, thread local pools may keep running out of items, and there is a need for a thread-safe-pool

    thread local pools will fall back to the master pool instead of allocating more memory or freeing it and
    interacting with os, malloc,free; in a single batch allocation for a full charge with only atomic operations


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

/**
 * @brief Lock-free implementation of the master pool structure.
 * 
 * The pool uses atomic operations to safely manage item allocation and recycling
 * across multiple threads without requiring locks.
 */
typedef struct master_pool_s
{
    void                       *memptr;
    MasterPoolItemCreateHandle  create_item_handle;
    MasterPoolItemDestroyHandle destroy_item_handle;
    
    // Head index for the lock-free stack
    atomic_uint                 head;
    
    // Items counter
    atomic_uint                 count;
    
    // Maximum capacity
    uint32_t              cap;
    
    // Next pointers for the lock-free stack (indices, not actual pointers)
    atomic_uint                *next;
    
    // The pool items
    void                      **items;
} master_pool_t;

/**
 * @brief Retrieves a specified number of items from the master pool.
 *
 * Uses atomic operations to safely remove items from the pool without locking.
 * If the pool doesn't have enough items, it calls the create handler to make new ones.
 *
 * @param pool The master pool.
 * @param iptr Pointer to the array where the items will be stored.
 * @param count The number of items to retrieve.
 * @param userdata User data passed to the create handler.
 */
static inline void masterpoolGetItems(master_pool_t *const pool, master_pool_item_t const **const iptr,
                                      const uint32_t count, void *userdata)
{
    uint32_t acquired = 0;
    
    // Try to get items from the pool
    while (acquired < count && atomicLoad(&pool->count) > 0) {
        // Get the current head
        uint32_t old_head = atomicLoad(&pool->head);
        if (old_head == UINT32_MAX) {
            // Empty stack, break and create new items
            break;
        }
        
        // Get the next item in line
        uint32_t new_head = atomicLoad(&pool->next[old_head]);
        
        // Try to update the head with compare-and-swap
        if (atomicCompareExchange(&pool->head, &old_head, new_head)) {
            // Success! We got an item
            iptr[acquired++] = pool->items[old_head];
            atomicSub(&pool->count, 1);
        }
        // If CAS fails, another thread took the item, try again
    }
    
    // Create any remaining items needed
    for (; acquired < count; acquired++) {
        iptr[acquired] = pool->create_item_handle(pool, userdata);
    }
}

/**
 * @brief Reuses a specified number of items by returning them to the master pool.
 *
 * Uses atomic operations to safely add items back to the pool without locking.
 * If the pool is full, it calls the destroy handler to free the excess items.
 *
 * @param pool The master pool.
 * @param iptr Pointer to the array of items to be reused.
 * @param count The number of items to reuse.
 * @param userdata User data passed to the destroy handler.
 */
static inline void masterpoolReuseItems(master_pool_t *const pool, master_pool_item_t **const iptr,
                                        const uint32_t count, void *userdata)
{
    uint32_t returned = 0;
    
    // Try to return items to the pool while there's room
    while (returned < count && atomicLoad(&pool->count) < pool->cap) {
        // Find an empty slot in the next array
        uint32_t slot = returned;
        
        // Store the item
        pool->items[slot] = iptr[returned];
        
        // Get the current head
        uint32_t old_head = atomicLoad(&pool->head);
        
        // Set our next pointer to the current head
        atomicStore(&pool->next[slot], old_head);
        
        // Try to become the new head with compare-and-swap
        if (atomicCompareExchange(&pool->head, &old_head, slot)) {
            // Success! We added an item
            atomicAdd(&pool->count, 1);
            returned++;
        } else {
            // Someone else changed the head, try again
            continue;
        }
    }
    
    // Destroy any remaining items
    for (; returned < count; returned++) {
        pool->destroy_item_handle(pool, iptr[returned], userdata);
    }
}

/**
 * @brief Installs create and destroy callbacks for the master pool.
 * 
 * @param pool The master pool.
 * @param create_h The handler to create pool items.
 * @param destroy_h The handler to destroy pool items.
 */
void masterpoolInstallCallBacks(master_pool_t *pool, MasterPoolItemCreateHandle create_h,
                                MasterPoolItemDestroyHandle destroy_h);

/**
 * @brief Creates a master pool with a specified capacity.
 * 
 * @param capacity The maximum number of items the pool can hold.
 * @return A pointer to the created master pool.
 */
master_pool_t *masterpoolCreateWithCapacity(uint32_t capacity);

/**
 * @brief Destroys the master pool and frees its resources.
 * 
 * @param pool The master pool to destroy.
 */
void masterpoolDestroy(master_pool_t *pool);
