/**
 * @file master_pool.c
 * @brief Implementation of the lock-free master object pool.
 */

#include "master_pool.h"
#include "wdef.h"

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
 * @param capacity The maximum number of items the pool can hold.
 * @return A pointer to the created master pool.
 */
master_pool_t *masterpoolCreateWithCapacity(uint32_t capacity)
{
    capacity = max((uint32_t)1, capacity);
    
    // Calculate required memory size
    size_t items_size = capacity * sizeof(void*);
    size_t next_size = capacity * sizeof(atomic_uint);
    size_t total_size = sizeof(master_pool_t) + items_size + next_size;
    
    // Ensure alignment
    total_size = ALIGN2(total_size + ((kCpuLineCacheSize + 1) / 2), kCpuLineCacheSize);

    // Check for overflow
    if (total_size < sizeof(master_pool_t))
    {
        printError("buffer size out of range");
        terminateProgram(1);
    }

    // Allocate memory
    uintptr_t ptr = (uintptr_t)memoryAllocate(total_size);
    master_pool_t *pool = (master_pool_t *)ALIGN2(ptr, kCpuLineCacheSize);

    // Initialize the pool structure
    pool->memptr = (void*)ptr;
    pool->cap = capacity;
    pool->create_item_handle = defaultCreateHandle;
    pool->destroy_item_handle = defaultDestroyHandle;
    
    // Initialize atomic variables
    atomicStore(&pool->head, UINT32_MAX); // Empty stack marker
    atomicStore(&pool->count, 0);
    
    // Set up memory layout
    // Items array comes right after the master_pool_t structure
    pool->items = (void**)(pool + 1);
    
    // Next array comes after items array
    pool->next = (atomic_uint*)(((char*)pool->items) + items_size);
    
    // Initialize next array
    for (uint32_t i = 0; i < capacity; i++) {
        atomicStore(&pool->next[i], UINT32_MAX);
    }

    return pool;
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
    // No mutex needed, atomic exchange
    pool->create_item_handle = create_h;
    pool->destroy_item_handle = destroy_h;
    
    // Ensure memory ordering for callback installation
    atomicThreadFence(memory_order_release);
}

/**
 * Destroys the master pool and frees all items.
 * @param pool The master pool to destroy.
 */
void masterpoolDestroy(master_pool_t *pool)
{
    // Free any items still in the pool
    uint32_t head = atomicLoad(&pool->head);
    while (head != UINT32_MAX) {
        void* item = pool->items[head];
        head = atomicLoad(&pool->next[head]);
        
        // Destroy item if not NULL
        if (item) {
            pool->destroy_item_handle(pool, item, NULL);
        }
    }
    
    // Free the pool memory
    memoryFree(pool->memptr);
}
