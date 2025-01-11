#include "master_pool.h"
#include "worker.h"


static master_pool_item_t* defaultCreateHandle(struct master_pool_s *pool, void *userdata)
{
    (void) pool;
    (void) userdata;
    printError("MasterPool Callback is not set. this is a bug");
    exit(1);
}

static void defaultDestroyHandle(struct master_pool_s *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    (void) userdata;
    (void) item;
    printError("MasterPool Callback is not set. this is a bug");
    exit(1);
}

master_pool_t *newMasterPoolWithCap(unsigned int pool_width)
{

    pool_width = max(1, pool_width);
    // half of the pool is used, other half is free at startup
    pool_width = 2 * pool_width;

    const unsigned long container_len = pool_width * sizeof(master_pool_item_t *);

    int64_t memsize = (int64_t) (sizeof(master_pool_t) + container_len);
    // ensure we have enough space to offset the allocation by line cache (for alignment)
    MUSTALIGN2(memsize + ((kCpuLineCacheSize + 1) / 2), kCpuLineCacheSize);
    memsize = ALIGN2(memsize + ((kCpuLineCacheSize + 1) / 2), kCpuLineCacheSize);

    // check for overflow
    if (memsize < (int64_t) sizeof(master_pool_t))
    {
        printError("buffer size out of range");
        exit(1);
    }

    // allocate memory, placing master_pool_t at a line cache address boundary
    uintptr_t ptr = (uintptr_t) memoryAllocate(memsize);

    MUSTALIGN2(ptr, kCpuLineCacheSize);

    // align pointer to line cache boundary
    master_pool_t *pool_ptr = (master_pool_t *) ALIGN2(ptr, kCpuLineCacheSize); // NOLINT

#ifdef DEBUG
    memorySet(pool_ptr, 0xEB, sizeof(master_pool_t) + container_len);
#endif

    master_pool_t pool = {.memptr              = pool_ptr,
                          .cap                 = pool_width,
                          .len                 = 0,
                          .create_item_handle  = defaultCreateHandle,
                          .destroy_item_handle = defaultDestroyHandle};

    memcpy(pool_ptr, &pool, sizeof(master_pool_t));
    initMutex(&(pool_ptr->mutex));

    return pool_ptr;
}
