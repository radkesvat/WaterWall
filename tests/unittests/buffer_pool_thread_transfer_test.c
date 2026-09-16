#include "wwapi.h"

#include <pthread.h>

typedef struct pool_thread_probe_s
{
    buffer_pool_t *pool;
    atomic_uint    accesses;
    atomic_bool    may_access;
} pool_thread_probe_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void *accessPool(void *userdata)
{
    pool_thread_probe_t *probe = userdata;

    while (! atomicLoadExplicit(&probe->may_access, memory_order_acquire))
    {
        YIELD_THREAD();
    }

    sbuf_t *buf = bufferpoolGetSmallBuffer(probe->pool);
    bufferpoolReuseBuffer(probe->pool, buf);
    buf = bufferpoolGetMediumBuffer(probe->pool);
    require(sbufGetTotalCapacityNoPadding(buf) == MEDIUM_BUFFER_SIZE_RAM_HIGH,
            "worker transfer changed medium capacity");
    bufferpoolReuseBuffer(probe->pool, buf);
    buf = bufferpoolGetSpliceBuffer(probe->pool);
#if WW_HAVE_SPLICE
    require(buf != NULL && sbufGetTotalCapacityNoPadding(buf) == 32, "worker transfer changed splice capacity");
    bufferpoolReuseBuffer(probe->pool, buf);
#else
    require(buf == NULL && errno == ENOSYS, "unsupported splice checkout did not return ENOSYS");
#endif
    atomicAddExplicit(&probe->accesses, 1, memory_order_relaxed);
    return NULL;
}

static void startAndJoinGeneration(pool_thread_probe_t *probe, pthread_t *thread)
{
    atomicStoreExplicit(&probe->may_access, true, memory_order_release);
    require(pthread_join(*thread, NULL) == 0, "failed to join pool owner thread");
}

int main(void)
{
    master_pool_t      *large_master = masterpoolCreateWithCapacity(8);
    master_pool_t      *small_master = masterpoolCreateWithCapacity(8);
    master_pool_t      *medium_master = masterpoolCreateWithCapacity(8);
    master_pool_t      *splice_master = masterpoolCreateWithCapacity(8);
    buffer_pool_t      *pool          = bufferpoolCreate(
        large_master, medium_master, small_master, splice_master, 8, 8192, MEDIUM_BUFFER_SIZE_RAM_HIGH, 4096);
    pool_thread_probe_t first        = {
               .pool       = pool,
               .may_access = true,
    };
    pool_thread_probe_t second = {
        .pool = pool,
    };
    pthread_t first_thread;
    pthread_t second_thread;

    /*
     * Create both generations before the first exits, so the operating system
     * cannot recycle its thread ID and accidentally hide a missing transfer.
     */
    require(pthread_create(&first_thread, NULL, accessPool, &first) == 0, "failed to create first pool owner thread");
    require(pthread_create(&second_thread, NULL, accessPool, &second) == 0,
            "failed to create replacement pool owner thread");
    require(pthread_join(first_thread, NULL) == 0, "failed to join first pool owner thread");
    bufferpoolResetThreadOwnership(pool);
    startAndJoinGeneration(&second, &second_thread);
    require(atomicLoadRelaxed(&first.accesses) == 1 && atomicLoadRelaxed(&second.accesses) == 1,
            "both pool owner generations did not complete");

    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolMakeEmpty(medium_master);
    masterpoolMakeEmpty(splice_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);
    masterpoolDestroy(medium_master);
    masterpoolDestroy(splice_master);
    puts("buffer pool thread transfer tests passed");
    return 0;
}
