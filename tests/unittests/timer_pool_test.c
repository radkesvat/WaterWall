#include "ev_memory.h"
#include "wevent.h"
#include "wloop_internal.h"
#include "worker_registry_fixture.h"

#if defined(OS_UNIX)
#include <sys/wait.h>
#include <unistd.h>
#endif

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void unexpectedTimer(wtimer_t *timer)
{
    discard timer;
    require(false, "an unexpired or cancelled timer ran");
}

static wtimer_t *addTimer(wloop_t *loop)
{
    wtimer_t *timer = wtimerAdd(loop, unexpectedTimer, 60000, 1);
    require(timer != NULL, "timer installation failed");
    require(timer->allocation_pool == loop->timer_pool, "timer lost its pool provenance");
    return timer;
}

static void testReuseAndMasterTransfer(uint32_t width)
{
    const long      outstanding = eventloopAllocCount() - eventloopFreeCount();
    master_pool_t  *master      = masterpoolCreateWithCapacity(2 * width);
    generic_pool_t *first       = genericpoolCreateWithDefaultAllocatorAndCapacity(master, sizeof(wtimeout_t), width);
    generic_pool_t *second      = genericpoolCreateWithDefaultAllocatorAndCapacity(master, sizeof(wtimeout_t), width);
    require(master && first && second, "pool construction failed");
    wloop_t *loop    = wloopCreate(0, NULL, 0);
    loop->timer_pool = first;

    testWorkerUnbindWID();
    wtimer_t *foreign = wtimerAdd(loop, unexpectedTimer, 60000, 1);
    require(foreign != NULL && foreign->allocation_pool == NULL && first->len == 0,
            "foreign timer creation borrowed a worker-local pool");
    wtimerDelete(foreign);
    testWorkerBindWID(0);

    wtimer_t *warm = addTimer(loop);
    weventSetUserData(warm, first);
    wtimerDelete(warm);
    const long allocations = eventloopAllocCount();
    const long frees       = eventloopFreeCount();
    for (unsigned int i = 0; i < 128; ++i)
    {
        wtimer_t *timer = addTimer(loop);
        require(timer == warm && timer->userdata == NULL && ! timer->pending && ! timer->quiesced,
                "timer cache failed to reuse or reset a record");
        wtimerDelete(timer);
    }
    require(eventloopAllocCount() == allocations && eventloopFreeCount() == frees,
            "warm timer churn performed a heap allocation or free");
    require(masterpoolGetCheckedOut(master) == 0, "deleted timers remain checked out");

    /* Move idle storage between local caches through the real master pool. */
    genericpoolShrink(first);
    loop->timer_pool           = second; /* No timers remain on the loop. */
    const long before_transfer = eventloopAllocCount();
    wtimer_t  *transferred     = addTimer(loop);
    require(transferred == warm && eventloopAllocCount() == before_transfer,
            "master refill did not reuse idle timer storage");
    wtimerDelete(transferred);

    wloopDestroy(&loop);
    genericpoolDestroy(first);
    genericpoolDestroy(second);
    masterpoolMakeEmpty(master);
    masterpoolDestroy(master);
    require(eventloopAllocCount() - eventloopFreeCount() == outstanding, "timer pool family leaked storage");
}

#if defined(OS_UNIX)
static pool_item_t *refuseTimerAllocation(generic_pool_t *pool)
{
    discard pool;
    return NULL;
}

static void testAllocationFailureIsFatal(void)
{
    const pid_t child = fork();
    require(child >= 0, "failed to fork timer allocation failure case");
    if (child == 0)
    {
        master_pool_t  *master = masterpoolCreateWithCapacity(2);
        generic_pool_t *pool   = genericpoolCreateWithCapacity(master, 1, refuseTimerAllocation, memoryFree);
        require(master != NULL && pool != NULL, "failed to construct allocation failure fixture");
        wloop_t *loop    = wloopCreate(0, NULL, 0);
        loop->timer_pool = pool;
        discard wtimerAdd(loop, unexpectedTimer, 60000, 1);
        _Exit(0);
    }
    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for timer allocation failure case");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 1, "timer allocation failure did not terminate the process");
}
#endif

static unsigned int callbacks;

static void reentrantTimer(wtimer_t *timer)
{
    ++callbacks;
    wloop_t        *loop = timer->loop;
    generic_pool_t *pool = timer->allocation_pool;
    require(masterpoolGetCheckedOut(pool->mp) == 1, "executing timer was recycled before callback return");
    wtimerDelete(timer);
    wtimer_t *nested = addTimer(loop);
    require(nested != timer && masterpoolGetCheckedOut(pool->mp) == 2, "nested timer reused pending callback storage");
    wtimerDelete(nested);
}

static void testDeferredReclamation(void)
{
    const long      outstanding = eventloopAllocCount() - eventloopFreeCount();
    master_pool_t  *master      = masterpoolCreateWithCapacity(8);
    generic_pool_t *pool        = genericpoolCreateWithDefaultAllocatorAndCapacity(master, sizeof(wtimeout_t), 4);
    require(master && pool, "deferred fixture pool construction failed");
    wloop_t *loop    = wloopCreate(0, NULL, 0);
    loop->timer_pool = pool;
    wtimer_t *timer  = wtimerAdd(loop, reentrantTimer, 60000, 1);
    require(timer != NULL, "callback timer installation failed");
    wtimerTestMakePendingOneShot(timer);
    discard wloopProcessEvents(loop, 0);
    require(callbacks == 1 && masterpoolGetCheckedOut(master) == 0,
            "pending callback did not return its timer exactly once");

    wtimer_t *pending = addTimer(loop);
    wtimer_t *heap    = addTimer(loop);
    wtimerTestMakePendingOneShot(pending);
    /* This isolated loop has no poller or concurrent producers to wake. */
    atomicStoreExplicit(&loop->normal_admission_open, false, memory_order_release);
    wloopQuiesceNormalWork(loop);
    require(pending->quiesced && heap->quiesced && masterpoolGetCheckedOut(master) == 2,
            "quiescence recycled timers before owner drain");
    wtimerDelete(heap);
    require(masterpoolGetCheckedOut(master) == 1, "deferred explicit deletion did not return its timer");
    wloopDestroy(&loop);
    require(masterpoolGetCheckedOut(master) == 0, "loop teardown leaked a deferred timer");

    loop             = wloopCreate(0, NULL, 0);
    loop->timer_pool = pool;
    pending          = addTimer(loop);
    discard addTimer(loop);
    wtimerTestMakePendingOneShot(pending);
    wloopDestroy(&loop);
    require(masterpoolGetCheckedOut(master) == 0, "raw loop teardown leaked pending or heap timers");

    genericpoolDestroy(pool);
    masterpoolMakeEmpty(master);
    masterpoolDestroy(master);
    require(eventloopAllocCount() - eventloopFreeCount() == outstanding, "deferred timer cleanup leaked storage");
}

int main(void)
{
    test_worker_registry_t registry = {0};
    GSTATE.workers_count            = 1;
    testWorkerRegistryInstall(&registry);
    testWorkerBindWID(0);

    const uint32_t widths[] = {kRamProfileS1Memory,
                               kRamProfileS2Memory,
                               kRamProfileM1Memory,
                               kRamProfileM2Memory,
                               kRamProfileL1Memory,
                               kRamProfileL2Memory};
    for (size_t i = 0; i < ARRAY_SIZE(widths); ++i)
    {
        testReuseAndMasterTransfer(widths[i]);
    }
#if defined(OS_UNIX)
    testAllocationFailureIsFatal();
#endif
    testDeferredReclamation();
    testWorkerUnbindWID();
    testWorkerRegistryRestore(&registry);
    puts("timer_pool_test: all cases passed");
    return 0;
}
