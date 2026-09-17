#include "ev_memory.h"
#include "wevent.h"
#include "wloop_internal.h"
#include "worker_registry_fixture.h"

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
    wtimer_t *timer = NULL;
    require(wtimerTryAdd(loop, unexpectedTimer, 60000, 1, &timer) == kWTimerTryAddInstalled,
            "timer installation failed");
    require(timer->allocation_pool == loop->timer_pool, "timer lost its pool provenance");
    return timer;
}

static void testReuseAndMasterTransfer(uint32_t width)
{
    const long      outstanding = eventloopAllocCount() - eventloopFreeCount();
    master_pool_t  *master      = masterpoolCreateWithCapacity(2 * width);
    generic_pool_t *first       = wtimerPoolCreate(master, width);
    generic_pool_t *second      = wtimerPoolCreate(master, width);
    require(master && first && second, "pool construction failed");
    wloop_t *loop    = wloopCreate(0, NULL, 0);
    loop->timer_pool = first;

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
    require(eventloopAllocCount() == before_transfer, "master refill allocated instead of reusing idle timers");
    wtimerDelete(transferred);

    wloopDestroy(&loop);
    genericpoolDestroy(first);
    genericpoolDestroy(second);
    masterpoolMakeEmpty(master);
    masterpoolDestroy(master);
    require(eventloopAllocCount() - eventloopFreeCount() == outstanding, "timer pool family leaked storage");
}

static void testRefillFailure(void)
{
    master_pool_t  *master = masterpoolCreateWithCapacity(2);
    generic_pool_t *pool   = wtimerPoolCreate(master, 2);
    require(master && pool, "failure fixture pool construction failed");
    wloop_t *loop    = wloopCreate(0, NULL, 0);
    loop->timer_pool = pool;
    wtimer_t *timer  = NULL;
    eventloopTestFailNextTryZalloc();
    require(wtimerTryAdd(loop, unexpectedTimer, 60000, 1, &timer) == kWTimerTryAddResourceFailure && timer == NULL,
            "cold refill failure did not report ResourceFailure");
    require(masterpoolGetCheckedOut(master) == 0 && pool->len == 0 && loop->ntimers == 0,
            "failed refill changed ownership or published a timer");

    timer = addTimer(loop);
    wtimerDelete(timer);
    genericpoolShrink(pool);
    /* One cached master item is enough even if creation of the rest of the
     * requested refill batch fails. */
    generic_pool_t *receiver = wtimerPoolCreate(master, 4);
    require(receiver != NULL, "partial-refill pool construction failed");
    loop->timer_pool = receiver;
    eventloopTestFailNextTryZalloc();
    timer = addTimer(loop);
    require(masterpoolGetCheckedOut(master) == 1, "partial refill lost checkout accounting");
    wtimerDelete(timer);

    wloopDestroy(&loop);
    genericpoolDestroy(receiver);
    genericpoolDestroy(pool);
    require(masterpoolGetCheckedOut(master) == 0, "partial refill leaked a timer");
    masterpoolMakeEmpty(master);
    masterpoolDestroy(master);
}

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
    generic_pool_t *pool        = wtimerPoolCreate(master, 4);
    require(master && pool, "deferred fixture pool construction failed");
    wloop_t *loop    = wloopCreate(0, NULL, 0);
    loop->timer_pool = pool;
    wtimer_t *timer  = NULL;
    require(wtimerTryAdd(loop, reentrantTimer, 60000, 1, &timer) == kWTimerTryAddInstalled,
            "callback timer installation failed");
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
    testRefillFailure();
    testDeferredReclamation();
    testWorkerUnbindWID();
    testWorkerRegistryRestore(&registry);
    puts("timer_pool_test: all cases passed");
    return 0;
}
