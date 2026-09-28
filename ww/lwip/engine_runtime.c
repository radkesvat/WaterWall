#include "engine_runtime.h"

#include "global_state.h"
#include "loggers/internal_logger.h"
#include "lwip/timeouts.h"
#include "wevent.h"
#include "worker.h"

typedef struct engine_slot_s
{
    ww_lwip_engine_t *engine;
    wloop_t          *loop;
    wtimer_t         *timer;
    uint8_t           owner;
    bool              quiesced;
} engine_slot_t;

/* A private sidecar preserves the public worker/global-state layouts. */
static engine_slot_t *slots;
static uint8_t        slot_count;
#if defined(WW_LWIP_TEST_SEAM)
static bool fail_slots;
void        wwLwipRuntimeTestFailSlots(bool fail)
{
    assert(slots == NULL);
    fail_slots = fail;
}
#endif

static void scheduleEngine(ww_lwip_engine_t *engine, void *argument);

bool wwLwipEngineOwnerIsCurrent(uint8_t owner, const struct wloop_s *loop)
{
    /* Teardown has already detached worker->loop. The engine retains its saved
     * loop until this owner releases it, before wloopDestroy(). */
    return currentThreadIsEventWorkerWID(owner) && loop != NULL && wloopGetWID((wloop_t *) loop) == owner;
}

bool wwLwipRuntimeInitialize(uint8_t workers)
{
    assert(slots == NULL && workers > 0 && workers <= 254);
#if defined(WW_LWIP_TEST_SEAM)
    if (fail_slots)
        return false;
#endif
    engine_slot_t *storage = calloc(workers, sizeof(*storage));
    if (storage == NULL)
        return false;
    for (uint8_t owner = 0; owner < workers; ++owner)
        storage[owner].owner = owner;
    wwLwipEngineSharedInit();
    slot_count = workers;
    slots      = storage;
    return true;
}

static void onEngineTimer(wtimer_t *timer)
{
    engine_slot_t *slot = weventGetUserdata(timer);
    assert(slot != NULL && slot->timer == timer);
    assert(getLoopEventWorkerWID(weventGetLoop(timer)) == slot->owner);
    slot->timer = NULL;
    if (! slot->quiesced)
        wwLwipEngineCheckTimeouts(slot->engine);
    /* The executing one-shot is reclaimed by pending-event release. Its
     * replacement (if any) was installed by the outer engine scope's leave. */
}

static void detachTimer(engine_slot_t *slot)
{
    wtimer_t *timer = slot->timer;
    slot->timer     = NULL;
    if (timer != NULL)
    {
        weventSetUserData(timer, NULL);
        wtimerDelete(timer);
    }
}

static void scheduleEngine(ww_lwip_engine_t *engine, void *argument)
{
    engine_slot_t *slot = argument;
    assert(currentThreadIsEventWorkerWID(slot->owner) && slot->engine == engine);
    if (slot->quiesced || ! wloopNormalDispatchAllowed(slot->loop))
        return;
    const uint32_t delay        = wwLwipEngineNextTimeout(engine);
    const uint32_t native_delay = delay == 0 ? 1 : delay;
    if (delay != SYS_TIMEOUTS_SLEEPTIME_INFINITE && slot->timer != NULL &&
        slot->timer->next_timeout <= getHRTimeUs() + (uint64_t) native_delay * 1000)
    {
        /* Preserve an earlier or already-pending wakeup. Replacing due work
         * after every packet can indefinitely slide its one-ms yield forward. */
        return;
    }
    detachTimer(slot);
    if (delay != SYS_TIMEOUTS_SLEEPTIME_INFINITE)
    {
        /* Due work yields to the loop; never recursively poll the stack. */
        slot->timer = wtimerAdd(slot->loop, onEngineTimer, native_delay, 1);
        if (slot->timer != NULL)
            weventSetUserData(slot->timer, slot);
    }
}

ww_lwip_engine_t *wwLwipRuntimeGet(uint8_t owner)
{
    if (! currentThreadIsEventWorkerWID(owner))
        return NULL;
    if (slots == NULL || owner >= slot_count)
        return NULL;
    engine_slot_t *slot = &slots[owner];
    if (slot->quiesced)
        return NULL;
    if (slot->engine != NULL)
        return wloopNormalDispatchAllowed(slot->loop) ? slot->engine : NULL;
    wloop_t *loop = getWorkerLoop(owner);
    if (loop == NULL || ! wloopNormalDispatchAllowed(loop))
        return NULL;
    ww_lwip_engine_t *engine = wwLwipEngineCreate(owner, loop);
    if (engine == NULL)
        return NULL;
    slot->loop   = loop;
    slot->engine = engine;
    wwLwipEngineSetWake(engine, scheduleEngine, slot);
    scheduleEngine(engine, slot);
    if (slot->timer == NULL && wwLwipEngineNextTimeout(engine) != SYS_TIMEOUTS_SLEEPTIME_INFINITE)
    {
        /* Timer admission can close during lazy construction. */
        slot->engine = NULL;
        slot->loop   = NULL;
        wwLwipEngineSetWake(engine, NULL, NULL);
        wwLwipEngineDestroy(engine);
        return NULL;
    }
    return engine;
}

void wwLwipRuntimeQuiesceWorker(uint8_t owner)
{
    assert(currentThreadIsEventWorkerWID(owner));
    if (slots == NULL)
        return;
    assert(owner < slot_count);
    engine_slot_t *slot = &slots[owner];
    slot->quiesced      = true;
    detachTimer(slot);
    if (slot->engine != NULL)
        wwLwipEngineQuiesce(slot->engine);
}

void wwLwipRuntimeDestroyWorker(uint8_t owner)
{
    assert(currentThreadIsEventWorkerWID(owner));
    if (slots == NULL)
        return;
    assert(owner < slot_count);
    engine_slot_t *slot = &slots[owner];
    if (slot->timer != NULL || (slot->engine != NULL && ! slot->quiesced))
    {
        LOGF("lwIP engine teardown preceded owner timer quiescence");
        abortProgramNow(1);
    }
    ww_lwip_engine_t *engine = slot->engine;
    slot->engine             = NULL;
    slot->quiesced           = true;
    if (engine != NULL)
    {
        assert(slot->loop != NULL);
        wwLwipEngineDestroy(engine);
    }
    slot->loop = NULL;
}

void wwLwipRuntimeFinalize(void)
{
    if (slots == NULL)
        return;
    for (uint8_t owner = 0; owner < slot_count; ++owner)
    {
        if (slots[owner].engine != NULL || slots[owner].timer != NULL)
        {
            LOGF("lwIP shared finalization preceded worker engine teardown");
            abortProgramNow(1);
        }
    }
    wwLwipEngineSharedCleanup();
    free(slots);
    slots      = NULL;
    slot_count = 0;
}
