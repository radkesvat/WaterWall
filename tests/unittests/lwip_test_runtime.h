#pragma once

#include "ww_lwip.h"
#include "wwapi.h"

/* Direct raw fixtures establish the production random/crypto prerequisites.
 * Engine lifecycle is explicit below; cleanup erases the process test secret
 * only after every engine has been released. */
static inline bool lwipTestRuntimeInitialize(void)
{
    if (! globalstateInitializeSecureRandom())
    {
        return false;
    }
    if (! frandGlobalInit())
    {
        globalstateDestroySecureRandom();
        return false;
    }
    frandInit();

    if (wCryptoGlobalInit() != kWCryptoOk)
    {
        frandThreadCleanup();
        frandGlobalCleanup();
        globalstateDestroySecureRandom();
        return false;
    }

    wwLwipInitializeProtocolState();
    return true;
}

static inline void lwipTestRuntimeCleanup(void)
{
    wwLwipTestEraseTcpIsnSecret();
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
}

/* Raw protocol fixtures use explicit logical owners without starting loops.
 * Real worker/timer/shutdown behavior is covered by lwip_engine_runtime and
 * lwip_shutdown. These loop records supply only stable owner identity. */
#include "engine.h"
#include "wevent.h"

static worker_t          lwip_test_workers[8];
static wloop_t           lwip_test_loops[8];
static ww_lwip_engine_t *lwip_test_engines[8];
static ww_lwip_engine_t *lwip_test_previous;
static worker_t         *lwip_test_saved_workers;
static uint32_t          lwip_test_saved_count;
static uint8_t           lwip_test_saved_initialized;
static wid_t             lwip_test_saved_wid, lwip_test_active = kInvalidWID;
static unsigned          lwip_test_count;

static inline void lwipTestEngineSelect(wid_t wid)
{
    assert(wid < lwip_test_count);
    if (lwip_test_active != kInvalidWID)
    {
        testWorkerBindWID(lwip_test_active);
        wwLwipEngineLeave(lwip_test_engines[lwip_test_active], lwip_test_previous);
    }
    testWorkerBindWID(wid);
    if (lwip_test_engines[wid] == NULL)
        lwip_test_engines[wid] = wwLwipEngineCreate(wid, &lwip_test_loops[wid]);
    if (lwip_test_engines[wid] == NULL || ! wwLwipEngineEnter(lwip_test_engines[wid], &lwip_test_previous))
        abort();
    lwip_test_active = wid;
}
static inline void lwipTestEngineBegin(unsigned workers)
{
    assert(workers > 0 && workers <= ARRAY_SIZE(lwip_test_workers));
    lwip_test_saved_workers     = GSTATE.workers;
    lwip_test_saved_count       = GSTATE.workers_count;
    lwip_test_saved_initialized = GSTATE.flag_initialized;
    lwip_test_saved_wid         = getWID();
    lwip_test_count             = workers;
    for (unsigned i = 0; i < workers; ++i)
    {
        lwip_test_loops[i].wid = i;
        lwip_test_workers[i]   = (worker_t) {.wid = (wid_t) i, .has_event_loop = true, .loop = &lwip_test_loops[i]};
    }
    GSTATE.workers          = lwip_test_workers;
    GSTATE.workers_count    = workers;
    GSTATE.flag_initialized = true;
    wwLwipEngineSharedInit();
    lwipTestEngineSelect(0);
}
static inline void lwipTestEngineEnd(void)
{
    GSTATE.workers          = lwip_test_workers;
    GSTATE.workers_count    = lwip_test_count;
    GSTATE.flag_initialized = true;
    testWorkerBindWID(lwip_test_active);
    wwLwipEngineLeave(lwip_test_engines[lwip_test_active], lwip_test_previous);
    for (unsigned i = 0; i < lwip_test_count; ++i)
    {
        if (lwip_test_engines[i] != NULL)
        {
            testWorkerBindWID((wid_t) i);
            wwLwipEngineDestroy(lwip_test_engines[i]);
            lwip_test_engines[i] = NULL;
        }
    }
    wwLwipEngineSharedCleanup();
    lwip_test_active = kInvalidWID;
    testWorkerBindWID(lwip_test_saved_wid);
    GSTATE.workers          = lwip_test_saved_workers;
    GSTATE.workers_count    = lwip_test_saved_count;
    GSTATE.flag_initialized = lwip_test_saved_initialized;
}
