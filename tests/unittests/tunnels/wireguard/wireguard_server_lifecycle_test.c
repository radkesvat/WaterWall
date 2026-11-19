/* Real server startup rollback and central shutdown with pending dispatch and
 * all-worker retirement. Cancellation runs on both owner and foreign threads.
 * CTest: waterwall.wireguard_server_lifecycle_unit */
#include "wireguard_server_fixture.h"

typedef struct held_retirement_s
{
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *arg1, *arg2, *arg3;
    unsigned                     submissions, worker_count;
} held_retirement_t;
static held_retirement_t held_retirement;
static bool holdRetirementCompletion(wid_t wid, WorkerMessageCallback callback, WorkerMessageCleanupCallback cleanup,
                                     void *arg1, void *arg2, void *arg3)
{
    if (++held_retirement.submissions <= held_retirement.worker_count)
        return false;
    twfRequire(wid == 0 && cleanup != NULL && held_retirement.callback == NULL,
               "retirement posted an unexpected completion");
    held_retirement.callback = callback;
    held_retirement.cleanup  = cleanup;
    held_retirement.arg1     = arg1;
    held_retirement.arg2     = arg2;
    held_retirement.arg3     = arg3;
    return true;
}
static void *cancelHeldRetirement(void *argument)
{
    discard argument;
    twfRequire(! currentThreadIsWorker(), "retirement cancellation borrowed a worker context");
    held_retirement.cleanup(
        held_retirement.arg1, held_retirement.arg2, held_retirement.arg3, kWorkerMessageCancelTeardown);
    held_retirement.cleanup = NULL;
    return NULL;
}

static void casePartialConstruction(wid_t workers, const char *settings)
{
    testCaseSet("WireGuardServer partial helper construction rollback");
    wg_server_fixture_t f;
    wgServerFixtureBase(&f, workers);
    twfRequire(wgServerFixtureConstruct(&f, settings) == NULL, "invalid helper settings did not refuse construction");
    twfRequire(wg_destroyed_server == 1 && wg_destroyed_ptc == 1 &&
                   wg_destroyed_binder == (strstr(settings, "sweep") != NULL ? 1U : 0U) &&
                   wg_destroyed_controller == (strstr(settings, "sweep") != NULL ? 1U : 0U),
               "partial construction did not destroy every constructed helper exactly once");
    wgServerFixtureClose(&f, wwLifecycleStartupRollback());
}
static void caseStartRefusal(wid_t workers, bool refuse_timer)
{
    testCaseSet("WireGuardServer partial start rollback");
    wg_server_fixture_t f;
    wgServerFixtureSetup(&f, workers, "");
    if (refuse_timer)
        wloopCloseNormalAdmission(f.env.loops[0]);
    else
        workerMessagesCloseAdmission(&f.env.workers[workers - 1]);
    twfRequire(! wwStartupSucceeded(wgServerFixtureStart(&f)), "closed worker admission did not refuse startup");
    twfRequire(f.state->timer == NULL, "failed server startup retained its timer");
    wgServerFixtureClose(&f, wwLifecycleStartupRollback());
}

static void *cancelDetached(void *argument)
{
    twfRequire(! currentThreadIsWorker(), "foreign cancellation borrowed a worker identity");
    workerMessagesCleanupPendingDetached(argument, kWorkerMessageCancelTeardown);
    return NULL;
}
static void caseQueuedShutdown(wid_t workers, bool foreign)
{
    testCaseSet("WireGuardServer queued ingress/output shutdown");
    wg_server_fixture_t f;
    wgServerFixtureSetup(&f, workers, "");
    twfRequire(wwStartupSucceeded(wgServerFixtureStart(&f)), "normal startup failed");
    wgServerFixturePump(&f);
    wgServerFixtureProof(&f);
    wgServerFixtureOpenUdp(&f);
    const wid_t    ingress_worker = workers - 1;
    const unsigned outputs        = f.client_count;
    discard        tosSetCurrentWorker(ingress_worker);
    sbuf_t        *junk = bufferpoolGetSmallBuffer(f.env.pools[ingress_worker]);
    sbufSetLength(junk, 4);
    sbufWriteZeros(junk, 4);
    tunnelNextUpStreamPayload(f.adapter, f.ingress[ingress_worker], junk);
    discard    tosSetCurrentWorker(0);
    binding_t *binding = &f.state->bindings[0];
    sbuf_t    *packet  = bufferpoolGetSmallBuffer(f.env.pools[0]);
    sbufSetLength(packet, 4);
    sbufWriteZeros(packet, 4);
    twfRequire(output(f.state, packet, &f.state->engine.peers[0], &binding->ingress->ip, binding->ingress->port),
               "authenticated output did not queue");
    twfRequire(atomic_load(&f.state->dispatch.count) == 2 && atomic_load(&binding->ingress->references) == 4,
               "queued work did not retain exact ingress ownership");
    nodemanagerQuiesceRequest(wwLifecycleProcessShutdown());
    if (foreign)
    {
        /* Detachment is an actual worker API. Its pending cleanup is explicitly
         * legal after the owner's loop has ceased normal dispatch. */
        for (wid_t wid = 0; wid < workers; ++wid)
        {
            discard                 tosSetCurrentWorker(wid);
            wloop_t                *loop;
            worker_message_queue_t *queue;
            workerMessagesCloseAdmissionAndDetach(&f.env.workers[wid], &loop, &queue);
            pthread_t thread;
            twfRequire(pthread_create(&thread, NULL, cancelDetached, queue) == 0 && pthread_join(thread, NULL) == 0,
                       "foreign detached cleanup failed");
            workerMessagesDestroyDetached(queue);
            /* Preserve the saved loop for the owner's remaining lifecycle. */
            f.env.workers[wid].loop = loop;
        }
    }
    else
        wgServerFixturePump(&f); /* Accepted dispatch executes its closed-gate path. */
    twfRequire(atomic_load(&f.state->dispatch.count) == 0 && atomic_load(&f.state->dispatch.bytes) == 0 &&
                   atomic_load(&binding->ingress->references) == 2 && f.client_count == outputs &&
                   ! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, junk) &&
                   ! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, packet),
               "closed admission published, rearmed, or failed to settle queued work exactly once");
    const unsigned settled = g_twf_buffers.total_recycled;
    discard        tosSetCurrentWorker(0);
    packet = bufferpoolGetSmallBuffer(f.env.pools[0]);
    sbufSetLength(packet, 4);
    output(f.state, packet, &f.state->engine.peers[0], &binding->ingress->ip, binding->ingress->port);
    twfRequire(atomic_load(&f.state->dispatch.count) == 0 && g_twf_buffers.total_recycled == settled + 1,
               "post-close output reacquired dispatch admission");
    wgServerFixtureClose(&f, wwLifecycleProcessShutdown());
    twfRequire(f.ingress_finished == 1, "ingress was not destroyed exactly once by its creator");
}

static void caseRetirementShutdown(wid_t workers, bool completion_pending)
{
    testCaseSet("WireGuardServer shutdown while retirement or completion is pending");
    wg_server_fixture_t f;
    wgServerFixtureSetup(&f, workers, "");
    twfRequire(wwStartupSucceeded(wgServerFixtureStart(&f)), "startup failed");
    wgServerFixturePump(&f);
    wgServerFixtureProof(&f);
    wgServerFixtureOpenUdp(&f);
    binding_t     *binding = &f.state->bindings[0];
    const uint64_t epoch   = binding->epoch;
    if (completion_pending)
    {
        held_retirement = (held_retirement_t) {.worker_count = workers};
        wg_submit_hook  = holdRetirementCompletion;
    }
    retireBinding(f.state, 0);
    twfRequire(binding->occupied && binding->retiring && ! binding->usable && ! atomic_load(&binding->retirement_done),
               "retirement did not close the existing binding before posting owner work");
    if (completion_pending)
    {
        wgServerFixturePump(&f);
        twfRequire(held_retirement.callback != NULL && ! atomic_load(&binding->retirement_done),
                   "completion was not held behind the owner acknowledgments");
        wg_submit_hook = NULL;
    }
    wgServerFixtureQuiesce(&f, wwLifecycleProcessShutdown());
    if (completion_pending)
    {
        pthread_t thread;
        twfRequire(pthread_create(&thread, NULL, cancelHeldRetirement, NULL) == 0 && pthread_join(thread, NULL) == 0,
                   "foreign retirement completion cleanup failed");
    }
    twfRequire(atomic_load(&binding->retirement_done) && ! atomic_load(&binding->retirement_ok) && binding->occupied &&
                   binding->retiring && ! binding->usable && binding->epoch == epoch,
               "canceled retirement reopened a range or lost its binding context");
    reconcile(f.state);
    twfRequire(binding->occupied && binding->retiring && binding->epoch == epoch,
               "failed retirement completion permitted range reuse");
    wgServerFixtureClose(&f, wwLifecycleProcessShutdown());
}

int main(void)
{
    for (wid_t workers = 1; workers <= 4; workers += 3)
    {
        casePartialConstruction(workers, ",\"mtu\":67");
        casePartialConstruction(workers, ",\"sweep-interval-ms\":0");
        caseStartRefusal(workers, false);
        caseStartRefusal(workers, true);
        caseQueuedShutdown(workers, false);
        caseQueuedShutdown(workers, true);
        caseRetirementShutdown(workers, false);
        caseRetirementShutdown(workers, true);
    }
    return 0;
}
