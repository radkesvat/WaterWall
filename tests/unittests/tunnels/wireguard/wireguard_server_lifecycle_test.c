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

static unsigned packet_init_count[kTosMaxWorkers];

static void countPacketInit(tunnel_t *t, line_t *line)
{
    const wid_t wid = getCurrentWorkerWID();
    twfRequire(line == tunnelchainGetWorkerPacketLine(t->chain, wid) && lineIsAlive(line),
               "packet-side Init did not use the current worker's live packet line");
    ++packet_init_count[wid];
}

static void casePacketInitPerWorker(wid_t workers)
{
    testCaseSet("WireGuardServer initializes its packet edge once on each worker");
    wg_server_fixture_t f;
    wgServerFixtureSetup(&f, workers, "");
    f.state->ptc->fnInitU = countPacketInit;
    memoryZero(packet_init_count, sizeof(packet_init_count));
    twfRequire(wwStartupSucceeded(wgServerFixtureStart(&f)), "server startup failed");
    for (wid_t wid = 0; wid < workers; ++wid)
    {
        twfRequire(packet_init_count[wid] == 0, "packet-side Init ran before its worker queue was pumped");
        tosPumpWorker(&f.env, wid);
        twfRequire(packet_init_count[wid] == 1, "worker did not receive exactly one packet-side Init");
    }
    wgServerFixtureClose(&f, wwLifecycleProcessShutdown());
}

static void *cancelDetached(void *argument)
{
    twfRequire(! currentThreadIsWorker(), "foreign cancellation borrowed a worker identity");
    workerMessagesCleanupPendingDetached(argument, kWorkerMessageCancelTeardown);
    return NULL;
}

static void caseCarrierAdmissionAndDetach(void)
{
    testCaseSet("WireGuardServer keepalive admission and remote-worker detach");
    wg_server_fixture_t f;
    wgServerFixtureSetup(&f, 2, "");
    twfRequireEqualU32(f.state->engine.padding_mtu, 1420, "connection-mode server default padding MTU");
    twfRequire(wwStartupSucceeded(wgServerFixtureStart(&f)), "server startup failed");
    wgServerFixtureProof(&f);
    wgServerFixtureOpenUdp(&f);
    wireguard_peer_t *peer = f.state->engine.first_peer;
    twfRequire(peer->passive_keepalive && f.client_count == 0, "authenticated UDP did not arm a passive reply");
    peer->passive_keepalive_millis = wireguardRecoveryNow() - KEEPALIVE_TIMEOUT * 1000U;

    discard tosSetCurrentWorker(1);
    line_t *carrier = f.ingress[1];
    tunnelNextUpStreamPause(f.adapter, carrier);
    discard tosSetCurrentWorker(0);
    wireguardserverTick(f.state->timer);
    twfRequire(peer->passive_keepalive && atomicLoad(&f.state->dispatch.count) == 0,
               "paused carrier consumed the due reply");
    discard tosSetCurrentWorker(1);
    tunnelNextUpStreamResume(f.adapter, carrier);
    discard tosSetCurrentWorker(0);

    atomicStore(&f.state->dispatch.count, 512);
    wireguardserverTick(f.state->timer);
    twfRequire(peer->passive_keepalive && atomicLoad(&f.state->dispatch.count) == 512,
               "full WireGuard dispatch consumed the due reply");
    atomicStore(&f.state->dispatch.count, 0);
    workerMessagesCloseAdmission(&f.env.workers[1]);
    wireguardserverTick(f.state->timer);
    twfRequire(peer->passive_keepalive && atomicLoad(&f.state->dispatch.count) == 0,
               "worker refusal consumed the due reply");
    twfRequire(workerMessagesOpenAdmission(&f.env.workers[1]), "failed to reopen carrier worker admission");
    wireguardserverTick(f.state->timer);
    twfRequire(! peer->passive_keepalive && atomicLoad(&f.state->dispatch.count) == 1,
               "writable carrier failed to admit the pending reply");
    discard tosSetCurrentWorker(1);
    tunnelNextUpStreamPause(f.adapter, carrier);
    tosPumpWorker(&f.env, 1);
    twfRequire(f.client_count == 1 &&
                   sbufGetLength(f.to_client[0]) == sizeof(message_transport_data_t) + WIREGUARD_AUTHTAG_LEN &&
                   wireguardGetMessageType(sbufGetRawPtr(f.to_client[0]), sbufGetLength(f.to_client[0])) ==
                       MESSAGE_TRANSPORT_DATA,
               "a later Pause swallowed the already-admitted keepalive");

    discard tosSetCurrentWorker(0);
    peer->curr_keypair.keypair_millis = getTickMS() - REJECT_AFTER_TIME * 1000U;
    sbuf_t  *pending                  = wgServerFixtureUdpPacket(&f, 40002);
    uint8_t *bytes                    = sbufGetMutablePtr(pending);
    /* Address the proved client using the engine worker's buffer. */
    memoryCopy(bytes + 16, bytes + 12, 4);
    twfRequire(calcFullPacketChecksum(bytes, sbufGetLength(pending)), "inner checksum failed");
    tunnelPrevDownStreamPayload(f.state->ptc, tunnelchainGetWorkerPacketLine(f.chain, 0), pending);
    tosPumpWorker(&f.env, 0);
    twfRequire(f.state->binding_head->pending == pending, "keyless return packet did not occupy the binding slot");
    discard tosSetCurrentWorker(1);
    tunnelNextUpStreamFinish(f.adapter, carrier);
    wgAdapterFinish(f.adapter, carrier);
    twfRequire(f.state->binding_head->pending == NULL &&
                   ! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, pending) &&
                   ! twfLedgerContains(g_twf_buffers.recycled, g_twf_buffers.recycled_count, pending),
               "carrier worker retained or locally recycled another worker's pending buffer");
    discard tosSetCurrentWorker(0);
    wgServerFixtureClose(&f, wwLifecycleProcessShutdown());
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
    binding_t *binding = f.state->binding_head;
    sbuf_t    *packet  = bufferpoolGetSmallBuffer(f.env.pools[0]);
    sbufSetLength(packet, 4);
    sbufWriteZeros(packet, 4);
    twfRequire(wireguardserverOutput(
                   f.state, packet, f.state->engine.first_peer, &binding->ingress->ip, binding->ingress->port),
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
    discard tosSetCurrentWorker(0);
    packet = bufferpoolGetSmallBuffer(f.env.pools[0]);
    sbufSetLength(packet, 4);
    twfRequire(! wireguardserverOutput(
                   f.state, packet, f.state->engine.first_peer, &binding->ingress->ip, binding->ingress->port) &&
                   atomicLoad(&f.state->dispatch.count) == 0 &&
                   ! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, packet),
               "post-close output retained its packet or reacquired dispatch admission");
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
    binding_t     *binding = f.state->binding_head;
    const uint64_t epoch   = binding->epoch;
    if (completion_pending)
    {
        held_retirement = (held_retirement_t) {.worker_count = workers};
        wg_submit_hook  = holdRetirementCompletion;
    }
    wireguardserverRetireBinding(f.state, binding);
    twfRequire(wireguardserverBindingByEpoch(f.state, epoch) == binding && binding->retiring && ! binding->usable,
               "retirement did not close the existing binding before posting owner work");
    if (completion_pending)
    {
        wgServerFixturePump(&f);
        twfRequire(held_retirement.callback != NULL && wireguardserverBindingByEpoch(f.state, epoch) == binding,
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
    twfRequire(wireguardserverBindingByEpoch(f.state, epoch) == binding && binding->retiring && ! binding->usable &&
                   binding->epoch == epoch,
               "canceled retirement reopened a range or lost its binding context");
    wireguardserverReconcile(f.state, false);
    twfRequire(wireguardserverBindingByEpoch(f.state, epoch) == binding && binding->retiring && binding->epoch == epoch,
               "failed retirement completion permitted range reuse");
    wgServerFixtureClose(&f, wwLifecycleProcessShutdown());
}

int main(void)
{
    caseCarrierAdmissionAndDetach();
    for (wid_t workers = 1; workers <= 4; workers += 3)
    {
        casePartialConstruction(workers, ",\"max-pending-bytes\":0");
        casePartialConstruction(workers, ",\"sweep-interval-ms\":0");
        caseStartRefusal(workers, false);
        caseStartRefusal(workers, true);
        casePacketInitPerWorker(workers);
        caseQueuedShutdown(workers, false);
        caseQueuedShutdown(workers, true);
        caseRetirementShutdown(workers, false);
        caseRetirementShutdown(workers, true);
    }
    return 0;
}
