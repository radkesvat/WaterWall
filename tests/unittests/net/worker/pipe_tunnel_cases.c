/* Cross-worker pipe publication, private-pipe byte/identity transfer, refusal/late-dispatch cancellation and exact
 * borrowed/owned line settlement. Source lines are fixture-owned; companions are pipe-owned normal lines. CTest:
 * waterwall.worker_context_helpers_unit; see the driver for ordering and CLI. */
#include "worker_fixture.h"

static atomic_bool       g_pipe_stop_in_fast_check_seam;
static atomic_uint       g_pipe_init_count;
static atomic_uint       g_pipe_owned_finish_count;
static atomic_uint       g_pipe_borrowed_finish_count;
static atomic_uint       g_pipe_owned_payload_count;
static atomic_uint       g_pipe_borrowed_payload_count;
static _Atomic(line_t *) g_pipe_owned_line;

void pipeTunnelAfterFastStopCheckTestSeam(tunnel_t *wrapper, line_t *source_line)
{
    discard source_line;
    if (atomicExchangeExplicit(&g_pipe_stop_in_fast_check_seam, false, memory_order_acq_rel))
    {
        wrapper->onQuiesceRequest(wrapper, testShutdownContext());
    }
}

static void pipeTestOwnedInit(tunnel_t *t, line_t *line)
{
    discard t;
    require(currentThreadIsEventWorkerWID(lineGetWID(line)), "pipe Init ran outside its target worker");
    atomicStoreExplicit(&g_pipe_owned_line, line, memory_order_release);
    atomicAddExplicit(&g_pipe_init_count, 1, memory_order_relaxed);
}

typedef struct pipe_payload_lifetime_s
{

    atomic_uint releases;
} pipe_payload_lifetime_t;

static sbuf_t *pipeTestPayload(pipe_payload_lifetime_t *lifetime)
{
    *lifetime = (pipe_payload_lifetime_t) {0};
    atomic_init(&lifetime->releases, 0);
#if WW_HAVE_SPLICE
    sbuf_t *buf = sbufCreateSplice(64);
    require(sbufSpliceInitPipe(buf, 0) == 0, "failed to create payload private pipe");
    uint8_t data[32];
    for (unsigned i = 0; i < sizeof(data); ++i)
        data[i] = (uint8_t) i;
    require(write(sbufSpliceMetadata(buf).pipefd[1], data + 8, 24) == 24, "pipe payload write failed");
    buf->capacity += 24;
    sbufSetLength(buf, 24);
    sbufShiftLeft(buf, 8);
    memoryCopy(sbufGetMutablePtr(buf), data, 8);
#else
    sbuf_t *buf = sbufCreate(32);
    sbufSetLength(buf, 32);
#endif
    watchBufferDisposal(buf, &lifetime->releases);
    return buf;
}

static void pipeCheckPayload(sbuf_t *buf)
{
#if WW_HAVE_SPLICE
    require(sbufIsSplice(buf) && sbufGetLength(buf) == 32 && sbufGetResidentPrefixLength(buf) == 8,
            "worker message changed splice representation");
    sbuf_t *ordinary = sbufCreate(32);
    sbufSpliceReadToBuffer(buf, ordinary, 32);
    for (unsigned i = 0; i < 32; ++i)
        require(sbufGetMutablePtr(ordinary)[i] == i, "worker message changed splice byte order");
    sbufDestroy(ordinary);
#else
    discard buf;
#endif
}

static void pipeTestOwnedPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    require(currentThreadIsEventWorkerWID(lineGetWID(line)), "pipe owned Payload ran outside its target worker");
    pipeCheckPayload(buf);
    atomicAddExplicit(&g_pipe_owned_payload_count, 1, memory_order_relaxed);
    sbufDestroy(buf);
}

static void pipeTestBorrowedPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    require(currentThreadIsEventWorkerWID(lineGetWID(line)), "pipe borrowed Payload ran outside its owner worker");
    pipeCheckPayload(buf);
    atomicAddExplicit(&g_pipe_borrowed_payload_count, 1, memory_order_relaxed);
    sbufDestroy(buf);
}

typedef struct pipe_down_call_s
{
    tunnel_t                             *wrapper;
    line_t                               *line;
    sbuf_t                               *payload;
    atomic_bool                          *done;
    worker_message_enqueue_test_failure_e failure;
    bool                                  finish;
} pipe_down_call_t;

static void pipeDownCallOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard           arg2;
    discard           arg3;
    pipe_down_call_t *call = arg1;
    require(worker->wid == lineGetWID(call->line), "pipe downstream callback ran on the wrong worker");
#ifdef WW_WORKER_MESSAGE_TEST_SEAM
    if (call->failure != kWorkerMessageEnqueueFailNone)
    {
        workerMessagesEnqueueTestSetFailure(call->failure);
    }
#endif
    if (call->finish)
    {
        call->wrapper->fnFinD(call->wrapper, call->line);
    }
    else
    {
        call->wrapper->fnPayloadD(call->wrapper, call->line, call->payload);
    }
    if (call->done != NULL)
    {
        atomicStoreExplicit(call->done, true, memory_order_release);
    }
}

static void pipeWorkerStopCall(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg3;
    ((tunnel_t *) arg1)->onWorkerStop(arg1, worker->wid, testShutdownContext());
    if (arg2 != NULL)
    {
        atomicStoreExplicit((atomic_bool *) arg2, true, memory_order_release);
    }
}

static void pipeTestOwnedFinish(tunnel_t *t, line_t *line)
{
    discard t;
    require(currentThreadIsEventWorkerWID(lineGetWID(line)), "pipe owned Finish ran outside its target worker");
    atomicAddExplicit(&g_pipe_owned_finish_count, 1, memory_order_relaxed);
}

static void pipeTestBorrowedFinish(tunnel_t *t, line_t *line)
{
    discard t;
    require(currentThreadIsEventWorkerWID(lineGetWID(line)), "pipe borrowed Finish ran outside its owner worker");
    atomicAddExplicit(&g_pipe_borrowed_finish_count, 1, memory_order_relaxed);
}

#ifdef WW_WORKER_MESSAGE_LINK_WRAP

static atomic_uint g_pipe_shutdown_requests;

bool __real_wloopPostEvent(wloop_t *loop, wevent_t *event);
bool __wrap_wloopPostEvent(wloop_t *loop, wevent_t *event);
bool __wrap_signalmanagerRequestShutdownPreservingAcceptedStatus(int exit_code);

bool __wrap_signalmanagerRequestShutdownPreservingAcceptedStatus(int exit_code)
{
    require(exit_code == 1, "pipe refusal requested the wrong shutdown status");
    atomicAddExplicit(&g_pipe_shutdown_requests, 1, memory_order_relaxed);
    return true;
}

bool __wrap_wloopPostEvent(wloop_t *loop, wevent_t *event)
{
    if (atomicLoadExplicit(&g_fail_wakeup_post, memory_order_acquire))
    {
        return false;
    }
    return __real_wloopPostEvent(loop, event);
}
#endif

static line_t *allocateLineForTunnel(tunnel_t *owner, wid_t wid)
{
    line_t *line = memoryAllocateCacheAlignedZero(sizeof(line_t) + tunnelGetLineStateSize(owner));
    require(line != NULL, "failed to allocate a pipe test line");
    atomicStoreU32Relaxed(&line->refc, 1);
    line->alive = true;
    line->wid   = wid;
    return line;
}

void testPipeToRejectsBadWorkers(void)
{
    tunnel_t *child = tunnelCreate(NULL, 0, 0);
    require(child != NULL, "failed to create the pipe test child tunnel");

    tunnel_t *pipe_tunnel = pipetunnelCreate(child);
    require(pipe_tunnel != NULL, "failed to create the pipe tunnel");

    // pipeTo() takes the child and reaches its parent through t->prev; the pipe
    // line state sits at the parent's offset.
    child->prev                = pipe_tunnel;
    pipe_tunnel->lstate_offset = 0;

    line_t *owned_line = allocateLineForTunnel(pipe_tunnel, 0);

    /*
     * Self-target, the out-of-range identity and an out-of-range slot must all be
     * refused. In a release build these used to be unchecked, and pipeTo() would
     * go on to create a pair line for a worker that cannot own it.
     */
    require(! pipeTo(child, owned_line, 0), "pipeTo accepted the current worker as its target");
    require(! pipeTo(child, owned_line, (wid_t) (getTotalWorkersCount())),
            "pipeTo accepted the out-of-range identity as its target");
    require(! pipeTo(child, owned_line, kInvalidWID), "pipeTo accepted kInvalidWID as its target");
    require(! pipeTo(child, owned_line, (wid_t) getTotalWorkersCount()),
            "pipeTo accepted an out-of-range target worker");

    // A source line this worker does not own is refused as well.
    line_t *foreign_line = allocateLineForTunnel(pipe_tunnel, 1);
    require(! pipeTo(child, foreign_line, 0), "pipeTo accepted a source line owned by another worker");

    // Every rejection happened before any pair line was built.
    require(atomicLoadU32Relaxed(&owned_line->refc) == 1, "rejected pipeTo leaked a source line reference");
    require(atomicLoadU32Relaxed(&foreign_line->refc) == 1, "rejected pipeTo leaked a source line reference");

    memoryFreeAligned(foreign_line);
    memoryFreeAligned(owned_line);
    tunnelDestroy(pipe_tunnel);
}

static void requirePipeLineStateZero(tunnel_t *pipe_tunnel, line_t *line, const char *message)
{
    const uint8_t *state = lineGetState(line, pipe_tunnel);
    for (uint32_t i = 0; i < tunnelGetLineStateSize(pipe_tunnel); ++i)
    {
        require(state[i] == 0, message);
    }
}

void pipeQueueBarrier(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;
    discard arg3;
    atomicStoreExplicit((atomic_bool *) arg1, true, memory_order_release);
}

void testPipePublicationIsLinearizedWithPreStop(void)
{
    atomicStoreRelaxed(&g_pipe_init_count, 0);
    atomicStoreRelaxed(&g_pipe_owned_finish_count, 0);
    atomicStoreRelaxed(&g_pipe_borrowed_finish_count, 0);
    atomicStoreRelaxed(&g_pipe_owned_payload_count, 0);
    atomicStoreRelaxed(&g_pipe_borrowed_payload_count, 0);
    atomicStoreExplicit(&g_pipe_owned_line, NULL, memory_order_release);

    tunnel_t *previous = tunnelCreate(NULL, 0, 0);
    tunnel_t *child    = tunnelCreate(NULL, 0, 0);
    require(previous != NULL && child != NULL, "failed to create pipe publication endpoints");
    child->fnInitU       = pipeTestOwnedInit;
    child->fnPayloadU    = pipeTestOwnedPayload;
    child->fnFinU        = pipeTestOwnedFinish;
    previous->fnPayloadD = pipeTestBorrowedPayload;
    previous->fnFinD     = pipeTestBorrowedFinish;

    tunnel_t *pipe_tunnel = pipetunnelCreate(child);
    require(pipe_tunnel != NULL, "failed to create pipe publication tunnel");
    tunnelBind(previous, pipe_tunnel);
    tunnelBind(pipe_tunnel, child);
    pipe_tunnel->lstate_offset = 0;
    child->lstate_offset       = (uint32_t) (tunnelGetLineStateSize(pipe_tunnel) - tunnelGetLineStateSize(child));

    tunnel_chain_t *chain = tunnelchainCreate(getWorkersCount());
    require(chain != NULL, "failed to create pipe publication chain");
    chain->sum_line_state_size = tunnelGetLineStateSize(pipe_tunnel);
    previous->chain            = chain;
    pipe_tunnel->chain         = chain;
    child->chain               = chain;
    tunnelchainFinalize(chain);

    pipe_tunnel->onStart(pipe_tunnel);
    line_t *source = lineCreate(tunnelchainGetLinePools(chain), 0);
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 1,
            "pipe stop-race fixture began with the wrong line count");

    atomicStoreExplicit(&g_pipe_stop_in_fast_check_seam, true, memory_order_release);
    require(! pipeTo(child, source, 1), "pipe publication crossed a completed PreStop transition");
    require(! atomicLoadExplicit(&g_pipe_stop_in_fast_check_seam, memory_order_acquire),
            "pipe fast-check stop seam was not reached");
    requirePipeLineStateZero(pipe_tunnel, source, "stop-winning pipeTo published source line state");
    require(atomicLoadRelaxed(&g_pipe_init_count) == 0, "stop-winning pipeTo emitted Init");
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 1,
            "stop-winning pipeTo retained its staged owned line");

    lineDestroy(source);
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0,
            "stop-winning pipe fixture retained its borrowed source line");
    tunnelchainDestroy(chain);
    pipetunnelDestroy(pipe_tunnel, testShutdownContext());
    tunnelDestroy(previous);

    previous = tunnelCreate(NULL, 0, 0);
    child    = tunnelCreate(NULL, 0, 0);
    require(previous != NULL && child != NULL, "failed to recreate pipe publication endpoints");
    child->fnInitU       = pipeTestOwnedInit;
    child->fnPayloadU    = pipeTestOwnedPayload;
    child->fnFinU        = pipeTestOwnedFinish;
    previous->fnPayloadD = pipeTestBorrowedPayload;
    previous->fnFinD     = pipeTestBorrowedFinish;
    pipe_tunnel          = pipetunnelCreate(child);
    require(pipe_tunnel != NULL, "failed to recreate pipe publication tunnel");
    tunnelBind(previous, pipe_tunnel);
    tunnelBind(pipe_tunnel, child);
    pipe_tunnel->lstate_offset = 0;
    child->lstate_offset       = (uint32_t) (tunnelGetLineStateSize(pipe_tunnel) - tunnelGetLineStateSize(child));

    chain = tunnelchainCreate(getWorkersCount());
    require(chain != NULL, "failed to recreate pipe publication chain");
    chain->sum_line_state_size = tunnelGetLineStateSize(pipe_tunnel);
    previous->chain            = chain;
    pipe_tunnel->chain         = chain;
    child->chain               = chain;
    tunnelchainFinalize(chain);
    pipe_tunnel->onStart(pipe_tunnel);

    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);
    for (wid_t wid = 1; wid < getWorkersCount(); ++wid)
    {
        waitForAtomicBool(&getWorker(wid)->message_admission_open,
                          "worker did not open message admission for the live pipe fixture");
    }

    /* Earlier identity cases intentionally leave a worker-1 message queued
     * while the loops are stopped. Drain through a barrier before injecting a
     * wakeup-post refusal, otherwise that old wakeup legitimately coalesces the
     * new message before the refusal seam is reached. */
    atomic_bool barrier_ran;
    atomic_init(&barrier_ran, false);
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) pipeQueueBarrier, NULL, &barrier_ran, NULL, NULL),
            "failed to admit the pipe queue-drain barrier");
    waitForAtomicBool(&barrier_ran, "pipe queue-drain barrier did not run on worker 1");

#ifdef WW_WORKER_MESSAGE_LINK_WRAP
    const worker_message_enqueue_test_failure_e pipe_failures[] = {
        kWorkerMessageEnqueueFailDequeGrowth,
        kWorkerMessageEnqueueFailWakeupPost,
    };
    atomicStoreRelaxed(&g_pipe_shutdown_requests, 0);
    for (uint32_t failure_index = 0; failure_index < ARRAY_SIZE(pipe_failures); ++failure_index)
    {
        line_t *refused_source = lineCreate(tunnelchainGetLinePools(chain), 0);
        workerMessagesEnqueueTestSetFailure(pipe_failures[failure_index]);
        require(! pipeTo(child, refused_source, 1), "pipe Init queue refusal was reported as admitted");
        requirePipeLineStateZero(pipe_tunnel, refused_source, "pipe Init refusal retained borrowed line state");
        require(atomicLoadRelaxed(&g_pipe_init_count) == 0, "pipe Init refusal ran a late callback");
        require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 1,
                "pipe Init refusal retained its staged owned line or pair reference");
        lineDestroy(refused_source);
        require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0,
                "pipe Init refusal retained the borrowed source allocation");
    }
    require(atomicLoadRelaxed(&g_pipe_shutdown_requests) == ARRAY_SIZE(pipe_failures),
            "pipe queue refusals did not each request one terminal reconciliation");
#endif

    source = lineCreate(tunnelchainGetLinePools(chain), 0);
    require(pipeTo(child, source, 1), "publication-winning pipeTo rejected a valid pair");
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_init_count) != 1; ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_init_count) == 1, "publication-winning pipe Init did not reach worker 1");

    pipe_payload_lifetime_t up_lifetime;
    pipe_tunnel->fnPayloadU(pipe_tunnel, source, pipeTestPayload(&up_lifetime));
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_owned_payload_count) != 1; ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_owned_payload_count) == 1,
            "pipe upstream Payload did not reach the owned line exactly once");
    require(atomicLoadRelaxed(&up_lifetime.releases) == 1, "pipe upstream Payload was not released exactly once");

    pipe_payload_lifetime_t down_lifetime;
    pipe_down_call_t        down_call = {
               .wrapper = pipe_tunnel,
               .line    = atomicLoadExplicit(&g_pipe_owned_line, memory_order_acquire),
               .payload = pipeTestPayload(&down_lifetime),
               .finish  = false,
    };
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) pipeDownCallOnWorker, NULL, &down_call, NULL, NULL),
            "failed to admit the pipe downstream Payload fixture");
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_borrowed_payload_count) != 1; ++attempt)
    {
        discard wloopProcessEvents(getWorkerLoop(0), 0);
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_borrowed_payload_count) == 1,
            "pipe downstream Payload did not reach the borrowed line exactly once");
    require(atomicLoadRelaxed(&down_lifetime.releases) == 1, "pipe downstream Payload was not released exactly once");

    line_t *upstream_finished_source = lineCreate(tunnelchainGetLinePools(chain), 0);
    require(pipeTo(child, upstream_finished_source, 1), "failed to create the upstream-Finish pipe pair");
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_init_count) != 2; ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_init_count) == 2, "upstream-Finish pair Init did not reach worker 1");
    pipe_tunnel->fnFinU(pipe_tunnel, upstream_finished_source);
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_owned_finish_count) != 1; ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_owned_finish_count) == 1,
            "upstream Finish did not close the owned role exactly once");
    require(atomicLoadRelaxed(&g_pipe_borrowed_finish_count) == 0,
            "upstream Finish reflected back toward its already-finished sender");
    require(lineIsAlive(upstream_finished_source), "pipe destroyed its borrowed upstream-Finish line");
    requirePipeLineStateZero(
        pipe_tunnel, upstream_finished_source, "upstream Finish retained the borrowed line-state attachment");
    lineDestroy(upstream_finished_source);

    line_t *downstream_finished_source = lineCreate(tunnelchainGetLinePools(chain), 0);
    require(pipeTo(child, downstream_finished_source, 1), "failed to create the downstream-Finish pipe pair");
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_init_count) != 3; ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_init_count) == 3, "downstream-Finish pair Init did not reach worker 1");
    pipe_down_call_t finish_call = {
        .wrapper = pipe_tunnel,
        .line    = atomicLoadExplicit(&g_pipe_owned_line, memory_order_acquire),
        .finish  = true,
    };
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) pipeDownCallOnWorker, NULL, &finish_call, NULL, NULL),
            "failed to admit the pipe downstream Finish fixture");
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_borrowed_finish_count) != 1; ++attempt)
    {
        discard wloopProcessEvents(getWorkerLoop(0), 0);
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_borrowed_finish_count) == 1,
            "downstream Finish did not close the borrowed role exactly once");
    require(atomicLoadRelaxed(&g_pipe_owned_finish_count) == 1,
            "downstream Finish reflected back toward its already-finished sender");
    require(lineIsAlive(downstream_finished_source), "pipe destroyed its borrowed downstream-Finish line");
    requirePipeLineStateZero(
        pipe_tunnel, downstream_finished_source, "downstream Finish retained the borrowed line-state attachment");
    lineDestroy(downstream_finished_source);

    line_t *worker_stop_source = lineCreate(tunnelchainGetLinePools(chain), 0);
    require(pipeTo(child, worker_stop_source, 1), "failed to create the worker-stop pipe pair");
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_init_count) != 4; ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_init_count) == 4, "worker-stop pair Init did not reach worker 1");
    pipe_tunnel->onWorkerStop(pipe_tunnel, 0, testShutdownContext());
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) pipeWorkerStopCall, NULL, pipe_tunnel, NULL, NULL),
            "failed to admit the pipe worker-1 stop fixture");
    atomic_bool worker_stop_completed;
    atomic_init(&worker_stop_completed, false);
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) pipeQueueBarrier, NULL, &worker_stop_completed, NULL, NULL),
            "failed to admit the pipe worker-stop barrier");
    waitForAtomicBool(&worker_stop_completed, "pipe worker-stop barrier did not run on worker 1");
    for (uint32_t attempt = 0; attempt < 5000 && (atomicLoadRelaxed(&g_pipe_owned_finish_count) != 3 ||
                                                  atomicLoadRelaxed(&g_pipe_borrowed_finish_count) != 3);
         ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_owned_finish_count) == 3 && atomicLoadRelaxed(&g_pipe_borrowed_finish_count) == 3,
            "worker-stop did not finish both roles of every live pipe pair exactly once");
    require(lineIsAlive(worker_stop_source), "worker-stop destroyed its borrowed source line");
    requirePipeLineStateZero(pipe_tunnel, worker_stop_source, "worker-stop retained borrowed line state");
    lineDestroy(worker_stop_source);

    pipe_tunnel->onStop(pipe_tunnel, testShutdownContext());
    require(lineIsAlive(source), "pipe stop destroyed its borrowed source line");
    requirePipeLineStateZero(pipe_tunnel, source, "pipe stop retained the borrowed line-state attachment");
    require(atomicLoadRelaxed(&g_pipe_borrowed_finish_count) == 3,
            "pipe stop did not finish the borrowed role exactly once");
    require(atomicLoadRelaxed(&g_pipe_owned_finish_count) == 3,
            "pipe stop did not finish the initialized owned role exactly once");
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 1,
            "pipe stop did not reclaim its owned line and pair references");

    lineDestroy(source);
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0,
            "pipe publication fixture retained a line after final borrowed release");
    tunnelchainDestroy(chain);
    pipetunnelDestroy(pipe_tunnel, testShutdownContext());
    tunnelDestroy(previous);
}

typedef struct pipe_message_case_fixture_s
{
    tunnel_t       *previous;
    tunnel_t       *child;
    tunnel_t       *wrapper;
    tunnel_chain_t *chain;
    line_t         *borrowed;
    line_t         *owned;
} pipe_message_case_fixture_t;

static void pipeMessageCaseSetup(pipe_message_case_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    atomicStoreRelaxed(&g_pipe_init_count, 0);
    atomicStoreRelaxed(&g_pipe_owned_finish_count, 0);
    atomicStoreRelaxed(&g_pipe_borrowed_finish_count, 0);
    atomicStoreRelaxed(&g_pipe_owned_payload_count, 0);
    atomicStoreRelaxed(&g_pipe_borrowed_payload_count, 0);
    atomicStoreExplicit(&g_pipe_owned_line, NULL, memory_order_release);

    fixture->previous = tunnelCreate(NULL, 0, 0);
    fixture->child    = tunnelCreate(NULL, 0, 0);
    require(fixture->previous != NULL && fixture->child != NULL, "failed to create pipe message endpoints");
    fixture->child->fnInitU       = pipeTestOwnedInit;
    fixture->child->fnPayloadU    = pipeTestOwnedPayload;
    fixture->child->fnFinU        = pipeTestOwnedFinish;
    fixture->previous->fnPayloadD = pipeTestBorrowedPayload;
    fixture->previous->fnFinD     = pipeTestBorrowedFinish;

    fixture->wrapper = pipetunnelCreate(fixture->child);
    require(fixture->wrapper != NULL, "failed to create pipe message wrapper");
    tunnelBind(fixture->previous, fixture->wrapper);
    tunnelBind(fixture->wrapper, fixture->child);
    fixture->wrapper->lstate_offset = 0;
    fixture->child->lstate_offset =
        (uint32_t) (tunnelGetLineStateSize(fixture->wrapper) - tunnelGetLineStateSize(fixture->child));

    fixture->chain = tunnelchainCreate(getWorkersCount());
    require(fixture->chain != NULL, "failed to create pipe message chain");
    fixture->chain->sum_line_state_size = tunnelGetLineStateSize(fixture->wrapper);
    fixture->previous->chain            = fixture->chain;
    fixture->wrapper->chain             = fixture->chain;
    fixture->child->chain               = fixture->chain;
    tunnelchainFinalize(fixture->chain);
    fixture->wrapper->onStart(fixture->wrapper);

    fixture->borrowed = lineCreate(tunnelchainGetLinePools(fixture->chain), 0);
    require(fixture->borrowed != NULL && pipeTo(fixture->child, fixture->borrowed, 1),
            "failed to publish the pipe message pair");
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_init_count) != 1; ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_init_count) == 1, "pipe message pair Init did not reach worker 1");
    fixture->owned = atomicLoadExplicit(&g_pipe_owned_line, memory_order_acquire);
    require(fixture->owned != NULL, "pipe message pair did not publish its owned line");
}

static void pipeMessageCaseDrainAndDestroy(pipe_message_case_fixture_t *fixture)
{
    fixture->wrapper->onQuiesceRequest(fixture->wrapper, testShutdownContext());
    fixture->wrapper->onWorkerStop(fixture->wrapper, 0, testShutdownContext());

    atomic_bool worker_done;
    atomic_init(&worker_done, false);
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) pipeWorkerStopCall, NULL, fixture->wrapper, &worker_done, NULL),
            "failed to admit the pipe message worker drain");
    waitForAtomicBool(&worker_done, "pipe message worker drain did not complete");

    require(lineIsAlive(fixture->borrowed), "pipe destroyed the borrowed message-case line");
    requirePipeLineStateZero(fixture->wrapper, fixture->borrowed, "pipe message case retained borrowed line state");
    lineDestroy(fixture->borrowed);
    require(masterpoolGetCheckedOut(fixture->chain->masterpool_line_pool) == 0,
            "pipe message case retained an owned line or pair reference");

    /* Repeated stop is intentionally harmless after both authoritative worker
     * inventories have been drained. */
    fixture->wrapper->onWorkerStop(fixture->wrapper, 0, testShutdownContext());
    tunnelchainDestroy(fixture->chain);
    pipetunnelDestroy(fixture->wrapper, testShutdownContext());
    tunnelDestroy(fixture->previous);
}

typedef struct pipe_blocking_barrier_s
{
    atomic_bool entered;
    atomic_bool release;
    atomic_bool done;
} pipe_blocking_barrier_t;

static void pipeBlockingBarrier(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard                  worker;
    discard                  arg2;
    discard                  arg3;
    pipe_blocking_barrier_t *barrier = arg1;
    atomicStoreExplicit(&barrier->entered, true, memory_order_release);
    while (! atomicLoadExplicit(&barrier->release, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    atomicStoreExplicit(&barrier->done, true, memory_order_release);
}

static void pipeRunRefusalCase(bool upstream, bool finish, worker_message_enqueue_test_failure_e failure)
{
    pipe_message_case_fixture_t fixture;
    pipeMessageCaseSetup(&fixture);
    atomicStoreRelaxed(&g_pipe_shutdown_requests, 0);

    pipe_payload_lifetime_t lifetime;
    sbuf_t                 *payload = finish ? NULL : pipeTestPayload(&lifetime);
    if (upstream)
    {
        workerMessagesEnqueueTestSetFailure(failure);
        if (finish)
        {
            fixture.wrapper->fnFinU(fixture.wrapper, fixture.borrowed);
        }
        else
        {
            fixture.wrapper->fnPayloadU(fixture.wrapper, fixture.borrowed, payload);
        }
    }
    else
    {
        atomic_bool done;
        atomic_init(&done, false);
        pipe_down_call_t call = {
            .wrapper = fixture.wrapper,
            .line    = fixture.owned,
            .payload = payload,
            .done    = &done,
            .failure = failure,
            .finish  = finish,
        };
        require(sendWorkerMessageForceQueueWithCleanup(
                    1, (WorkerMessageCallback) pipeDownCallOnWorker, NULL, &call, NULL, NULL),
                "failed to admit the pipe refusal driver");
        waitForAtomicBool(&done, "pipe refusal driver did not complete");
    }

    require(atomicLoadRelaxed(&g_pipe_shutdown_requests) == 1,
            "pipe Payload/Finish refusal did not request one terminal reconciliation");
    if (! finish)
    {
        require(atomicLoadRelaxed(&lifetime.releases) == 1, "refused pipe Payload was not recycled exactly once");
        require(atomicLoadRelaxed(&g_pipe_owned_payload_count) == 0 &&
                    atomicLoadRelaxed(&g_pipe_borrowed_payload_count) == 0,
                "refused pipe Payload reached a user callback");
    }
    pipeMessageCaseDrainAndDestroy(&fixture);
}

static void pipeRunAdmittedLateCase(bool upstream, bool finish)
{
    pipe_message_case_fixture_t fixture;
    pipeMessageCaseSetup(&fixture);

    pipe_payload_lifetime_t lifetime;
    sbuf_t                 *payload = finish ? NULL : pipeTestPayload(&lifetime);
    pipe_blocking_barrier_t barrier;
    memoryZero(&barrier, sizeof(barrier));
    atomic_init(&barrier.entered, false);
    atomic_init(&barrier.release, false);
    atomic_init(&barrier.done, false);

    if (upstream)
    {
        require(sendWorkerMessageForceQueueWithCleanup(
                    1, (WorkerMessageCallback) pipeBlockingBarrier, NULL, &barrier, NULL, NULL),
                "failed to admit the pipe late-dispatch barrier");
        waitForAtomicBool(&barrier.entered, "pipe late-dispatch barrier did not stop worker 1");
        if (finish)
        {
            fixture.wrapper->fnFinU(fixture.wrapper, fixture.borrowed);
        }
        else
        {
            fixture.wrapper->fnPayloadU(fixture.wrapper, fixture.borrowed, payload);
        }
        fixture.wrapper->onQuiesceRequest(fixture.wrapper, testShutdownContext());
        atomicStoreExplicit(&barrier.release, true, memory_order_release);
        waitForAtomicBool(&barrier.done, "pipe late-dispatch barrier did not release worker 1");
        if (! finish)
        {
            for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&lifetime.releases) == 0; ++attempt)
            {
                wwSleepMS(1);
            }
        }
        else
        {
            for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_owned_finish_count) == 0; ++attempt)
            {
                wwSleepMS(1);
            }
        }
    }
    else
    {
        atomic_bool done;
        atomic_init(&done, false);
        pipe_down_call_t call = {
            .wrapper = fixture.wrapper,
            .line    = fixture.owned,
            .payload = payload,
            .done    = &done,
            .failure = kWorkerMessageEnqueueFailNone,
            .finish  = finish,
        };
        require(sendWorkerMessageForceQueueWithCleanup(
                    1, (WorkerMessageCallback) pipeDownCallOnWorker, NULL, &call, NULL, NULL),
                "failed to admit the downstream late-dispatch driver");
        waitForAtomicBool(&done, "downstream late-dispatch driver did not admit its pipe message");
        fixture.wrapper->onQuiesceRequest(fixture.wrapper, testShutdownContext());
        for (uint32_t attempt = 0; attempt < 5000 && (! finish ? atomicLoadRelaxed(&lifetime.releases) == 0
                                                               : atomicLoadRelaxed(&g_pipe_borrowed_finish_count) == 0);
             ++attempt)
        {
            discard wloopProcessEvents(getWorkerLoop(0), 0);
            wwSleepMS(1);
        }
    }

    if (! finish)
    {
        require(atomicLoadRelaxed(&lifetime.releases) == 1, "late pipe Payload was not recycled exactly once");
        require(atomicLoadRelaxed(&g_pipe_owned_payload_count) == 0 &&
                    atomicLoadRelaxed(&g_pipe_borrowed_payload_count) == 0,
                "late pipe Payload crossed a terminal pair");
    }
    pipeMessageCaseDrainAndDestroy(&fixture);
}

static void pipeRunQueuedSourceClose(void)
{
    pipe_message_case_fixture_t fixture;
    pipeMessageCaseSetup(&fixture);
    pipe_blocking_barrier_t barrier = {0};
    atomic_init(&barrier.entered, false);
    atomic_init(&barrier.release, false);
    atomic_init(&barrier.done, false);
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) pipeBlockingBarrier, NULL, &barrier, NULL, NULL),
            "source-close barrier refused");
    waitForAtomicBool(&barrier.entered, "source-close barrier not entered");
    pipe_payload_lifetime_t lifetime;
    fixture.wrapper->fnPayloadU(fixture.wrapper, fixture.borrowed, pipeTestPayload(&lifetime));
    lineRef(fixture.borrowed);
    fixture.wrapper->fnFinU(fixture.wrapper, fixture.borrowed);
    lineDestroy(fixture.borrowed);
    atomicStoreExplicit(&barrier.release, true, memory_order_release);
    waitForAtomicBool(&barrier.done, "source-close barrier not released");
    atomic_bool done;
    atomic_init(&done, false);
    require(
        sendWorkerMessageForceQueueWithCleanup(1, (WorkerMessageCallback) pipeQueueBarrier, NULL, &done, NULL, NULL),
        "source-close completion refused");
    waitForAtomicBool(&done, "source-close completion missing");
    require(atomicLoadRelaxed(&lifetime.releases) == 1 && atomicLoadRelaxed(&g_pipe_owned_payload_count) == 1 &&
                atomicLoadRelaxed(&g_pipe_owned_finish_count) == 1,
            "source closure lost queued private-pipe bytes or Finish ordering");
    lineUnref(fixture.borrowed);
    require(masterpoolGetCheckedOut(fixture.chain->masterpool_line_pool) == 0, "queued source close leaked lines");
    tunnelchainDestroy(fixture.chain);
    pipetunnelDestroy(fixture.wrapper, testShutdownContext());
    tunnelDestroy(fixture.previous);
}

void testPipePayloadFinishLateAndRefused(void)
{
    pipeRunQueuedSourceClose();
#ifdef WW_WORKER_MESSAGE_LINK_WRAP
    const worker_message_enqueue_test_failure_e failures[] = {
        kWorkerMessageEnqueueFailDequeGrowth,
        kWorkerMessageEnqueueFailWakeupPost,
    };
    for (uint32_t failure_index = 0; failure_index < ARRAY_SIZE(failures); ++failure_index)
    {
        for (uint32_t upstream = 0; upstream < 2; ++upstream)
        {
            pipeRunRefusalCase(upstream != 0, false, failures[failure_index]);
            pipeRunRefusalCase(upstream != 0, true, failures[failure_index]);
        }
    }
#endif

    pipeRunAdmittedLateCase(true, false);
    pipeRunAdmittedLateCase(true, true);
    pipeRunAdmittedLateCase(false, false);
    pipeRunAdmittedLateCase(false, true);
}
