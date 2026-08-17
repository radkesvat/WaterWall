#include "pipe_tunnel.h"

/* Cross-worker pipe forwarding with one explicit owner for each pair. */

#include "global_state.h"
#include "line.h"
#include "loggers/internal_logger.h"
#include "managers/node_manager.h"
#include "managers/signal_manager.h"
#include "tunnel.h"

typedef struct pipe_pair_s pipe_pair_t;

#ifdef WW_PIPE_TUNNEL_TEST_SEAM
void pipeTunnelAfterFastStopCheckTestSeam(tunnel_t *wrapper, line_t *source_line);
#endif

typedef enum pipe_line_role_e
{
    kPipeLineNone = 0,
    kPipeLineBorrowed,
    kPipeLineOwned,
} pipe_line_role_t;

typedef struct pipetunnel_line_state_s
{
    pipe_pair_t *pair;
    uint8_t      role;
} pipetunnel_line_state_t;

typedef struct pipetunnel_state_s
{
    /* Kept first so the wrapper's historical child lookup remains trivial. */
    tunnel_t    *child;
    pipe_pair_t *pairs;
    wmutex_t     pairs_lock;
    atomic_bool  stopping;
    bool         pairs_lock_initialized;
} pipetunnel_state_t;

struct pipe_pair_s
{
    pipe_pair_t *prev;
    pipe_pair_t *next;
    tunnel_t    *wrapper;
    line_t      *borrowed_line;
    line_t      *owned_line;
    atomic_uint  refs;
    atomic_bool  borrowed_attached;
    atomic_bool  owned_attached;
    atomic_bool  registered;
    atomic_bool  terminal;
    atomic_bool  prev_finished;
    atomic_bool  next_finished;
    atomic_bool  owned_init_delivered;
};

typedef enum pipe_message_type_e
{
    kPipeMessageInit,
    kPipeMessageEst,
    kPipeMessageFin,
    kPipeMessagePayload,
    kPipeMessagePause,
    kPipeMessageResume,
} pipe_message_type_t;

typedef enum pipe_send_result_e
{
    kPipeSendAdmitted,
    kPipeSendAlreadyTerminal,
    kPipeSendRefused,
} pipe_send_result_t;

static void pipeReconcileLine(pipe_pair_t *pair, line_t *line);

static pipetunnel_state_t *pipeTunnelState(tunnel_t *t)
{
    return tunnelGetState(t);
}

static tunnel_t *getParentTunnel(tunnel_t *t)
{
    return t->prev;
}

/* Queued cleanup may run after logical line death, so it needs a physical-only
 * reference just like other worker-message cleanup paths. */
static inline void lineLockForce(line_t *const line)
{
    assert(line->refc < LINE_REFC_MAX);
    if (0 == atomicIncRelaxed(&line->refc))
    {
        assert(false);
    }
}

static void pipePairRef(pipe_pair_t *pair)
{
    const w_atomic_uint_value_t previous = atomicAddExplicit(&pair->refs, 1, memory_order_relaxed);
    assert(previous != 0 && previous < UINT_MAX);
    discard previous;
}

static void pipePairUnref(pipe_pair_t *pair)
{
    const w_atomic_uint_value_t previous = atomicSubExplicit(&pair->refs, 1, memory_order_acq_rel);
    assert(previous != 0);
    if (previous != 1)
    {
        return;
    }

    assert(! atomicLoadExplicit(&pair->registered, memory_order_relaxed));
    assert(! atomicLoadExplicit(&pair->borrowed_attached, memory_order_relaxed));
    assert(! atomicLoadExplicit(&pair->owned_attached, memory_order_relaxed));

    /* The pair, rather than either attached side, owns these physical
     * references. Keeping them through the last queued message prevents a
     * sender from racing a detach and incrementing a line that has already
     * returned to the pool. */
    lineUnlock(pair->borrowed_line);
    lineUnlock(pair->owned_line);
    memoryFree(pair);
}

static void pipePairMaybeUnregister(pipe_pair_t *pair)
{
    pipetunnel_state_t *state                      = pipeTunnelState(pair->wrapper);
    bool                release_registry_reference = false;

    /* Both sides may detach concurrently. Recheck them while serialized so
     * the classic two stores/two stale loads race cannot strand a registry-only
     * pair after each detacher observed the other side as still attached. */
    mutexLock(&state->pairs_lock);
    if (atomicLoadExplicit(&pair->registered, memory_order_acquire) &&
        ! atomicLoadExplicit(&pair->borrowed_attached, memory_order_acquire) &&
        ! atomicLoadExplicit(&pair->owned_attached, memory_order_acquire))
    {
        atomicStoreExplicit(&pair->registered, false, memory_order_release);
        if (pair->prev != NULL)
        {
            pair->prev->next = pair->next;
        }
        else
        {
            assert(state->pairs == pair);
            state->pairs = pair->next;
        }
        if (pair->next != NULL)
        {
            pair->next->prev = pair->prev;
        }
        pair->prev                 = NULL;
        pair->next                 = NULL;
        release_registry_reference = true;
    }
    mutexUnlock(&state->pairs_lock);

    if (release_registry_reference)
    {
        /* Registry ownership. */
        pipePairUnref(pair);
    }
}

static void pipePairDetach(pipe_pair_t *pair, line_t *line)
{
    atomic_bool *attached;

    if (line == pair->borrowed_line)
    {
        attached = &pair->borrowed_attached;
    }
    else
    {
        assert(line == pair->owned_line);
        attached = &pair->owned_attached;
    }

    bool expected = true;
    if (! atomic_compare_exchange_strong_explicit(
            attached, &expected, false, memory_order_acq_rel, memory_order_acquire))
    {
        return;
    }

    pipetunnel_line_state_t *ls = lineGetState(line, pair->wrapper);
    if (ls->pair == pair)
    {
        memoryZero(ls, sizeof(*ls));
    }

    /* This attached side's pair reference. The pair-held line references are
     * released together only after both sides and all messages detach. */
    pipePairUnref(pair);
    pipePairMaybeUnregister(pair);
}

static void pipeCloseBorrowed(pipe_pair_t *pair)
{
    line_t   *line = pair->borrowed_line;
    tunnel_t *t    = pair->wrapper;

    pipePairRef(pair);
    lineLockForce(line);
    pipePairDetach(pair, line);

    if (lineIsAlive(line) && ! atomicLoadExplicit(&pair->prev_finished, memory_order_acquire))
    {
        tunnelPrevDownStreamFinish(t, line);
    }
    lineUnlock(line);
    pipePairUnref(pair);
}

static void pipeCloseOwned(pipe_pair_t *pair)
{
    line_t   *line = pair->owned_line;
    tunnel_t *t    = pair->wrapper;

    pipePairRef(pair);
    lineLockForce(line);
    pipePairDetach(pair, line);

    if (lineIsAlive(line) && atomicLoadExplicit(&pair->owned_init_delivered, memory_order_acquire) &&
        ! atomicLoadExplicit(&pair->next_finished, memory_order_acquire))
    {
        tunnelNextUpStreamFinish(t, line);
    }
    if (lineIsAlive(line))
    {
        lineDestroy(line);
    }
    lineUnlock(line);
    pipePairUnref(pair);
}

static void pipeReconcileLine(pipe_pair_t *pair, line_t *line)
{
    if (line == pair->borrowed_line && atomicLoadExplicit(&pair->borrowed_attached, memory_order_acquire))
    {
        pipeCloseBorrowed(pair);
    }
    else if (line == pair->owned_line && atomicLoadExplicit(&pair->owned_attached, memory_order_acquire))
    {
        pipeCloseOwned(pair);
    }
}

static void pipeEscalateRefusal(void)
{
    /* The pair registry is already a complete local terminal owner. Escalation
     * guarantees its no-message Stop fallback will run if the target worker
     * never observes another callback. */
    /* Pair reconciliation remains mandatory after a successful shutdown
     * request, but a queue refusal caused by that accepted shutdown must not
     * race it and replace status zero with an operational failure. */
    if (! signalmanagerRequestShutdownPreservingAcceptedStatus(1))
    {
        abortProgramNow(1);
    }
}

static void pipeDiscardPayload(sbuf_t *payload)
{
    if (payload != NULL)
    {
        /* The buffer originated on the opposite worker. Destruction is
         * provenance-safe from either immediate or late cleanup context. */
        sbufDestroy(payload);
    }
}

static void cleanupQueuedPipeMessage(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard      reason;
    pipe_pair_t *pair    = arg1;
    line_t      *line_to = arg2;
    sbuf_t      *payload = arg3;

    atomicStoreExplicit(&pair->terminal, true, memory_order_release);
    pipeDiscardPayload(payload);
    if (currentThreadIsEventWorkerWID(lineGetWID(line_to)))
    {
        pipeReconcileLine(pair, line_to);
    }
    lineUnlock(line_to);
    pipePairUnref(pair);
}

static bool pipeMessageLineIsUsable(pipe_pair_t *pair, line_t *line_to, sbuf_t *payload)
{
    const bool attached = line_to == pair->borrowed_line
                              ? atomicLoadExplicit(&pair->borrowed_attached, memory_order_acquire)
                              : atomicLoadExplicit(&pair->owned_attached, memory_order_acquire);
    const bool alive    = lineIsAlive(line_to);
    const bool terminal = atomicLoadExplicit(&pair->terminal, memory_order_acquire);

    if (alive && attached && ! terminal)
    {
        pipetunnel_line_state_t *ls = lineGetState(line_to, pair->wrapper);
        if (ls->pair == pair)
        {
            return true;
        }
    }

    atomicStoreExplicit(&pair->terminal, true, memory_order_release);
    pipeDiscardPayload(payload);
    pipeReconcileLine(pair, line_to);
    lineUnlock(line_to);
    pipePairUnref(pair);
    return false;
}

static void pipeApplyUp(pipe_pair_t *pair, line_t *line_to, sbuf_t *payload, pipe_message_type_t type)
{
    if (! pipeMessageLineIsUsable(pair, line_to, payload))
    {
        return;
    }

    tunnel_t *t    = pair->wrapper;
    tunnel_t *next = t->next;

    if (type == kPipeMessageFin)
    {
        pipeCloseOwned(pair);
        lineUnlock(line_to);
        pipePairUnref(pair);
        return;
    }

    switch (type)
    {
    case kPipeMessageInit:
        atomicStoreExplicit(&pair->owned_init_delivered, true, memory_order_release);
        next->fnInitU(next, line_to);
        break;
    case kPipeMessageEst:
        next->fnEstU(next, line_to);
        break;
    case kPipeMessagePayload:
        next->fnPayloadU(next, line_to, payload);
        break;
    case kPipeMessagePause:
        next->fnPauseU(next, line_to);
        break;
    case kPipeMessageResume:
        next->fnResumeU(next, line_to);
        break;
    case kPipeMessageFin:
        assert(false);
        break;
    }

    lineUnlock(line_to);
    pipePairUnref(pair);
}

static void pipeApplyDown(pipe_pair_t *pair, line_t *line_to, sbuf_t *payload, pipe_message_type_t type)
{
    if (! pipeMessageLineIsUsable(pair, line_to, payload))
    {
        return;
    }

    tunnel_t *t    = pair->wrapper;
    tunnel_t *prev = t->prev;

    if (type == kPipeMessageFin)
    {
        pipeCloseBorrowed(pair);
        lineUnlock(line_to);
        pipePairUnref(pair);
        return;
    }

    if (type == kPipeMessageEst && lineIsEstablished(line_to))
    {
        lineUnlock(line_to);
        pipePairUnref(pair);
        return;
    }

    switch (type)
    {
    case kPipeMessageEst:
        prev->fnEstD(prev, line_to);
        break;
    case kPipeMessagePayload:
        prev->fnPayloadD(prev, line_to, payload);
        break;
    case kPipeMessagePause:
        prev->fnPauseD(prev, line_to);
        break;
    case kPipeMessageResume:
        prev->fnResumeD(prev, line_to);
        break;
    case kPipeMessageInit:
    case kPipeMessageFin:
        assert(false);
        break;
    }

    lineUnlock(line_to);
    pipePairUnref(pair);
}

#define PIPE_UP_RECEIVER(name, type)                                                                                   \
    static void name(worker_t *worker, void *arg1, void *arg2, void *arg3)                                             \
    {                                                                                                                  \
        discard worker;                                                                                                \
        pipeApplyUp(arg1, arg2, arg3, type);                                                                           \
    }

#define PIPE_DOWN_RECEIVER(name, type)                                                                                 \
    static void name(worker_t *worker, void *arg1, void *arg2, void *arg3)                                             \
    {                                                                                                                  \
        discard worker;                                                                                                \
        pipeApplyDown(arg1, arg2, arg3, type);                                                                         \
    }

PIPE_UP_RECEIVER(onMsgReceivedUpInit, kPipeMessageInit)
PIPE_UP_RECEIVER(onMsgReceivedUpEst, kPipeMessageEst)
PIPE_UP_RECEIVER(onMsgReceivedUpFin, kPipeMessageFin)
PIPE_UP_RECEIVER(onMsgReceivedUpPayload, kPipeMessagePayload)
PIPE_UP_RECEIVER(onMsgReceivedUpPause, kPipeMessagePause)
PIPE_UP_RECEIVER(onMsgReceivedUpResume, kPipeMessageResume)
PIPE_DOWN_RECEIVER(onMsgReceivedDownEst, kPipeMessageEst)
PIPE_DOWN_RECEIVER(onMsgReceivedDownFin, kPipeMessageFin)
PIPE_DOWN_RECEIVER(onMsgReceivedDownPayload, kPipeMessagePayload)
PIPE_DOWN_RECEIVER(onMsgReceivedDownPause, kPipeMessagePause)
PIPE_DOWN_RECEIVER(onMsgReceivedDownResume, kPipeMessageResume)

#undef PIPE_UP_RECEIVER
#undef PIPE_DOWN_RECEIVER

static WorkerMessageCallback pipeUpCallback(pipe_message_type_t type)
{
    switch (type)
    {
    case kPipeMessageInit:
        return (WorkerMessageCallback) onMsgReceivedUpInit;
    case kPipeMessageEst:
        return (WorkerMessageCallback) onMsgReceivedUpEst;
    case kPipeMessageFin:
        return (WorkerMessageCallback) onMsgReceivedUpFin;
    case kPipeMessagePayload:
        return (WorkerMessageCallback) onMsgReceivedUpPayload;
    case kPipeMessagePause:
        return (WorkerMessageCallback) onMsgReceivedUpPause;
    case kPipeMessageResume:
        return (WorkerMessageCallback) onMsgReceivedUpResume;
    }
    return NULL;
}

static WorkerMessageCallback pipeDownCallback(pipe_message_type_t type)
{
    switch (type)
    {
    case kPipeMessageEst:
        return (WorkerMessageCallback) onMsgReceivedDownEst;
    case kPipeMessageFin:
        return (WorkerMessageCallback) onMsgReceivedDownFin;
    case kPipeMessagePayload:
        return (WorkerMessageCallback) onMsgReceivedDownPayload;
    case kPipeMessagePause:
        return (WorkerMessageCallback) onMsgReceivedDownPause;
    case kPipeMessageResume:
        return (WorkerMessageCallback) onMsgReceivedDownResume;
    case kPipeMessageInit:
        return NULL;
    }
    return NULL;
}

static pipe_send_result_t pipeSend(pipe_pair_t *pair, line_t *line_to, pipe_message_type_t type, sbuf_t *payload,
                                   bool upstream)
{
    if (atomicLoadExplicit(&pair->terminal, memory_order_acquire))
    {
        pipeDiscardPayload(payload);
        return kPipeSendAlreadyTerminal;
    }

    WorkerMessageCallback callback = upstream ? pipeUpCallback(type) : pipeDownCallback(type);
    assert(callback != NULL);

    pipePairRef(pair);
    lineLockForce(line_to);
    if (sendWorkerMessageForceQueueWithCleanup(
            lineGetWID(line_to), callback, cleanupQueuedPipeMessage, pair, line_to, payload) ==
        kWorkerMessageSubmitAccepted)
    {
        return kPipeSendAdmitted;
    }
    return kPipeSendRefused;
}

static pipe_pair_t *pipeLinePair(tunnel_t *t, line_t *line)
{
    pipetunnel_line_state_t *ls = lineGetState(line, t);
    return ls->pair;
}

static void pipetunnelDefaultUpStreamInit(tunnel_t *t, line_t *line)
{
    pipe_pair_t *pair = pipeLinePair(t, line);
    if (pair == NULL)
    {
        tunnelNextUpStreamInit(t, line);
        return;
    }
    const pipe_send_result_t result = pipeSend(pair, pair->owned_line, kPipeMessageInit, NULL, true);
    if (result != kPipeSendAdmitted)
    {
        pipeReconcileLine(pair, line);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
    }
}

static void pipetunnelDefaultUpStreamEst(tunnel_t *t, line_t *line)
{
    pipe_pair_t *pair = pipeLinePair(t, line);
    if (pair == NULL)
    {
        tunnelNextUpStreamEst(t, line);
        return;
    }
    const pipe_send_result_t result = pipeSend(pair, pair->owned_line, kPipeMessageEst, NULL, true);
    if (result != kPipeSendAdmitted)
    {
        pipeReconcileLine(pair, line);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
    }
}

static void pipetunnelDefaultUpStreamFin(tunnel_t *t, line_t *line)
{
    pipe_pair_t *pair = pipeLinePair(t, line);
    if (pair == NULL)
    {
        tunnelNextUpStreamFinish(t, line);
        return;
    }

    pipePairRef(pair);
    atomicStoreExplicit(&pair->prev_finished, true, memory_order_release);
    pipePairDetach(pair, line);
    const pipe_send_result_t result = pipeSend(pair, pair->owned_line, kPipeMessageFin, NULL, true);
    if (result != kPipeSendAdmitted)
    {
        atomicStoreExplicit(&pair->terminal, true, memory_order_release);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
    }
    pipePairUnref(pair);
}

static void pipetunnelDefaultUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    pipe_pair_t *pair = pipeLinePair(t, line);
    if (pair == NULL)
    {
        tunnelNextUpStreamPayload(t, line, payload);
        return;
    }
    const pipe_send_result_t result = pipeSend(pair, pair->owned_line, kPipeMessagePayload, payload, true);
    if (result != kPipeSendAdmitted)
    {
        pipeReconcileLine(pair, line);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
    }
}

static void pipetunnelDefaultUpStreamPause(tunnel_t *t, line_t *line)
{
    pipe_pair_t *pair = pipeLinePair(t, line);
    if (pair == NULL)
    {
        tunnelNextUpStreamPause(t, line);
        return;
    }
    const pipe_send_result_t result = pipeSend(pair, pair->owned_line, kPipeMessagePause, NULL, true);
    if (result != kPipeSendAdmitted)
    {
        pipeReconcileLine(pair, line);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
    }
}

static void pipetunnelDefaultUpStreamResume(tunnel_t *t, line_t *line)
{
    pipe_pair_t *pair = pipeLinePair(t, line);
    if (pair == NULL)
    {
        tunnelNextUpStreamResume(t, line);
        return;
    }
    const pipe_send_result_t result = pipeSend(pair, pair->owned_line, kPipeMessageResume, NULL, true);
    if (result != kPipeSendAdmitted)
    {
        pipeReconcileLine(pair, line);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
    }
}

static void pipetunnelDefaultDownStreamInit(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
    assert(false);
}

static void pipetunnelDefaultDownStreamEst(tunnel_t *t, line_t *line)
{
    pipe_pair_t *pair = pipeLinePair(t, line);
    if (pair == NULL)
    {
        tunnelPrevDownStreamEst(t, line);
        return;
    }

    lineMarkEstablished(line);
    const pipe_send_result_t result = pipeSend(pair, pair->borrowed_line, kPipeMessageEst, NULL, false);
    if (result != kPipeSendAdmitted)
    {
        atomicStoreExplicit(&pair->terminal, true, memory_order_release);
        pipeReconcileLine(pair, line);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
    }
}

static void pipetunnelDefaultDownStreamFin(tunnel_t *t, line_t *line)
{
    pipe_pair_t *pair = pipeLinePair(t, line);
    if (pair == NULL)
    {
        tunnelPrevDownStreamFinish(t, line);
        return;
    }

    pipePairRef(pair);
    atomicStoreExplicit(&pair->next_finished, true, memory_order_release);
    pipePairDetach(pair, line);
    const pipe_send_result_t result = pipeSend(pair, pair->borrowed_line, kPipeMessageFin, NULL, false);
    if (result != kPipeSendAdmitted)
    {
        atomicStoreExplicit(&pair->terminal, true, memory_order_release);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
    }
    if (lineIsAlive(line))
    {
        lineDestroy(line);
    }
    pipePairUnref(pair);
}

static void pipetunnelDefaultDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    pipe_pair_t *pair = pipeLinePair(t, line);
    if (pair == NULL)
    {
        tunnelPrevDownStreamPayload(t, line, payload);
        return;
    }
    const pipe_send_result_t result = pipeSend(pair, pair->borrowed_line, kPipeMessagePayload, payload, false);
    if (result != kPipeSendAdmitted)
    {
        pipeReconcileLine(pair, line);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
    }
}

static void pipetunnelDefaultDownStreamPause(tunnel_t *t, line_t *line)
{
    pipe_pair_t *pair = pipeLinePair(t, line);
    if (pair == NULL)
    {
        tunnelPrevDownStreamPause(t, line);
        return;
    }
    const pipe_send_result_t result = pipeSend(pair, pair->borrowed_line, kPipeMessagePause, NULL, false);
    if (result != kPipeSendAdmitted)
    {
        pipeReconcileLine(pair, line);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
    }
}

static void pipetunnelDefaultDownStreamResume(tunnel_t *t, line_t *line)
{
    pipe_pair_t *pair = pipeLinePair(t, line);
    if (pair == NULL)
    {
        tunnelPrevDownStreamResume(t, line);
        return;
    }
    const pipe_send_result_t result = pipeSend(pair, pair->borrowed_line, kPipeMessageResume, NULL, false);
    if (result != kPipeSendAdmitted)
    {
        pipeReconcileLine(pair, line);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
    }
}

static void pipetunnelDefaultOnChain(tunnel_t *t, tunnel_chain_t *tc)
{
    tunnel_t *child = pipeTunnelState(t)->child;
    tunnelchainInsert(tc, t);
    tunnelBind(t, child);
    child->onChain(child, tc);
}

static void pipetunnelDefaultOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset)
{
    t->chain_index   = index;
    t->lstate_offset = *mem_offset;
    *mem_offset += t->lstate_size;
}

static void pipetunnelDefaultOnPrepair(tunnel_t *t)
{
    discard t;
}

static void pipetunnelDefaultOnStart(tunnel_t *t)
{
    atomicStoreExplicit(&pipeTunnelState(t)->stopping, false, memory_order_release);
}

static void pipetunnelDefaultOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    pipetunnel_state_t *state = pipeTunnelState(t);

    mutexLock(&state->pairs_lock);
    /*
     * The stop transition and pair publication share this lock. Once this
     * store is visible, no later pipeTo() commit can enter the registry; every
     * pair committed before it is visited by this sweep.
     */
    atomicStoreExplicit(&state->stopping, true, memory_order_release);
    for (pipe_pair_t *pair = state->pairs; pair != NULL; pair = pair->next)
    {
        atomicStoreExplicit(&pair->terminal, true, memory_order_release);
    }
    mutexUnlock(&state->pairs_lock);
}

static pipe_pair_t *pipeFindPairForWorker(pipetunnel_state_t *state, wid_t wid, line_t **line_out)
{
    pipe_pair_t *result = NULL;
    *line_out           = NULL;

    mutexLock(&state->pairs_lock);
    for (pipe_pair_t *pair = state->pairs; pair != NULL; pair = pair->next)
    {
        if (! atomicLoadExplicit(&pair->registered, memory_order_acquire))
        {
            continue;
        }
        if (atomicLoadExplicit(&pair->borrowed_attached, memory_order_acquire) &&
            lineGetWID(pair->borrowed_line) == wid)
        {
            result    = pair;
            *line_out = pair->borrowed_line;
        }
        else if (atomicLoadExplicit(&pair->owned_attached, memory_order_acquire) && lineGetWID(pair->owned_line) == wid)
        {
            result    = pair;
            *line_out = pair->owned_line;
        }
        if (result != NULL)
        {
            pipePairRef(result);
            break;
        }
    }
    mutexUnlock(&state->pairs_lock);
    return result;
}

static void pipeDrainWorker(tunnel_t *t, wid_t wid)
{
    pipetunnel_state_t *state = pipeTunnelState(t);
    assert(currentThreadIsEventWorkerWID(wid));

    for (;;)
    {
        line_t      *line = NULL;
        pipe_pair_t *pair = pipeFindPairForWorker(state, wid, &line);
        if (pair == NULL)
        {
            return;
        }
        atomicStoreExplicit(&pair->terminal, true, memory_order_release);
        pipeReconcileLine(pair, line);
        pipePairUnref(pair);
    }
}

static void pipetunnelDefaultOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    pipetunnel_state_t *state = pipeTunnelState(t);
    discard             context;
    if (state->pairs != NULL)
    {
        LOGF("PipeTunnel: final stop reached with live cross-worker pairs");
        abortProgramNow(1);
    }
}

static void pipetunnelDefaultOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    pipeDrainWorker(t, wid);
}

tunnel_t *pipetunnelCreate(tunnel_t *child)
{
    const uint32_t child_lstate_size = tunnelGetLineStateSize(child);
    if (UNLIKELY((size_t) child_lstate_size > UINT32_MAX - sizeof(pipetunnel_line_state_t)))
    {
        return NULL;
    }

    const uint32_t wrapper_lstate_size = child_lstate_size + (uint32_t) sizeof(pipetunnel_line_state_t);
    tunnel_t      *pt = tunnelCreate(tunnelGetNode(child), sizeof(pipetunnel_state_t), wrapper_lstate_size);
    if (! pt)
    {
        return NULL;
    }

    pipetunnel_state_t *state = pipeTunnelState(pt);
    *state                    = (pipetunnel_state_t) {.child = child};
    atomic_init(&state->stopping, false);
    if (! mutexTryInit(&state->pairs_lock))
    {
        tunnelDestroy(pt);
        return NULL;
    }
    state->pairs_lock_initialized = true;

    pt->fnInitU          = &pipetunnelDefaultUpStreamInit;
    pt->fnInitD          = &pipetunnelDefaultDownStreamInit;
    pt->fnPayloadU       = &pipetunnelDefaultUpStreamPayload;
    pt->fnPayloadD       = &pipetunnelDefaultDownStreamPayload;
    pt->fnEstU           = &pipetunnelDefaultUpStreamEst;
    pt->fnEstD           = &pipetunnelDefaultDownStreamEst;
    pt->fnFinU           = &pipetunnelDefaultUpStreamFin;
    pt->fnFinD           = &pipetunnelDefaultDownStreamFin;
    pt->fnPauseU         = &pipetunnelDefaultUpStreamPause;
    pt->fnPauseD         = &pipetunnelDefaultDownStreamPause;
    pt->fnResumeU        = &pipetunnelDefaultUpStreamResume;
    pt->fnResumeD        = &pipetunnelDefaultDownStreamResume;
    pt->onChain          = &pipetunnelDefaultOnChain;
    pt->onIndex          = &pipetunnelDefaultOnIndex;
    pt->onPrepare        = &pipetunnelDefaultOnPrepair;
    pt->onStart          = &pipetunnelDefaultOnStart;
    pt->onQuiesceRequest = &pipetunnelDefaultOnQuiesceRequest;
    pt->onStop           = &pipetunnelDefaultOnStop;
    pt->onWorkerStop     = &pipetunnelDefaultOnWorkerStop;
    pt->onDestroy        = &pipetunnelDestroy;
    return pt;
}

void pipetunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    pipetunnel_state_t *state = pipeTunnelState(t);
    assert(state->pairs == NULL);
    if (state->pairs_lock_initialized)
    {
        mutexDestroy(&state->pairs_lock);
        state->pairs_lock_initialized = false;
    }
    tunnelOwnedChildDestroy(state->child);
    state->child = NULL;
    tunnelDestroy(t);
}

static void pipeTunnelLogWIDViolation(const char *reason, tunnel_t *parent_tunnel, line_t *line, wid_t wid_to)
{
    LOGE("PipeTunnel: %s, line: %p, tunnel: %p", reason, (void *) line, (void *) parent_tunnel);
    LOGE("PipeTunnel: WID: %d, line WID: %d , to WID: %d",
         workerWIDForLog(getWID()),
         workerWIDForLog(lineGetWID(line)),
         workerWIDForLog(wid_to));
}

bool pipeTo(tunnel_t *t, line_t *line, wid_t wid_to)
{
    tunnel_t                *parent = getParentTunnel(t);
    pipetunnel_state_t      *state  = pipeTunnelState(parent);
    pipetunnel_line_state_t *source = lineGetState(line, parent);
    const wid_t              wid    = lineGetWID(line);

    if (UNLIKELY(! lineIsOnCurrentEventWorker(line)))
    {
        pipeTunnelLogWIDViolation("pipe source line is not owned by the calling worker", parent, line, wid_to);
        return false;
    }
    if (UNLIKELY(! workerWIDIsEventWorker(wid_to) || wid_to == wid ||
                 atomicLoadExplicit(&state->stopping, memory_order_acquire)))
    {
        pipeTunnelLogWIDViolation("pipe target must be a different active event worker", parent, line, wid_to);
        return false;
    }
    if (source->pair != NULL)
    {
        LOGE("PipeTunnel: source line %p is already attached to a cross-worker pair", (void *) line);
        return false;
    }

#ifdef WW_PIPE_TUNNEL_TEST_SEAM
    /* Deterministically lets a test place PreStop between the fast rejection
     * and the in-lock publication decision. */
    pipeTunnelAfterFastStopCheckTestSeam(parent, line);
#endif

    pipe_pair_t *pair = memoryAllocateZero(sizeof(*pair));
    if (pair == NULL)
    {
        LOGE("PipeTunnel: failed to allocate cross-worker pair metadata");
        return false;
    }

    line_t *owned = lineCreateForWorker(wid, tunnelchainGetLinePools(tunnelGetChain(t)), wid_to);
    lineCopyUsers(owned, line);

    /* Stage all metadata without publishing either line state. */
    *pair = (pipe_pair_t) {
        .wrapper       = parent,
        .borrowed_line = line,
        .owned_line    = owned,
    };
    atomic_init(&pair->refs, 0);
    atomic_init(&pair->borrowed_attached, false);
    atomic_init(&pair->owned_attached, false);
    atomic_init(&pair->registered, false);
    atomic_init(&pair->terminal, false);
    atomic_init(&pair->prev_finished, false);
    atomic_init(&pair->next_finished, false);
    atomic_init(&pair->owned_init_delivered, false);

    mutexLock(&state->pairs_lock);
    if (UNLIKELY(atomicLoadExplicit(&state->stopping, memory_order_acquire)))
    {
        mutexUnlock(&state->pairs_lock);
        /* The owned line has never been initialized or published. The source
         * remains borrowed and untouched. lineDestroy() releases copied user
         * metadata through the normal line reclamation path. */
        lineDestroy(owned);
        memoryFree(pair);
        return false;
    }

    /* Registry, both attachments, and their physical references become
     * observable as one lock-linearized commit. */
    atomicStoreExplicit(&pair->refs, 4, memory_order_relaxed); /* registry, two sides, this function */
    atomicStoreExplicit(&pair->borrowed_attached, true, memory_order_relaxed);
    atomicStoreExplicit(&pair->owned_attached, true, memory_order_relaxed);
    atomicStoreExplicit(&pair->registered, true, memory_order_relaxed);
    lineLock(line);
    lineLock(owned);
    *source                         = (pipetunnel_line_state_t) {.pair = pair, .role = kPipeLineBorrowed};
    pipetunnel_line_state_t *target = lineGetState(owned, parent);
    *target                         = (pipetunnel_line_state_t) {.pair = pair, .role = kPipeLineOwned};
    pair->next                      = state->pairs;
    if (state->pairs != NULL)
    {
        state->pairs->prev = pair;
    }
    state->pairs = pair;
    mutexUnlock(&state->pairs_lock);

    const pipe_send_result_t result   = pipeSend(pair, owned, kPipeMessageInit, NULL, true);
    const bool               admitted = result == kPipeSendAdmitted;
    if (! admitted)
    {
        LOGE("PipeTunnel: failed to admit required Init from worker %d to worker %d",
             workerWIDForLog(wid),
             workerWIDForLog(wid_to));
        atomicStoreExplicit(&pair->terminal, true, memory_order_release);
        /* The caller still owns and closes the borrowed line on false. */
        pipePairDetach(pair, line);
        /* No callback owns the never-delivered target line after a synchronous
         * queue refusal. Reconcile that side here as part of the transaction;
         * its Init was never visible, so this only detaches and destroys the
         * staged owned line. */
        pipeReconcileLine(pair, owned);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
    }
    pipePairUnref(pair);
    return admitted;
}
