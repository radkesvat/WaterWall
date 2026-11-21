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

/* One payload direction of a pair. Payload queued on the receiving worker is
 * out of reach of the Pause that worker relays back, so each direction bounds
 * it and holds its own producer meanwhile. */
typedef struct pipe_flow_s
{
    /* Queue charge sent and not yet dispatched on the receiving worker. */
    atomic_ullong queued;
    /* Set by the sender when it holds its producer; taken by the receiver when
     * it sees the queue at the low watermark. */
    atomic_bool drain_wanted;
    /* Sending worker only: the two independent reasons its producer is paused. */
    bool held;
    bool peer_paused;
} pipe_flow_t;

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
    /* up: borrowed to owned, produced by the previous tunnel.
     * down: owned to borrowed, produced by the next tunnel. */
    pipe_flow_t up;
    pipe_flow_t down;
};

typedef enum pipe_message_type_e
{
    kPipeMessageInit,
    kPipeMessageEst,
    kPipeMessageFin,
    kPipeMessagePayload,
    kPipeMessagePause,
    kPipeMessageResume,
    kPipeMessageDrained,
} pipe_message_type_t;

typedef enum pipe_send_result_e
{
    kPipeSendAdmitted,
    kPipeSendAlreadyTerminal,
    kPipeSendRefused,
} pipe_send_result_t;

static void               pipeReconcileLine(pipe_pair_t *pair, line_t *line);
static pipe_send_result_t pipeSend(pipe_pair_t *pair, line_t *line_to, pipe_message_type_t type, sbuf_t *payload,
                                   bool upstream);

static pipetunnel_state_t *pipeTunnelState(tunnel_t *t)
{
    return tunnelGetState(t);
}

static tunnel_t *getParentTunnel(tunnel_t *t)
{
    return t->prev;
}

/* Queued cleanup may run after logical line death, so it needs a physical
 * reference just like other worker-message cleanup paths. Pair ownership keeps
 * the count nonzero; this helper must never resurrect a reclaimed line. */
static inline void lineRefForce(line_t *const line)
{
    const uint32_t previous = atomicIncU32Relaxed(&line->refc);
    if (UNLIKELY(previous == 0 || previous == LINE_REFC_MAX))
    {
        LOGF("PipeTunnel: forced physical reference is dead or overflowed");
        abortProgramNow(1);
    }
}

static void pipePairRef(pipe_pair_t *pair)
{
    const w_atomic_uint_value_t previous = atomicAddExplicit(&pair->refs, 1, memory_order_relaxed);
    assert(previous != 0 && previous < UINT_MAX);
    if (UNLIKELY(previous == 0 || previous == UINT_MAX))
    {
        LOGF("PipeTunnel: pair reference count is dead or overflowed (%u)", (unsigned int) previous);
        abortProgramNow(1);
    }
}

static void pipePairUnref(pipe_pair_t *pair)
{
    const w_atomic_uint_value_t previous = atomicSubExplicit(&pair->refs, 1, memory_order_acq_rel);
    assert(previous != 0);
    if (UNLIKELY(previous == 0))
    {
        LOGF("PipeTunnel: pair reference count underflow");
        abortProgramNow(1);
    }
    if (previous != 1)
    {
        return;
    }

    const bool registered        = atomicLoadExplicit(&pair->registered, memory_order_relaxed);
    const bool borrowed_attached = atomicLoadExplicit(&pair->borrowed_attached, memory_order_relaxed);
    const bool owned_attached    = atomicLoadExplicit(&pair->owned_attached, memory_order_relaxed);
    assert(! registered && ! borrowed_attached && ! owned_attached);
    if (UNLIKELY(registered || borrowed_attached || owned_attached))
    {
        LOGF("PipeTunnel: final pair release occurred while still registered or attached");
        abortProgramNow(1);
    }

    /* The pair, rather than either attached side, owns these physical
     * references. Keeping them through the last queued message prevents a
     * sender from racing a detach and incrementing a line that has already
     * returned to the pool. */
    lineUnref(pair->borrowed_line);
    lineUnref(pair->owned_line);
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
            if (UNLIKELY(state->pairs != pair))
            {
                LOGF("PipeTunnel: pair registry head mismatch during unregister");
                abortProgramNow(1);
            }
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
        if (UNLIKELY(line != pair->owned_line))
        {
            LOGF("PipeTunnel: detach received an unrelated line");
            abortProgramNow(1);
        }
        attached = &pair->owned_attached;
    }

    if (! atomicExchangeExplicit(attached, false, memory_order_acq_rel))
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
    lineRefForce(line);
    pipePairDetach(pair, line);

    if (lineIsAlive(line) && ! atomicLoadExplicit(&pair->prev_finished, memory_order_acquire))
    {
        tunnelPrevDownStreamFinish(t, line);
    }
    lineUnref(line);
    pipePairUnref(pair);
}

static void pipeCloseOwned(pipe_pair_t *pair)
{
    line_t   *line = pair->owned_line;
    tunnel_t *t    = pair->wrapper;

    pipePairRef(pair);
    lineRefForce(line);
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
    lineUnref(line);
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
    if (currentThreadOwnsWorker(lineGetWID(line_to)))
    {
        pipeReconcileLine(pair, line_to);
    }
    lineUnref(line_to);
    pipePairUnref(pair);
}

static bool pipeMessageLineIsUsable(pipe_pair_t *pair, line_t *line_to, sbuf_t *payload)
{
    const bool borrowed = line_to == pair->borrowed_line;
    const bool attached =
        atomicLoadExplicit(borrowed ? &pair->borrowed_attached : &pair->owned_attached, memory_order_acquire);
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

    // A message queued before this exact side sent Finish cannot be delivered
    // there. Its surviving peer still has ordered payload and Finish to dispatch.
    const bool retired_normally =
        ! attached && atomicLoadExplicit(borrowed ? &pair->prev_finished : &pair->next_finished, memory_order_acquire);
    const bool reconcile = terminal || ! retired_normally;
    if (reconcile)
        atomicStoreExplicit(&pair->terminal, true, memory_order_release);
    pipeDiscardPayload(payload);
    if (reconcile)
        pipeReconcileLine(pair, line_to);
    lineUnref(line_to);
    pipePairUnref(pair);
    return false;
}

/* Sending worker, before the payload is queued. True when this payload takes
 * the queue over the bound and the producer is not paused yet. */
static bool pipeFlowCharge(pipe_flow_t *flow, uint64_t charge)
{
    const uint64_t queued = atomicAddU64Explicit(&flow->queued, charge, memory_order_relaxed) + charge;
    if (queued <= kPipeTunnelQueueHighWater || flow->held)
    {
        return false;
    }
    /* The payload is queued after this request, so its own dispatch observes
     * the request even when every earlier one has already been settled. */
    flow->held = true;
    atomicStoreExplicit(&flow->drain_wanted, true, memory_order_release);
    return ! flow->peer_paused;
}

/* Sending worker: Pause or Resume relayed from the receiving worker. False while
 * the bound holds the producer, which then keeps the one Pause it already has. */
static bool pipeFlowSetPeerPaused(pipe_flow_t *flow, bool paused)
{
    flow->peer_paused = paused;
    return ! flow->held;
}

/* Sending worker: the receiving worker reported the queue at the low watermark. */
static bool pipeFlowRelease(pipe_flow_t *flow)
{
    if (! flow->held)
    {
        return false;
    }
    flow->held = false;
    return ! flow->peer_paused;
}

/* Receiving worker, after the payload was dispatched on line. */
static void pipeFlowSettle(pipe_pair_t *pair, line_t *line, uint64_t charge, bool upstream)
{
    pipe_flow_t   *flow   = upstream ? &pair->up : &pair->down;
    const uint64_t queued = atomicSubU64Explicit(&flow->queued, charge, memory_order_relaxed) - charge;
    if (queued > kPipeTunnelQueueLowWater || ! atomicExchangeExplicit(&flow->drain_wanted, false, memory_order_acq_rel))
    {
        return;
    }
    /* A side that closed inside the dispatch has sent its Finish, and nothing
     * may follow that. The Finish ends the sender's wait instead. */
    if (! lineIsAlive(line) || ((pipetunnel_line_state_t *) lineGetState(line, pair->wrapper))->pair != pair)
    {
        return;
    }
    const pipe_send_result_t result =
        pipeSend(pair, upstream ? pair->borrowed_line : pair->owned_line, kPipeMessageDrained, NULL, ! upstream);
    if (result != kPipeSendAdmitted)
    {
        pipeReconcileLine(pair, line);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
    }
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
        lineUnref(line_to);
        pipePairUnref(pair);
        return;
    }

    switch (type)
    {
    case kPipeMessageInit:
        atomicStoreExplicit(&pair->owned_init_delivered, true, memory_order_release);
        tunnelUpStreamInit(next, line_to);
        break;
    case kPipeMessageEst:
        tunnelUpStreamEst(next, line_to);
        break;
    case kPipeMessagePayload: {
        const uint64_t charge = sbufGetQueueCharge(payload);
        tunnelUpStreamPayload(next, line_to, payload);
        pipeFlowSettle(pair, line_to, charge, true);
        break;
    }
    case kPipeMessagePause:
        if (pipeFlowSetPeerPaused(&pair->down, true))
        {
            tunnelUpStreamPause(next, line_to);
        }
        break;
    case kPipeMessageResume:
        if (pipeFlowSetPeerPaused(&pair->down, false))
        {
            tunnelUpStreamResume(next, line_to);
        }
        break;
    case kPipeMessageDrained:
        if (pipeFlowRelease(&pair->down))
        {
            tunnelUpStreamResume(next, line_to);
        }
        break;
    case kPipeMessageFin:
        assert(false);
        break;
    }

    lineUnref(line_to);
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
        lineUnref(line_to);
        pipePairUnref(pair);
        return;
    }

    if (type == kPipeMessageEst && lineIsEstablished(line_to))
    {
        lineUnref(line_to);
        pipePairUnref(pair);
        return;
    }

    switch (type)
    {
    case kPipeMessageEst:
        tunnelDownStreamEst(prev, line_to);
        break;
    case kPipeMessagePayload: {
        const uint64_t charge = sbufGetQueueCharge(payload);
        tunnelDownStreamPayload(prev, line_to, payload);
        pipeFlowSettle(pair, line_to, charge, false);
        break;
    }
    case kPipeMessagePause:
        if (pipeFlowSetPeerPaused(&pair->up, true))
        {
            tunnelDownStreamPause(prev, line_to);
        }
        break;
    case kPipeMessageResume:
        if (pipeFlowSetPeerPaused(&pair->up, false))
        {
            tunnelDownStreamResume(prev, line_to);
        }
        break;
    case kPipeMessageDrained:
        if (pipeFlowRelease(&pair->up))
        {
            tunnelDownStreamResume(prev, line_to);
        }
        break;
    case kPipeMessageInit:
    case kPipeMessageFin:
        assert(false);
        break;
    }

    lineUnref(line_to);
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
PIPE_UP_RECEIVER(onMsgReceivedUpDrained, kPipeMessageDrained)
PIPE_DOWN_RECEIVER(onMsgReceivedDownEst, kPipeMessageEst)
PIPE_DOWN_RECEIVER(onMsgReceivedDownFin, kPipeMessageFin)
PIPE_DOWN_RECEIVER(onMsgReceivedDownPayload, kPipeMessagePayload)
PIPE_DOWN_RECEIVER(onMsgReceivedDownPause, kPipeMessagePause)
PIPE_DOWN_RECEIVER(onMsgReceivedDownResume, kPipeMessageResume)
PIPE_DOWN_RECEIVER(onMsgReceivedDownDrained, kPipeMessageDrained)

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
    case kPipeMessageDrained:
        return (WorkerMessageCallback) onMsgReceivedUpDrained;
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
    case kPipeMessageDrained:
        return (WorkerMessageCallback) onMsgReceivedDownDrained;
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
    if (UNLIKELY(callback == NULL))
    {
        LOGF("PipeTunnel: pipeSend message kind %d has no callback", (int) type);
        abortProgramNow(1);
    }

    pipePairRef(pair);
    lineRefForce(line_to);
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
    /* The up flow's sender state belongs to the borrowed line's worker. */
    assert(line == pair->borrowed_line);
    const bool               hold   = pipeFlowCharge(&pair->up, sbufGetQueueCharge(payload));
    const pipe_send_result_t result = pipeSend(pair, pair->owned_line, kPipeMessagePayload, payload, true);
    if (result != kPipeSendAdmitted)
    {
        pipeReconcileLine(pair, line);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
        return;
    }
    if (hold)
    {
        tunnelPrevDownStreamPause(t, line);
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
    LOGF("PipeTunnel: downStreamInit is disabled");
    assert(false);
    abortProgramNow(1);
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
    /* The down flow's sender state belongs to the owned line's worker. */
    assert(line == pair->owned_line);
    const bool               hold   = pipeFlowCharge(&pair->down, sbufGetQueueCharge(payload));
    const pipe_send_result_t result = pipeSend(pair, pair->borrowed_line, kPipeMessagePayload, payload, false);
    if (result != kPipeSendAdmitted)
    {
        pipeReconcileLine(pair, line);
        if (result == kPipeSendRefused)
        {
            pipeEscalateRefusal();
        }
        return;
    }
    if (hold)
    {
        tunnelNextUpStreamPause(t, line);
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
    assert(currentThreadOwnsWorker(wid));

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
    if (UNLIKELY(state->pairs != NULL))
    {
        LOGF("PipeTunnel: destroyed while active pairs remain in registry");
        abortProgramNow(1);
    }
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

    if (UNLIKELY(! lineIsOnCurrentWorker(line)))
    {
        pipeTunnelLogWIDViolation("pipe source line is not owned by the calling worker", parent, line, wid_to);
        return false;
    }
    if (UNLIKELY(! workerWIDIsRegistered(wid_to) || wid_to == wid ||
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
    const address_context_t *destination = lineGetDestinationAddressContext(line);
    const uint8_t            offer       = addresscontextGetTransportOffer(destination);
    if (offer == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportBoth);
        return false;
    }

#ifdef WW_PIPE_TUNNEL_TEST_SEAM
    /* Deterministically lets a test place PreStop between the fast rejection
     * and the in-lock publication decision. */
    pipeTunnelAfterFastStopCheckTestSeam(parent, line);
#endif

    pipe_pair_t *pair = memoryAllocateZero(sizeof(*pair));

    line_t *owned = lineCreateForWorker(wid, tunnelchainGetLinePools(tunnelGetChain(t)), wid_to);
    lineCopyIngressContext(owned, line);
    const line_mark_t *mark = lineGetMark(line);
    if (mark != NULL)
        lineSetMark(owned, mark);
    addresscontextSetTransportOffer(lineGetDestinationAddressContext(owned), offer);

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
    atomic_init(&pair->up.queued, 0);
    atomic_init(&pair->up.drain_wanted, false);
    atomic_init(&pair->down.queued, 0);
    atomic_init(&pair->down.drain_wanted, false);

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
    lineRef(line);
    lineRef(owned);
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
