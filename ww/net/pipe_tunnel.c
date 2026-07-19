#include "pipe_tunnel.h"

/*
 * Implements pipe tunnel behavior for forwarding line events across workers.
 */

#include "global_state.h"
#include "line.h"
#include "loggers/internal_logger.h"
#include "managers/node_manager.h"
#include "tunnel.h"

typedef struct pipetunnel_line_state_s
{
    line_t *pair_line;

} pipetunnel_line_state_t;

typedef enum pipe_message_type_e
{
    kPipeMessageInit,
    kPipeMessageEst,
    kPipeMessageFin,
    kPipeMessagePayload,
    kPipeMessagePause,
    kPipeMessageResume,
} pipe_message_type_t;

/**
 * @brief Return the parent tunnel that owns this piped child.
 *
 * @param t Child tunnel.
 * @return tunnel_t* Parent tunnel.
 */
static tunnel_t *getParentTunnel(tunnel_t *t)
{
    return t->prev;
}

/**
 * @brief Increases the reference count of the line. even if line is not alive
 *
 * @param line Pointer to the line.
 */
static inline void lineLockForce(line_t *const line)
{
    // basic overflow protection
    assert(line->refc < (((0x1ULL << ((sizeof(line->refc) * 8ULL) - 1ULL)) - 1ULL) |
                         (0xFULL << ((sizeof(line->refc) * 8ULL) - 4ULL))));
    if (0 == atomicIncRelaxed(&line->refc))
    {
        assert(false);
    }
}

static void pipeReleasePayloadForLine(line_t *line_to, sbuf_t *payload)
{
    if (payload == NULL)
    {
        return;
    }

    if (getWID() == lineGetWID(line_to))
    {
        lineReuseBuffer(line_to, payload);
        return;
    }

    sbufDestroy(payload);
}

static void cleanupQueuedPipeMessage(void *arg1, void *arg2, void *arg3)
{
    discard arg1;

    line_t *line_to = arg2;
    sbuf_t *payload = arg3;

    pipeReleasePayloadForLine(line_to, payload);
    lineUnlock(line_to);
}

static bool pipeMessageLineIsUsable(line_t *line_to, sbuf_t *payload)
{
    if (lineIsAlive(line_to))
    {
        return true;
    }

    assert(line_to->refc > 0);
    pipeReleasePayloadForLine(line_to, payload);
    lineUnlock(line_to);
    return false;
}

static void pipeApplyUp(tunnel_t *parent_tun, line_t *line_to, sbuf_t *payload, pipe_message_type_t type)
{
    if (! pipeMessageLineIsUsable(line_to, payload))
    {
        return;
    }

    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(line_to, parent_tun);

    if (type == kPipeMessageFin)
    {
        if (lstate->pair_line != NULL)
        {
            lineUnlock(lstate->pair_line);
            lstate->pair_line = NULL;
        }
    }
    else
    {
        assert(lstate->pair_line);
    }

    tunnel_t *next = parent_tun->next;
    switch (type)
    {
    case kPipeMessageInit:
        next->fnInitU(next, line_to);
        break;
    case kPipeMessageEst:
        next->fnEstU(next, line_to);
        break;
    case kPipeMessageFin:
        next->fnFinU(next, line_to);
        lineDestroy(line_to);
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
    }

    lineUnlock(line_to);
}

static void pipeApplyDown(tunnel_t *parent_tun, line_t *line_to, sbuf_t *payload, pipe_message_type_t type)
{
    if (! pipeMessageLineIsUsable(line_to, payload))
    {
        return;
    }

    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(line_to, parent_tun);

    if (type == kPipeMessageFin)
    {
        if (lstate->pair_line != NULL)
        {
            lineUnlock(lstate->pair_line);
            lstate->pair_line = NULL;
        }
    }

    if (type == kPipeMessageEst && lineIsEstablished(line_to))
    {
        lineUnlock(line_to);
        return;
    }

    tunnel_t *prev = parent_tun->prev;
    switch (type)
    {
    case kPipeMessageInit:
        prev->fnInitD(prev, line_to);
        break;
    case kPipeMessageEst:
        prev->fnEstD(prev, line_to);
        break;
    case kPipeMessageFin:
        prev->fnFinD(prev, line_to);
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
    }

    lineUnlock(line_to);
}

static void onMsgReceivedUpInit(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    pipeApplyUp(arg1, arg2, arg3, kPipeMessageInit);
}

static void onMsgReceivedUpEst(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    pipeApplyUp(arg1, arg2, arg3, kPipeMessageEst);
}

static void onMsgReceivedUpFin(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    pipeApplyUp(arg1, arg2, arg3, kPipeMessageFin);
}

static void onMsgReceivedUpPayload(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    pipeApplyUp(arg1, arg2, arg3, kPipeMessagePayload);
}

static void onMsgReceivedUpPause(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    pipeApplyUp(arg1, arg2, arg3, kPipeMessagePause);
}

static void onMsgReceivedUpResume(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    pipeApplyUp(arg1, arg2, arg3, kPipeMessageResume);
}

static void onMsgReceivedDownEst(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    pipeApplyDown(arg1, arg2, arg3, kPipeMessageEst);
}

static void onMsgReceivedDownFin(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    pipeApplyDown(arg1, arg2, arg3, kPipeMessageFin);
}

static void onMsgReceivedDownPayload(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    pipeApplyDown(arg1, arg2, arg3, kPipeMessagePayload);
}

static void onMsgReceivedDownPause(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    pipeApplyDown(arg1, arg2, arg3, kPipeMessagePause);
}

static void onMsgReceivedDownResume(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    pipeApplyDown(arg1, arg2, arg3, kPipeMessageResume);
}

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
    assert(false);
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
        break;
    }
    assert(false);
    return NULL;
}

static void sendMessageUp(tunnel_t *t, line_t *l_to, pipe_message_type_t type, sbuf_t *payload)
{
    lineLockForce(l_to);
    discard sendWorkerMessageForceQueueWithCleanup(
        lineGetWID(l_to), pipeUpCallback(type), cleanupQueuedPipeMessage, t, l_to, payload);
}

static void sendMessageDown(tunnel_t *t, line_t *l_to, pipe_message_type_t type, sbuf_t *payload)
{
    lineLockForce(l_to);
    discard sendWorkerMessageForceQueueWithCleanup(
        lineGetWID(l_to), pipeDownCallback(type), cleanupQueuedPipeMessage, t, l_to, payload);
}

/**
 * @brief Initialize the upstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 */
static void pipetunnelDefaultUpStreamInit(tunnel_t *t, line_t *l)
{

    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if (lstate->pair_line == NULL)
    {
        tunnelNextUpStreamInit(t, l);
        return;
    }

    sendMessageUp(t, lstate->pair_line, kPipeMessageInit, NULL);
}

/**
 * @brief Establish the upstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 */
static void pipetunnelDefaultUpStreamEst(tunnel_t *t, line_t *l)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if (lstate->pair_line == NULL)
    {
        tunnelNextUpStreamEst(t, l);
        return;
    }

    sendMessageUp(t, lstate->pair_line, kPipeMessageEst, NULL);
}

/**
 * @brief Finalize the upstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 */
static void pipetunnelDefaultUpStreamFin(tunnel_t *t, line_t *l)
{
    assert(lineIsAlive(l));

    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if (lstate->pair_line == NULL)
    {
        tunnelNextUpStreamFinish(t, l);
        return;
    }

    line_t *line_to   = lstate->pair_line;
    lstate->pair_line = NULL;

    sendMessageUp(t, line_to, kPipeMessageFin, NULL);
    lineUnlock(line_to);
}

/**
 * @brief Handle upstream payload.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 * @param payload Pointer to the payload.
 */
static void pipetunnelDefaultUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *payload)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if (lstate->pair_line == NULL)
    {
        tunnelNextUpStreamPayload(t, l, payload);
        return;
    }

    sendMessageUp(t, lstate->pair_line, kPipeMessagePayload, payload);
}

/**
 * @brief Pause the upstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 */
static void pipetunnelDefaultUpStreamPause(tunnel_t *t, line_t *l)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if (lstate->pair_line == NULL)
    {
        tunnelNextUpStreamPause(t, l);
        return;
    }

    sendMessageUp(t, lstate->pair_line, kPipeMessagePause, NULL);
}

/**
 * @brief Resume the upstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 */
static void pipetunnelDefaultUpStreamResume(tunnel_t *t, line_t *l)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if (lstate->pair_line == NULL)
    {
        tunnelNextUpStreamResume(t, l);
        return;
    }

    sendMessageUp(t, lstate->pair_line, kPipeMessageResume, NULL);
}

/*
    Downstream
*/

/**
 * @brief Initialize the downstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 */
static void pipetunnelDefaultDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    assert(false); // unreachable code
}

/**
 * @brief Establish the downstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 */
static void pipetunnelDefaultDownStreamEst(tunnel_t *t, line_t *l)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if (lstate->pair_line == NULL)
    {
        tunnelPrevDownStreamEst(t, l);
        return;
    }

    lineMarkEstablished(l);

    sendMessageDown(t, lstate->pair_line, kPipeMessageEst, NULL);
}

/**
 * @brief Finalize the downstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 */
static void pipetunnelDefaultDownStreamFin(tunnel_t *t, line_t *l)
{
    assert(lineIsAlive(l));

    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if (lstate->pair_line == NULL)
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    line_t *line_to   = lstate->pair_line;
    lstate->pair_line = NULL;

    sendMessageDown(t, line_to, kPipeMessageFin, NULL);
    lineUnlock(line_to);
    lineDestroy(l);
}

/**
 * @brief Handle downstream payload.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 * @param payload Pointer to the payload.
 */
static void pipetunnelDefaultDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *payload)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if (lstate->pair_line == NULL)
    {
        tunnelPrevDownStreamPayload(t, l, payload);
        return;
    }

    sendMessageDown(t, lstate->pair_line, kPipeMessagePayload, payload);
}

/**
 * @brief Pause the downstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 */
static void pipetunnelDefaultDownStreamPause(tunnel_t *t, line_t *l)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if (lstate->pair_line == NULL)
    {
        tunnelPrevDownStreamPause(t, l);
        return;
    }

    sendMessageDown(t, lstate->pair_line, kPipeMessagePause, NULL);
}

/**
 * @brief Resume the downstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 */
static void pipetunnelDefaultDownStreamResume(tunnel_t *t, line_t *l)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if (lstate->pair_line == NULL)
    {
        tunnelPrevDownStreamResume(t, l);
        return;
    }

    sendMessageDown(t, lstate->pair_line, kPipeMessageResume, NULL);
}

/**
 * @brief Handle the tunnel chain.
 *
 * @param t Pointer to the tunnel.
 * @param tc Pointer to the tunnel chain.
 */
static void pipetunnelDefaultOnChain(tunnel_t *t, tunnel_chain_t *tc)
{
    tunnel_t *child = *(tunnel_t **) tunnelGetState(t);

    tunnelchainInsert(tc, t);
    tunnelBind(t, child);
    child->onChain(child, tc);
}

/**
 * @brief Handle the tunnel index.
 *
 * @param t Pointer to the tunnel.
 * @param index index.
 * @param mem_offset Pointer to the memory offset.
 */
static void pipetunnelDefaultOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset)
{

    t->chain_index   = index;
    t->lstate_offset = *mem_offset;

    *mem_offset += t->lstate_size;

    // child object is already in chain and will be indexed automatically
}

/**
 * @brief Prepare the tunnel.
 *
 * @param t Pointer to the tunnel.
 */
static void pipetunnelDefaultOnPrepair(tunnel_t *t)
{
    discard t;
}

/**
 * @brief Start the tunnel.
 *
 * @param t Pointer to the tunnel.
 */
static void pipetunnelDefaultOnStart(tunnel_t *t)
{
    discard t;
}

/**
 * @brief Stop the tunnel.
 *
 * @param t Pointer to the tunnel.
 */
static void pipetunnelDefaultOnStop(tunnel_t *t)
{
    discard t;
}

/**
 * @brief Create a new pipeline tunnel.
 *
 * @param child Pointer to the child tunnel.
 * @return tunnel_t* Pointer to the created tunnel.
 */
tunnel_t *pipetunnelCreate(tunnel_t *child)
{
    tunnel_t *pt = tunnelCreate(
        tunnelGetNode(child), sizeof(tunnel_t *), tunnelGetLineStateSize(child) + sizeof(pipetunnel_line_state_t));
    if (pt == NULL)
    {
        // Handle memory allocation failure
        return NULL;
    }

    pt->fnInitU    = &pipetunnelDefaultUpStreamInit;
    pt->fnInitD    = &pipetunnelDefaultDownStreamInit;
    pt->fnPayloadU = &pipetunnelDefaultUpStreamPayload;
    pt->fnPayloadD = &pipetunnelDefaultDownStreamPayload;
    pt->fnEstU     = &pipetunnelDefaultUpStreamEst;
    pt->fnEstD     = &pipetunnelDefaultDownStreamEst;
    pt->fnFinU     = &pipetunnelDefaultUpStreamFin;
    pt->fnFinD     = &pipetunnelDefaultDownStreamFin;
    pt->fnPauseU   = &pipetunnelDefaultUpStreamPause;
    pt->fnPauseD   = &pipetunnelDefaultDownStreamPause;
    pt->fnResumeU  = &pipetunnelDefaultUpStreamResume;
    pt->fnResumeD  = &pipetunnelDefaultDownStreamResume;

    pt->onChain   = &pipetunnelDefaultOnChain;
    pt->onIndex   = &pipetunnelDefaultOnIndex;
    pt->onPrepare = &pipetunnelDefaultOnPrepair;
    pt->onStart   = &pipetunnelDefaultOnStart;
    pt->onStop    = &pipetunnelDefaultOnStop;

    pt->onDestroy = &pipetunnelDestroy;

    memoryCopy(&(pt->state[0]), (void *) &child, sizeof(tunnel_t *));

    return pt;
}

/**
 * @brief Destroy the pipeline tunnel.
 *
 * @param t Pointer to the tunnel.
 */
void pipetunnelDestroy(tunnel_t *t)
{
    tunnel_t *child = *(tunnel_t **) tunnelGetState(t);
    child->onDestroy(child);
    tunnelDestroy(t);
}

/**
 * @brief Pipe to a specific WID.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 * @param wid_to WID to pipe to.
 */
bool pipeTo(tunnel_t *t, line_t *l, wid_t wid_to)
{
    tunnel_t                *parent_tunnel = getParentTunnel(t);
    pipetunnel_line_state_t *ls            = (pipetunnel_line_state_t *) lineGetState(l, parent_tunnel);

    wid_t wid = lineGetWID(l);

    // we no longer need these checks, thank god all related bugs are fixed
#ifdef DEBUG
    if (wid_to == getWID())
    {
        LOGF("PipeTunnel: Pipe to self is not allowed, line: %p, tunnel: %p", l, parent_tunnel);
        LOGF("PipeTunnel: WID: %d, line WID: %d , to WID: %d", getWID(), lineGetWID(l), wid_to);
        assert(false);
        terminateProgram(1);
        return false;
    }
    if (wid != getWID())
    {
        LOGF("PipeTunnel: Pipe From different WID is not allowed, line: %p, tunnel: %p", l, parent_tunnel);
        LOGF("PipeTunnel: WID: %d, line WID: %d , to WID: %d", getWID(), lineGetWID(l), wid_to);
        assert(false);
        terminateProgram(1);
        return false;
    }
#endif

    if (ls->pair_line)
    {
        return false;
        // assert(false);
        // parent_tunnel->fnFinU(parent_tunnel, l);
    }
    assert(ls->pair_line == NULL);
    ls->pair_line = lineCreateForWorker(wid, tunnelchainGetLinePools(tunnelGetChain(t)), wid_to);
    lineCopyUsers(ls->pair_line, l);

    pipetunnel_line_state_t *ls_lineto = lineGetState(ls->pair_line, parent_tunnel);
    ls_lineto->pair_line               = l;

    lineLock(l);
    lineLock(ls->pair_line);

    parent_tunnel->fnInitU(parent_tunnel, l);
    return true;
}
