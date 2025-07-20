#include "pipe_tunnel.h"
#include "context.h"
#include "generic_pool.h"
#include "loggers/internal_logger.h"
#include "managers/node_manager.h"
#include "tunnel.h"

typedef struct pipetunnel_line_state_s
{
    line_t *pair_line;

} pipetunnel_line_state_t;

typedef struct pipetunnel_msg_event_s
{
    tunnel_t *tunnel;
    context_t ctx;

} pipetunnel_msg_event_t;

static tunnel_t *getParentTunnel(tunnel_t *t)
{
    return (tunnel_t *) (((uint8_t *) t) - sizeof(tunnel_t));
}

/**
 * @brief Get the size of the pipeline message.
 *
 * @return size_t Size of the pipeline message.
 */
size_t pipeTunnelGetMesageSize(void)
{
    return sizeof(pipetunnel_msg_event_t);
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

/**
 * @brief Send a message upstream.
 *
 * @param ls Pointer to the line state.
 * @param msg Pointer to the message event.
 * @param wid_to WID to send the message to.
 */
static void sendMessageUp(line_t *l_to, pipetunnel_msg_event_t *msg);

/**
 * @brief Send a message downstream.
 *
 * @param ls Pointer to the line state.
 * @param msg Pointer to the message event.
 * @param wid_to WID to send the message to.
 */
static void sendMessageDown(line_t *l_to, pipetunnel_msg_event_t *msg);
/**
 * @brief Callback for when a message is received upstream.
 *
 * @param ev Pointer to the event.
 */
static void onMsgReceivedUp(wevent_t *ev)
{
    pipetunnel_msg_event_t  *msg_ev     = weventGetUserdata(ev);
    tunnel_t                *parent_tun = msg_ev->tunnel;
    line_t                  *line_to    = msg_ev->ctx.line;
    wid_t                    wid        = lineGetWID(line_to);
    pipetunnel_line_state_t *lstate     = (pipetunnel_line_state_t *) lineGetState(line_to, parent_tun);

    if (! lineIsAlive(line_to))
    {
        assert(line_to->refc > 0);
        if (msg_ev->ctx.payload != NULL)
        {
            contextReusePayload(&msg_ev->ctx);
        }
    }
    else
    {

        if (msg_ev->ctx.fin)
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
        contextApplyOnTunnelU(&msg_ev->ctx, parent_tun->next);

        if (msg_ev->ctx.fin)
        {
            lineDestroy(line_to);
        }
    }
    lineUnlock(line_to);

    genericpoolReuseItem(getWorkerPipeTunnelMsgPool(wid), msg_ev);
}

/**
 * @brief Send a message upstream.
 *
 * @param ls Pointer to the line state.
 * @param msg Pointer to the message event.
 * @param wid_to WID to send the message to.
 */
static void sendMessageUp(line_t *l_to, pipetunnel_msg_event_t *msg)
{

    lineLockForce(l_to);
    wid_t wid_to = lineGetWID(l_to);

    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(wid_to);
    ev.cb   = onMsgReceivedUp;
    weventSetUserData(&ev, msg);
    wloopPostEvent(getWorkerLoop(wid_to), &ev);
}

/**
 * @brief Callback for when a message is received downstream.
 *
 * @param ev Pointer to the event.
 */
static void onMsgReceivedDown(wevent_t *ev)
{
    pipetunnel_msg_event_t  *msg_ev     = weventGetUserdata(ev);
    tunnel_t                *parent_tun = msg_ev->tunnel;
    line_t                  *line_to    = msg_ev->ctx.line;
    wid_t                    wid        = lineGetWID(line_to);
    pipetunnel_line_state_t *lstate     = (pipetunnel_line_state_t *) lineGetState(line_to, parent_tun);

    if (! lineIsAlive(line_to))
    {
        assert(line_to->refc > 0);
        if (msg_ev->ctx.payload != NULL)
        {
            contextReusePayload(&msg_ev->ctx);
        }
    }
    else
    {
        if (msg_ev->ctx.fin)
        {
            if (lstate->pair_line != NULL)
            {
                lineUnlock(lstate->pair_line);
                lstate->pair_line = NULL;
            }
        }
        if (msg_ev->ctx.est && lineIsEstablished(line_to))
        {
            ;
        }
        else
        {
            contextApplyOnTunnelD(&msg_ev->ctx, parent_tun->prev);
        }
    }
    lineUnlock(line_to);

    genericpoolReuseItem(getWorkerPipeTunnelMsgPool(wid), msg_ev);
}

/**
 * @brief Send a message downstream.
 *
 * @param ls Pointer to the line state.
 * @param msg Pointer to the message event.
 * @param wid_to WID to send the message to.
 */
static void sendMessageDown(line_t *l_to, pipetunnel_msg_event_t *msg)
{
    lineLockForce(l_to);
    wid_t wid_to = lineGetWID(l_to);

    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(wid_to);
    ev.cb   = onMsgReceivedDown;
    weventSetUserData(&ev, msg);
    wloopPostEvent(getWorkerLoop(wid_to), &ev);
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

    line_t *line_to = lstate->pair_line;

    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(l)));
    context_t               ctx = {.line = line_to, .init = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageUp(line_to, msg);
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

    line_t *line_to = lstate->pair_line;

    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(l)));
    context_t               ctx = {.line = line_to, .est = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageUp(line_to, msg);
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

    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(l)));
    context_t               ctx = {.line = line_to, .fin = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageUp(line_to, msg);
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

    line_t *line_to = lstate->pair_line;

    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(l)));
    context_t               ctx = {.line = line_to, .payload = payload};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageUp(line_to, msg);
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

    line_t *line_to = lstate->pair_line;

    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(l)));
    context_t               ctx = {.line = line_to, .pause = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageUp(line_to, msg);
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

    line_t *line_to = lstate->pair_line;

    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(l)));
    context_t               ctx = {.line = line_to, .resume = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageUp(line_to, msg);
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
static void pipetunnelDefaultdownStreamInit(tunnel_t *t, line_t *l)
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
static void pipetunnelDefaultdownStreamEst(tunnel_t *t, line_t *l)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if (lstate->pair_line == NULL)
    {
        tunnelPrevDownStreamEst(t, l);
        return;
    }

    line_t *line_to = lstate->pair_line;

    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(l)));
    context_t               ctx = {.line = line_to, .est = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageDown(line_to, msg);
}

/**
 * @brief Finalize the downstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 */
static void pipetunnelDefaultdownStreamFin(tunnel_t *t, line_t *l)
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

    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(l)));
    context_t               ctx = {.line = line_to, .fin = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageDown(line_to, msg);
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
static void pipetunnelDefaultdownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *payload)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if (lstate->pair_line == NULL)
    {
        tunnelPrevDownStreamPayload(t, l, payload);
        return;
    }

    line_t *line_to = lstate->pair_line;

    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(l)));
    context_t               ctx = {.line = line_to, .payload = payload};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageDown(line_to, msg);
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

    line_t *line_to = lstate->pair_line;

    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(l)));
    context_t               ctx = {.line = line_to, .pause = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageDown(line_to, msg);
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

    line_t *line_to = lstate->pair_line;

    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(l)));
    context_t               ctx = {.line = line_to, .resume = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageDown(line_to, msg);
}

/**
 * @brief Handle the tunnel chain.
 *
 * @param t Pointer to the tunnel.
 * @param tc Pointer to the tunnel chain.
 */
static void pipetunnelDefaultOnChain(tunnel_t *t, tunnel_chain_t *tc)
{
    tunnel_t *child = tunnelGetState(t);

    tunnelchainInsert(tc, t);
    tunnelBind(t, child);
    child->onChain(child, tc);
}

/**
 * @brief Handle the tunnel index.
 *
 * @param t Pointer to the tunnel.
 * @param arr Pointer to the tunnel array.
 * @param index Pointer to the index.
 * @param mem_offset Pointer to the memory offset.
 */
static void pipetunnelDefaultOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset)
{
    tunnelarrayInsert(arr, t);
    tunnel_t *child = tunnelGetState(t);

    t->chain_index   = *index;
    t->lstate_offset = *mem_offset;

    *mem_offset += t->lstate_size;
    (*index)++;

    child->onIndex(child, arr, index, mem_offset);
}

/**
 * @brief Prepare the tunnel.
 *
 * @param t Pointer to the tunnel.
 */
static void pipetunnelDefaultOnPrepair(tunnel_t *t)
{
    tunnel_t *child = tunnelGetState(t);
    child->onPrepair(child);
}

/**
 * @brief Start the tunnel.
 *
 * @param t Pointer to the tunnel.
 */
static void pipetunnelDefaultOnStart(tunnel_t *t)
{
    tunnel_t *child = tunnelGetState(t);
    child->onStart(child);
}

/**
 * @brief Create a new pipeline tunnel.
 *
 * @param child Pointer to the child tunnel.
 * @return tunnel_t* Pointer to the created tunnel.
 */
tunnel_t *pipetunnelCreate(tunnel_t *child)
{
    tunnel_t *pt = tunnelCreate(tunnelGetNode(child), tunnelGetStateSize(child) + sizeof(tunnel_t),
                                tunnelGetLineStateSize(child) + sizeof(line_t) + sizeof(pipetunnel_line_state_t));
    if (pt == NULL)
    {
        // Handle memory allocation failure
        return NULL;
    }

    pt->fnInitU    = &pipetunnelDefaultUpStreamInit;
    pt->fnInitD    = &pipetunnelDefaultdownStreamInit;
    pt->fnPayloadU = &pipetunnelDefaultUpStreamPayload;
    pt->fnPayloadD = &pipetunnelDefaultdownStreamPayload;
    pt->fnEstU     = &pipetunnelDefaultUpStreamEst;
    pt->fnEstD     = &pipetunnelDefaultdownStreamEst;
    pt->fnFinU     = &pipetunnelDefaultUpStreamFin;
    pt->fnFinD     = &pipetunnelDefaultdownStreamFin;
    pt->fnPauseU   = &pipetunnelDefaultUpStreamPause;
    pt->fnPauseD   = &pipetunnelDefaultDownStreamPause;
    pt->fnResumeU  = &pipetunnelDefaultUpStreamResume;
    pt->fnResumeD  = &pipetunnelDefaultDownStreamResume;

    pt->onChain   = &pipetunnelDefaultOnChain;
    pt->onIndex   = &pipetunnelDefaultOnIndex;
    pt->onPrepair = &pipetunnelDefaultOnPrepair;
    pt->onStart   = &pipetunnelDefaultOnStart;

    pt->onDestroy = &pipetunnelDestroy;
    tunnelSetState(pt, child);

    return pt;
}

/**
 * @brief Destroy the pipeline tunnel.
 *
 * @param t Pointer to the tunnel.
 */
void pipetunnelDestroy(tunnel_t *t)
{
    tunnel_t *child = tunnelGetState(t);
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

    if (ls->pair_line)
    {
        return false;
        // assert(false);
        // parent_tunnel->fnFinU(parent_tunnel, l);
    }
    assert(ls->pair_line == NULL);
    ls->pair_line = lineCreate(tunnelchainGetLinePool(tunnelGetChain(parent_tunnel), getWID()), wid_to);
    ls->pair_line->pool = tunnelchainGetLinePool(tunnelGetChain(parent_tunnel), wid_to);

    pipetunnel_line_state_t *ls_lineto = lineGetState(ls->pair_line, parent_tunnel);
    ls_lineto->pair_line               = l;

    lineLock(l);
    lineLock(ls->pair_line);

    parent_tunnel->fnInitU(parent_tunnel, l);
    return true;
}
