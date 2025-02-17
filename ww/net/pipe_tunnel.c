#include "pipe_tunnel.h"
#include "context.h"
#include "generic_pool.h"
#include "loggers/internal_logger.h"
#include "managers/node_manager.h"
#include "tunnel.h"

typedef struct pipetunnel_line_state_s
{
    atomic_int   refc;
    atomic_bool  closed;
    atomic_wid_t from_wid;
    atomic_wid_t to_wid;
    bool         active;
    bool         left_open;
    bool         right_open;

} pipetunnel_line_state_t;

typedef struct pipetunnel_msg_event_s
{
    tunnel_t *tunnel;
    context_t ctx;

} pipetunnel_msg_event_t;

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
 * @brief Initialize the line state.
 *
 * @param ls Pointer to the line state.
 * @param wid_to WID to initialize.
 */
static void initializeLineState(pipetunnel_line_state_t *ls, wid_t wid_from, wid_t wid_to)
{
    atomicStoreExplicit(&ls->refc, 0, memory_order_relaxed);
    atomicStoreExplicit(&ls->closed, false, memory_order_relaxed);
    atomicStoreExplicit(&ls->from_wid, wid_from, memory_order_relaxed);
    atomicStoreExplicit(&ls->to_wid, wid_to, memory_order_relaxed);
    ls->active     = true;
    ls->left_open  = true;
    ls->right_open = true;
}

/**
 * @brief Deinitialize the line state.
 *
 * @param ls Pointer to the line state.
 */
static void deinitializeLineState(pipetunnel_line_state_t *ls)
{
    atomicStoreExplicit(&ls->refc, 0, memory_order_relaxed);
    atomicStoreExplicit(&ls->closed, false, memory_order_relaxed);
    atomicStoreExplicit(&ls->from_wid, 0, memory_order_relaxed);
    atomicStoreExplicit(&ls->to_wid, 0, memory_order_relaxed);
    ls->active     = false;
    ls->left_open  = false;
    ls->right_open = false;
}

/**
 * @brief Lock the line state.
 *
 * @param ls Pointer to the line state.
 */
static void lock(pipetunnel_line_state_t *ls)
{
    int old_refc = (int) atomicAddExplicit(&ls->refc, 1, memory_order_relaxed);

    (void) old_refc;
}

/**
 * @brief Unlock the line state.
 *
 * @param ls Pointer to the line state.
 */
static void unlock(pipetunnel_line_state_t *ls)
{
    int old_refc = (int) atomicAddExplicit(&ls->refc, -1, memory_order_relaxed);
    if (old_refc == 1)
    {
        deinitializeLineState(ls);
    }
}

/**
 * @brief Send a message upstream.
 *
 * @param ls Pointer to the line state.
 * @param msg Pointer to the message event.
 * @param wid_to WID to send the message to.
 */
static void sendMessageUp(pipetunnel_line_state_t *ls, pipetunnel_msg_event_t *msg, wid_t wid_to);

/**
 * @brief Send a message downstream.
 *
 * @param ls Pointer to the line state.
 * @param msg Pointer to the message event.
 * @param wid_to WID to send the message to.
 */
static void sendMessageDown(pipetunnel_line_state_t *ls, pipetunnel_msg_event_t *msg, wid_t wid_to);

/**
 * @brief Callback for when a message is received upstream.
 *
 * @param ev Pointer to the event.
 */
static void onMsgReceivedUp(wevent_t *ev)
{
    pipetunnel_msg_event_t  *msg_ev = weventGetUserdata(ev);
    tunnel_t                *t      = msg_ev->tunnel;
    line_t                  *l      = msg_ev->ctx.line;
    wid_t                    wid    = (wid_t) wloopGetWID(weventGetLoop(ev));
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if ((wid_t) atomicLoadRelaxed(&(lstate->to_wid)) != wid)
    {
        sendMessageUp(lstate, msg_ev, (wid_t) atomicLoadRelaxed(&(lstate->to_wid)));
        unlock(lstate);
        return;
    }

    if (! lstate->right_open)
    {
        if (msg_ev->ctx.payload != NULL)
        {
            contextReusePayload(&msg_ev->ctx);
        }
    }
    else
    {
        contextApplyOnTunnelU(&msg_ev->ctx, (tunnel_t *) tunnelGetState(t));
    }
    genericpoolReuseItem(getWorkerPipeTunnelMsgPool(wid), msg_ev);
    unlock(lstate);
}

/**
 * @brief Send a message upstream.
 *
 * @param ls Pointer to the line state.
 * @param msg Pointer to the message event.
 * @param wid_to WID to send the message to.
 */
static void sendMessageUp(pipetunnel_line_state_t *ls, pipetunnel_msg_event_t *msg, wid_t wid_to)
{

    lock(ls);
    // struct msg_event *evdata = genericpoolGetItem(getWorkerPipeTunnelMsgPool(wid_from));
    // *evdata = (struct msg_event){.ls = ls, .function = *(void **) (&fn), .arg = arg, .target_wid = wid_to};

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
    pipetunnel_msg_event_t  *msg_ev = weventGetUserdata(ev);
    tunnel_t                *t      = msg_ev->tunnel;
    line_t                  *l      = msg_ev->ctx.line;
    wid_t                    wid    = (wid_t) wloopGetWID(weventGetLoop(ev));
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(l, t);

    if ((wid_t) atomicLoadRelaxed(&(lstate->from_wid)) != wid)
    {
        sendMessageDown(lstate, msg_ev, (wid_t) atomicLoadRelaxed(&(lstate->from_wid)));
        unlock(lstate);
        return;
    }

    if (! lstate->left_open)
    {
        if (msg_ev->ctx.payload != NULL)
        {
            contextReusePayload(&msg_ev->ctx);
        }
    }
    else
    {
        contextApplyOnTunnelD(&msg_ev->ctx, t->prev);
    }
    genericpoolReuseItem(getWorkerPipeTunnelMsgPool(wid), msg_ev);
    unlock(lstate);
}

/**
 * @brief Send a message downstream.
 *
 * @param ls Pointer to the line state.
 * @param msg Pointer to the message event.
 * @param wid_to WID to send the message to.
 */
static void sendMessageDown(pipetunnel_line_state_t *ls, pipetunnel_msg_event_t *msg, wid_t wid_to)
{

    lock(ls);

    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(wid_to);
    ev.cb   = onMsgReceivedUp;
    weventSetUserData(&ev, msg);
    wloopPostEvent(getWorkerLoop(wid_to), &ev);
}

/**
 * @brief Initialize the upstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultUpStreamInit(tunnel_t *t, line_t *line)
{

    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(line, t);
    tunnel_t                *child  = tunnelGetState(t);

    if (! lstate->active)
    {
        child->fnInitU(child, line);
        return;
    }

    if (atomicLoadExplicit(&lstate->closed, memory_order_relaxed))
    {
        return;
    }
    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(line)));
    context_t               ctx = {.line = line, .init = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageUp(lstate, msg, (wid_t) atomicLoadRelaxed(&lstate->to_wid));
}

/**
 * @brief Establish the upstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultUpStreamEst(tunnel_t *t, line_t *line)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(line, t);
    tunnel_t                *child  = tunnelGetState(t);

    if (! lstate->active)
    {
        child->fnEstU(child, line);
        return;
    }

    if (atomicLoadExplicit(&lstate->closed, memory_order_relaxed))
    {
        return;
    }
    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(line)));
    context_t               ctx = {.line = line, .est = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageUp(lstate, msg, (wid_t) atomicLoadRelaxed(&lstate->to_wid));
}

/**
 * @brief Finalize the upstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultUpStreamFin(tunnel_t *t, line_t *line)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(line, t);
    tunnel_t                *child  = tunnelGetState(t);

    if (! lstate->active)
    {
        child->fnFinU(child, line);
        return;
    }

    lstate->left_open = false;

    if (atomicLoadExplicit(&lstate->closed, memory_order_relaxed))
    {
        return;
    }

    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(line)));
    context_t               ctx = {.line = line, .fin = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageUp(lstate, msg, (wid_t) atomicLoadRelaxed(&lstate->to_wid));
    unlock(lstate);
}

/**
 * @brief Handle upstream payload.
 *
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 * @param payload Pointer to the payload.
 */
void pipetunnelDefaultUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(line, t);
    tunnel_t                *child  = tunnelGetState(t);

    if (! lstate->active)
    {
        child->fnPayloadU(child, line, payload);
        return;
    }

    if (atomicLoadExplicit(&lstate->closed, memory_order_relaxed))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(line)), payload);
        return;
    }
    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(line)));
    context_t               ctx = {.line = line, .payload = payload};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageUp(lstate, msg, (wid_t) atomicLoadRelaxed(&lstate->to_wid));
}

/**
 * @brief Pause the upstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultUpStreamPause(tunnel_t *t, line_t *line)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(line, t);
    tunnel_t                *child  = tunnelGetState(t);

    if (! lstate->active)
    {
        child->fnPauseU(child, line);
        return;
    }

    if (atomicLoadExplicit(&lstate->closed, memory_order_relaxed))
    {
        return;
    }
    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(line)));
    context_t               ctx = {.line = line, .pause = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageUp(lstate, msg, (wid_t) atomicLoadRelaxed(&lstate->to_wid));
}

/**
 * @brief Resume the upstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultUpStreamResume(tunnel_t *t, line_t *line)
{

    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(line, t);
    tunnel_t                *child  = tunnelGetState(t);

    if (! lstate->active)
    {
        child->fnResumeU(child, line);
        return;
    }

    if (atomicLoadExplicit(&lstate->closed, memory_order_relaxed))
    {
        return;
    }
    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(line)));
    context_t               ctx = {.line = line, .resume = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageUp(lstate, msg, (wid_t) atomicLoadRelaxed(&lstate->to_wid));
}

/*
    Downstream
*/

/**
 * @brief Initialize the downstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultdownStreamInit(tunnel_t *t, line_t *line)
{
    (void) t;
    (void) line;
    assert(false); // unreachable code
}

/**
 * @brief Establish the downstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultdownStreamEst(tunnel_t *t, line_t *line)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(line, t);
    tunnel_t                *child  = tunnelGetState(t);

    if (! lstate->active)
    {
        child->fnEstD(child, line);
        return;
    }

    if (atomicLoadExplicit(&lstate->closed, memory_order_relaxed))
    {
        return;
    }

    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(line)));
    context_t               ctx = {.line = line, .est = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageDown(lstate, msg, (wid_t) atomicLoadRelaxed(&lstate->from_wid));
}

/**
 * @brief Finalize the downstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultdownStreamFin(tunnel_t *t, line_t *line)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(line, t);
    tunnel_t                *child  = tunnelGetState(t);

    if (! lstate->active)
    {
        child->fnFinD(child, line);
        return;
    }

    if (atomicLoadExplicit(&lstate->closed, memory_order_relaxed))
    {
        return;
    }
    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(line)));
    context_t               ctx = {.line = line, .fin = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageDown(lstate, msg, (wid_t) atomicLoadRelaxed(&lstate->from_wid));
    unlock(lstate);
}

/**
 * @brief Handle downstream payload.
 *
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 * @param payload Pointer to the payload.
 */
void pipetunnelDefaultdownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(line, t);
    tunnel_t                *child  = tunnelGetState(t);

    if (! lstate->active)
    {
        child->fnPayloadD(child, line, payload);
        return;
    }

    if (atomicLoadExplicit(&lstate->closed, memory_order_relaxed))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(line)), payload);
        return;
    }
    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(line)));
    context_t               ctx = {.line = line, .payload = payload};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageDown(lstate, msg, (wid_t) atomicLoadRelaxed(&lstate->from_wid));
}

/**
 * @brief Pause the downstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultDownStreamPause(tunnel_t *t, line_t *line)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(line, t);
    tunnel_t                *child  = tunnelGetState(t);

    if (! lstate->active)
    {
        child->fnPauseD(child, line);
        return;
    }

    if (atomicLoadExplicit(&lstate->closed, memory_order_relaxed))
    {
        return;
    }
    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(line)));
    context_t               ctx = {.line = line, .pause = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageDown(lstate, msg, (wid_t) atomicLoadRelaxed(&lstate->from_wid));
}

/**
 * @brief Resume the downstream pipeline.
 *
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultDownStreamResume(tunnel_t *t, line_t *line)
{
    pipetunnel_line_state_t *lstate = (pipetunnel_line_state_t *) lineGetState(line, t);
    tunnel_t                *child  = tunnelGetState(t);

    if (! lstate->active)
    {
        child->fnResumeD(child, line);
        return;
    }

    if (atomicLoadExplicit(&lstate->closed, memory_order_relaxed))
    {
        return;
    }
    pipetunnel_msg_event_t *msg = genericpoolGetItem(getWorkerPipeTunnelMsgPool(lineGetWID(line)));
    context_t               ctx = {.line = line, .resume = true};

    msg->tunnel = t;
    msg->ctx    = ctx;

    sendMessageDown(lstate, msg, (wid_t) atomicLoadRelaxed(&lstate->from_wid));
}

/**
 * @brief Handle the tunnel chain.
 *
 * @param t Pointer to the tunnel.
 * @param tc Pointer to the tunnel chain.
 */
void pipetunnelDefaultOnChain(tunnel_t *t, tunnel_chain_t *tc)
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
void pipetunnelDefaultOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset)
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
void pipetunnelDefaultOnPrepair(tunnel_t *t)
{
    tunnel_t *child = tunnelGetState(t);
    child->onStart(child);
}

/**
 * @brief Start the tunnel.
 *
 * @param t Pointer to the tunnel.
 */
void pipetunnelDefaultOnStart(tunnel_t *t)
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
    tunnelDestroy(tunnelGetState(t));
    tunnelDestroy(t);
}

/**
 * @brief Pipe to a specific WID.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 * @param wid_to WID to pipe to.
 */
void pipeTo(tunnel_t *t, line_t *l, wid_t wid_to)
{
    tunnel_t                *parent_t = (tunnel_t *) (((uint8_t *) t) - sizeof(tunnel_t));
    pipetunnel_line_state_t *ls       = (pipetunnel_line_state_t *) lineGetState(l, parent_t);

    if (ls->active)
    {
        LOGW("double pipe (beta)");

        if (atomicLoadExplicit(&ls->closed, memory_order_relaxed))
        {
            return;
        }
        atomicStoreExplicit(&ls->to_wid, wid_to, memory_order_relaxed);
    }
    else
    {
        initializeLineState(ls, lineGetWID(l), wid_to);
    }
    t->fnInitU(t, l);
}
