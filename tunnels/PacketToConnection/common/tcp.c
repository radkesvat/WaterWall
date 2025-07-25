#include "structure.h"

#include "loggers/network_logger.h"

static void localThreadSendFin(worker_t *worker, void *arg_lstate, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;
    discard arg3;

#if SHOW_ALL_LOGS
    LOGD("PacketToConnection: closing connection if possible");
#endif
    ptc_lstate_t *lstate = (ptc_lstate_t *) arg_lstate;
    tunnel_t     *t      = lstate->tunnel;
    line_t       *l      = lstate->line;

    atomicDec(&lstate->messages);

    if (! lineIsAlive(l))
    {
        LOCK_TCPIP_CORE();
        if (lstate->messages == 0)
        {
            ptcLinestateDestroy(lstate);
        }
        UNLOCK_TCPIP_CORE();
        return;
    }

#if SHOW_ALL_LOGS
    LOGD("PacketToConnection: sending fin");
#endif
    lineLock(l);
    lineDestroy(l);
    tunnelNextUpStreamFinish(t, l);
    lineUnlock(l);

    LOCK_TCPIP_CORE();
    // we got the lock so we can load relaxed
    if (atomicLoadRelaxed(&lstate->messages) == 0)
    {
        ptcLinestateDestroy(lstate);
    }
    UNLOCK_TCPIP_CORE();
}

// Error callback: called when something goes wrong on the connection.
void lwipThreadPtcTcpConnectionErrorCallback(void *arg, err_t err)
{
    if (err != ERR_OK)
    {
        LOGD("PacketToConnection: tcp connection error %d", err);
    }
    if (arg == NULL)
    {
        return;
    }

    ptc_lstate_t *lstate     = (ptc_lstate_t *) arg;
    wid_t         target_wid = lineGetWID(lstate->line);
    // wid_t         current_wid = g etWID();

    // here we have the tcpip mutex locked
    lstate->tcp_pcb->callback_arg = NULL;
    lstate->tcp_pcb->sent         = NULL;
    lstate->tcp_pcb               = NULL;

    atomicInc(&lstate->messages);

    sendWorkerMessageForceQueue(target_wid, localThreadSendFin, lstate, NULL, NULL);
}

static void localThreadPtcTcpRecvCallback(struct worker_s *worker, void *arg1, void *arg2, void *arg3)
{
    discard       arg3;
    discard       worker;
    ptc_lstate_t *lstate = (ptc_lstate_t *) arg1;
    line_t       *l      = lstate->line;
    sbuf_t       *buf    = arg2;

    atomicDec(&lstate->messages);

    if (! lineIsAlive(l))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        LOCK_TCPIP_CORE();
        if (lstate->messages == 0)
        {
            ptcLinestateDestroy(lstate);
        }
        UNLOCK_TCPIP_CORE();
        return;
    }

// p is impossible to be null, null is handled on tcpip thread before calling this function
#if SHOW_ALL_LOGS
    printDebug("PacketToConnection: sending %d bytes\n", sbufGetLength(buf));
#endif

    uint32_t len = sbufGetLength(buf);

    lineLock(l);
    tunnelNextUpStreamPayload(lstate->tunnel, lstate->line, buf);
    if (! lineIsAlive(l))
    {
        lineUnlock(l);
        return;
    }

    if (lstate->read_paused)
    {
        lstate->read_paused_len += len;
    }
    else
    {
        LOCK_TCPIP_CORE();
        if (lstate->tcp_pcb)
        {
            tcp_recved(lstate->tcp_pcb, len);
        }
        UNLOCK_TCPIP_CORE();
    }

    lineUnlock(l);
}

err_t lwipThreadPtcTcpRecvCallback(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    ptc_lstate_t *lstate = (ptc_lstate_t *) arg;

    wid_t          wid = getWID();
    buffer_pool_t *bp  = getWorkerBufferPool(wid);
    sbuf_t        *buf = NULL;

    // If p is NULL, it means the remote end closed the connection.
    if (err != ERR_OK || p == NULL)
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        assert(tpcb != NULL);
        tcp_close(tpcb);

        lwipThreadPtcTcpConnectionErrorCallback(lstate, err);

        return ERR_OK;
    }

    /*
        This is a chained buffer and we must copy it anyway, so dont bother all nodes for it
    */
    if (p->tot_len <= bufferpoolGetLargeBufferSize(bp))
    {

        if (p->tot_len <= bufferpoolGetSmallBufferSize(bp))
        {
            buf = bufferpoolGetSmallBuffer(bp);
        }
        else
        {
            buf = bufferpoolGetLargeBuffer(bp);
        }

        sbufSetLength(buf, p->tot_len);
        pbuf_copy_partial(p, sbufGetMutablePtr(buf), p->tot_len, 0);
    }
    else
    {
        assert(false); // not implemented
    }
    pbuf_free(p);

    wid_t target_wid = lineGetWID(lstate->line);
    // wid_t current_wid = getWID();

    atomicInc(&lstate->messages);

    sendWorkerMessageForceQueue(target_wid, localThreadPtcTcpRecvCallback, lstate, buf, NULL);

    // bool doing_direct_stack    = (current_wid == target_wid) && (atomicLoad(&lstate->messages) == 0);
    // lstate->stack_owned_locked = doing_direct_stack;
    // if (! doing_direct_stack)
    // {
    //     atomicInc(&lstate->messages);
    //     sendWorkerMessageForceQueue(target_wid, localThreadPtcTcpRecvCallback, lstate, buf, NULL);
    // }
    // else
    // {
    //     sendWorkerMessage(target_wid, localThreadPtcTcpRecvCallback, lstate, buf, NULL);
    // }
    return ERR_OK;
}

static void localThreadPtcAcceptCallBack(struct worker_s *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg3;
    discard arg2;

    ptc_lstate_t *lstate = arg1;

    struct tcp_pcb *newpcb = lstate->tcp_pcb;
    tunnel_t       *t      = lstate->tunnel;
    line_t         *l      = lstate->line;

    atomicDec(&lstate->messages);

    if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
    {
        char src_ip[40];
        char dst_ip[40];

        // Replace ipaddr_ntoa with ip4AddrNetworkToAddress
        stringCopyN(src_ip, ipAddrNetworkToAddress(&newpcb->local_ip), 40);
        stringCopyN(dst_ip, ipAddrNetworkToAddress(&newpcb->remote_ip), 40);

        LOGD("PacketToConnection: new connection accepted  [%s:%d] <= [%s:%d]", src_ip, newpcb->local_port, dst_ip,
             newpcb->remote_port);
    }

    lineLock(l);

    tunnelNextUpStreamInit(t, l);
    if (! lineIsAlive(l))
    {
#if SHOW_ALL_LOGS
        LOGD("PacketToConnection: tcp socket just got closed by upstream before anything happend");
#endif
        lineUnlock(l);
        return;
    }

    lineUnlock(l);
}

err_t lwipThreadPtcTcpAccptCallback(void *arg, struct tcp_pcb *newpcb, err_t err)
{

    if (err != ERR_OK)
    {
        if (newpcb != NULL)
        {
            tcp_close(newpcb);
        }
        return err;
    }
    wid_t current_wid = getWID();
    wid_t target_wid  = current_wid != GSTATE.lwip_wid ? current_wid : getNextDistributionWID();

    tunnel_t *t = (tunnel_t *) arg;

    line_t *l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), target_wid);

    ptc_lstate_t *lstate = lineGetState(l, t);

    ptcLinestateInitialize(lstate, target_wid, t, l, newpcb);
    lstate->is_tcp = true;

    l->routing_context.src_ctx.type_ip    = true; // we have a client ip
    l->routing_context.src_ctx.proto_tcp  = true; // tcp client
    l->routing_context.src_ctx.ip_address = newpcb->remote_ip;
    addresscontextSetIpPort(&l->routing_context.src_ctx, &newpcb->remote_ip, newpcb->remote_port);

    addresscontextSetIpPort(&l->routing_context.dest_ctx, &newpcb->local_ip, newpcb->local_port);

    newpcb->callback_arg = lstate;
    newpcb->sent = ptcTcpSendCompleteCallback;
    tcp_nagle_disable(newpcb);

    // Set the receive callback for the new connection.
    tcp_recv(newpcb, lwipThreadPtcTcpRecvCallback);
    // Optionally, set the error callback.
    tcp_err(newpcb, lwipThreadPtcTcpConnectionErrorCallback);

    atomicInc(&lstate->messages);
    // i think its better to offload it right away, direct calling will hold the tcpip stack for longer time
    sendWorkerMessageForceQueue(target_wid, localThreadPtcAcceptCallBack, lstate, NULL, NULL);

    // bool doing_direct_stack    = (current_wid == target_wid) && (atomicLoad(&lstate->messages) == 0);
    // lstate->stack_owned_locked = doing_direct_stack;
    // if (! doing_direct_stack)
    // {
    //     atomicInc(&lstate->messages);
    //     sendWorkerMessageForceQueue(target_wid, localThreadPtcAcceptCallBack, lstate, NULL, NULL);
    // }
    // else
    // {
    //     sendWorkerMessage(target_wid, localThreadPtcAcceptCallBack, lstate, NULL, NULL);
    // }

    return ERR_OK;
}
