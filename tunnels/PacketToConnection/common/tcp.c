#include "structure.h"

#include "loggers/network_logger.h"

static void localThreadSendFin(worker_t *worker, void *arg_lstate, void *arg2, void *arg3)
{
    (void) worker;
    (void) arg2;
    (void) arg3;

    ptc_lstate_t *lstate = (ptc_lstate_t *) arg_lstate;
    tunnel_t     *t      = lstate->tunnel;
    line_t       *l      = lstate->line;

    lineLock(l);
    lineDestroy(l);
    ptcLinestateDestroy(lstate);

    tunnelNextUpStreamFinish(t, l);

    lineUnlock(l);
}

// Error callback: called when something goes wrong on the connection.
void ptcTcpConnectionErrorCallback(void *arg, err_t err)
{
    if (err != ERR_OK)
    {
        LOGD("PacketToConnection: tcp connection error %d", err);
    }

    ptc_lstate_t *lstate = (ptc_lstate_t *) arg;
    mutexLock(&lstate->lock);
    lstate->is_closing            = true;
    lstate->tcp_pcb->callback_arg = NULL;
    lstate->tcp_pcb               = NULL;
    mutexUnlock(&lstate->lock);
    sendWorkerMessage(lineGetWID(lstate->line), localThreadSendFin, lstate, NULL, NULL);
}

static void localThreadPtcTcpRecvCallback(struct worker_s *worker, void *arg1, void *arg2, void *arg3)
{
    (void) arg3;
    (void) worker;
    ptc_lstate_t *lstate = (ptc_lstate_t *) arg1;
    line_t       *l      = lstate->line;
    sbuf_t       *buf    = arg2;
    // p is impossible to be null, null is handled on tcpip thread before calling this function

    printASCII("PacketToConnection: tcp packet received", sbufGetRawPtr(buf), sbufGetBufLength(buf));

    mutexLock(&lstate->lock);

    lineLock(l);
    ptcTunnelUpStreamPayload(lstate->tunnel, lstate->line, buf);
    if (! lineIsAlive(l))
    {
        LOGW("PacketToConnection: tcp socket just got closed by upstream before anything happend");

        lineUnlock(l);
        mutexUnlock(&lstate->lock);
        return;
    }
    lstate->direct_stack = false;

    lineUnlock(l);

    mutexUnlock(&lstate->lock);
}

err_t lwipThreadPtcTcpRecvCallback(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    ptc_lstate_t *lstate = (ptc_lstate_t *) arg;

    wid_t          wid = getWID();
    buffer_pool_t *bp  = getWorkerBufferPool(wid);
    sbuf_t        *buf;

    // If p is NULL, it means the remote end closed the connection.
    if (err != ERR_OK || p == NULL)
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        tcp_close(tpcb);

        ptcTcpConnectionErrorCallback(lstate, err);

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
        pbuf_copy_partial(p, sbufGetMutablePtr(buf), p->tot_len,0);
    }
    else
    {
        assert(false); // not implemented
    }
    pbuf_free(p);

    wid_t target_wid  = lineGetWID(lstate->line);
    wid_t current_wid = getWID();
    mutexLock(&lstate->lock);
    lstate->direct_stack = current_wid == target_wid;
    mutexUnlock(&lstate->lock);
    sendWorkerMessage(target_wid, localThreadPtcTcpRecvCallback, lstate, buf, NULL);
    return ERR_OK;
}

static void localThreadPtcAcceptCallBack(struct worker_s *worker, void *arg1, void *arg2, void *arg3)
{
    (void) worker;
    (void) arg3;
    (void) arg2;

    ptc_lstate_t *lstate = arg1;

    mutexLock(&lstate->lock);

    if (lstate->is_closing)
    {
        mutexUnlock(&lstate->lock);
        return;
    }

    struct tcp_pcb *newpcb = lstate->tcp_pcb;
    tunnel_t       *t      = lstate->tunnel;
    line_t         *l      = lstate->line;

    if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
    {
        char src_ip[40];
        char dst_ip[40];

        // Replace ipaddr_ntoa with ip4AddrNetworkToAaddress
        stringCopyN(src_ip, ip4AddrNetworkToAaddress(&newpcb->local_ip), 40);
        stringCopyN(dst_ip, ip4AddrNetworkToAaddress(&newpcb->remote_ip), 40);

        LOGI("PacketToConnection: new connection accepted  [%s:%d] <= [%s:%d]", src_ip, newpcb->local_port, dst_ip,
             newpcb->remote_port);
    }

    lineLock(l);

    tunnelNextUpStreamInit(t, l);
    if (! lineIsAlive(l))
    {
        LOGW("PacketToConnection: tcp socket just got closed by upstream before anything happend");

        lineUnlock(l);
        mutexUnlock(&lstate->lock);
        return;
    }
    lstate->direct_stack = false;

    lineUnlock(l);

    mutexUnlock(&lstate->lock);
}

err_t lwipThreadPtcTcpAccptCallback(void *arg, struct tcp_pcb *newpcb, err_t err)
{

    if (err != ERR_OK)
    {
        tcp_close(newpcb);
        return err;
    }
    wid_t current_wid = getWID();
    wid_t target_wid  = current_wid != GSTATE.lwip_wid ? current_wid : getNextDistributionWID();

    tunnel_t *t = (tunnel_t *) arg;

    line_t *l = lineCreate(tunnelchainGetLinePool(tunnelGetChain(t), current_wid), target_wid);

    ptc_lstate_t *lstate = lineGetState(l, t);

    ptcLinestateInitialize(lstate, target_wid, t, l, newpcb);

    l->routing_context.src_ctx.type_ip    = true; // we have a client ip
    l->routing_context.src_ctx.proto_tcp  = true; // tcp client
    l->routing_context.src_ctx.ip_address = newpcb->remote_ip;

    newpcb->callback_arg = lstate;

    // Set the receive callback for the new connection.
    tcp_recv(newpcb, lwipThreadPtcTcpRecvCallback);
    // Optionally, set the error callback.
    tcp_err(newpcb, ptcTcpConnectionErrorCallback);

    lstate->direct_stack = current_wid == target_wid;

    sendWorkerMessage(target_wid, localThreadPtcAcceptCallBack, lstate, NULL, NULL);

    return ERR_OK;
}
