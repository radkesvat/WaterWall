#include "structure.h"

#include "loggers/network_logger.h"

bool tcpoverudpclientUpdateKcp(tcpoverudpclient_lstate_t *ls, bool flush)
{
    assert(ls != NULL && ls->line != NULL && lineIsAlive(ls->line));

    line_t   *l            = ls->line;
    tunnel_t *t            = ls->tunnel;
    uint64    current_time = wloopNowMS(getWorkerLoop(lineGetWID(l)));

    bool ret = true;

    lineLock(l);

    if (flush)
    {
        ikcp_flush(ls->k_handle);
    }
    ikcp_update(ls->k_handle, (IUINT32) current_time);

    while (lineIsAlive(l) && contextqueueLen(&ls->cq_u) > 0)
    {
        context_t *c = contextqueuePop(&ls->cq_u);
        contextApplyOnNextTunnelU(c, t);
        contextDestroy(c);
    }

    while (lineIsAlive(l) && contextqueueLen(&ls->cq_d) > 0)
    {
        context_t *c = contextqueuePop(&ls->cq_d);
        if (ls->can_downstream)
        {
            contextApplyOnPrevTunnelD(c, t);
        }
        contextDestroy(c);
    }
    ret = lineIsAlive(l);

    lineUnlock(l);
    return ret;
}

void tcpoverudpclientKcpLoopIntervalCallback(wtimer_t *timer)
{

    tcpoverudpclient_lstate_t *ls = weventGetUserdata(timer);

    if (ls == NULL || ls->line == NULL || ! lineIsAlive(ls->line))
    {
        return;
    }

    uint64 current_time = wloopNowMS(getWorkerLoop(lineGetWID(ls->line)));

    if ((current_time - ls->last_recv) > kTcpOverUdpClientPingintervalMs)
    {
        if (! ls->ping_sent)
        {
            // LOGD("TcpOverUdpClient -> KCP[%d]: sending ping", ls->k_handle->conv);

            ls->ping_sent                        = true;
            uint8_t ping_buf[kFrameHeaderLength] = {kFrameFlagPing};
            ikcp_send(ls->k_handle, (const char *) ping_buf, (int) sizeof(ping_buf));
        }
        else if ((current_time - ls->last_recv) > kTcpOverUdpClientNoRecvTimeOut)
        {
            LOGW("TcpOverUdpClient -> KCP[%d]: no data received for too long, closing connection", ls->k_handle->conv);

            tunnel_t *t = ls->tunnel;
            line_t   *l = ls->line;
            tunnelUpStreamFin(t, l);
            tunnelPrevDownStreamFinish(t, l);
            return;
        }
    }

    if (tcpoverudpclientUpdateKcp(ls, false))
    {
        uint64_t next_update_time = ikcp_check(ls->k_handle, (IUINT32) current_time);
        wtimerReset(timer, (uint32_t) (next_update_time - current_time));
    }
}

int tcpoverudpclientKUdpOutput(const char *data, int len, ikcpcb *kcp, void *user)
{
    discard kcp;

    tcpoverudpclient_lstate_t *ls = (tcpoverudpclient_lstate_t *) user;

    if (ls == NULL || ls->line == NULL || ! lineIsAlive(ls->line))
    {
        return -1;
    }
    line_t *l = ls->line;

    if (ls->write_paused && ikcp_waitsnd(ls->k_handle) < KCP_SEND_WINDOW_LIMIT)
    {
        ls->write_paused = false;
        context_t *ctx   = contextCreateResume(l);
        contextqueuePush(&ls->cq_d, ctx);
    }

    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));

#ifdef DEBUG
    if (sbufGetRightCapacity(buf) < (uint32_t) KCP_MTU || (uint32_t) len > (uint32_t) KCP_MTU)
    {
        LOGF("tcpoverudpclientKUdpOutput: logical bug detected, buffer is too small, cannot send %d bytes", len);

        terminateProgram(1);
    }
#endif

    sbufSetLength(buf, (uint32_t) len);
    sbufWriteLarge(buf, data, len);
    context_t *ctx = contextCreatePayload(l, buf);
    contextqueuePush(&ls->cq_u, ctx);

    return 0;
}
