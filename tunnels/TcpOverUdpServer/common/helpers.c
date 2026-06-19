#include "structure.h"

#include "loggers/network_logger.h"

static bool tcpoverudpserverQueuePacketContext(context_queue_t *queue, line_t *l, const uint8_t *packet, size_t packet_len)
{
    if (packet_len == 0 || packet_len > UINT32_MAX)
    {
        return false;
    }

    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf  = NULL;

    if (packet_len <= bufferpoolGetSmallBufferSize(pool))
    {
        buf = bufferpoolGetSmallBuffer(pool);
    }
    else if (packet_len <= bufferpoolGetLargeBufferSize(pool))
    {
        buf = bufferpoolGetLargeBuffer(pool);
    }
    else
    {
        return false;
    }

    if (packet_len > sbufGetMaximumWriteableSize(buf))
    {
        lineReuseBuffer(l, buf);
        return false;
    }

    sbufSetLength(buf, (uint32_t) packet_len);
    sbufWriteLarge(buf, packet, (uint32_t) packet_len);
    context_t *ctx = contextCreatePayload(l, buf);
    contextqueuePush(queue, ctx);
    return true;
}

static bool tcpoverudpserverEmitOuterPacket(void *ctx, const uint8_t *packet, size_t packet_len)
{
    tcpoverudpserver_lstate_t *ls = (tcpoverudpserver_lstate_t *) ctx;

    if (ls == NULL || ls->line == NULL || ! lineIsAlive(ls->line))
    {
        return false;
    }

    return tcpoverudpserverQueuePacketContext(&ls->cq_d, ls->line, packet, packet_len);
}

bool tcpoverudpserverInputKcpPacket(void *ctx, const uint8_t *packet, size_t packet_len)
{
    tcpoverudpserver_lstate_t *ls = (tcpoverudpserver_lstate_t *) ctx;

    if (ls == NULL || ls->k_handle == NULL || packet == NULL || packet_len > INT_MAX)
    {
        return false;
    }

    return ikcp_input(ls->k_handle, (const char *) packet, (long) packet_len) >= 0;
}

bool tcpoverudpserverUpdateKcp(tcpoverudpserver_lstate_t *ls, bool flush)
{
    assert(ls != NULL && ls->k_handle != NULL && ls->line != NULL && lineIsAlive(ls->line));

    line_t   *l            = ls->line;
    tunnel_t *t            = ls->tunnel;
    uint64_t  current_time = wloopNowMS(getWorkerLoop(lineGetWID(l)));

    bool ret = true;

    lineLock(l);

    if (flush)
    {
        ikcp_flush(ls->k_handle);
    }
    ikcp_update(ls->k_handle, (IUINT32) current_time);

    while (lineIsAlive(l) && ls->k_handle != NULL && contextqueueLen(&ls->cq_d) > 0)
    {
        context_t *c = contextqueuePop(&ls->cq_d);
        contextApplyOnPrevTunnelD(c, t);
        contextDestroy(c);
    }

    while (lineIsAlive(l) && ls->k_handle != NULL && contextqueueLen(&ls->cq_u) > 0)
    {
        context_t *c = contextqueuePop(&ls->cq_u);
        if (ls->can_upstream)
        {
            contextApplyOnNextTunnelU(c, t);
        }
        contextDestroy(c);
    }
    ret = lineIsAlive(l) && ls->k_handle != NULL;

    lineUnlock(l);
    return ret;
}

static uint32_t tcpoverudpserverGetNextKcpDelay(tcpoverudpserver_lstate_t *ls, uint64_t current_time)
{
    IUINT32 current32        = (IUINT32) current_time;
    IUINT32 next_update_time = ikcp_check(ls->k_handle, current32);
    IINT32  delay            = (IINT32) (next_update_time - current32);

    return delay <= 0 ? 1U : (uint32_t) delay;
}

void tcpoverudpserverKcpLoopIntervalCallback(wtimer_t *timer)
{

    tcpoverudpserver_lstate_t *ls = weventGetUserdata(timer);

    if (ls == NULL || ls->k_handle == NULL || ls->line == NULL || ! lineIsAlive(ls->line))
    {
        return;
    }
    uint64_t                  current_time = wloopNowMS(getWorkerLoop(lineGetWID(ls->line)));
    tcpoverudpserver_tstate_t *ts           = tunnelGetState(ls->tunnel);

    if ((current_time - ls->last_recv) > ts->ping_interval_ms)
    {
        if (! ls->ping_sent)
        {
            // LOGD("TcpOverUdpServer -> KCP[%d]: sending ping", ls->k_handle->conv);

            ls->ping_sent                        = true;
            uint8_t ping_buf[kFrameHeaderLength] = {kFrameFlagPing};
            ikcp_send(ls->k_handle, (const char *) ping_buf, (int) sizeof(ping_buf));
        }
        else if ((current_time - ls->last_recv) > ts->no_recv_timeout_ms)
        {
            LOGW("TcpOverUdpServer -> KCP[%d]: no data received for too long, closing connection", ls->k_handle->conv);

            line_t   *l = ls->line;
            tunnel_t *t = ls->tunnel;

            lineLock(l);
            // close upstream side first, our own DownStreamFin propagates downstream
            // and destroys the line when it reaches the creator adapter
            tunnelNextUpStreamFinish(t, l);
            if (lineIsAlive(l))
            {
                tunnelDownStreamFin(t, l);
            }
            lineUnlock(l);
            return;
        }
    }
    if (tcpoverudpserverUpdateKcp(ls, false))
    {
        wtimerReset(timer, tcpoverudpserverGetNextKcpDelay(ls, current_time));
    }
}

int tcpoverudpserverKUdpOutput(const char *data, int len, ikcpcb *kcp, void *user)
{
    discard kcp;

    tcpoverudpserver_lstate_t *ls = (tcpoverudpserver_lstate_t *) user;

    if (ls == NULL || ls->k_handle == NULL || ls->line == NULL || ! lineIsAlive(ls->line))
    {
        return -1;
    }
    line_t *l = ls->line;

    if (ls->write_paused && ikcp_waitsnd(ls->k_handle) < tcpoverudpserverGetKcpSendBufferLimit(ls))
    {
        ls->write_paused = false;
        context_t *ctx   = contextCreateResume(l);
        contextqueuePush(&ls->cq_u, ctx);
    }

    if (ls->fec_encoder != NULL)
    {
        if (! tcpoverudpFecEncodePacket(ls->fec_encoder, (const uint8_t *) data, (size_t) len,
                                        tcpoverudpserverEmitOuterPacket, ls))
        {
            return -1;
        }
        return 0;
    }

    return tcpoverudpserverQueuePacketContext(&ls->cq_d, l, (const uint8_t *) data, (size_t) len) ? 0 : -1;
}
