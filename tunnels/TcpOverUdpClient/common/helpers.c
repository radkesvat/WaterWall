#include "structure.h"

#include "loggers/network_logger.h"

static bool tcpoverudpclientQueuePacketContext(context_queue_t *queue, line_t *l, const uint8_t *packet,
                                               size_t packet_len)
{
    // Only KCP output reaches here, with at most the optional FEC envelope added.
    assert(packet != NULL && packet_len > 0 &&
           packet_len <= kTcpOverUdpClientKcpMaximumMtu + kTcpOverUdpFecOuterHeaderSize);

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

    sbufSetLength(buf, (uint32_t) packet_len);
    sbufWriteLarge(buf, packet, (uint32_t) packet_len);
    context_t *ctx = contextCreatePayload(l, buf);
    contextqueuePush(queue, ctx);
    return true;
}

static bool tcpoverudpclientEmitOuterPacket(void *ctx, const uint8_t *packet, size_t packet_len)
{
    tcpoverudpclient_lstate_t *ls = (tcpoverudpclient_lstate_t *) ctx;

    assert(ls != NULL && ls->k_handle != NULL && ls->line != NULL && lineIsAlive(ls->line));

    return tcpoverudpclientQueuePacketContext(&ls->cq_u, ls->line, packet, packet_len);
}

bool tcpoverudpclientInputKcpPacket(void *ctx, const uint8_t *packet, size_t packet_len)
{
    tcpoverudpclient_lstate_t *ls = (tcpoverudpclient_lstate_t *) ctx;

    assert(ls != NULL && ls->k_handle != NULL);

    // FEC validated the shard's uint16 length prefix before calling us.
    assert(packet != NULL && packet_len <= UINT16_MAX - 2U);

    return ikcp_input(ls->k_handle, (const char *) packet, (long) packet_len) >= 0;
}

bool tcpoverudpclientUpdateKcp(tcpoverudpclient_lstate_t *ls, bool flush)
{
    assert(ls != NULL && ls->k_handle != NULL && ls->line != NULL && lineIsAlive(ls->line));

    line_t   *l            = ls->line;
    tunnel_t *t            = ls->tunnel;
    uint64_t  current_time = wloopNowMS(getWorkerLoop(lineGetWID(l)));

    lineRef(l);

    if (flush)
    {
        ikcp_flush(ls->k_handle);
    }
    ikcp_update(ls->k_handle, (IUINT32) current_time);

    while (lineIsAlive(l) && ls->k_handle != NULL && contextqueueLen(&ls->cq_u) > 0)
    {
        context_t *c = contextqueuePop(&ls->cq_u);
        contextApplyOnNextTunnelU(c, t);
        contextDestroy(c);
    }

    // Reconcile our own pressure only after KCP and packet output have settled.
    // ACK-only input can release the hold without producing another packet.
    if (lineIsAlive(l) && ls->k_handle != NULL && ls->can_downstream)
    {
        const int queued = ikcp_waitsnd(ls->k_handle);
        const int limit  = tcpoverudpclientGetKcpSendBufferLimit(ls);
        if (! ls->source_paused && queued > limit)
        {
            ls->source_paused = true;
            tunnelPrevDownStreamPause(t, l);
        }
        else if (ls->source_paused && queued < limit)
        {
            ls->source_paused = false;
            tunnelPrevDownStreamResume(t, l);
        }
    }
    const bool alive = lineIsAlive(l) && ls->k_handle != NULL;

    lineUnref(l);
    return alive;
}

static uint32_t tcpoverudpclientGetNextKcpDelay(tcpoverudpclient_lstate_t *ls, uint64_t current_time)
{
    IUINT32 current32        = (IUINT32) current_time;
    IUINT32 next_update_time = ikcp_check(ls->k_handle, current32);
    IINT32  delay            = (IINT32) (next_update_time - current32);

    return delay <= 0 ? 1U : (uint32_t) delay;
}

void tcpoverudpclientKcpLoopIntervalCallback(wtimer_t *timer)
{

    tcpoverudpclient_lstate_t *ls = weventGetUserdata(timer);

    assert(ls != NULL && ls->k_timer == timer && ls->k_handle != NULL && ls->line != NULL && ls->tunnel != NULL &&
           lineIsAlive(ls->line));

    uint64_t                   current_time = wloopNowMS(getWorkerLoop(lineGetWID(ls->line)));
    tcpoverudpclient_tstate_t *ts           = tunnelGetState(ls->tunnel);

    if ((current_time - ls->last_recv) > ts->ping_interval_ms)
    {
        if (! ls->ping_sent)
        {
            // LOGD("TcpOverUdpClient -> KCP[%d]: sending ping", ls->k_handle->conv);

            ls->ping_sent                        = true;
            uint8_t ping_buf[kFrameHeaderLength] = {kFrameFlagPing};
            ikcp_send(ls->k_handle, (const char *) ping_buf, (int) sizeof(ping_buf));
        }
        else if ((current_time - ls->last_recv) > ts->no_recv_timeout_ms)
        {
            LOGW("TcpOverUdpClient -> KCP[%d]: no data received for too long, closing connection", ls->k_handle->conv);

            tunnel_t *t = ls->tunnel;
            line_t   *l = ls->line;

            lineRef(l);
            tunnelUpStreamFin(t, l);
            if (lineIsAlive(l))
            {
                tunnelPrevDownStreamFinish(t, l);
            }
            lineUnref(l);
            return;
        }
    }

    if (tcpoverudpclientUpdateKcp(ls, false))
    {
        wtimerReset(timer, tcpoverudpclientGetNextKcpDelay(ls, current_time));
    }
}

int tcpoverudpclientKUdpOutput(const char *data, int len, ikcpcb *kcp, void *user)
{
    discard kcp;

    tcpoverudpclient_lstate_t *ls = (tcpoverudpclient_lstate_t *) user;

    assert(ls != NULL && ls->k_handle != NULL && ls->line != NULL && lineIsAlive(ls->line));
    line_t *l = ls->line;

    if (ls->fec_encoder != NULL)
    {
        if (! tcpoverudpFecEncodePacket(
                ls->fec_encoder, (const uint8_t *) data, (size_t) len, tcpoverudpclientEmitOuterPacket, ls))
        {
            return -1;
        }
        return 0;
    }

    return tcpoverudpclientQueuePacketContext(&ls->cq_u, l, (const uint8_t *) data, (size_t) len) ? 0 : -1;
}
