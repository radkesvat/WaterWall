#include "structure.h"

#include "loggers/network_logger.h"

static bool tcpoverudpserverQueuePacketContext(context_queue_t *queue, line_t *l, const uint8_t *packet,
                                               size_t packet_len)
{
    /* KCP emits a nonempty datagram; FEC adds only its fixed outer header. */
    assert(packet != NULL && packet_len > 0 && packet_len <= UINT32_MAX);

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

static bool tcpoverudpserverEmitOuterPacket(void *ctx, const uint8_t *packet, size_t packet_len)
{
    tcpoverudpserver_lstate_t *ls = (tcpoverudpserver_lstate_t *) ctx;

    assert(ls != NULL && ls->k_handle != NULL && ls->line != NULL && lineIsAlive(ls->line));

    return tcpoverudpserverQueuePacketContext(&ls->cq_d, ls->line, packet, packet_len);
}

bool tcpoverudpserverInputKcpPacket(void *ctx, const uint8_t *packet, size_t packet_len)
{
    tcpoverudpserver_lstate_t *ls = (tcpoverudpserver_lstate_t *) ctx;

    assert(ls != NULL && ls->k_handle != NULL);

    /* The FEC decoder emits validated, uint16-sized shard contents. */
    assert(packet != NULL && packet_len <= INT_MAX);

    return ikcp_input(ls->k_handle, (const char *) packet, (long) packet_len) >= 0;
}

bool tcpoverudpserverUpdateKcp(tcpoverudpserver_lstate_t *ls, bool flush)
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

    while (lineIsAlive(l) && ls->k_handle != NULL && contextqueueLen(&ls->cq_d) > 0)
    {
        context_t *c = contextqueuePop(&ls->cq_d);
        contextApplyOnPrevTunnelD(c, t);
        contextDestroy(c);
    }

    // Reconcile only after KCP and its output callbacks settle, including ACK-only input.
    if (lineIsAlive(l) && ls->k_handle != NULL && ls->can_upstream)
    {
        const int queued = ikcp_waitsnd(ls->k_handle);
        const int limit  = tcpoverudpserverGetKcpSendBufferLimit(ls);
        if (! ls->source_paused && queued > limit)
        {
            ls->source_paused = true;
            tunnelNextUpStreamPause(t, l);
        }
        else if (ls->source_paused && queued < limit)
        {
            ls->source_paused = false;
            tunnelNextUpStreamResume(t, l);
        }
    }
    const bool alive = lineIsAlive(l) && ls->k_handle != NULL;

    lineUnref(l);
    return alive;
}

static uint32_t tcpoverudpserverGetNextKcpDelay(tcpoverudpserver_lstate_t *ls, uint64_t current_time)
{
    IUINT32 current32        = (IUINT32) current_time;
    IUINT32 next_update_time = ikcp_check(ls->k_handle, current32);
    IINT32  delay            = (IINT32) (next_update_time - current32);

    return delay <= 0 ? 1U : (uint32_t) delay;
}

// Queues the close frame, flushes it once, then destroys line state and finishes the prev side.
void tcpoverudpserverSendCloseAndFinish(tcpoverudpserver_lstate_t *ls)
{
    line_t   *l = ls->line;
    tunnel_t *t = ls->tunnel;

    uint8_t close_buf[kFrameHeaderLength] = {kFrameFlagClose};
    ikcp_send(ls->k_handle, (const char *) close_buf, (int) sizeof(close_buf));

    if (! tcpoverudpserverUpdateKcp(ls, true))
    {
        return;
    }

    tcpoverudpserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

void tcpoverudpserverKcpLoopIntervalCallback(wtimer_t *timer)
{

    tcpoverudpserver_lstate_t *ls = weventGetUserdata(timer);

    assert(ls != NULL && ls->k_timer == timer && ls->k_handle != NULL && ls->line != NULL && ls->tunnel != NULL &&
           lineIsAlive(ls->line));
    uint64_t                   current_time = wloopNowMS(getWorkerLoop(lineGetWID(ls->line)));
    tcpoverudpserver_tstate_t *ts           = tunnelGetState(ls->tunnel);
    const uint64_t             idle_ms      = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(ls->line))) - ls->last_recv;

    // After a service-side close, the close frame goes out only once the peer has acknowledged all queued
    // data, and the line then closes as at once when nothing is queued. Keeping the line until the close
    // frame itself is acknowledged would hold it for peers that never acknowledge it, and a client that
    // reuses its UDP port would reach that stale state. A peer silent for no-recv-timeout-ms releases it.
    if (ls->closing)
    {
        if (ikcp_waitsnd(ls->k_handle) == 0)
        {
            ls->closing = false;
            tcpoverudpserverSendCloseAndFinish(ls);
            return;
        }
        if (idle_ms > ts->no_recv_timeout_ms)
        {
            line_t   *l = ls->line;
            tunnel_t *t = ls->tunnel;

            tcpoverudpserverLinestateDestroy(ls);
            tunnelPrevDownStreamFinish(t, l);
            return;
        }
    }

    if (! ls->closing && idle_ms > ts->ping_interval_ms)
    {
        if (! ls->ping_sent)
        {
            // LOGD("TcpOverUdpServer -> KCP[%d]: sending ping", ls->k_handle->conv);

            ls->ping_sent                        = true;
            uint8_t ping_buf[kFrameHeaderLength] = {kFrameFlagPing};
            ikcp_send(ls->k_handle, (const char *) ping_buf, (int) sizeof(ping_buf));
        }
        else if (idle_ms > ts->no_recv_timeout_ms)
        {
            LOGW("TcpOverUdpServer -> KCP[%d]: no data received for too long, closing connection", ls->k_handle->conv);

            line_t   *l = ls->line;
            tunnel_t *t = ls->tunnel;

            lineRef(l);
            // close upstream side first, our own DownStreamFin propagates downstream
            // and destroys the line when it reaches the creator adapter
            tunnelNextUpStreamFinish(t, l);
            if (lineIsAlive(l))
            {
                tunnelDownStreamFin(t, l);
            }
            lineUnref(l);
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

    assert(ls != NULL && ls->k_handle != NULL && ls->line != NULL && lineIsAlive(ls->line));
    line_t *l = ls->line;

    if (ls->fec_encoder != NULL)
    {
        return tcpoverudpFecEncodePacket(
                   ls->fec_encoder, (const uint8_t *) data, (size_t) len, tcpoverudpserverEmitOuterPacket, ls)
                   ? 0
                   : -1;
    }

    return tcpoverudpserverQueuePacketContext(&ls->cq_d, l, (const uint8_t *) data, (size_t) len) ? 0 : -1;
}
