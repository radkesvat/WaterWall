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
    ikcp_update(ls->k_handle, (IUINT32) current_time);
    if (flush)
    {
        ikcp_flush(ls->k_handle);
    }

    while (contextqueueLen(&ls->cq_u) > 0 && lineIsAlive(l))
    {
        context_t *c = contextqueuePop(&ls->cq_u);
        contextApplyOnNextTunnelU(c, t);
    }

    while (contextqueueLen(&ls->cq_d) > 0 && lineIsAlive(l))
    {
        context_t *c = contextqueuePop(&ls->cq_d);
        if (ls->can_downstream)
        {
            contextApplyOnPrevTunnelD(c, t);
        }
        else
        {
            contextDestroy(c);
        }
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

    tcpoverudpclientUpdateKcp(ls, false);
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
        lineLock(l);
        ls->write_paused = false;
        context_t ctx    = {.line = l, .resume = true};
        contextqueuePush(&ls->cq_d, &ctx);
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
    context_t ctx = {
        .line    = l,
        .payload = buf,
    };
    contextqueuePush(&ls->cq_u, &ctx);

    return 0;
}
