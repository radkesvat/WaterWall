#include "structure.h"

#include "loggers/network_logger.h"

static void resumeUpSide(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg3;

    tunnel_t *t = (tunnel_t *) arg1;
    line_t   *l = (line_t *) arg2;

    if (lineIsAlive(l))
    {
        tunnelNextUpStreamResume(t, l);
    }
    lineUnlock(l);
}

void tcpoverudpserverKcpLoopIntervalCallback(wtimer_t *timer)
{

    tcpoverudpserver_lstate_t *ls = weventGetUserdata(timer);

    if (ls == NULL || ls->k_handle == NULL)
    {
        return;
    }

    // line is always alive here, otherwise we would not be here

    assert(lineIsAlive(ls->line));
    uint64 current_time = wloopNowMS(weventGetLoop(timer));

    ikcp_update(ls->k_handle, (IUINT32) current_time);
}

int tcpoverudpserverKUdpOutput(const char *data, int len, ikcpcb *kcp, void *user)
{
    discard kcp;

    tcpoverudpserver_lstate_t *ls = (tcpoverudpserver_lstate_t *) user;

    if (ls == NULL || ls->line == NULL)
    {
        return -1;
    }
    line_t *l   = ls->line;
    tunnel_t *t = ls->tunnel;

    assert(lineIsAlive(l));

    if (ls->write_paused && ikcp_waitsnd(ls->k_handle) < KCP_SEND_WINDOW_LIMIT)
    {
        lineLock(l);
        ls->write_paused = false;
        sendWorkerMessageForceQueue(lineGetWID(l), resumeUpSide, t, l, NULL);
    }

    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));

#ifdef DEBUG
    if (sbufGetRightCapacity(buf) < (uint32_t) KCP_MTU || (uint32_t) len > (uint32_t) KCP_MTU)
    {
        LOGF("tcpoverudpserverKUdpOutput: logical bug detected, buffer is too small, cannot send %d bytes", len);

        terminateProgram(1);
    }
#endif

    sbufSetLength(buf, (uint32_t) len);
    sbufWriteLarge(buf, data, len);
    tunnelPrevDownStreamPayload(ls->tunnel, ls->line, buf);

    return 0;
}
