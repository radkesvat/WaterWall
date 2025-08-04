#include "structure.h"

#include "loggers/network_logger.h"

static void pauseDownSide(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg3;

    tunnel_t *t = (tunnel_t *) arg1;
    line_t   *l = (line_t *) arg2;

    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);

    if (lineIsAlive(l) && ls->can_downstream)
    {
        tunnelPrevDownStreamPause(t, l);
    }
    lineUnlock(l);
}

void tcpoverudpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);

    if (ikcp_waitsnd(ls->k_handle) > KCP_SEND_WINDOW_LIMIT)
    {
        lineLock(l);
        ls->write_paused = true;
        sendWorkerMessageForceQueue(lineGetWID(l), pauseDownSide, t, l, NULL);
    }

    // Break buffer into chunks of less than 4096 bytes and send in order

    while (sbufGetLength(buf) > 0)
    {
        int write_size = min(KCP_MTU_WRITE, sbufGetLength(buf));

        sbufShiftLeft(buf, kFrameHeaderLength);
        sbufWriteUI8(buf, kFrameFlagData);

        ikcp_send(ls->k_handle, (void *) sbufGetMutablePtr(buf), write_size + kFrameHeaderLength);
        sbufShiftRight(buf, write_size + kFrameHeaderLength);
    }
    bufferpoolReuseBuffer(lineGetBufferPool(l), buf);

    // Update KCP state after sending to trigger immediate transmission
    tcpoverudpclientUpdateKcp(ls, false);
}
