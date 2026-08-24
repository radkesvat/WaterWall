#include "structure.h"

#include "loggers/network_logger.h"

static void pauseDownSide(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);

    if (ls->can_downstream)
    {
        tunnelPrevDownStreamPause(t, l);
    }
}

void tcpoverudpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);

    assert(ls->k_handle != NULL);

    if (ikcp_waitsnd(ls->k_handle) > tcpoverudpclientGetKcpSendBufferLimit(ls))
    {
        ls->write_paused    = true;
        buffer_pool_t *pool = lineGetBufferPool(l);
        if (UNLIKELY(! lineScheduleTask(l, pauseDownSide, t)))
        {
            if (! withLineLocked(l, pauseDownSide, t))
            {
                bufferpoolReuseBuffer(pool, buf);
                return;
            }
        }
    }

    // Break buffer into chunks of less than 4096 bytes and send in order

    tcpoverudpclient_tstate_t *ts            = tunnelGetState(t);
    int                        kcp_write_mtu = tcpoverudpclientGetKcpWriteMtu(ts);

    assert(kcp_write_mtu > 0);

    while (sbufGetLength(buf) > 0)
    {
        int write_size = min(kcp_write_mtu, (int) sbufGetLength(buf));

        sbufShiftLeft(buf, kFrameHeaderLength);
        sbufWriteUI8(buf, kFrameFlagData);

        ikcp_send(ls->k_handle, (void *) sbufGetMutablePtr(buf), write_size + kFrameHeaderLength);
        sbufShiftRight(buf, write_size + kFrameHeaderLength);
    }
    lineReuseBuffer(l, buf);

    // Update KCP state after sending to trigger immediate transmission
    tcpoverudpclientUpdateKcp(ls, false);
}
