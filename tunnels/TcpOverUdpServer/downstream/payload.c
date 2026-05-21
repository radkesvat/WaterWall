#include "structure.h"

#include "loggers/network_logger.h"

static void pauseDownSide(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    if (ls->can_upstream)
    {
        tunnelNextUpStreamPause(t, l);
    }

}

void tcpoverudpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->k_handle == NULL))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ikcp_waitsnd(ls->k_handle) > tcpoverudpserverGetKcpSendBufferLimit(ls))
    {
        ls->write_paused = true;
        lineScheduleTask(l, pauseDownSide, t);
    }

    // Break buffer into chunks of less than 4096 bytes and send in order

    tcpoverudpserver_tstate_t *ts = tunnelGetState(t);
    int                       kcp_write_mtu = tcpoverudpserverGetKcpWriteMtu(ts);

    if (UNLIKELY(kcp_write_mtu <= 0))
    {
        lineReuseBuffer(l, buf);
        return;
    }

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
    tcpoverudpserverUpdateKcp(ls,false);
}
