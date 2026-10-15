#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    assert(ls->k_handle != NULL);

    // Admit this entire payload in order before any outward callback can re-enter.

    tcpoverudpserver_tstate_t *ts            = tunnelGetState(t);
    int                        kcp_write_mtu = tcpoverudpserverGetKcpWriteMtu(ts);

    assert(kcp_write_mtu > 0);

    while (sbufGetLength(buf) > 0)
    {
        int write_size = (int) min((uint32_t) kcp_write_mtu, sbufGetLength(buf));

        sbufShiftLeft(buf, kFrameHeaderLength);
        sbufWriteUI8(buf, kFrameFlagData);

        ikcp_send(ls->k_handle, (void *) sbufGetMutablePtr(buf), write_size + kFrameHeaderLength);
        sbufShiftRight(buf, write_size + kFrameHeaderLength);
    }
    lineReuseBuffer(l, buf);

    // Update KCP state after sending to trigger immediate transmission
    tcpoverudpserverUpdateKcp(ls, false);
}
