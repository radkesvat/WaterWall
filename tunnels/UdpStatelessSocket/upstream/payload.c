#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    // sharing the exact code with downstream side (bidirectional tunnel)
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    if (lineGetWID(l) != state->io_wid)
    {
        sendWorkerMessage(state->io_wid, UdpStatelessLocalThreadSocketUpStream, t, l, buf);
    }
    else
    {
        UdpStatelessLocalThreadSocketUpStream(NULL, t, l, buf);
    }
}
