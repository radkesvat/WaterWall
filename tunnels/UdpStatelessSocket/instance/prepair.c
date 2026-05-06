#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelOnPrepair(tunnel_t *t)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    state->io = wloopCreateUdpServer(getWorkerLoop(getWID()), state->listen_address, state->listen_port);

    if (! state->io)
    {
        LOGF("UdpStatelessSocket: could not create udp socket");
        terminateProgram(1);
    }

    state->io_wid = wloopGetWid(weventGetLoop(state->io));

    weventSetUserData(state->io, t);
    wioSetCallBackRead(state->io, udpstatelesssocketOnRecvFrom);
    wioRead(state->io);

    if (nodeIsLastInChain(t->node))
    {
        state->WriteReceivedPacket = t->prev->fnPayloadD;
        state->write_tunnel        = t->prev;
    }
    else
    {
        state->WriteReceivedPacket = t->next->fnPayloadU;
        state->write_tunnel        = t->next;
    }
}
