#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelOnPrepair(tunnel_t *t)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    char                         interface_ip[INET_ADDRSTRLEN] = {0};
    const char                  *bind_address = state->listen_address;

    if (state->interface_name != NULL && ! state->source_ip_configured && ! socketOptionBindToDeviceSupported())
    {
        if (! getInterfaceIpString(state->interface_name, interface_ip, sizeof(interface_ip)))
        {
            LOGF("UdpStatelessSocket: could not get interface \"%s\" ip", state->interface_name);
            terminateProgram(1);
        }
        bind_address = interface_ip;
    }

    state->io = wloopCreateUdpServerWithBufferOptions(getWorkerLoop(getWID()), bind_address, state->listen_port,
                                                      state->interface_name, state->fwmark, state->send_buffer_size,
                                                      state->recv_buffer_size);

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
