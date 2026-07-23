#include "structure.h"

#include "loggers/network_logger.h"

static wio_t *udpstatelesssocketCreateUdpServer(udpstatelesssocket_tstate_t *state, const char *bind_address)
{
    sockaddr_u addr = {0};
    if (sockaddrSetIpAddressPort(&addr, bind_address, state->listen_port) != 0)
    {
        LOGE("UdpStatelessSocket: could not prepare bind address %s", bind_address);
        return NULL;
    }

    int sockfd = socket(addr.sa.sa_family, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        LOGE("UdpStatelessSocket: socket fd < 0");
        return NULL;
    }

    if (socketOptionBindToDevice(sockfd, state->interface_name) != 0)
    {
        LOGE("UdpStatelessSocket: setsockopt SO_BINDTODEVICE error");
        closesocket(sockfd);
        return NULL;
    }

    if (egressPinApply(sockfd, addr.sa.sa_family, state->interface_name) != 0)
    {
        LOGE("UdpStatelessSocket: egress pin failed");
        closesocket(sockfd);
        return NULL;
    }

    if (state->fwmark >= 0 && socketOptionSetFwMark(sockfd, state->fwmark) != 0)
    {
        LOGE("UdpStatelessSocket: setsockopt SO_MARK error");
        closesocket(sockfd);
        return NULL;
    }

    socketOptionServerAddressUse(sockfd);

    if (addr.sa.sa_family == AF_INET6)
    {
        ipV6Only(sockfd, 0);
    }

    if (bind(sockfd, &addr.sa, sockaddrLen(&addr)) < 0)
    {
        LOGE("UdpStatelessSocket: UDP bind failed");
        closesocket(sockfd);
        return NULL;
    }

    if (! socketOptionApplySendBuffer(sockfd, state->send_buffer_size))
    {
        LOGE("UdpStatelessSocket: set socket send buffer failed");
        closesocket(sockfd);
        return NULL;
    }

    if (! socketOptionApplyRecvBuffer(sockfd, state->recv_buffer_size))
    {
        LOGE("UdpStatelessSocket: set socket recv buffer failed");
        closesocket(sockfd);
        return NULL;
    }

    wio_t *io = wioGet(getWorkerLoop(getWID()), sockfd);
    if (io == NULL || wioIsClosed(io))
    {
        LOGE("UdpStatelessSocket: could not create event io");
        if (io == NULL)
        {
            // No event io took ownership of the socket, so release the fd here.
            closesocket(sockfd);
        }
        return NULL;
    }

    wioSetType(io, WIO_TYPE_UDP);
    wioSetLocaladdr(io, &addr.sa, (int) sockaddrLen(&addr));
    weventSetPriority(io, WEVENT_HIGH_PRIORITY);

    return io;
}

static void udpstatelesssocketRefreshLocalAddress(wio_t *io)
{
    sockaddr_u local_addr = {0};
    socklen_t  addr_len   = sizeof(local_addr);

    if (getsockname(wioGetFD(io), &local_addr.sa, &addr_len) == 0)
    {
        wioSetLocaladdr(io, &local_addr.sa, (int) addr_len);
    }
}

void udpstatelesssocketTunnelOnPrepair(tunnel_t *t)
{
    udpstatelesssocket_tstate_t *state                         = tunnelGetState(t);
    char                         interface_ip[INET_ADDRSTRLEN] = {0};
    const char                  *bind_address                  = state->listen_address;

    if (state->interface_name != NULL && ! state->source_ip_configured && ! socketOptionBindToDeviceSupported())
    {
        if (! getInterfaceIpString(state->interface_name, interface_ip, sizeof(interface_ip)))
        {
            LOGF("UdpStatelessSocket: could not get interface \"%s\" ip", state->interface_name);
            terminateProgram(1);
        }
        bind_address = interface_ip;
    }

    state->socket.io = udpstatelesssocketCreateUdpServer(state, bind_address);

    if (! state->socket.io)
    {
        LOGF("UdpStatelessSocket: could not create udp socket");
        terminateProgram(1);
    }

    udpstatelesssocketRefreshLocalAddress(state->socket.io);
    state->io_wid       = wloopGetWid(weventGetLoop(state->socket.io));
    state->is_chain_end = nodeIsLastInChain(t->node);

    weventSetUserData(state->socket.io, t);
    wioSetCallBackRead(state->socket.io, udpstatelesssocketOnRecvFrom);
    if (UNLIKELY(wioRead(state->socket.io) != 0))
    {
        state->socket.io = NULL;
        LOGF("UdpStatelessSocket: could not register udp socket with the event loop");
        terminateProgram(1);
    }
}
