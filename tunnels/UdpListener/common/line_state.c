#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerLinestateInitialize(udplistener_lstate_t *ls, line_t *l, tunnel_t *t, udpsock_t *uio,
                                    uint16_t real_localport, const sockaddr_u *peer_addr,
                                    const sockaddr_u *local_addr)
{
    assert(peer_addr != NULL);
    assert(local_addr != NULL);

    addresscontextFromSockAddrWithProtocol(&(l->routing_context.src_ctx), peer_addr, IP_PROTO_UDP);
    l->routing_context.peer_source_port = sockaddrPort((sockaddr_u *) peer_addr);
    addresscontextSetPort(&(l->routing_context.src_ctx), real_localport);

    sockaddr_u effective_local_addr = *local_addr;
    sockaddrSetPort(&effective_local_addr, real_localport);
    addresscontextFromSockAddrWithProtocol(&(l->routing_context.dest_ctx), &effective_local_addr, IP_PROTO_UDP);

    l->routing_context.local_listener_port = real_localport;

    *ls = (udplistener_lstate_t) {.line        = l,
                                  .uio         = uio,
                                  .tunnel      = t,
                                  .listener_fd = wioGetFD(uio->io),
                                  .read_paused = false,
                                  .peer_addr   = *peer_addr,
                                  .local_addr  = effective_local_addr};

    if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
    {

        sockaddr_u log_localaddr = effective_local_addr;
        sockaddrSetPort(&log_localaddr, real_localport);

        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        LOGD("UdpListener: Accepted FD:%x  [%s] <= [%s]",
             ls->listener_fd,
             SOCKADDR_STR(&log_localaddr, localaddrstr),
             SOCKADDR_STR((sockaddr_u *) peer_addr, peeraddrstr));
    }
}

void udplistenerLinestateDestroy(udplistener_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(udplistener_lstate_t)));
}
