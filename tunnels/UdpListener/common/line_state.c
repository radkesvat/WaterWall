#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerLinestateInitialize(udplistener_lstate_t *ls, line_t *l, tunnel_t *t, udpsock_t *uio,
                                    uint16_t real_localport)
{

    addresscontextFromSockAddr(&(l->routing_context.src_ctx), (sockaddr_u *) wioGetPeerAddr(uio->io));
    l->routing_context.src_ctx.type_ip   = true; // we have a client ip
    l->routing_context.src_ctx.proto_udp = true; // udp

    // sockaddrToIpAddr((const sockaddr_u *) wioGetPeerAddr(uio->io), &(l->routing_context.src_ctx.ip_address));
    // addresscontextSetPort(&(l->routing_context.src_ctx), real_localport);

    *ls = (udplistener_lstate_t) {
        .line = l, .uio = uio, .tunnel = t, .read_paused = false, .peer_addr = *(sockaddr_u *) wioGetPeerAddr(uio->io)};

    if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
    {

        struct sockaddr log_localaddr = *wioGetLocaladdr(uio->io);
        sockaddrSetPort((sockaddr_u *) &(log_localaddr), real_localport);

        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        LOGD("UdpListener: Accepted FD:%x  [%s] <= [%s]", wioGetFD(uio->io), SOCKADDR_STR(&log_localaddr, localaddrstr),
             SOCKADDR_STR(wioGetPeerAddr(uio->io), peeraddrstr));
    }
}

void udplistenerLinestateDestroy(udplistener_lstate_t *ls)
{
    memoryZeroAligned32(ls, sizeof(udplistener_lstate_t));
}
