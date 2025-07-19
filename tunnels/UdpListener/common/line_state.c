#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerLinestateInitialize(udplistener_lstate_t *ls, line_t *l, tunnel_t *t, udpsock_t *uio,
                                    uint16_t real_localport)
{

    l->routing_context.src_ctx.type_ip   = true; // we have a client ip
    l->routing_context.src_ctx.proto_udp = true; // udp
    sockaddrToIpAddr((const sockaddr_u *) wioGetPeerAddr(uio->io), &(l->routing_context.src_ctx.ip_address));
    l->routing_context.src_ctx.port = real_localport;

    *ls = (udplistener_lstate_t){.line = l, .uio = uio, .tunnel = t, .read_paused = false};

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
    memorySet(ls, 0, sizeof(udplistener_lstate_t));
}
