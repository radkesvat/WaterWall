#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);

    udpconnector_lstate_t *ls = lineGetState(l, t);


    wloop_t   *loop      = getWorkerLoop(getWID());
    sockaddr_u host_addr = {0};
    sockaddrSetIpAddressPort(&host_addr, "0.0.0.0", 0);

    int sockfd = socket(host_addr.sa.sa_family, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        LOGE("UdpConnector: socket fd < 0");
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

#ifdef OS_UNIX
    socketOptionReuseAddr(sockfd, 1);
#endif
    sockaddr_u addr;


    if (bind(sockfd, &addr.sa, sockaddrLen(&addr)) < 0)
    {
        LOGE("UdpConnector: UDP bind failed;");
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    wio_t *io = wioGet(loop, sockfd);

    udpconnectorLinestateInitialize(ls, t, l, io);

    wioSetCallBackRead(io, udpconnectorOnRecvFrom);
    wioRead(io);

    address_context_t *dest_ctx = lineGetDestinationAddressContext(l);
    address_context_t *src_ctx  = lineGetSourceAddressContext(l);

    switch (ts->dest_addr_selected.status)
    {
    case kDvsFromSource:
        addresscontextAddrCopy(dest_ctx, src_ctx);
        break;
    case kDvsConstant:
        addresscontextAddrCopy(dest_ctx, &(ts->constant_dest_addr));
        break;
    default:
    case kDvsFromDest:
        
        break;
    }
    switch (ts->dest_port_selected.status)
    {
    case kDvsFromSource:
        addresscontextCopyPort(dest_ctx, src_ctx);
        break;
    case kDvsConstant:
        addresscontextCopyPort(dest_ctx, &(ts->constant_dest_addr));
        break;
    default:
    case kDvsFromDest:
        break;
    }

    if(addresscontextIsDomain(dest_ctx) && ! addresscontextIsDomainResolved(dest_ctx))
    {
        if (! resolveContextSync(dest_ctx))
        {
            udpconnectorLinestateDestroy(ls);
            tunnelPrevDownStreamFinish(t, l);
            return;
        }
    }

    wioSetReadTimeout(ls->io, kUdpKeepExpireTime);
    // sockaddr_set_ipport(&(dest->addr),"www.gstatic.com",80);
   
    addr = addresscontextToSockAddr(dest_ctx);
    wioSetPeerAddr(ls->io, &addr.sa, sockaddrLen(&addr));

}

