#include "structure.h"

#include "loggers/network_logger.h"

static int createAndBindSocket(void)
{
    sockaddr_u host_addr = {0};
    sockaddrSetIpAddressPort(&host_addr, "0.0.0.0", 0);

    int sockfd = socket(host_addr.sa.sa_family, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        LOGE("UdpConnector: socket fd < 0");
        return -1;
    }

#ifdef OS_UNIX
    socketOptionReuseAddr(sockfd, 1);
#endif

    if (bind(sockfd, &host_addr.sa, sockaddrLen(&host_addr)) < 0)
    {
        LOGE("UdpConnector: UDP bind failed;");
        return -1;
    }

    return sockfd;
}

static void setupDestinationAddress(udpconnector_tstate_t *ts, address_context_t *dest_ctx, address_context_t *src_ctx)
{
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
}

static void setupDestinationPort(udpconnector_tstate_t *ts, address_context_t *dest_ctx, address_context_t *src_ctx)
{
    switch (ts->dest_port_selected.status)
    {
    case kDvsFromSource:
        addresscontextCopyPort(dest_ctx, src_ctx);
        break;
    case kDvsConstant:
        addresscontextCopyPort(dest_ctx, &(ts->constant_dest_addr));
        break;
    case kDvsRandom:
        addresscontextSetPort(dest_ctx, (fastRand() % (ts->random_dest_port_y - ts->random_dest_port_x + 1)) +
                                            ts->random_dest_port_x);
        break;
    default:
    case kDvsFromDest:
        break;
    }
}

static bool resolveDomainIfNeeded(address_context_t *dest_ctx)
{
    if (addresscontextIsDomain(dest_ctx) && ! addresscontextIsDomainResolved(dest_ctx))
    {
        return resolveContextSync(dest_ctx);
    }
    return true;
}

void udpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);
    udpconnector_lstate_t *ls = lineGetState(l, t);

    int sockfd = createAndBindSocket();
    if (sockfd < 0)
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    wloop_t *loop = getWorkerLoop(getWID());
    wio_t *io = wioGet(loop, sockfd);

    udpconnectorLinestateInitialize(ls, t, l, io);

     ls->idle_handle = idletableCreateItem(ts->idle_table, (hash_t) (wioGetFD(io)), ls, udpconnectorOnIdleConnectionExpire,
                                  lineGetWID(l), kUdpInitExpireTime);

    while (ls->idle_handle == NULL)
    {
        // a very rare case where the socket FD from another thread is still present in the idle table
        cycleDelay(100);
        ls->idle_handle = idletableCreateItem(ts->idle_table, (hash_t) (wioGetFD(io)), ls, udpconnectorOnIdleConnectionExpire,
                                      lineGetWID(l), kUdpInitExpireTime);
    }
    
    wioSetCallBackRead(io, udpconnectorOnRecvFrom);
    wioRead(io);

    address_context_t *dest_ctx = lineGetDestinationAddressContext(l);
    address_context_t *src_ctx  = lineGetSourceAddressContext(l);

    setupDestinationAddress(ts, dest_ctx, src_ctx);
    setupDestinationPort(ts, dest_ctx, src_ctx);

    if (!resolveDomainIfNeeded(dest_ctx))
    {
        udpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    sockaddr_u addr = addresscontextToSockAddr(dest_ctx);
    wioSetPeerAddr(ls->io, &addr.sa, sockaddrLen(&addr));

    if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        LOGD("UdpConnector: Communication begin FD:%x [%s] => [%s]", wioGetFD(io),
             SOCKADDR_STR(wioGetLocaladdr(io), localaddrstr),
             SOCKADDR_STR(wioGetPeerAddr(io), peeraddrstr));
    }

}
