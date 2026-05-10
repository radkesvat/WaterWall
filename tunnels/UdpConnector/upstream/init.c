#include "structure.h"

#include "loggers/network_logger.h"

static int createAndBindSocket(int family, bool reuse_addr)
{
    sockaddr_u host_addr = {0};

    const char *bind_address = family == AF_INET6 ? "::" : "0.0.0.0";

    if (family != AF_INET && family != AF_INET6)
    {
        LOGE("UdpConnector: unsupported socket family %d", family);
        return -1;
    }

    if (sockaddrSetIpAddressPort(&host_addr, bind_address, 0) != 0)
    {
        LOGE("UdpConnector: could not prepare bind address %s", bind_address);
        return -1;
    }

    int sockfd = socket(family, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        LOGE("UdpConnector: socket fd < 0");
        return -1;
    }
    int size   = 4 * 1024 * 1024; // 4MB
    int so_ret = socketOptionSendBuf(sockfd, size);
    if (so_ret != 0)
    {
        LOGE("UdpConnector: set socket send buffer failed, call: setsockopt , value: %d\n", so_ret);
        closesocket(sockfd);
        return -1;
    }
    so_ret = socketOptionRecvBuf(sockfd, size);
    if (so_ret != 0)
    {
        LOGE("UdpConnector: set socket recv buffer failed, call: setsockopt , value: %d\n", so_ret);
        closesocket(sockfd);
        return -1;
    }

    if (reuse_addr && socketOptionReuseAddr(sockfd, 1) != 0)
    {
        LOGE("UdpConnector: set socket reuseaddr failed");
        closesocket(sockfd);
        return -1;
    }

    if (bind(sockfd, &host_addr.sa, sockaddrLen(&host_addr)) < 0)
    {
        LOGE("UdpConnector: UDP bind failed;");
        closesocket(sockfd);
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
    address_context_t     *dest_ctx = lineGetDestinationAddressContext(l);
    address_context_t     *src_ctx  = lineGetSourceAddressContext(l);

    setupDestinationAddress(ts, dest_ctx, src_ctx);
    setupDestinationPort(ts, dest_ctx, src_ctx);

    if (! resolveDomainIfNeeded(dest_ctx))
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    if (! addresscontextCanConvertToSockAddr(dest_ctx) || ! addresscontextHasPort(dest_ctx))
    {
        LOGE("UdpConnector: destination address or port is not initialized");
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    sockaddr_u addr   = addresscontextToSockAddr(dest_ctx);
    int        family = addr.sa.sa_family;

    int sockfd = createAndBindSocket(family, ts->reuse_addr);
    if (sockfd < 0)
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    wloop_t *loop = getWorkerLoop(getWID());
    wio_t   *io   = wioGet(loop, sockfd);

    udpconnectorLinestateInitialize(ls, t, l, io);
    ls->peer_addr = addr;

    ls->idle_handle =
        idletableCreateItem(ts->idle_table, udpconnectorIdleKey(io), ls, udpconnectorOnIdleConnectionExpire,
                            lineGetWID(l), kUdpInitExpireTime);
    if (UNLIKELY(ls->idle_handle == NULL))
    {
        LOGE("UdpConnector: failed to register idle item for io id:%u FD:%x", wioGetID(io), wioGetFD(io));
        weventSetUserData(io, NULL);
        udpconnectorLinestateDestroy(ls);
        wioClose(io);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    wioSetCallBackClose(io, udpconnectorOnClose);
    wioSetCallBackRead(io, udpconnectorOnRecvFrom);
    wioSetPeerAddr(ls->io, &addr.sa, sockaddrLen(&addr));

    if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        LOGD("UdpConnector: Communication begin FD:%x [%s] => [%s]", wioGetFD(io),
             SOCKADDR_STR(wioGetLocaladdr(io), localaddrstr), SOCKADDR_STR(wioGetPeerAddr(io), peeraddrstr));
    }

    wioRead(io);
}
