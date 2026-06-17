#include "structure.h"

#include "loggers/network_logger.h"

typedef struct udpstatelesssocket_send_request_s
{
    tunnel_t  *tunnel;
    sbuf_t    *buf;
    sockaddr_u peer_addr;
} udpstatelesssocket_send_request_t;

typedef struct udpstatelesssocket_dns_request_s
{
    tunnel_t *tunnel;
    line_t   *line;
    sbuf_t   *buf;
    char     *domain;
    uint16_t  port;
    int       strategy;
} udpstatelesssocket_dns_request_t;

static void udpstatelesssocketCleanupSendRequest(void *arg1, void *arg2, void *arg3);

static bool udpstatelesssocketSockAddrEquals(const sockaddr_u *lhs, const sockaddr_u *rhs)
{
    if (lhs == NULL || rhs == NULL || lhs->sa.sa_family != rhs->sa.sa_family)
    {
        return false;
    }

    switch (lhs->sa.sa_family)
    {
    case AF_INET:
        return lhs->sin.sin_port == rhs->sin.sin_port && lhs->sin.sin_addr.s_addr == rhs->sin.sin_addr.s_addr;
    case AF_INET6:
        return lhs->sin6.sin6_port == rhs->sin6.sin6_port && memoryCompare(lhs->sin6.sin6_addr.s6_addr,
                                                                           rhs->sin6.sin6_addr.s6_addr,
                                                                           sizeof(lhs->sin6.sin6_addr.s6_addr)) == 0;
    default:
        return false;
    }
}

static sockaddr_u udpstatelesssocketSockAddrFromContext(const address_context_t *context)
{
    sockaddr_u addr = {0};

    assert(context != NULL);
    assert(addresscontextCanConvertToSockAddr(context));

    if (context->ip_address.type == IPADDR_TYPE_V4)
    {
        addr.sin.sin_family      = AF_INET;
        addr.sin.sin_port        = htons(context->port);
        addr.sin.sin_addr.s_addr = context->ip_address.u_addr.ip4.addr;
        return addr;
    }

    if (context->ip_address.type == IPADDR_TYPE_V6)
    {
        addr.sin6.sin6_family = AF_INET6;
        addr.sin6.sin6_port   = htons(context->port);
        memoryCopy(&addr.sin6.sin6_addr.s6_addr, &context->ip_address.u_addr.ip6, sizeof(addr.sin6.sin6_addr.s6_addr));
        return addr;
    }

    assert(false);
    return addr;
}

static bool udpstatelesssocketGetLinePeerAddr(line_t *l, sockaddr_u *addr_out)
{
    address_context_t *dest_ctx = lineGetDestinationAddressContext(l);

    if (! addresscontextCanConvertToSockAddr(dest_ctx) || ! addresscontextHasPort(dest_ctx))
    {
        return false;
    }

    *addr_out = udpstatelesssocketSockAddrFromContext(dest_ctx);
    return true;
}

static void udpstatelesssocketWriteOwnerPeer(tunnel_t *t, sbuf_t *buf)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    assert(getWID() == state->io_wid);

    if (UNLIKELY(isApplicationTerminating() || state->io == NULL))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return;
    }

    if (state->cached_peer_valid)
    {
        if (! udpstatelesssocketSockAddrEquals(wioGetPeerAddrU(state->io), &state->cached_peer_addr))
        {
            wioSetPeerAddr(state->io, &state->cached_peer_addr.sa, (int) sockaddrLen(&state->cached_peer_addr));
        }
    }
    else if (wioGetPeerAddrU(state->io)->sa.sa_family == 0)
    {
        LOGE("UdpStatelessSocket: no owner-worker peer is available for this UDP send");
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return;
    }

    wioWrite(state->io, buf);
}

static void udpstatelesssocketSendToPeer(tunnel_t *t, sbuf_t *buf, const sockaddr_u *peer_addr)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    if (UNLIKELY(isApplicationTerminating() || state->io == NULL))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return;
    }

    if (getWID() == state->io_wid)
    {
        state->cached_peer_addr  = *peer_addr;
        state->cached_peer_valid = true;
        udpstatelesssocketWriteOwnerPeer(t, buf);
        return;
    }

    udpstatelesssocket_send_request_t *request = memoryAllocate(sizeof(*request));
    if (request == NULL)
    {
        LOGE("UdpStatelessSocket: failed to allocate cross-worker send request");
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return;
    }

    *request = (udpstatelesssocket_send_request_t) {
        .tunnel    = t,
        .buf       = buf,
        .peer_addr = *peer_addr,
    };

    sendWorkerMessageWithCleanup(state->io_wid,
                                 udpstatelesssocketLocalThreadSocketUpStream,
                                 udpstatelesssocketCleanupSendRequest,
                                 request,
                                 NULL,
                                 NULL);
}

static void udpstatelesssocketCleanupSendRequest(void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    udpstatelesssocket_send_request_t *request = (udpstatelesssocket_send_request_t *) arg1;
    if (request == NULL)
    {
        return;
    }

    if (request->buf != NULL)
    {
        sbufDestroy(request->buf);
        request->buf = NULL;
    }
    memoryFree(request);
}

void udpstatelesssocketOnRecvFrom(wio_t *io, sbuf_t *buf)
{
    tunnel_t                    *t   = (tunnel_t *) (weventGetUserdata(io));
    wid_t                        wid = wloopGetWid(weventGetLoop(io));
    udpstatelesssocket_tstate_t *state;

    if (UNLIKELY(t == NULL))
    {
        assert(false);
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    if (UNLIKELY(isApplicationTerminating()))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    if (wioGetPeerAddrU(io)->sa.sa_family == 0)
    {
        assert(false);
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    state = tunnelGetState(t);

    if (UNLIKELY(wid != state->io_wid))
    {
        assert(false);
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    line_t *l = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), state->io_wid);

    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};

    LOGD("UdpStatelessSocket: received %u bytes from [%s] <= [%s]",
         sbufGetLength(buf),
         SOCKADDR_STR(wioGetLocaladdrU(io), localaddrstr),
         SOCKADDR_STR(wioGetPeerAddrU(io), peeraddrstr));

    addresscontextFromSockAddrWithProtocol(&l->routing_context.src_ctx, wioGetPeerAddrU(io), IP_PROTO_UDP);
    l->routing_context.local_listener_port = sockaddrPort(wioGetLocaladdrU(io));

#ifdef DEBUG
    lineLock(l);
#endif

    state->WriteReceivedPacket(state->write_tunnel, l, buf);

#ifdef DEBUG
    if (! lineIsAlive(l))
    {
        LOGF("UdpStatelessSocket: line is not alive, rule of packet tunnels is violated");
        terminateProgram(1);
    }

    lineUnlock(l);
#endif
}

void udpstatelesssocketLocalThreadSocketUpStream(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;
    discard arg3;

    udpstatelesssocket_send_request_t *request = (udpstatelesssocket_send_request_t *) arg1;
    tunnel_t                          *t       = request->tunnel;
    sbuf_t                            *buf     = request->buf;
    udpstatelesssocket_tstate_t       *state   = tunnelGetState(t);

    if (UNLIKELY(isApplicationTerminating() || state->io == NULL))
    {
        udpstatelesssocketCleanupSendRequest(request, NULL, NULL);
        return;
    }

    state->cached_peer_addr  = request->peer_addr;
    state->cached_peer_valid = true;

    udpstatelesssocketWriteOwnerPeer(t, buf);
    memoryFree(request);
}

static bool udpstatelesssocketSockAddrFromResolved(const dns_resolved_addr_t *resolved, uint16_t port,
                                                   sockaddr_u *addr_out)
{
    if (resolved == NULL || addr_out == NULL || (resolved->family != AF_INET && resolved->family != AF_INET6) ||
        (uintmax_t) resolved->addrlen > (uintmax_t) sizeof(*addr_out))
    {
        return false;
    }

    memoryZero(addr_out, sizeof(*addr_out));
    memoryCopy(addr_out, &resolved->addr, (size_t) resolved->addrlen);

    switch (addr_out->sa.sa_family)
    {
    case AF_INET:
        addr_out->sin.sin_port = htons(port);
        return true;
    case AF_INET6:
        addr_out->sin6.sin6_port = htons(port);
        return true;
    default:
        return false;
    }
}

static void udpstatelesssocketDnsRequestDestroy(udpstatelesssocket_dns_request_t *request)
{
    if (request == NULL)
    {
        return;
    }

    memoryFree(request->domain);
    memoryFree(request);
}

static bool udpstatelesssocketDnsCacheEntryMatches(const udpstatelesssocket_dns_cache_entry_t *entry,
                                                   const char *domain, uint16_t port, int strategy)
{
    return entry->port == port && entry->strategy == strategy && stringCompare(entry->domain, domain) == 0;
}

static bool udpstatelesssocketDnsCacheEntryIsFresh(const udpstatelesssocket_dns_cache_entry_t *entry,
                                                   unsigned int                                now_ms)
{
    return (unsigned int) (now_ms - entry->resolved_at_ms) < (unsigned int) kUdpStatelessSocketDnsRefreshIntervalMs;
}

static bool udpstatelesssocketDnsCacheLookup(udpstatelesssocket_tstate_t *state, const char *domain, uint16_t port,
                                             int strategy, sockaddr_u *addr_out)
{
    if (domain == NULL)
    {
        return false;
    }

    bool found = false;

    mutexLock(&state->dns_cache_mutex);

    const unsigned int now_ms = getTickMS();
    for (udpstatelesssocket_dns_cache_entry_t *entry = state->dns_cache; entry != NULL; entry = entry->next)
    {
        if (udpstatelesssocketDnsCacheEntryMatches(entry, domain, port, strategy) &&
            udpstatelesssocketDnsCacheEntryIsFresh(entry, now_ms))
        {
            *addr_out = entry->peer_addr;
            found     = true;
            break;
        }
    }

    mutexUnlock(&state->dns_cache_mutex);

    return found;
}

static void udpstatelesssocketDnsCacheStore(udpstatelesssocket_tstate_t *state, const char *domain, uint16_t port,
                                            int strategy, const sockaddr_u *peer_addr)
{
    if (domain == NULL || peer_addr == NULL)
    {
        return;
    }

    mutexLock(&state->dns_cache_mutex);

    for (udpstatelesssocket_dns_cache_entry_t *entry = state->dns_cache; entry != NULL; entry = entry->next)
    {
        if (udpstatelesssocketDnsCacheEntryMatches(entry, domain, port, strategy))
        {
            entry->peer_addr      = *peer_addr;
            entry->resolved_at_ms = getTickMS();
            mutexUnlock(&state->dns_cache_mutex);
            return;
        }
    }

    udpstatelesssocket_dns_cache_entry_t *entry = memoryAllocate(sizeof(*entry));
    if (entry == NULL)
    {
        mutexUnlock(&state->dns_cache_mutex);
        LOGE("UdpStatelessSocket: failed to allocate async dns cache entry");
        return;
    }

    char *domain_copy = stringDuplicate(domain);
    if (domain_copy == NULL)
    {
        memoryFree(entry);
        mutexUnlock(&state->dns_cache_mutex);
        LOGE("UdpStatelessSocket: failed to copy async dns cache domain");
        return;
    }

    *entry = (udpstatelesssocket_dns_cache_entry_t) {
        .domain         = domain_copy,
        .port           = port,
        .strategy       = strategy,
        .peer_addr      = *peer_addr,
        .resolved_at_ms = getTickMS(),
        .next           = state->dns_cache,
    };
    state->dns_cache = entry;

    mutexUnlock(&state->dns_cache_mutex);
}

static void udpstatelesssocketOnDnsResolved(void *userdata, int status, const char *error,
                                            const dns_resolved_addr_t *addrs, size_t naddrs)
{
    udpstatelesssocket_dns_request_t *request = userdata;
    line_t                           *line    = request->line;
    sbuf_t                           *buf     = request->buf;

    if (asyncdnsStatusIsShutdown(status) || ! lineIsAlive(line))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        lineUnlock(line);
        udpstatelesssocketDnsRequestDestroy(request);
        return;
    }

    if (status != ARES_SUCCESS || naddrs == 0)
    {
        LOGE("UdpStatelessSocket: async dns resolve failed for %s: %s",
             request->domain,
             error != NULL ? error : ares_strerror(status));
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        lineUnlock(line);
        udpstatelesssocketDnsRequestDestroy(request);
        return;
    }

    const dns_resolved_addr_t *selected =
        dnsstrategySelectResolvedAddress(addrs, naddrs, (enum domain_strategy) request->strategy);

    sockaddr_u peer_addr;
    if (! udpstatelesssocketSockAddrFromResolved(selected, request->port, &peer_addr))
    {
        LOGE("UdpStatelessSocket: async dns resolve returned no usable address for %s", request->domain);
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        lineUnlock(line);
        udpstatelesssocketDnsRequestDestroy(request);
        return;
    }

    {
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        LOGD("UdpStatelessSocket: %s resolved to [%s]", request->domain, SOCKADDR_STR(&peer_addr, peeraddrstr));
    }

    udpstatelesssocketDnsCacheStore(
        tunnelGetState(request->tunnel), request->domain, request->port, request->strategy, &peer_addr);
    udpstatelesssocketSendToPeer(request->tunnel, buf, &peer_addr);
    lineUnlock(line);
    udpstatelesssocketDnsRequestDestroy(request);
}

static bool udpstatelesssocketStartDnsResolve(tunnel_t *t, line_t *l, sbuf_t *buf, const address_context_t *dest_ctx)
{
    if (dest_ctx->domain == NULL || ! addresscontextHasPort(dest_ctx))
    {
        LOGE("UdpStatelessSocket: outbound destination domain or port is not ready");
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return false;
    }

    udpstatelesssocket_dns_request_t *request = memoryAllocate(sizeof(*request));
    if (request == NULL)
    {
        LOGE("UdpStatelessSocket: failed to allocate async dns request");
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return false;
    }

    char *domain_copy = stringDuplicate(dest_ctx->domain);
    if (domain_copy == NULL)
    {
        memoryFree(request);
        LOGE("UdpStatelessSocket: failed to copy async dns domain");
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return false;
    }

    *request = (udpstatelesssocket_dns_request_t) {
        .tunnel   = t,
        .line     = l,
        .buf      = buf,
        .domain   = domain_copy,
        .port     = dest_ctx->port,
        .strategy = dest_ctx->domain_strategy,
    };

    lineLock(l);
    int rc = workerResolveDomainServiceAsync(
        lineGetWID(l), request->domain, NULL, SOCK_DGRAM, udpstatelesssocketOnDnsResolved, request);
    if (rc != ARES_SUCCESS)
    {
        lineUnlock(l);
        LOGE("UdpStatelessSocket: failed to start async dns resolve for %s: %s", request->domain, ares_strerror(rc));
        udpstatelesssocketDnsRequestDestroy(request);
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return false;
    }

    return true;
}

void udpstatelesssocketTunnelWritePayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    address_context_t *dest_ctx = lineGetDestinationAddressContext(l);

    if (addresscontextIsDomain(dest_ctx) && ! addresscontextIsDomainResolved(dest_ctx))
    {
        if (addresscontextHasPort(dest_ctx))
        {
            sockaddr_u                   cached_addr;
            udpstatelesssocket_tstate_t *state = tunnelGetState(t);
            if (udpstatelesssocketDnsCacheLookup(
                    state, dest_ctx->domain, dest_ctx->port, dest_ctx->domain_strategy, &cached_addr))
            {
                char peeraddrstr[SOCKADDR_STRLEN] = {0};
                LOGD("UdpStatelessSocket: using cached async dns result for %s => [%s]",
                     dest_ctx->domain,
                     SOCKADDR_STR(&cached_addr, peeraddrstr));
                udpstatelesssocketSendToPeer(t, buf, &cached_addr);
                return;
            }
        }

        discard udpstatelesssocketStartDnsResolve(t, l, buf, dest_ctx);
        return;
    }

    sockaddr_u addr;
    if (! udpstatelesssocketGetLinePeerAddr(l, &addr))
    {
        LOGE("UdpStatelessSocket: outbound destination address is not ready");
        lineReuseBuffer(l, buf);
        return;
    }

    {
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        LOGD("UdpStatelessSocket: %u bytes Packet to => [%s]", sbufGetLength(buf), SOCKADDR_STR(&addr, peeraddrstr));
    }

    udpstatelesssocketSendToPeer(t, buf, &addr);
}
