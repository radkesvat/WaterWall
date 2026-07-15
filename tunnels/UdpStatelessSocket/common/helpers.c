#include "structure.h"

#include "loggers/network_logger.h"

#include "loggers/dns_logger.h"

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

static udpstatelesssocket_send_request_t *udpstatelesssocketSendRequestCreate(udpstatelesssocket_tstate_t *state)
{
    assert(state != NULL);
    assert(state->send_request_pools != NULL);
    assert(state->io_wid < getTotalWorkersCount());

    threadsafe_generic_pool_t *pool = state->send_request_pools[state->io_wid];
    assert(pool != NULL);

    udpstatelesssocket_send_request_t *request = (udpstatelesssocket_send_request_t *) threadsafegenericpoolGetItem(pool);
    *request = (udpstatelesssocket_send_request_t) {
        .pool = pool,
    };
    return request;
}

static void udpstatelesssocketSendRequestReuse(udpstatelesssocket_send_request_t *request)
{
    if (request == NULL)
    {
        return;
    }

    threadsafe_generic_pool_t *pool = request->pool;
    assert(pool != NULL);

    *request = (udpstatelesssocket_send_request_t) {0};
    threadsafegenericpoolReuseItem(pool, request);
}

local_idle_table_t *udpstatelesssocketGetWorkerIdleTable(udpstatelesssocket_tstate_t *ts)
{
    assert(ts != NULL);
    return udpsockGetWorkerIdleTable(&ts->socket);
}

local_idle_table_t *udpstatelesssocketGetLineIdleTable(udpstatelesssocket_tstate_t *ts, line_t *l)
{
    assert(l != NULL);
    assert(lineGetWID(l) == getWID());
    discard l;
    return udpstatelesssocketGetWorkerIdleTable(ts);
}

bool udpstatelesssocketLinestateOwnsLine(tunnel_t *t, line_t *l, udpstatelesssocket_lstate_t *ls)
{
    discard t;
    discard l;
    return ls != NULL && ls->idle_handle != NULL;
}

static bool udpstatelesssocketEndpointEquals(const sockaddr_u *left, const sockaddr_u *right)
{
    if (! sockaddrCmpIP(left, right))
    {
        return false;
    }

    sockaddr_u left_copy  = *left;
    sockaddr_u right_copy = *right;
    return sockaddrPort(&left_copy) == sockaddrPort(&right_copy);
}

static hash_t udpstatelesssocketPeerIdleKey(tunnel_t *t, const sockaddr_u *peer_addr, const sockaddr_u *local_addr)
{
    hash_t peeraddr_hash  = sockaddrCalcHashWithPort(peer_addr);
    hash_t localaddr_hash = sockaddrCalcHashWithPort(local_addr);
    hash_t tunnel_hash    = (hash_t) (uintptr_t) t;
    hash_t idle_key       = peeraddr_hash;

    idle_key ^= localaddr_hash + 0x9E3779B97F4A7C15ULL + (idle_key << 6) + (idle_key >> 2);
    idle_key ^= tunnel_hash + 0x9E3779B97F4A7C15ULL + (idle_key << 6) + (idle_key >> 2);
    return idle_key;
}

static bool udpstatelesssocketIdleLineMatchesPacket(const udpstatelesssocket_lstate_t *ls, tunnel_t *t,
                                                    const sockaddr_u *peer_addr, const sockaddr_u *local_addr)
{
    return ls != NULL && ls->tunnel == t && ls->line != NULL &&
           udpstatelesssocketEndpointEquals(&ls->peer_addr, peer_addr) &&
           udpstatelesssocketEndpointEquals(&ls->local_addr, local_addr);
}

static void udpstatelesssocketForwardPeerInit(tunnel_t *t, line_t *l, bool is_chain_end)
{
    if (is_chain_end)
    {
        tunnelPrevDownStreamInit(t, l);
        return;
    }

    tunnelNextUpStreamInit(t, l);
}

static void udpstatelesssocketForwardPeerPayload(tunnel_t *t, udpstatelesssocket_lstate_t *ls, sbuf_t *buf)
{
    line_t *line             = ls->line;
    bool    is_chain_end = ((udpstatelesssocket_tstate_t *) tunnelGetState(t))->is_chain_end;

    if (is_chain_end)
    {
        tunnelPrevDownStreamPayload(t, line, buf);
        return;
    }

    tunnelNextUpStreamPayload(t, line, buf);
}

static void udpstatelesssocketForwardPeerFinish(tunnel_t *t, line_t *l, bool is_chain_end)
{
    if (is_chain_end)
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tunnelNextUpStreamFinish(t, l);
}

static void udpstatelesssocketOnIdleConnectionExpire(local_idle_item_t *idle_udp)
{
    udpstatelesssocket_lstate_t *ls = idle_udp->userdata;
    assert(ls != NULL && ls->tunnel != NULL && ls->line != NULL);

    idle_udp->userdata = NULL;

    tunnel_t                    *t            = ls->tunnel;
    line_t                      *line         = ls->line;
    udpstatelesssocket_tstate_t *state        = tunnelGetState(t);
    bool                         is_chain_end = state->is_chain_end;

    ls->idle_handle = NULL;
    udpstatelesssocketLinestateDestroy(ls);
    udpstatelesssocketForwardPeerFinish(t, line, is_chain_end);
    lineDestroy(line);
}

void udpstatelesssocketCloseOwnedLineFromAdjacent(tunnel_t *t, line_t *l, bool is_chain_end)
{
    udpstatelesssocket_lstate_t *ls    = lineGetState(l, t);
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    if (! udpstatelesssocketLinestateOwnsLine(t, l, ls) || state->is_chain_end != is_chain_end)
    {
        return;
    }

    local_idle_item_t *idle = ls->idle_handle;

    if (idle != NULL)
    {
        bool deleted = localidletableRemoveIdleItemByHash(udpstatelesssocketGetLineIdleTable(state, l), idle->hash);
        if (! deleted)
        {
            LOGE("UdpStatelessSocket: failed to remove idle item for peer line");
            terminateProgram(1);
        }
        idle->userdata  = NULL;
        ls->idle_handle = NULL;
    }

    udpstatelesssocketLinestateDestroy(ls);
    lineDestroy(l);
}

static bool udpstatelesssocketGetLinePeerAddr(line_t *l, sockaddr_u *addr_out)
{
    address_context_t *dest_ctx = lineGetDestinationAddressContext(l);

    if (! addresscontextCanConvertToSockAddr(dest_ctx) || ! addresscontextHasPort(dest_ctx))
    {
        return false;
    }

    *addr_out = addresscontextToSockAddr(dest_ctx);
    return true;
}

static void udpstatelesssocketWriteOwnerPeer(tunnel_t *t, sbuf_t *buf, const sockaddr_u *peer_addr)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    assert(getWID() == state->io_wid);

    if (UNLIKELY(isApplicationTerminating() || state->socket.io == NULL))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return;
    }

    ssize_t nwrite;
    do
    {
        nwrite = sendto(wioGetFD(state->socket.io),
                        sbufGetRawPtr(buf),
                        (size_t) sbufGetLength(buf),
                        0,
                        &peer_addr->sa,
                        sockaddrLen((sockaddr_u *) peer_addr));
    } while (nwrite < 0 && socketERRNO() == EINTR);

    if (UNLIKELY(nwrite < 0))
    {
        const int err = socketERRNO();
        // EAGAIN/EWOULDBLOCK is a benign send-buffer-full drop for a stateless UDP socket; log it quietly.
        if (err == EAGAIN || err == EWOULDBLOCK)
        {
            if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
            {
                char peeraddrstr[SOCKADDR_STRLEN] = {0};
                LOGD("UdpStatelessSocket: dropped datagram to [%s]: %s",
                     SOCKADDR_STR(peer_addr, peeraddrstr),
                     socketStrError(err));
            }
        }
        else if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_ERROR))
        {
            char peeraddrstr[SOCKADDR_STRLEN] = {0};
            LOGE("UdpStatelessSocket: sendto failed for [%s]: %s",
                 SOCKADDR_STR(peer_addr, peeraddrstr),
                 socketStrError(err));
        }
    }
    else if (UNLIKELY((uint32_t) nwrite != sbufGetLength(buf)))
    {
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        LOGE("UdpStatelessSocket: short UDP datagram write to [%s]: %zd/%u bytes",
             SOCKADDR_STR(peer_addr, peeraddrstr),
             nwrite,
             sbufGetLength(buf));
    }

    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
}

static void udpstatelesssocketSendToPeer(tunnel_t *t, sbuf_t *buf, const sockaddr_u *peer_addr)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    if (UNLIKELY(isApplicationTerminating() || state->socket.io == NULL))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return;
    }

    if (getWID() == state->io_wid)
    {
        udpstatelesssocketWriteOwnerPeer(t, buf, peer_addr);
        return;
    }

    udpstatelesssocket_send_request_t *request = udpstatelesssocketSendRequestCreate(state);
    if (request == NULL)
    {
        LOGE("UdpStatelessSocket: failed to get cross-worker send request");
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return;
    }

    request->tunnel    = t;
    request->buf       = buf;
    request->peer_addr = *peer_addr;

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
    udpstatelesssocketSendRequestReuse(request);
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

    const sockaddr_u peer_addr  = *wioGetPeerAddrU(io);
    const sockaddr_u local_addr = *wioGetLocaladdrU(io);

    if (peer_addr.sa.sa_family == 0)
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

    if (state->verbose)
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        LOGD("UdpStatelessSocket: received %u bytes from [%s] <= [%s]",
             sbufGetLength(buf),
             SOCKADDR_STR(&local_addr, localaddrstr),
             SOCKADDR_STR(&peer_addr, peeraddrstr));
    }

    const bool          is_chain_end = state->is_chain_end;
    local_idle_table_t *table            = udpstatelesssocketGetWorkerIdleTable(state);
    hash_t              idle_key         = udpstatelesssocketPeerIdleKey(t, &peer_addr, &local_addr);

    local_idle_item_t *idle = localidletableGetIdleItemByHash(table, idle_key);
    if (idle != NULL)
    {
        udpstatelesssocket_lstate_t *existing = idle->userdata;
        if (! udpstatelesssocketIdleLineMatchesPacket(existing, t, &peer_addr, &local_addr))
        {
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
            return;
        }
    }

    if (idle == NULL)
    {
        idle = localidletableCreateItem(
            table, idle_key, NULL, udpstatelesssocketOnIdleConnectionExpire, kUdpStatelessSocketInitExpireTime);
        if (idle == NULL)
        {
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
            return;
        }

        line_t *l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);

        udpstatelesssocket_lstate_t *ls = lineGetState(l, t);
        udpstatelesssocketLinestateInitialize(ls, l, t, idle, &peer_addr, &local_addr);

        idle->userdata = ls;

        lineLock(l);
        udpstatelesssocketForwardPeerInit(t, l, is_chain_end);
        bool alive = lineIsAlive(l);
        lineUnlock(l);

        if (! alive)
        {
            LOGW("UdpStatelessSocket: peer line closed during init");
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
            return;
        }
    }
    else
    {
        localidletableKeepIdleItemForAtleast(table, idle, kUdpStatelessSocketKeepExpireTime);
    }

    udpstatelesssocket_lstate_t *ls = idle->userdata;
    if (ls == NULL)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    if (ls->read_paused)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    udpstatelesssocketForwardPeerPayload(t, ls, buf);
}

void udpstatelesssocketLocalThreadSocketUpStream(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;
    discard arg3;

    udpstatelesssocket_send_request_t *request = (udpstatelesssocket_send_request_t *) arg1;
    tunnel_t                    *t     = request->tunnel;
    sbuf_t                      *buf   = request->buf;
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    if (UNLIKELY(isApplicationTerminating() || state->socket.io == NULL))
    {
        udpstatelesssocketCleanupSendRequest(request, NULL, NULL);
        return;
    }

    request->buf = NULL;
    udpstatelesssocketWriteOwnerPeer(t, buf, &request->peer_addr);
    udpstatelesssocketSendRequestReuse(request);
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
        loggerPrint(getDnsLogger(), LOG_LEVEL_ERROR, "UdpStatelessSocket: failed to allocate async dns cache entry");
        return;
    }

    char *domain_copy = stringDuplicate(domain);
    if (domain_copy == NULL)
    {
        memoryFree(entry);
        mutexUnlock(&state->dns_cache_mutex);
        loggerPrint(getDnsLogger(), LOG_LEVEL_ERROR, "UdpStatelessSocket: failed to copy async dns cache domain");
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
        loggerPrint(getDnsLogger(),
                    LOG_LEVEL_ERROR,
                    "UdpStatelessSocket: async dns resolve failed for %s: %s",
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
        loggerPrint(getDnsLogger(),
                    LOG_LEVEL_ERROR,
                    "UdpStatelessSocket: async dns resolve returned no usable address for %s",
                    request->domain);
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        lineUnlock(line);
        udpstatelesssocketDnsRequestDestroy(request);
        return;
    }

    if (loggerCheckWriteLevel(getDnsLogger(), (log_level_e) LOG_LEVEL_DEBUG))
    {
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        loggerPrint(getDnsLogger(),
                    LOG_LEVEL_DEBUG,
                    "UdpStatelessSocket: %s resolved to [%s]",
                    request->domain,
                    SOCKADDR_STR(&peer_addr, peeraddrstr));
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
        loggerPrint(getDnsLogger(), LOG_LEVEL_ERROR, "UdpStatelessSocket: failed to allocate async dns request");
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return false;
    }

    char *domain_copy = stringDuplicate(dest_ctx->domain);
    if (domain_copy == NULL)
    {
        memoryFree(request);
        loggerPrint(getDnsLogger(), LOG_LEVEL_ERROR, "UdpStatelessSocket: failed to copy async dns domain");
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
        loggerPrint(getDnsLogger(),
                    LOG_LEVEL_ERROR,
                    "UdpStatelessSocket: failed to start async dns resolve for %s: %s",
                    request->domain,
                    ares_strerror(rc));
        udpstatelesssocketDnsRequestDestroy(request);
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return false;
    }

    return true;
}

void udpstatelesssocketTunnelWritePayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udpstatelesssocket_tstate_t *state    = tunnelGetState(t);
    address_context_t           *dest_ctx = lineGetDestinationAddressContext(l);

    udpstatelesssocket_lstate_t *ls = lineGetState(l, t);
    if (udpstatelesssocketLinestateOwnsLine(t, l, ls))
    {
        localidletableKeepIdleItemForAtleast(
            udpstatelesssocketGetLineIdleTable(state, l), ls->idle_handle, kUdpStatelessSocketKeepExpireTime);
        udpstatelesssocketSendToPeer(t, buf, &ls->peer_addr);
        return;
    }

    if (addresscontextIsDomain(dest_ctx) && ! addresscontextIsDomainResolved(dest_ctx))
    {
        if (addresscontextHasPort(dest_ctx))
        {
            sockaddr_u cached_addr;
            if (udpstatelesssocketDnsCacheLookup(
                    state, dest_ctx->domain, dest_ctx->port, dest_ctx->domain_strategy, &cached_addr))
            {
                if (loggerCheckWriteLevel(getDnsLogger(), (log_level_e) LOG_LEVEL_DEBUG))
                {
                    char peeraddrstr[SOCKADDR_STRLEN] = {0};
                    loggerPrint(getDnsLogger(),
                                LOG_LEVEL_DEBUG,
                                "UdpStatelessSocket: using cached async dns result for %s => [%s]",
                                dest_ctx->domain,
                                SOCKADDR_STR(&cached_addr, peeraddrstr));
                }
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

    if (state->verbose)
    {
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        LOGD("UdpStatelessSocket: %u bytes Packet to => [%s]", sbufGetLength(buf), SOCKADDR_STR(&addr, peeraddrstr));
    }

    udpstatelesssocketSendToPeer(t, buf, &addr);
}
