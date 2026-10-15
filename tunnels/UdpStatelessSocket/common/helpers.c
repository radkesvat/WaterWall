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

static void udpstatelesssocketCleanupSendRequest(void *arg1, void *arg2, void *arg3,
                                                 worker_message_cancel_reason_e reason);

static udpstatelesssocket_send_request_t *udpstatelesssocketSendRequestCreate(udpstatelesssocket_tstate_t *state,
                                                                              tunnel_t                    *tunnel)
{
    assert(state != NULL);
    assert(state->send_request_pools != NULL);
    assert(state->io_wid < getTotalWorkersCount());

    threadsafe_generic_pool_t *pool = state->send_request_pools[state->io_wid];
    assert(pool != NULL);

    udpstatelesssocket_send_request_t *request =
        (udpstatelesssocket_send_request_t *) threadsafegenericpoolGetItem(pool);
    *request = (udpstatelesssocket_send_request_t) {
        .pool   = pool,
        .tunnel = tunnel,
    };
    return request;
}

static void udpstatelesssocketSendRequestReuse(udpstatelesssocket_send_request_t *request)
{
    assert(request != NULL);

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
    assert(lineIsOnCurrentEventWorker(l));
    discard l;
    return udpstatelesssocketGetWorkerIdleTable(ts);
}

bool udpstatelesssocketLinestateOwnsLine(const udpstatelesssocket_lstate_t *ls)
{
    assert(ls != NULL);
    return ls->idle_handle != NULL;
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

static void udpstatelesssocketOnIdleConnectionExpire(local_idle_item_t *idle_udp)
{
    udpstatelesssocket_lstate_t *ls = idle_udp->userdata;
    assert(ls != NULL && ls->tunnel != NULL && ls->line != NULL);

    idle_udp->userdata = NULL;

    tunnel_t *t    = ls->tunnel;
    line_t   *line = ls->line;

    ls->idle_handle = NULL;
    udpstatelesssocketLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, line);
    lineDestroy(line);
}

void udpstatelesssocketCloseOwnedLineFromAdjacent(tunnel_t *t, line_t *l)
{
    udpstatelesssocket_lstate_t *ls    = lineGetState(l, t);
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    if (! udpstatelesssocketLinestateOwnsLine(ls))
    {
        // Borrowed transport/packet lines own no local resources and have no onward side to finish.
        return;
    }

    local_idle_item_t *idle = ls->idle_handle;

    idle->userdata  = NULL;
    ls->idle_handle = NULL;

    bool deleted = localidletableRemoveIdleItem(udpstatelesssocketGetLineIdleTable(state, l), idle);
    if (! deleted)
    {
        LOGF("UdpStatelessSocket: failed to remove idle item for peer line");
        abortProgramNow(1);
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

void udpstatelesssocketReleaseWrittenBuffer(sbuf_t *buf, bool detached_from_origin_worker)
{
    if (detached_from_origin_worker)
    {
        sbufDestroy(buf);
    }
    else
    {
        reuseBuffer(buf);
    }
}

void udpstatelesssocketOnSocketClose(wio_t *io)
{
    tunnel_t                    *t     = weventGetUserdata(io);
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    weventSetUserData(io, NULL);
    wioSetCallBackRead(io, NULL);
    wioSetCallBackClose(io, NULL);
    udpsockRetire(&state->socket);
}

static wio_t *udpstatelesssocketGetOwnerIo(udpstatelesssocket_tstate_t *state)
{
    assert(currentThreadIsEventWorkerWID(state->io_wid));
    return state->socket.io;
}

static void udpstatelesssocketWriteOwnerPeer(tunnel_t *t, sbuf_t *buf, const sockaddr_u *peer_addr,
                                             bool detached_from_origin_worker)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    wio_t                       *io    = udpstatelesssocketGetOwnerIo(state);

    if (UNLIKELY(io == NULL || ! wioIsOpened(io)))
    {
        udpstatelesssocketReleaseWrittenBuffer(buf, detached_from_origin_worker);
        return;
    }

    const uint32_t          length = sbufGetLength(buf);
    const udp_send_result_t result =
        udpSendBuffer(wioGetFD(io), wloopGetBufferPool(weventGetLoop(io)), buf, peer_addr, true);
    const int               nwrite = result.bytes;
    if (result.retire)
    {
        udpstatelesssocketReleaseWrittenBuffer(buf, detached_from_origin_worker);
        io->error = result.error;
        wioClose(io);
        return;
    }

    if (UNLIKELY(nwrite < 0))
    {
        const int err = result.error;
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
    else if (UNLIKELY((uint32_t) nwrite != length))
    {
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        LOGE("UdpStatelessSocket: short UDP datagram write to [%s]: %d/%u bytes",
             SOCKADDR_STR(peer_addr, peeraddrstr),
             nwrite,
             length);
    }

    udpstatelesssocketReleaseWrittenBuffer(buf, detached_from_origin_worker);
}

void udpstatelesssocketDispatchToPeer(tunnel_t *t, sbuf_t *buf, const sockaddr_u *peer_addr)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    // Writing inline is only legal on the socket's owning event worker; every
    // other caller hands the datagram to it as a worker message.
    if (currentThreadIsEventWorkerWID(state->io_wid))
    {
        udpstatelesssocketWriteOwnerPeer(t, buf, peer_addr, false);
        return;
    }

    udpstatelesssocket_send_request_t *request = udpstatelesssocketSendRequestCreate(state, t);
    request->buf                               = buf;
    request->peer_addr                         = *peer_addr;

    sendWorkerMessageWithCleanup(state->io_wid,
                                 udpstatelesssocketLocalThreadSocketUpStream,
                                 udpstatelesssocketCleanupSendRequest,
                                 request,
                                 NULL,
                                 NULL);
}

static void udpstatelesssocketCleanupSendRequest(void *arg1, void *arg2, void *arg3,
                                                 worker_message_cancel_reason_e reason)
{
    discard reason;
    discard arg2;
    discard arg3;

    udpstatelesssocket_send_request_t *request = (udpstatelesssocket_send_request_t *) arg1;
    // The message either runs or cancels; only the run path detaches the buffer.
    assert(request != NULL && request->buf != NULL);
    sbufDestroy(request->buf);
    request->buf = NULL;
    udpstatelesssocketSendRequestReuse(request);
}

static void udpstatelesssocketHandleRecvFrom(tunnel_t *t, wio_t *io, sbuf_t *buf, wid_t wid)
{
    udpstatelesssocket_tstate_t *state      = tunnelGetState(t);
    const sockaddr_u             peer_addr  = *wioGetPeerAddrU(io);
    const sockaddr_u             local_addr = *wioGetLocaladdrU(io);

    if (peer_addr.sa.sa_family == 0)
    {
        LOGF("UdpStatelessSocket: received a datagram without a peer address family");
        abortProgramNow(1);
    }

    if (UNLIKELY(wid != state->io_wid))
    {
        LOGF("UdpStatelessSocket: socket receive ran on worker %u instead of owner worker %u",
             (unsigned int) wid,
             (unsigned int) state->io_wid);
        abortProgramNow(1);
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

    local_idle_table_t *table        = udpstatelesssocketGetWorkerIdleTable(state);
    hash_t              idle_key     = udpstatelesssocketPeerIdleKey(t, &peer_addr, &local_addr);

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

        if (! lineCallWithRef(l, tunnelNextUpStreamInit, t))
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

    tunnelNextUpStreamPayload(t, ls->line, buf);
}

void udpstatelesssocketOnRecvFrom(wio_t *io, sbuf_t *buf)
{
    wid_t     wid = wloopGetWid(weventGetLoop(io));
    tunnel_t *t   = (tunnel_t *) weventGetUserdata(io);

    if (UNLIKELY(t == NULL || ! wioIsOpened(io)))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    udpstatelesssocketHandleRecvFrom(t, io, buf, wid);
}

void udpstatelesssocketLocalThreadSocketUpStream(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;
    discard arg3;

    udpstatelesssocket_send_request_t *request = (udpstatelesssocket_send_request_t *) arg1;
    tunnel_t                          *t       = request->tunnel;

    sbuf_t *buf  = request->buf;
    request->buf = NULL;
    udpstatelesssocketWriteOwnerPeer(t, buf, &request->peer_addr, true);
    udpstatelesssocketSendRequestReuse(request);
}

static bool udpstatelesssocketSockAddrFromResolved(const dns_resolved_addr_t *resolved, uint16_t port,
                                                   sockaddr_u *addr_out)
{
    assert(addr_out != NULL);
    if (resolved == NULL || (resolved->family != AF_INET && resolved->family != AF_INET6) ||
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
    assert(request != NULL);

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

bool udpstatelesssocketDnsCacheLookup(udpstatelesssocket_tstate_t *state, const char *domain, uint16_t port,
                                      int strategy, sockaddr_u *addr_out)
{
    assert(domain != NULL && addr_out != NULL);

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

static void udpstatelesssocketDnsCacheEntryDestroy(udpstatelesssocket_dns_cache_entry_t *entry)
{
    memoryFree(entry->domain);
    memoryFree(entry);
}

static void udpstatelesssocketDnsCacheReclaimExpiredLocked(udpstatelesssocket_tstate_t *state, unsigned int now_ms)
{
    udpstatelesssocket_dns_cache_entry_t **slot = &state->dns_cache;
    while (*slot != NULL)
    {
        udpstatelesssocket_dns_cache_entry_t *entry = *slot;
        if (udpstatelesssocketDnsCacheEntryIsFresh(entry, now_ms))
        {
            slot = &entry->next;
            continue;
        }

        *slot = entry->next;
        assert(state->dns_cache_count != 0);
        --state->dns_cache_count;
        udpstatelesssocketDnsCacheEntryDestroy(entry);
    }
}

static void udpstatelesssocketDnsCacheEvictOldestLocked(udpstatelesssocket_tstate_t *state)
{
    udpstatelesssocket_dns_cache_entry_t **slot = &state->dns_cache;
    assert(*slot != NULL); // Only called when the cache is at capacity, under its mutex.

    while ((*slot)->next != NULL)
    {
        slot = &(*slot)->next;
    }

    udpstatelesssocket_dns_cache_entry_t *oldest = *slot;
    *slot                                        = NULL;
    assert(state->dns_cache_count != 0);
    --state->dns_cache_count;
    udpstatelesssocketDnsCacheEntryDestroy(oldest);
}

void udpstatelesssocketDnsCacheStore(udpstatelesssocket_tstate_t *state, const char *domain, uint16_t port,
                                     int strategy, const sockaddr_u *peer_addr)
{
    assert(domain != NULL && peer_addr != NULL);

    mutexLock(&state->dns_cache_mutex);

    const unsigned int now_ms = getTickMS();
    udpstatelesssocketDnsCacheReclaimExpiredLocked(state, now_ms);

    for (udpstatelesssocket_dns_cache_entry_t *entry = state->dns_cache; entry != NULL; entry = entry->next)
    {
        if (udpstatelesssocketDnsCacheEntryMatches(entry, domain, port, strategy))
        {
            entry->peer_addr      = *peer_addr;
            entry->resolved_at_ms = now_ms;
            mutexUnlock(&state->dns_cache_mutex);
            return;
        }
    }

    if (state->dns_cache_count == kUdpStatelessSocketDnsCacheCapacity)
    {
        udpstatelesssocketDnsCacheEvictOldestLocked(state);
    }

    udpstatelesssocket_dns_cache_entry_t *entry       = memoryAllocate(sizeof(*entry));
    char                                 *domain_copy = stringDuplicate(domain);
    *entry = (udpstatelesssocket_dns_cache_entry_t) {
        .domain         = domain_copy,
        .port           = port,
        .strategy       = strategy,
        .peer_addr      = *peer_addr,
        .resolved_at_ms = now_ms,
        .next           = state->dns_cache,
    };
    state->dns_cache = entry;
    ++state->dns_cache_count;

    mutexUnlock(&state->dns_cache_mutex);
}

void udpstatelesssocketDnsCacheClear(udpstatelesssocket_tstate_t *state)
{
    mutexLock(&state->dns_cache_mutex);
    udpstatelesssocket_dns_cache_entry_t *entry = state->dns_cache;
    state->dns_cache                            = NULL;
    state->dns_cache_count                      = 0;
    mutexUnlock(&state->dns_cache_mutex);

    while (entry != NULL)
    {
        udpstatelesssocket_dns_cache_entry_t *next = entry->next;
        udpstatelesssocketDnsCacheEntryDestroy(entry);
        entry = next;
    }
}

static void udpstatelesssocketOnDnsResolved(void *userdata, int status, const char *error,
                                            const dns_resolved_addr_t *addrs, size_t naddrs)
{
    udpstatelesssocket_dns_request_t *request = userdata;
    line_t                           *line    = request->line;
    sbuf_t                           *buf     = request->buf;
    tunnel_t                         *t       = request->tunnel;

    if (asyncdnsStatusIsShutdown(status) || ! lineIsAlive(line))
    {
        /* The request's line reference preserves allocation memory, not its logical
         * life. DNS completion always runs on the submitting owner worker, so
         * recycle through that worker rather than reading a dead line. */
        bufferpoolReuseBuffer(getCurrentEventWorkerBufferPool(), buf);
        lineUnref(line);
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
        lineReuseBuffer(line, buf);
        lineUnref(line);
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
        lineReuseBuffer(line, buf);
        lineUnref(line);
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

    udpstatelesssocketDnsCacheStore(tunnelGetState(t), request->domain, request->port, request->strategy, &peer_addr);
    udpstatelesssocketDispatchToPeer(t, buf, &peer_addr);
    lineUnref(line);
    udpstatelesssocketDnsRequestDestroy(request);
}

static void udpstatelesssocketStartDnsResolve(tunnel_t *t, line_t *l, sbuf_t *buf, const address_context_t *dest_ctx)
{
    assert(addresscontextIsDomain(dest_ctx));
    if (! addresscontextHasPort(dest_ctx))
    {
        LOGE("UdpStatelessSocket: outbound destination domain or port is not ready");
        lineReuseBuffer(l, buf);
        return;
    }

    udpstatelesssocket_dns_request_t *request     = memoryAllocate(sizeof(*request));
    char                             *domain_copy = stringDuplicate(dest_ctx->domain);
    *request = (udpstatelesssocket_dns_request_t) {
        .tunnel   = t,
        .line     = l,
        .buf      = buf,
        .domain   = domain_copy,
        .port     = dest_ctx->port,
        .strategy = dest_ctx->domain_strategy,
    };

    lineRef(l);
    int rc = workerResolveDomainServiceAsync(
        lineGetWID(l), request->domain, NULL, SOCK_DGRAM, udpstatelesssocketOnDnsResolved, request);
    if (rc != ARES_SUCCESS)
    {
        lineUnref(l);
        loggerPrint(getDnsLogger(),
                    LOG_LEVEL_ERROR,
                    "UdpStatelessSocket: failed to start async dns resolve for %s: %s",
                    request->domain,
                    ares_strerror(rc));
        udpstatelesssocketDnsRequestDestroy(request);
        lineReuseBuffer(l, buf);
        return;
    }
}

void udpstatelesssocketTunnelWritePayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    if (udpsockIsRetired(&state->socket))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    address_context_t *dest_ctx = lineGetDestinationAddressContext(l);

    udpstatelesssocket_lstate_t *ls = lineGetState(l, t);
    if (udpstatelesssocketLinestateOwnsLine(ls))
    {
        localidletableKeepIdleItemForAtleast(
            udpstatelesssocketGetLineIdleTable(state, l), ls->idle_handle, kUdpStatelessSocketKeepExpireTime);
        udpstatelesssocketDispatchToPeer(t, buf, &ls->peer_addr);
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
                udpstatelesssocketDispatchToPeer(t, buf, &cached_addr);
                return;
            }
        }

        udpstatelesssocketStartDnsResolve(t, l, buf, dest_ctx);
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

    udpstatelesssocketDispatchToPeer(t, buf, &addr);
}
