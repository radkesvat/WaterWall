#include "structure.h"

#include "loggers/network_logger.h"

#if defined(UDPCONNECTOR_POOL_TEST_HOOKS)
bool g_udpconnector_pool_test_force_hash_zero        = false;
bool g_udpconnector_pool_test_fail_socket_alloc      = false;
bool g_udpconnector_pool_test_fail_binding_alloc     = false;
bool g_udpconnector_pool_test_fail_socket_map_insert = false;
bool g_udpconnector_pool_test_fail_line_map_insert   = false;
#endif

static const char *getSourceBindIp(const udpconnector_tstate_t *ts, char *interface_ip, size_t interface_ip_len)
{
    if (ts->source_ip != NULL)
    {
        return ts->source_ip;
    }

    if (ts->interface_name == NULL || socketOptionBindToDeviceSupported())
    {
        return NULL;
    }

    if (! getInterfaceIpString(ts->interface_name, interface_ip, interface_ip_len))
    {
        LOGE("UdpConnector: could not get interface \"%s\" ip", ts->interface_name);
        return NULL;
    }

    return interface_ip;
}

static int createAndBindSocket(int family, const udpconnector_tstate_t *ts)
{
    sockaddr_u  host_addr                     = {0};
    char        interface_ip[INET_ADDRSTRLEN] = {0};
    const char *bind_address                  = getSourceBindIp(ts, interface_ip, sizeof(interface_ip));

    if (family != AF_INET && family != AF_INET6)
    {
        LOGE("UdpConnector: unsupported socket family %d", family);
        return -1;
    }

    if (bind_address == NULL)
    {
        if (ts->source_ip == NULL && ts->interface_name != NULL && ! socketOptionBindToDeviceSupported())
        {
            return -1;
        }
        bind_address = family == AF_INET6 ? "::" : "0.0.0.0";
    }

    if (sockaddrSetIpAddressPort(&host_addr, bind_address, 0) != 0)
    {
        LOGE("UdpConnector: could not prepare bind address %s", bind_address);
        return -1;
    }
    if (host_addr.sa.sa_family != family)
    {
        LOGE("UdpConnector: source-ip address family does not match destination address family");
        return -1;
    }

    int sockfd = socketToFd(socket(family, SOCK_DGRAM, 0));
    if (sockfd < 0)
    {
        LOGE("UdpConnector: socket fd < 0");
        return -1;
    }
    if (! socketOptionApplySendBuffer(sockfd, ts->send_buffer_size))
    {
        LOGE("UdpConnector: set socket send buffer failed");
        closesocket(sockfd);
        return -1;
    }
    if (! socketOptionApplyRecvBuffer(sockfd, ts->recv_buffer_size))
    {
        LOGE("UdpConnector: set socket recv buffer failed");
        closesocket(sockfd);
        return -1;
    }

    if (socketOptionBindToDevice(sockfd, ts->interface_name) != 0)
    {
        LOGE("UdpConnector: setsockopt SO_BINDTODEVICE error");
        closesocket(sockfd);
        return -1;
    }

    if (egressPinApply(sockfd, family, ts->interface_name) != 0)
    {
        LOGE("UdpConnector: egress pin failed");
        closesocket(sockfd);
        return -1;
    }

    if (ts->fwmark >= 0 && socketOptionSetFwMark(sockfd, ts->fwmark) != 0)
    {
        LOGE("UdpConnector: setsockopt SO_MARK error");
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

udpconnector_worker_pool_t *udpconnectorGetLineWorkerPool(udpconnector_tstate_t *ts, line_t *l)
{
    assert(ts != NULL);
    assert(ts->worker_pools != NULL);
    assert(l != NULL);
    assert(lineIsOnCurrentEventWorker(l));

    const wid_t wid = lineGetWID(l);
    assert(wid < getWorkersCount());
    assert(ts->worker_pools[wid].wid == wid);
    return &ts->worker_pools[wid];
}

static udpconnector_pool_socket_t **udpconnectorPoolSocketList(udpconnector_worker_pool_t *pool, int family)
{
    assert(family == AF_INET || family == AF_INET6);
    return family == AF_INET ? &pool->v4_sockets : &pool->v6_sockets;
}

static uint32_t *udpconnectorPoolSocketCount(udpconnector_worker_pool_t *pool, int family)
{
    assert(family == AF_INET || family == AF_INET6);
    return family == AF_INET ? &pool->v4_sockets_count : &pool->v6_sockets_count;
}

static void udpconnectorPoolSocketLink(udpconnector_pool_socket_t *sock)
{
    udpconnector_worker_pool_t  *pool  = sock->worker_pool;
    udpconnector_pool_socket_t **head  = udpconnectorPoolSocketList(pool, sock->family);
    uint32_t                    *count = udpconnectorPoolSocketCount(pool, sock->family);

    assert(! sock->linked);
    sock->prev = NULL;
    sock->next = *head;
    if (*head != NULL)
    {
        (*head)->prev = sock;
    }
    *head        = sock;
    sock->linked = true;
    ++*count;
}

static void udpconnectorPoolSocketUnlink(udpconnector_pool_socket_t *sock)
{
    udpconnector_worker_pool_t  *pool  = sock->worker_pool;
    udpconnector_pool_socket_t **head  = udpconnectorPoolSocketList(pool, sock->family);
    uint32_t                    *count = udpconnectorPoolSocketCount(pool, sock->family);

    assert(sock->linked && *count > 0);

    if (sock->prev != NULL)
    {
        assert(sock->prev->next == sock);
        sock->prev->next = sock->next;
    }
    else
    {
        assert(*head == sock);
        *head = sock->next;
    }

    if (sock->next != NULL)
    {
        assert(sock->next->prev == sock);
        sock->next->prev = sock->prev;
    }

    sock->prev   = NULL;
    sock->next   = NULL;
    sock->linked = false;
    --*count;
}

udpconnector_pool_socket_t *udpconnectorPoolSocketCreate(tunnel_t *t, udpconnector_worker_pool_t *pool, int family)
{
    assert(pool != NULL);
    assert(currentThreadIsEventWorkerWID(pool->wid));

#if defined(UDPCONNECTOR_POOL_TEST_HOOKS)
    if (g_udpconnector_pool_test_fail_socket_alloc)
    {
        return NULL;
    }
#endif

    udpconnector_tstate_t *ts = tunnelGetState(t);

    udpconnector_pool_socket_t *sock = memoryAllocateZero(sizeof(*sock));
    if (UNLIKELY(sock == NULL))
    {
        return NULL;
    }

    sock->tunnel      = t;
    sock->worker_pool = pool;
    sock->wid         = pool->wid;
    sock->family      = family;
    sock->state       = kUdpConnectorPoolSocketAccepting;
    sock->peer_map    = udpconnector_peer_binding_map_init();

    int sockfd = createAndBindSocket(family, ts);
    if (sockfd < 0)
    {
        udpconnector_peer_binding_map_drop(&sock->peer_map);
        memoryFree(sock);
        return NULL;
    }

    wloop_t *loop = getCurrentEventWorkerLoop();
    wio_t   *io   = wioGet(loop, sockfd);
    if (UNLIKELY(io == NULL || wioIsClosed(io)))
    {
        if (io == NULL)
        {
            closesocket(sockfd);
        }
        udpconnector_peer_binding_map_drop(&sock->peer_map);
        memoryFree(sock);
        return NULL;
    }

    sock->io = io;

    weventSetUserData(io, sock);
    wioSetCallBackRead(io, udpconnectorOnSocketRecvFrom);

    const int read_result = wioRead(io);

    if (UNLIKELY(read_result != 0))
    {
        weventSetUserData(io, NULL);
        wioSetCallBackRead(io, NULL);
        wioClose(io);
        udpconnector_peer_binding_map_drop(&sock->peer_map);
        memoryFree(sock);
        return NULL;
    }

    /* Event dispatch cannot interleave on this worker before the current
     * callback returns. Install close ownership only after read arming has
     * succeeded, then publish the fully usable socket in the pool registry. */
    wioSetCallBackClose(io, udpconnectorOnSocketClose);
    udpconnectorPoolSocketLink(sock);

    return sock;
}

void udpconnectorPoolSocketRetire(udpconnector_pool_socket_t *sock)
{
    assert(currentThreadIsEventWorkerWID(sock->wid));

    assert(sock->active_bindings_count == 0);
    assert(udpconnector_peer_binding_map_size(&sock->peer_map) == 0);

    udpconnectorPoolSocketUnlink(sock);
    sock->state = kUdpConnectorPoolSocketClosing;

    if (sock->io != NULL)
    {
        weventSetUserData(sock->io, NULL);
        wioSetCallBackClose(sock->io, NULL);
        wioSetCallBackRead(sock->io, NULL);
        wioClose(sock->io);
        sock->io = NULL;
    }

    udpconnector_peer_binding_map_drop(&sock->peer_map);
    memoryFree(sock);
}

static bool udpconnectorSocketMapInsert(udpconnector_pool_socket_t *sock, udpconnector_peer_key_t key,
                                        udpconnector_binding_t *binding)
{
#if defined(UDPCONNECTOR_POOL_TEST_HOOKS)
    if (g_udpconnector_pool_test_fail_socket_map_insert)
    {
        return false;
    }
#endif

    const udpconnector_peer_binding_map_result inserted =
        udpconnector_peer_binding_map_insert(&sock->peer_map, key, binding);
    if (inserted.ref == NULL)
    {
        return false;
    }
    assert(inserted.inserted);
    return inserted.inserted;
}

static bool udpconnectorLineMapInsert(udpconnector_lstate_t *ls, udpconnector_peer_key_t key,
                                      udpconnector_binding_t *binding)
{
#if defined(UDPCONNECTOR_POOL_TEST_HOOKS)
    if (g_udpconnector_pool_test_fail_line_map_insert)
    {
        return false;
    }
#endif

    const udpconnector_peer_binding_map_result inserted =
        udpconnector_peer_binding_map_insert(&ls->peer_bindings, key, binding);
    if (inserted.ref == NULL)
    {
        return false;
    }
    assert(inserted.inserted);
    return inserted.inserted;
}

static void udpconnectorBindingMapErase(udpconnector_peer_binding_map_t *map, udpconnector_peer_key_t key,
                                        const udpconnector_binding_t *binding)
{
    const udpconnector_peer_binding_map_value *value = udpconnector_peer_binding_map_get(map, key);
    const bool                                 consistent =
        value != NULL && value->second == binding && udpconnector_peer_binding_map_erase(map, key) == 1;
    if (UNLIKELY(! consistent))
    {
        LOGF("UdpConnector: peer-binding map disagrees with published binding ownership");
        abortProgramNow(1);
    }
}

udpconnector_binding_t *udpconnectorAcquireBinding(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls,
                                                   const sockaddr_u *peer_addr)
{
    assert(peer_addr != NULL);
    assert(peer_addr->sa.sa_family == AF_INET || peer_addr->sa.sa_family == AF_INET6);
    udpconnector_tstate_t  *ts  = tunnelGetState(t);
    udpconnector_peer_key_t key = udpconnectorPeerKeyFromSockAddr(peer_addr);

    if (ls->fixed_binding != NULL)
    {
        assert(udpconnectorPeerKeyEquals(&ls->fixed_binding->peer_key, &key));
        if (! udpconnectorPeerKeyEquals(&ls->fixed_binding->peer_key, &key))
        {
            return NULL;
        }
        return ls->fixed_binding;
    }

    const udpconnector_peer_binding_map_value *line_binding =
        udpconnector_peer_binding_map_get(&ls->peer_bindings, key);
    if (line_binding != NULL)
    {
        assert(line_binding->second != NULL && line_binding->second->active);
        return line_binding->second;
    }

    udpconnector_worker_pool_t *worker_pool = udpconnectorGetLineWorkerPool(ts, l);
    if (worker_pool->quiescing)
    {
        return NULL;
    }

    udpconnector_pool_socket_t *sock_list = *udpconnectorPoolSocketList(worker_pool, key.family);
    udpconnector_pool_socket_t *candidate = NULL;

    for (udpconnector_pool_socket_t *curr = sock_list; curr != NULL; curr = curr->next)
    {
        if (curr->state != kUdpConnectorPoolSocketAccepting)
        {
            continue;
        }

        if (! udpconnector_peer_binding_map_contains(&curr->peer_map, key))
        {
            candidate = curr;
            break;
        }
    }

    if (candidate == NULL)
    {
        candidate = udpconnectorPoolSocketCreate(t, worker_pool, key.family);
        if (candidate == NULL)
        {
            return NULL;
        }
    }

#if defined(UDPCONNECTOR_POOL_TEST_HOOKS)
    if (g_udpconnector_pool_test_fail_binding_alloc)
    {
        if (candidate->active_bindings_count == 0)
        {
            udpconnectorPoolSocketRetire(candidate);
        }
        return NULL;
    }
#endif

    udpconnector_binding_t *binding = memoryAllocateZero(sizeof(*binding));
    if (UNLIKELY(binding == NULL))
    {
        if (candidate->active_bindings_count == 0)
        {
            udpconnectorPoolSocketRetire(candidate);
        }
        return NULL;
    }

    binding->socket    = candidate;
    binding->peer_key  = key;
    binding->peer_addr = *peer_addr;
    binding->line      = l;
    binding->ls        = ls;

    if (! udpconnectorSocketMapInsert(candidate, key, binding))
    {
        memoryFree(binding);
        if (candidate->active_bindings_count == 0)
        {
            udpconnectorPoolSocketRetire(candidate);
        }
        return NULL;
    }

    const bool fixed = ts->balance_mode == kUdpConnectorBalanceModeConnection || ls->route_destination_pinned;
    if (! fixed && ! udpconnectorLineMapInsert(ls, key, binding))
    {
        const int erased = udpconnector_peer_binding_map_erase(&candidate->peer_map, key);
        assert(erased == 1);
        discard erased;
        memoryFree(binding);
        if (candidate->active_bindings_count == 0)
        {
            udpconnectorPoolSocketRetire(candidate);
        }
        return NULL;
    }

    if (fixed)
    {
        ls->fixed_binding = binding;
    }

    binding->line_prev = NULL;
    binding->line_next = ls->bindings_head;
    if (ls->bindings_head != NULL)
    {
        ls->bindings_head->line_prev = binding;
    }
    ls->bindings_head      = binding;
    binding->socket_linked = true;
    binding->line_linked   = true;
    binding->active        = true;
    ++candidate->active_bindings_count;
    ++worker_pool->active_bindings_count;
    ++ls->bindings_count;

    return binding;
}

void udpconnectorBindingDetach(udpconnector_binding_t *binding, udpconnector_detach_disposition_t disposition)
{
    discard disposition;
    assert(binding->active && binding->socket_linked && binding->line_linked);
    assert(binding->socket != NULL && binding->ls != NULL && binding->line != NULL);
    assert(currentThreadIsEventWorkerWID(binding->socket->wid));

    udpconnector_pool_socket_t *sock = binding->socket;
    udpconnector_lstate_t      *ls   = binding->ls;
    udpconnector_worker_pool_t *pool = sock->worker_pool;

    if (ls->last_send_binding == binding)
    {
        ls->last_send_binding = NULL;
    }

    if (sock->state == kUdpConnectorPoolSocketAccepting)
    {
        sock->state = kUdpConnectorPoolSocketDraining;
    }

    assert(sock->active_bindings_count > 0 && pool->active_bindings_count > 0);

    udpconnectorBindingMapErase(&sock->peer_map, binding->peer_key, binding);
    --sock->active_bindings_count;
    --pool->active_bindings_count;
    binding->socket_linked = false;

    if (ls->fixed_binding == binding)
    {
        ls->fixed_binding = NULL;
    }
    else
    {
        udpconnectorBindingMapErase(&ls->peer_bindings, binding->peer_key, binding);
    }

    assert(ls->bindings_count > 0);

    if (binding->line_prev != NULL)
    {
        assert(binding->line_prev->line_next == binding);
        binding->line_prev->line_next = binding->line_next;
    }
    else
    {
        assert(ls->bindings_head == binding);
        ls->bindings_head = binding->line_next;
    }

    if (binding->line_next != NULL)
    {
        assert(binding->line_next->line_prev == binding);
        binding->line_next->line_prev = binding->line_prev;
    }

    binding->line_prev   = NULL;
    binding->line_next   = NULL;
    binding->line_linked = false;
    binding->active      = false;
    --ls->bindings_count;
    memoryFree(binding);

    if (sock->state != kUdpConnectorPoolSocketClosing && sock->active_bindings_count == 0)
    {
        udpconnectorPoolSocketRetire(sock);
    }
}

void udpconnectorLineDetach(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls,
                            udpconnector_detach_disposition_t disposition)
{
    assert(lineIsOnCurrentEventWorker(l));

    // 1. Settle idle handle
    if (disposition == kUdpConnectorDetachIdleExpire || disposition == kUdpConnectorDetachWorkerDrain)
    {
        ls->idle_handle = NULL;
    }
    else if (ls->idle_handle != NULL)
    {
        local_idle_item_t *item = ls->idle_handle;
        ls->idle_handle         = NULL;
        bool removed            = localidletableRemoveIdleItem(udpconnectorGetWorkerIdleTable(tunnelGetState(t)), item);
        if (! removed)
        {
            LOGF("UdpConnector: failed to remove idle item for line");
            abortProgramNow(1);
        }
    }

    if (disposition == kUdpConnectorDetachFinish)
    {
        udpconnector_binding_t *binding = ls->last_send_binding;
        assert(binding != NULL && binding->active);

        if (binding->socket->state != kUdpConnectorPoolSocketClosing && binding->socket->io != NULL &&
            ! wioIsClosed(binding->socket->io))
        {
            while (bufferqueueGetBufCount(&ls->pause_queue) > 0)
            {
                sbuf_t *buf = bufferqueuePopFront(&ls->pause_queue);
                wioWriteDatagram(binding->socket->io, buf, &binding->peer_addr);
            }
        }
        else
        {
            buffer_pool_t *pool = lineGetBufferPool(l);
            while (bufferqueueGetBufCount(&ls->pause_queue) > 0)
            {
                bufferpoolReuseBuffer(pool, bufferqueuePopFront(&ls->pause_queue));
            }
        }
    }

    while (ls->bindings_head != NULL)
    {
        udpconnectorBindingDetach(ls->bindings_head, disposition);
    }

    assert(ls->fixed_binding == NULL && ls->last_send_binding == NULL);
    assert(ls->bindings_count == 0 && udpconnector_peer_binding_map_size(&ls->peer_bindings) == 0);

    udpconnectorLinestateDestroy(ls);

    if (disposition != kUdpConnectorDetachFinish)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
}

void udpconnectorOnSocketRecvFrom(wio_t *io, sbuf_t *buf)
{
    udpconnector_pool_socket_t *sock = (udpconnector_pool_socket_t *) (weventGetUserdata(io));
    buffer_pool_t              *pool = wloopGetBufferPool(weventGetLoop(io));
    if (sock == NULL || sock->state == kUdpConnectorPoolSocketClosing)
    {
        bufferpoolReuseBuffer(pool, buf);
        return;
    }

    assert(currentThreadIsEventWorkerWID(sock->wid));
    assert(sock->io == io && sock->linked);

    sockaddr_u src_addr = *wioGetPeerAddrU(io);

    udpconnector_peer_key_t                    key = udpconnectorPeerKeyFromSockAddr(&src_addr);
    const udpconnector_peer_binding_map_value *val = udpconnector_peer_binding_map_get(&sock->peer_map, key);
    if (val == NULL)
    {
        bufferpoolReuseBuffer(pool, buf);
        return;
    }
    udpconnector_binding_t *binding = val->second;

    line_t                *l  = binding->line;
    udpconnector_lstate_t *ls = binding->ls;
    assert(binding->active && binding->socket_linked && binding->line_linked);
    assert(binding->socket == sock && l != NULL && ls != NULL && ls->line == l);
    assert(lineIsAlive(l) && lineIsOnCurrentEventWorker(l));

    if (ls->read_paused)
    {
        bufferpoolReuseBuffer(pool, buf);
        return;
    }

    tunnel_t              *t  = sock->tunnel;
    udpconnector_tstate_t *ts = tunnelGetState(t);

    assert(ls->idle_handle != NULL);
    localidletableKeepIdleItemForAtleast(udpconnectorGetLineIdleTable(ts, l), ls->idle_handle, kUdpKeepExpireTime);

    lineRef(l);
    if (! ls->established)
    {
        ls->established = true;
        tunnelPrevDownStreamEst(t, l);
        if (! lineIsAlive(l))
        {
            bufferpoolReuseBuffer(pool, buf);
            lineUnref(l);
            return;
        }
    }

    tunnelPrevDownStreamPayload(t, l, buf);
    lineUnref(l);
}

void udpconnectorOnSocketClose(wio_t *io)
{
    udpconnector_pool_socket_t *sock = (udpconnector_pool_socket_t *) (weventGetUserdata(io));
    if (sock == NULL)
    {
        return;
    }

    assert(currentThreadIsEventWorkerWID(sock->wid));
    assert(sock->io == io && sock->linked);
    tunnel_t *t = sock->tunnel;

    sock->state = kUdpConnectorPoolSocketClosing;
    udpconnectorPoolSocketUnlink(sock);

    weventSetUserData(io, NULL);
    wioSetCallBackClose(io, NULL);
    wioSetCallBackRead(io, NULL);
    sock->io = NULL;

    while (sock->active_bindings_count > 0)
    {
        udpconnector_binding_t *binding = NULL;
        c_foreach(it, udpconnector_peer_binding_map, sock->peer_map)
        {
            binding = it.ref->second;
            break;
        }

        if (UNLIKELY(binding == NULL || binding->line == NULL || binding->ls == NULL))
        {
            LOGF("UdpConnector: closing socket retained an invalid active binding");
            abortProgramNow(1);
        }

        line_t                *l  = binding->line;
        udpconnector_lstate_t *ls = binding->ls;
        lineRef(l);
        udpconnectorLineDetach(t, l, ls, kUdpConnectorDetachSocketFailure);
        lineUnref(l);
    }

    if (UNLIKELY(udpconnector_peer_binding_map_size(&sock->peer_map) != 0))
    {
        LOGF("UdpConnector: closing socket retained binding-map entries after line drain");
        abortProgramNow(1);
    }

    udpconnector_peer_binding_map_drop(&sock->peer_map);
    memoryFree(sock);
}

#if defined(UDPCONNECTOR_POOL_TEST_HOOKS)
uint32_t udpconnectorTestGetSocketCount(tunnel_t *t, wid_t wid, int family)
{
    udpconnector_tstate_t      *ts    = tunnelGetState(t);
    udpconnector_worker_pool_t *pool  = &ts->worker_pools[wid];
    uint32_t                    count = 0;
    for (udpconnector_pool_socket_t *s = (family == AF_INET ? pool->v4_sockets : pool->v6_sockets); s != NULL;
         s                             = s->next)
    {
        count++;
    }
    return count;
}

uint32_t udpconnectorTestGetSocketBindingCount(const udpconnector_pool_socket_t *sock)
{
    return sock != NULL ? sock->active_bindings_count : 0;
}

udpconnector_pool_socket_state_e udpconnectorTestGetSocketState(const udpconnector_pool_socket_t *sock)
{
    return sock != NULL ? sock->state : kUdpConnectorPoolSocketClosing;
}

wio_t *udpconnectorTestGetSocketWio(const udpconnector_pool_socket_t *sock)
{
    return sock != NULL ? sock->io : NULL;
}

udpconnector_pool_socket_t *udpconnectorTestGetFirstSocket(tunnel_t *t, wid_t wid, int family)
{
    udpconnector_tstate_t      *ts   = tunnelGetState(t);
    udpconnector_worker_pool_t *pool = &ts->worker_pools[wid];
    return family == AF_INET ? pool->v4_sockets : pool->v6_sockets;
}

udpconnector_binding_t *udpconnectorTestGetLineFixedBinding(const udpconnector_lstate_t *ls)
{
    return ls != NULL ? ls->fixed_binding : NULL;
}

uint32_t udpconnectorTestGetLineBindingCount(const udpconnector_lstate_t *ls)
{
    return ls != NULL ? ls->bindings_count : 0;
}

udpconnector_binding_t *udpconnectorTestGetLineFirstBinding(const udpconnector_lstate_t *ls)
{
    return ls != NULL ? ls->bindings_head : NULL;
}
#endif
