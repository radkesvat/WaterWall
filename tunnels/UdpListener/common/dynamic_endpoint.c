#include "structure.h"

#include "loggers/network_logger.h"

static void udplistenerRecycleDynamicBuffer(buffer_pool_t *pool, sbuf_t *buf)
{
    bufferpoolReuseBuffer(pool, buf);
}

static void udplistenerRequireDynamicEndpointWorker(udplistener_dynamic_endpoint_handle_t handle, const char *operation)
{
    if (UNLIKELY(! currentThreadIsEventWorkerWID(handle.owner_wid)))
    {
        LOGF("UdpListener: dynamic endpoint %s arrived outside owner worker", operation);
        abortProgramNow(1);
    }
}

udplistener_dynamic_endpoint_t *udplistenerFindDynamicEndpoint(tunnel_t                             *t,
                                                               udplistener_dynamic_endpoint_handle_t handle)
{
    if (t == NULL || ! udplistenerDynamicEndpointHandleIsValid(handle))
    {
        return NULL;
    }

    if (! currentThreadIsEventWorkerWID(handle.owner_wid))
    {
        return NULL;
    }

    udplistener_tstate_t *ts = tunnelGetState(t);
    if (ts->worker_registries == NULL || handle.owner_wid >= ts->workers_count)
    {
        return NULL;
    }

    udplistener_worker_registry_t  *reg = &ts->worker_registries[handle.owner_wid];
    udplistener_endpoint_map_t_iter it  = udplistener_endpoint_map_t_find(&reg->endpoints, handle.generation);
    if (it.ref == udplistener_endpoint_map_t_end(&reg->endpoints).ref ||
        ! udplistenerDynamicEndpointHandleEquals(it.ref->second->handle, handle))
    {
        return NULL;
    }

    return it.ref->second;
}

bool udplistenerDynamicEndpointOpen(tunnel_t *t, wid_t wid, const udplistener_dynamic_endpoint_open_request_t *req,
                                    udplistener_dynamic_endpoint_open_result_t *res_out)
{
    if (res_out != NULL)
    {
        *res_out = (udplistener_dynamic_endpoint_open_result_t) {0};
    }

    if (t == NULL || req == NULL || res_out == NULL || ! currentThreadIsEventWorkerWID(wid))
    {
        return false;
    }

    udplistener_tstate_t *ts = tunnelGetState(t);
    if (! atomic_load_explicit(&ts->dynamic_admission_open, memory_order_acquire) || ts->worker_registries == NULL ||
        wid >= ts->workers_count || ! currentThreadIsEventWorkerWID(wid))
    {
        return false;
    }

    ip_addr_t expected_peer_ip = req->expected_peer_ip;
    normalizeIpAddr(&expected_peer_ip);
    if ((expected_peer_ip.type != IPADDR_TYPE_V4 && expected_peer_ip.type != IPADDR_TYPE_V6) ||
        ipAddrIsWildcard(&expected_peer_ip))
    {
        return false;
    }

    if (vec_ipmask_t_size(&ts->white_list) > 0 && ! socketManagerIpMatchesAcl(expected_peer_ip, &ts->white_list))
    {
        return false;
    }
    if (vec_ipmask_t_size(&ts->black_list) > 0 && socketManagerIpMatchesAcl(expected_peer_ip, &ts->black_list))
    {
        return false;
    }

    udplistener_worker_registry_t *reg = &ts->worker_registries[wid];
    if (reg->next_generation == 0)
    {
        /* Do not wrap a value handle into a generation that may still be live. */
        return false;
    }

    const uint64_t generation = reg->next_generation++;
    if (udplistener_endpoint_map_t_find(&reg->endpoints, generation).ref !=
        udplistener_endpoint_map_t_end(&reg->endpoints).ref)
    {
        return false;
    }

    bound_udp_config_t cfg = {
        .bind_address     = ts->listen_address,
        .port             = 0,
        .interface_name   = ts->interface_name,
        .fwmark           = ts->fwmark,
        .send_buffer_size = ts->send_buffer_size > 0 ? (uint32_t) ts->send_buffer_size : 0,
        .recv_buffer_size = ts->recv_buffer_size > 0 ? (uint32_t) ts->recv_buffer_size : 0,
        .bind_policy      = kBoundUdpBindPolicyExclusive,
        /* Match SocketManager's listener fallback: on platforms without
         * SO_BINDTODEVICE, an interface selects its local bind address. */
        .source_ip_configured = false,
    };

    wio_t *wio = boundUdpSocketCreate(getCurrentEventWorkerLoop(), &cfg);
    if (wio == NULL)
    {
        return false;
    }

    sockaddr_u    *local_addr = wioGetLocaladdrU(wio);
    const uint16_t local_port = local_addr != NULL ? sockaddrPort(local_addr) : 0;
    if (local_port == 0)
    {
        wioClose(wio);
        return false;
    }

#ifdef UDPLISTENER_DYNAMIC_ENDPOINT_TEST_HOOKS
    if (udplistenerDynamicEndpointTestShouldFail(kUdpListenerDynamicEndpointTestFaultAllocateEndpoint))
    {
        wioClose(wio);
        return false;
    }
#endif

    udplistener_dynamic_endpoint_t *ep = memoryAllocateZero(sizeof(*ep));
    if (ep == NULL)
    {
        wioClose(wio);
        return false;
    }

    ep->handle               = (udplistener_dynamic_endpoint_handle_t) {.owner_wid = wid, .generation = generation};
    ep->state                = kDynamicEndpointPrepared;
    ep->wio                  = wio;
    ep->bound_local_addr     = *local_addr;
    ep->bound_local_port     = local_port;
    ep->expected_peer_ip     = expected_peer_ip;
    ep->expected_source_port = req->expected_source_port;
    ep->source_port_pinned   = req->expected_source_port != 0;
    ep->line                 = NULL;
    ep->tunnel               = t;

    weventSetUserData(wio, ep);
    wioSetCallBackRead(wio, udplistenerOnDynamicEndpointRead);

#ifdef UDPLISTENER_DYNAMIC_ENDPOINT_TEST_HOOKS
    const bool fail_publication =
        udplistenerDynamicEndpointTestShouldFail(kUdpListenerDynamicEndpointTestFaultPublishEndpoint);
#else
    const bool fail_publication = false;
#endif
    const udplistener_endpoint_map_t_result inserted =
        fail_publication ? (udplistener_endpoint_map_t_result) {0}
                         : udplistener_endpoint_map_t_insert(&reg->endpoints, generation, ep);
    if (inserted.ref == NULL || ! inserted.inserted)
    {
        weventSetUserData(wio, NULL);
        wioSetCallBackRead(wio, NULL);
        wioClose(wio);
        memoryFree(ep);
        return false;
    }

    res_out->handle           = ep->handle;
    res_out->bound_local_addr = ep->bound_local_addr;
    res_out->bound_local_port = ep->bound_local_port;
    return true;
}

bool udplistenerDynamicEndpointActivate(tunnel_t *t, udplistener_dynamic_endpoint_handle_t handle)
{
    if (t == NULL || ! udplistenerDynamicEndpointHandleIsValid(handle) ||
        ! currentThreadIsEventWorkerWID(handle.owner_wid))
    {
        return false;
    }

    udplistener_tstate_t *ts = tunnelGetState(t);
    if (! atomic_load_explicit(&ts->dynamic_admission_open, memory_order_acquire))
    {
        return false;
    }

    udplistener_dynamic_endpoint_t *ep = udplistenerFindDynamicEndpoint(t, handle);
    if (ep == NULL || ep->state != kDynamicEndpointPrepared)
    {
        return false;
    }

    if (ep->wio == NULL || wioIsClosed(ep->wio))
    {
        /* A prepared endpoint that cannot arm reads has no usable handle.
         * Remove it here so failed activation cannot strand an unpublished
         * socket/registry object if a caller has no later close opportunity. */
        udplistenerDynamicEndpointClose(t, handle);
        return false;
    }

    /* Publish active before arming reads: a backend may report readiness immediately. */
    ep->state = kDynamicEndpointActive;
    if (UNLIKELY(wioRead(ep->wio) != 0))
    {
        udplistenerDynamicEndpointClose(t, handle);
        return false;
    }

    return true;
}

void udplistenerDynamicEndpointClose(tunnel_t *t, udplistener_dynamic_endpoint_handle_t handle)
{
    if (t == NULL || ! udplistenerDynamicEndpointHandleIsValid(handle))
    {
        return;
    }

    udplistenerRequireDynamicEndpointWorker(handle, "close");

    udplistener_dynamic_endpoint_t *ep = udplistenerFindDynamicEndpoint(t, handle);
    if (ep == NULL)
    {
        return;
    }

    udplistener_tstate_t           *ts  = tunnelGetState(t);
    udplistener_worker_registry_t  *reg = &ts->worker_registries[handle.owner_wid];
    udplistener_endpoint_map_t_iter it  = udplistener_endpoint_map_t_find(&reg->endpoints, handle.generation);
    assert(it.ref != udplistener_endpoint_map_t_end(&reg->endpoints).ref);

    ep->state = kDynamicEndpointClosing;
    udplistener_endpoint_map_t_erase_at(&reg->endpoints, it);

    if (ep->wio != NULL)
    {
        weventSetUserData(ep->wio, NULL);
        wioSetCallBackRead(ep->wio, NULL);
        wioClose(ep->wio);
        ep->wio = NULL;
    }

    if (ep->line != NULL)
    {
        line_t *l = ep->line;
        ep->line  = NULL;

        /* The provider owns this normal line. Keep a temporary reference
         * across the callback so a broken downstream implementation cannot
         * turn the diagnostic below into a use-after-free. */
        lineLock(l);
        udplistenerLinestateDestroy(lineGetState(l, t));
        tunnelNextUpStreamFinish(t, l);
        if (UNLIKELY(! lineIsAlive(l)))
        {
            lineUnlock(l);
            LOGF("UdpListener: a downstream tunnel destroyed a provider-owned dynamic UDP line during Finish");
            abortProgramNow(1);
        }
        lineDestroy(l);
        lineUnlock(l);
    }

    memoryFree(ep);
}

bool udplistenerGetLineInfo(tunnel_t *t, const line_t *line, udplistener_dynamic_line_info_t *info_out)
{
    if (info_out != NULL)
    {
        *info_out = (udplistener_dynamic_line_info_t) {0};
    }

    if (t == NULL || line == NULL || info_out == NULL || ! lineIsOnCurrentEventWorker(line))
    {
        return false;
    }

    const udplistener_lstate_t *ls = lineGetState((line_t *) line, t);
    if (ls->source_kind != kUdpListenerSourceDynamic || ls->tunnel != t || ls->line != line ||
        ! udplistenerDynamicEndpointHandleIsValid(ls->dynamic_handle) ||
        ls->dynamic_handle.owner_wid != lineGetWID(line) || ls->bound_local_port == 0)
    {
        return false;
    }

    udplistener_dynamic_endpoint_t *ep = udplistenerFindDynamicEndpoint(t, ls->dynamic_handle);
    if (ep == NULL || (ep->state != kDynamicEndpointActive && ep->state != kDynamicEndpointClosing) ||
        ep->line != line || ep->bound_local_port != ls->bound_local_port)
    {
        return false;
    }

    *info_out = (udplistener_dynamic_line_info_t) {
        .handle           = ls->dynamic_handle,
        .expected_wid     = ls->dynamic_handle.owner_wid,
        .generation       = ls->dynamic_handle.generation,
        .bound_local_port = ls->bound_local_port,
        .is_dynamic       = true,
    };
    return true;
}

void udplistenerOnDynamicEndpointRead(wio_t *io, sbuf_t *buf)
{
    wloop_t *const loop = weventGetLoop(io);
    const wid_t    wid  = getLoopEventWorkerWID(loop);
    if (UNLIKELY(! currentThreadIsEventWorkerWID(wid)))
    {
        LOGF("UdpListener: dynamic endpoint read arrived outside its event worker");
        abortProgramNow(1);
    }

    /* Init may synchronously close the endpoint and reclaim its WIO. Keep the
     * callback buffer's owning pool independently of that external callback. */
    buffer_pool_t *const callback_pool = wloopGetBufferPool(loop);

    udplistener_dynamic_endpoint_t *ep = weventGetUserdata(io);
    if (ep == NULL || ep->state != kDynamicEndpointActive)
    {
        udplistenerRecycleDynamicBuffer(callback_pool, buf);
        return;
    }

    if (wid != ep->handle.owner_wid)
    {
        LOGF("UdpListener: dynamic endpoint read arrived on a foreign worker");
        abortProgramNow(1);
    }

    sockaddr_u *peer_sockaddr = wioGetPeerAddrU(io);
    ip_addr_t   peer_ip;
    if (peer_sockaddr == NULL || ! sockaddrToNormalizedIpAddr(peer_sockaddr, &peer_ip) ||
        ! ipAddrEqualsExact(&peer_ip, &ep->expected_peer_ip))
    {
        udplistenerRecycleDynamicBuffer(callback_pool, buf);
        return;
    }

    const uint16_t peer_port = sockaddrPort(peer_sockaddr);
    if (ep->expected_source_port != 0)
    {
        if (peer_port != ep->expected_source_port)
        {
            udplistenerRecycleDynamicBuffer(callback_pool, buf);
            return;
        }
    }
    else if (! ep->source_port_pinned)
    {
        if (peer_port == 0)
        {
            udplistenerRecycleDynamicBuffer(callback_pool, buf);
            return;
        }
        ep->expected_source_port = peer_port;
        ep->source_port_pinned   = true;
    }
    else if (peer_port != ep->expected_source_port)
    {
        udplistenerRecycleDynamicBuffer(callback_pool, buf);
        return;
    }

    ep->pinned_peer_addr = *peer_sockaddr;

    tunnel_t *listener = ep->tunnel;
    line_t   *line     = ep->line;
    if (line == NULL)
    {
        line = lineCreate(tunnelchainGetLinePools(tunnelGetChain(listener)), wid);
        if (line == NULL)
        {
            udplistenerRecycleDynamicBuffer(callback_pool, buf);
            return;
        }

        addresscontextFromSockAddrWithProtocol(&line->routing_context.src_ctx, peer_sockaddr, IP_PROTO_UDP);
        line->routing_context.peer_source_port = peer_port;
        addresscontextSetPort(&line->routing_context.src_ctx, ep->bound_local_port);

        sockaddr_u effective_local_addr = ep->bound_local_addr;
        sockaddrSetPort(&effective_local_addr, ep->bound_local_port);
        addresscontextFromSockAddrWithProtocol(&line->routing_context.dest_ctx, &effective_local_addr, IP_PROTO_UDP);
        line->routing_context.local_listener_port = ep->bound_local_port;

        udplistener_lstate_t *ls = lineGetState(line, listener);
        *ls                      = (udplistener_lstate_t) {
                                 .tunnel           = listener,
                                 .line             = line,
                                 .source_kind      = kUdpListenerSourceDynamic,
                                 .dynamic_handle   = ep->handle,
                                 .bound_local_port = ep->bound_local_port,
                                 .uio              = NULL,
                                 .idle_handle      = NULL,
                                 .listener_fd      = wioGetFD(ep->wio),
                                 .peer_addr        = *peer_sockaddr,
                                 .local_addr       = effective_local_addr,
                                 .read_paused      = false,
        };

        /* Publish before Init: synchronous Finish can now detach it exactly once. */
        ep->line = line;
        if (! withLineLocked(line, tunnelNextUpStreamInit, listener))
        {
            /* The endpoint, WIO, and line may all have been reclaimed during
             * Init. callback_pool remains valid for the current worker. */
            udplistenerRecycleDynamicBuffer(callback_pool, buf);
            return;
        }
    }

    udplistener_lstate_t *ls = lineGetState(line, listener);
    if (ls->read_paused)
    {
        udplistenerRecycleDynamicBuffer(callback_pool, buf);
        return;
    }

    tunnelNextUpStreamPayload(listener, line, buf);
}

udplistener_dynamic_provider_t udplistenerGetDynamicProvider(tunnel_t *t)
{
    if (t == NULL)
    {
        return (udplistener_dynamic_provider_t) {0};
    }

    return (udplistener_dynamic_provider_t) {
        .instance      = t,
        .open          = udplistenerDynamicEndpointOpen,
        .activate      = udplistenerDynamicEndpointActivate,
        .close         = udplistenerDynamicEndpointClose,
        .get_line_info = udplistenerGetLineInfo,
    };
}
