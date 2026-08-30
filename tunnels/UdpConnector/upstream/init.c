#include "structure.h"

#include "loggers/network_logger.h"

uint32_t udpconnectorSelectWeightedDestinationIndex(const udpconnector_tstate_t *ts)
{
    if (ts->destinations_count == 0)
    {
        return 0;
    }

    assert(ts->destinations_weight_total > 0);

    uint64_t pick       = fastRand64() % ts->destinations_weight_total;
    uint64_t cumulative = 0;

    for (uint32_t i = 0; i < ts->destinations_count; ++i)
    {
        cumulative += ts->destinations[i].weight;
        if (pick < cumulative)
        {
            return i;
        }
    }

    return ts->destinations_count - 1;
}

const udpconnector_destination_t *udpconnectorSelectWeightedDestination(const udpconnector_tstate_t *ts)
{
    if (ts->destinations_count == 0)
    {
        return NULL;
    }

    return &ts->destinations[udpconnectorSelectWeightedDestinationIndex(ts)];
}

void udpconnectorSetupDestinationAddress(const dynamic_value_t   *dest_addr_selected,
                                         const address_context_t *constant_dest_addr, address_context_t *dest_ctx,
                                         const address_context_t *original_dest_ctx, address_context_t *src_ctx)
{
    switch (dest_addr_selected->status)
    {
    case kDvsFromSource:
        addresscontextCopy(dest_ctx, src_ctx);
        break;
    case kDvsConstant:
        addresscontextCopy(dest_ctx, constant_dest_addr);
        break;
    case kDvsFromDest:
        addresscontextCopy(dest_ctx, original_dest_ctx);
        break;
    default:
        break;
    }
}

void udpconnectorSetupDestinationPort(const dynamic_value_t   *dest_port_selected,
                                      const address_context_t *constant_dest_addr, uint16_t random_dest_port_x,
                                      uint16_t random_dest_port_y, address_context_t *dest_ctx,
                                      const address_context_t *original_dest_ctx, address_context_t *src_ctx)
{
    switch (dest_port_selected->status)
    {
    case kDvsFromSource:
        addresscontextCopyPort(dest_ctx, src_ctx);
        break;
    case kDvsConstant:
        addresscontextCopyPort(dest_ctx, (address_context_t *) constant_dest_addr);
        break;
    case kDvsRandom:
        addresscontextSetPort(dest_ctx,
                              (fastRand() % (random_dest_port_y - random_dest_port_x + 1)) + random_dest_port_x);
        break;
    case kDvsFromDest:
        addresscontextCopyPort(dest_ctx, (address_context_t *) original_dest_ctx);
        break;
    default:
        break;
    }
}

const dns_resolved_addr_t *udpconnectorSelectResolvedAddress(const dns_resolved_addr_t *addrs, size_t naddrs,
                                                             int strategy)
{
    return dnsstrategySelectResolvedAddress(addrs, naddrs, (enum domain_strategy) strategy);
}

bool udpconnectorApplyResolvedAddress(address_context_t *dest_ctx, const dns_resolved_addr_t *resolved)
{
    return dnsstrategyApplyResolvedAddress(dest_ctx, resolved);
}

static void udpconnectorSeedPacketDestinationCache(udpconnector_tstate_t *ts, udpconnector_lstate_t *ls,
                                                   const address_context_t *dest_ctx)
{
    if (ts->balance_mode != kUdpConnectorBalanceModePacket || ls->packet_destinations == NULL ||
        ls->packet_initial_destination_index >= ls->packet_destinations_count)
    {
        return;
    }

    udpconnector_packet_destination_t *cache = &ls->packet_destinations[ls->packet_initial_destination_index];
    if (! cache->has_context)
    {
        addresscontextCopy(&cache->dest_ctx, dest_ctx);
        cache->has_context = true;
    }
}

bool udpconnectorDomainResolverPrepare(tunnel_t *resolver, tunnel_t *connector, line_t *l,
                                       domainresolver_direction_t direction, void *user_lstate)
{
    discard resolver;
    discard direction;

    udpconnector_tstate_t                 *ts                         = tunnelGetState(connector);
    udpconnector_domain_resolver_lstate_t *ls                         = user_lstate;
    address_context_t                     *dest_ctx                   = lineGetDestinationAddressContext(l);
    address_context_t                     *src_ctx                    = lineGetSourceAddressContext(l);
    const dynamic_value_t                 *dest_addr_selected         = &ts->dest_addr_selected;
    const dynamic_value_t                 *dest_port_selected         = &ts->dest_port_selected;
    const address_context_t               *constant_dest_addr         = &ts->constant_dest_addr;
    uint16_t                               random_dest_port_x         = ts->random_dest_port_x;
    uint16_t                               random_dest_port_y         = ts->random_dest_port_y;
    uint32_t                               selected_destination_index = udpconnectorSelectWeightedDestinationIndex(ts);
    const udpconnector_destination_t      *selected_destination =
        ts->destinations_count > 0 ? &ts->destinations[selected_destination_index] : NULL;

    ls->route_destination_pinned = addresscontextDestinationIsPinned(dest_ctx);
    if (ls->route_destination_pinned)
    {
        /* A protocol tunnel (currently SOCKS5 UDP ASSOCIATE) negotiated this
         * endpoint. Preserve it through the ordinary connector path instead
         * of applying a static proxy destination a second time. */
        addresscontextSetDestinationPinned(dest_ctx, false);
        addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
        if (! addresscontextHasPort(dest_ctx))
        {
            LOGE("UdpConnector: negotiated destination has no port");
            return false;
        }
        addresscontextSetDomainStrategy(dest_ctx, (enum domain_strategy) ts->domain_strategy);
        return true;
    }

    if (ts->balance_mode == kUdpConnectorBalanceModePacket)
    {
        addresscontextCopy(&ls->packet_base_dest_ctx, dest_ctx);
        ls->packet_initial_destination_index = selected_destination_index;
    }

    if (selected_destination != NULL)
    {
        dest_addr_selected = &selected_destination->dest_addr_selected;
        dest_port_selected = &selected_destination->dest_port_selected;
        constant_dest_addr = &selected_destination->constant_dest_addr;
        random_dest_port_x = selected_destination->random_dest_port_x;
        random_dest_port_y = selected_destination->random_dest_port_y;
    }

    address_context_t original_dest_ctx = {0};
    addresscontextCopy(&original_dest_ctx, dest_ctx);

    udpconnectorSetupDestinationAddress(dest_addr_selected, constant_dest_addr, dest_ctx, &original_dest_ctx, src_ctx);
    udpconnectorSetupDestinationPort(dest_port_selected,
                                     constant_dest_addr,
                                     random_dest_port_x,
                                     random_dest_port_y,
                                     dest_ctx,
                                     &original_dest_ctx,
                                     src_ctx);
    addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
    addresscontextReset(&original_dest_ctx);

    if (! addresscontextHasPort(dest_ctx))
    {
        LOGE("UdpConnector: destination port is not initialized");
        return false;
    }

    addresscontextSetDomainStrategy(dest_ctx, (enum domain_strategy) ts->domain_strategy);

    return true;
}

void udpconnectorDomainResolverUserStateDestroy(tunnel_t *resolver, tunnel_t *connector, line_t *l, void *user_lstate)
{
    discard resolver;
    discard connector;
    discard l;

    udpconnector_domain_resolver_lstate_t *ls = user_lstate;
    addresscontextReset(&ls->packet_base_dest_ctx);
}

void udpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    if (UNLIKELY(tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l)))
    {
        LOGF("UdpConnector: worker packet line reached an L4-only node");
        abortProgramNow(1);
    }

    udpconnector_tstate_t                 *ts = tunnelGetState(t);
    udpconnector_lstate_t                 *ls = lineGetState(l, t);
    udpconnector_domain_resolver_lstate_t *resolver_ls =
        domainresolverTunnelGetUserLineState(ts->domain_resolver_tunnel, l);
    address_context_t *dest_ctx = lineGetDestinationAddressContext(l);

    if (UNLIKELY(! udpconnectorLinestateInitialize(ls, t, l)))
    {
        LOGE("UdpConnector: failed to initialize per-line packet destination state");
        udpconnectorLineDetach(t, l, ls, kUdpConnectorDetachInitRollback);
        return;
    }
    if (UNLIKELY(resolver_ls == NULL))
    {
        LOGF("UdpConnector: internal DomainResolver prepare state is missing");
        abortProgramNow(1);
    }

    ls->route_destination_pinned = resolver_ls->route_destination_pinned;

    if (! ls->route_destination_pinned && ts->balance_mode == kUdpConnectorBalanceModePacket)
    {
        addresscontextCopy(&ls->packet_base_dest_ctx, &resolver_ls->packet_base_dest_ctx);
        ls->packet_initial_destination_index = resolver_ls->packet_initial_destination_index;
    }

    if (! addresscontextCanConvertToSockAddr(dest_ctx) || ! addresscontextHasPort(dest_ctx))
    {
        LOGE("UdpConnector: destination address or port is not initialized");
        goto fail;
    }

    sockaddr_u addr = addresscontextToSockAddr(dest_ctx);
    ls->peer_addr   = addr;

    udpconnector_worker_pool_t *worker_pool = udpconnectorGetLineWorkerPool(ts, l);
    if (UNLIKELY(worker_pool->quiescing))
    {
        goto fail;
    }

    ls->line_idle_id = ++worker_pool->next_line_idle_id;
    ls->idle_handle  = localidletableCreateItem(udpconnectorGetWorkerIdleTable(ts),
                                               (hash_t) ls->line_idle_id,
                                               ls,
                                               udpconnectorOnIdleConnectionExpire,
                                               kUdpInitExpireTime);
    if (UNLIKELY(ls->idle_handle == NULL))
    {
        LOGE("UdpConnector: failed to register idle item for line");
        goto fail;
    }

    udpconnector_binding_t *binding = udpconnectorAcquireBinding(t, l, ls, &addr);

    if (UNLIKELY(binding == NULL))
    {
        LOGE("UdpConnector: failed to acquire UDP socket binding");
        udpconnectorLineDetach(t, l, ls, kUdpConnectorDetachInitRollback);
        return;
    }

    ls->last_send_binding = binding;
    udpconnectorSeedPacketDestinationCache(ts, ls, dest_ctx);

    const bool resume_prev = ls->queue_pause_sent;
    const bool replay_packet_queue =
        ! ls->route_destination_pinned && ts->balance_mode == kUdpConnectorBalanceModePacket;
    ls->write_paused = false;

    lineRef(l);
    bool alive = true;
    if (! ls->established)
    {
        ls->established = true;
        tunnelPrevDownStreamEst(t, l);
        alive = lineIsAlive(l);
    }

    if (alive)
    {
        if (replay_packet_queue)
        {
            alive = udpconnectorReplayWriteQueue(ls);
        }
        else
        {
            udpconnectorFlushWriteQueue(ls);
        }
    }

    if (alive && resume_prev && udpconnectorQueuedWriteBytes(ls) == 0 && ! ls->write_paused)
    {
        ls->queue_pause_sent = false;
        tunnelPrevDownStreamResume(t, l);
        alive = lineIsAlive(l);
    }
    lineUnref(l);

    return;

fail:
    udpconnectorLineDetach(t, l, ls, kUdpConnectorDetachInitRollback);
}
