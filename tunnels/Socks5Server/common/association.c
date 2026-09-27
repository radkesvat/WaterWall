#include "internal.h"

#include "loggers/network_logger.h"

uint16_t socks5serverGetLocalPort(const line_t *l)
{
    const routing_context_t *route = lineGetRoutingContext((line_t *) l);
    if (route->local_listener_port != 0)
    {
        return route->local_listener_port;
    }

    return lineGetSourceAddressContext((line_t *) l)->port;
}

socks5server_assoc_entry_t *socks5serverFindWorkerAssociation(tunnel_t *t, wid_t wid, uint64_t generation)
{
    assert(t != NULL);
    if (generation == 0)
    {
        return NULL;
    }
    socks5server_tstate_t *ts = tunnelGetState(t);
    if (ts->worker_associations == NULL || wid >= ts->workers_count || ! currentThreadIsEventWorkerWID(wid))
    {
        return NULL;
    }

    socks5server_assoc_map_t     *map = &ts->worker_associations[wid];
    socks5server_assoc_map_t_iter it  = socks5server_assoc_map_t_find(map, generation);
    if (it.ref == socks5server_assoc_map_t_end(map).ref)
    {
        return NULL;
    }
    return &it.ref->second;
}

bool socks5serverAssociationIsActive(tunnel_t *t, wid_t wid, udplistener_dynamic_endpoint_handle_t handle,
                                     uint16_t assigned_port, socks5server_assoc_entry_t **entry_out)
{
    if (entry_out != NULL)
    {
        *entry_out = NULL;
    }

    if (! udplistenerDynamicEndpointHandleIsValid(handle) || handle.owner_wid != wid || assigned_port == 0)
    {
        return false;
    }

    socks5server_assoc_entry_t *entry = socks5serverFindWorkerAssociation(t, wid, handle.generation);
    if (entry == NULL || ! entry->active || entry->owner_wid != wid || entry->generation != handle.generation ||
        ! udplistenerDynamicEndpointHandleEquals(entry->dynamic_handle, handle) ||
        entry->assigned_port != assigned_port)
    {
        return false;
    }

    if (entry_out != NULL)
    {
        *entry_out = entry;
    }
    return true;
}

bool socks5serverValidateUdpClientAssociation(tunnel_t *t, line_t *l, socks5server_lstate_t *ls,
                                              bool validate_provider_metadata)
{
    assert(t != NULL && l != NULL && ls != NULL && lineIsOnCurrentEventWorker(l));

    const wid_t    wid        = lineGetWID(l);
    const uint16_t local_port = lineGetRoutingContext(l)->local_listener_port;
    if (! socks5serverAssociationIsActive(t, wid, ls->dynamic_handle, local_port, NULL))
    {
        return false;
    }

    if (! validate_provider_metadata)
    {
        return true;
    }

    socks5server_tstate_t *ts = tunnelGetState(t);
    if (ts->dynamic_provider.instance == NULL || ts->dynamic_provider.get_line_info == NULL)
    {
        return false;
    }

    udplistener_dynamic_line_info_t info = {0};
    if (! ts->dynamic_provider.get_line_info(ts->dynamic_provider.instance, l, &info) || ! info.is_dynamic ||
        info.expected_wid != wid || info.generation != ls->dynamic_handle.generation ||
        ! udplistenerDynamicEndpointHandleEquals(info.handle, ls->dynamic_handle) ||
        info.bound_local_port != local_port)
    {
        return false;
    }

    return true;
}

bool socks5serverRegisterUdpAssociation(tunnel_t *t, line_t *l, const user_handle_t *user_handle,
                                        const address_context_t *udp_peer_hint, uint16_t *assigned_port_out)
{
    assert(assigned_port_out != NULL);
    socks5server_tstate_t *ts  = tunnelGetState(t);
    wid_t                  wid = lineGetWID(l);

    if (ts->worker_associations == NULL || wid >= ts->workers_count || ! currentThreadIsEventWorkerWID(wid) ||
        ! lineIsAuthenticated(l) || ! lineIsAlive(l))
    {
        return false;
    }

    if (ts->dynamic_provider.instance == NULL || ts->dynamic_provider.open == NULL ||
        ts->dynamic_provider.activate == NULL || ts->dynamic_provider.close == NULL)
    {
        return false;
    }

    const address_context_t *src_ctx = lineGetSourceAddressContext(l);
    if (! addresscontextIsIp(src_ctx))
    {
        return false;
    }

    ip_addr_t expected_peer_ip = src_ctx->ip_address;
    normalizeIpAddr(&expected_peer_ip);
    if (ipAddrIsWildcard(&expected_peer_ip))
    {
        return false;
    }

    uint16_t expected_source_port = 0;

    if (udp_peer_hint != NULL && addresscontextIsIp(udp_peer_hint))
    {
        ip_addr_t requested_peer_ip = udp_peer_hint->ip_address;
        normalizeIpAddr(&requested_peer_ip);
        if (! ipAddrIsWildcard(&requested_peer_ip) && ! ipAddrEqualsExact(&requested_peer_ip, &expected_peer_ip))
        {
            /* RFC 1928 permits a hint, not a client-selected foreign relay identity. */
            return false;
        }
        expected_source_port = udp_peer_hint->port;
    }
    else if (udp_peer_hint != NULL)
    {
        expected_source_port = udp_peer_hint->port;
    }

    socks5server_lstate_t *ls = lineGetState(l, t);
    if (ls->dynamic_handle.generation != 0)
    {
        return false;
    }

    udplistener_dynamic_endpoint_open_request_t req = {
        .expected_peer_ip     = expected_peer_ip,
        .expected_source_port = expected_source_port,
    };
    udplistener_dynamic_endpoint_open_result_t res;

    if (! ts->dynamic_provider.open(ts->dynamic_provider.instance, wid, &req, &res))
    {
        return false;
    }

    if (! udplistenerDynamicEndpointHandleIsValid(res.handle) || res.handle.owner_wid != wid ||
        res.bound_local_port == 0 || sockaddrPort(&res.bound_local_addr) != res.bound_local_port)
    {
        if (res.handle.owner_wid == wid)
        {
            ts->dynamic_provider.close(ts->dynamic_provider.instance, res.handle);
        }
        return false;
    }

    const char *src_username = lineGetAuthenticatedUsername(l);
    const char *src_password = lineGetAuthenticatedPassword(l);

    socks5server_assoc_entry_t entry = {
        .generation     = res.handle.generation,
        .owner_wid      = wid,
        .dynamic_handle = res.handle,
        .assigned_port  = res.bound_local_port,
        .user_handle    = *user_handle,
        .auth_username  = src_username != NULL ? stringDuplicate(src_username) : NULL,
        .auth_password  = src_password != NULL ? stringDuplicate(src_password) : NULL,
        .active         = false,
    };

    if ((src_username != NULL && entry.auth_username == NULL) || (src_password != NULL && entry.auth_password == NULL))
    {
        socks5serverAssocEntryFreeCreds(&entry);
        ts->dynamic_provider.close(ts->dynamic_provider.instance, res.handle);
        return false;
    }

    socks5server_assoc_map_t *map = &ts->worker_associations[wid];
    if (! socks5server_assoc_map_t_insert(map, res.handle.generation, entry).inserted)
    {
        socks5serverAssocEntryFreeCreds(&entry);
        ts->dynamic_provider.close(ts->dynamic_provider.instance, res.handle);
        return false;
    }

    socks5server_assoc_map_t_iter it = socks5server_assoc_map_t_find(map, res.handle.generation);
    assert(it.ref != socks5server_assoc_map_t_end(map).ref);
    it.ref->second.active = true;
    ls->dynamic_handle    = res.handle;

    if (! ts->dynamic_provider.activate(ts->dynamic_provider.instance, res.handle))
    {
        ls->dynamic_handle = (udplistener_dynamic_endpoint_handle_t) {0};
        socks5serverAssocEntryFreeCreds(&it.ref->second);
        socks5server_assoc_map_t_erase_at(map, it);
        ts->dynamic_provider.close(ts->dynamic_provider.instance, res.handle);
        return false;
    }

    *assigned_port_out = res.bound_local_port;
    return true;
}

void socks5serverUnregisterUdpAssociation(tunnel_t *t, socks5server_lstate_t *ls)
{
    if (ls->dynamic_handle.generation == 0)
    {
        return;
    }

    socks5server_tstate_t                *ts     = tunnelGetState(t);
    udplistener_dynamic_endpoint_handle_t handle = ls->dynamic_handle;
    ls->dynamic_handle                           = (udplistener_dynamic_endpoint_handle_t) {0};

    if (handle.owner_wid >= ts->workers_count || ! currentThreadIsEventWorkerWID(handle.owner_wid))
    {
        LOGF("Socks5Server: control association handle has an invalid owner worker");
        abortProgramNow(1);
    }

    socks5server_assoc_map_t     *map = &ts->worker_associations[handle.owner_wid];
    socks5server_assoc_map_t_iter it  = socks5server_assoc_map_t_find(map, handle.generation);
    if (it.ref != socks5server_assoc_map_t_end(map).ref &&
        udplistenerDynamicEndpointHandleEquals(it.ref->second.dynamic_handle, handle))
    {
        socks5serverAssocEntryFreeCreds(&it.ref->second);
        socks5server_assoc_map_t_erase_at(map, it);
    }

    if (ts->dynamic_provider.close != NULL)
    {
        ts->dynamic_provider.close(ts->dynamic_provider.instance, handle);
    }
}
