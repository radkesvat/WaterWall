#include "internal.h"

#include "loggers/network_logger.h"

static line_t *socks5serverGetOrCreateUdpRemoteLine(tunnel_t *t, line_t *client_l, socks5server_lstate_t *client_ls,
                                                    const socks5_address_t *identity, const user_handle_t *user_handle)
{
    assert(client_ls->kind == kSocks5ServerLineKindUdpClient);
    uint8_t wire[kSocks5AddressMaxEncoded];
    size_t  written;
    if (! socks5AddressEncode(identity, wire, sizeof(wire), &written))
    {
        LOGF("Socks5Server: validated UDP identity cannot be encoded");
        abortProgramNow(1);
    }
    socks5server_remote_key_t      lookup = {.address = *identity, .hash = calcHashBytes(wire, written)};
    socks5server_remote_map_t_iter it     = socks5server_remote_map_t_find(&client_ls->udp_remote_lines, &lookup);
    if (it.ref != socks5server_remote_map_t_end(&client_ls->udp_remote_lines).ref)
        return it.ref->second;

    socks5server_remote_key_t *remote_key = memoryAllocate(sizeof(*remote_key));
    if (remote_key == NULL)
        return NULL;
    *remote_key = lookup;

    line_t                *remote_l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(client_l));
    socks5server_lstate_t *remote_ls = lineGetState(remote_l, t);

    socks5serverLinestateInitialize(remote_ls, t, remote_l, kSocks5ServerLineKindUdpRemote);
    remote_ls->client_line          = client_l;
    remote_ls->client_line_ref_held = true;
    remote_ls->remote_key           = remote_key;
    remote_ls->dynamic_handle       = client_ls->dynamic_handle;
    remote_ls->user_handle          = *user_handle;

    lineRef(client_l);

    lineGetRoutingContext(remote_l)->local_listener_port = socks5serverGetLocalPort(client_l);
    socks5serverAddressToContext(identity, lineGetDestinationAddressContext(remote_l));
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(remote_l), IP_PROTO_UDP);

    if (client_ls->auth_username != NULL)
    {
        remote_ls->auth_username = stringDuplicate(client_ls->auth_username);
    }
    if (client_ls->auth_password != NULL)
    {
        remote_ls->auth_password = stringDuplicate(client_ls->auth_password);
    }
    if ((client_ls->auth_username != NULL && remote_ls->auth_username == NULL) ||
        (client_ls->auth_password != NULL && remote_ls->auth_password == NULL))
        goto unpublished;
    socks5serverRecordLineUser(remote_l, remote_ls, user_handle);

    if (! socks5server_remote_map_t_insert(&client_ls->udp_remote_lines, remote_key, remote_l).inserted)
        goto unpublished;

    if (! lineCallWithRef(remote_l, tunnelNextUpStreamInit, t))
    {
        return NULL;
    }

    return remote_l;

unpublished:
    /* No next Init occurred. Settle this creator's ownership without a callback. */
    socks5serverDetachRemoteFromClient(remote_ls);
    socks5serverLinestateDestroy(remote_ls);
    lineDestroy(remote_l);
    return NULL;
}

bool socks5serverHandleUdpClientPayload(tunnel_t *t, line_t *l, socks5server_lstate_t *ls, sbuf_t *buf)
{
    socks5serverRequireCurrentLineWorker(l, "UDP client payload");

    /* A remote Init/Payload can close the provider endpoint and therefore this
     * different line.  Keep the allocation and pool identity independent of
     * that callback before touching any remote-line helper. */
    buffer_pool_t *const client_pool = lineGetBufferPool(l);
    lineRef(l);
    ls = lineGetState(l, t);

    const bool first_payload     = ! ls->udp_first_payload_validated;
    const bool association_valid = socks5serverValidateUdpClientAssociation(t, l, ls, first_payload);
    if (! lineIsAlive(l))
    {
        bufferpoolReuseBuffer(client_pool, buf);
        lineUnref(l);
        return false;
    }

    if (! association_valid)
    {
        bufferpoolReuseBuffer(client_pool, buf);
        socks5serverRejectUdpClientLine(t, l);
        lineUnref(l);
        return false;
    }
    ls->udp_first_payload_validated = true;

    const uint8_t *raw = sbufGetRawPtr(buf);
    size_t         len = sbufGetLength(buf);

    if (len < 4 || raw[0] != 0 || raw[1] != 0)
    {
        bufferpoolReuseBuffer(client_pool, buf);
        socks5serverCloseUdpClientLine(t, l);
        lineUnref(l);
        return false;
    }

    if (raw[2] != 0)
    {
        bufferpoolReuseBuffer(client_pool, buf);
        lineUnref(l);
        return true;
    }

    socks5_address_t        identity;
    socks5_address_result_t parse_res = socks5AddressDecode(raw + 3, len - 3, &identity);
    if (parse_res != kSocks5AddressComplete)
    {
        const bool empty_domain = len >= 5 && raw[3] == kSocks5AddressDomain && raw[4] == 0;
        bufferpoolReuseBuffer(client_pool, buf);
        /* An empty domain is a malformed datagram, not an association failure.
         * Other unsupported address types retain their existing close policy. */
        if (parse_res == kSocks5AddressInvalid && ! empty_domain)
        {
            socks5serverCloseUdpClientLine(t, l);
            lineUnref(l);
            return false;
        }
        lineUnref(l);
        return true;
    }

    line_t *remote_l = socks5serverGetOrCreateUdpRemoteLine(t, l, ls, &identity, &ls->user_handle);
    if (! lineIsAlive(l))
    {
        bufferpoolReuseBuffer(client_pool, buf);
        lineUnref(l);
        return false;
    }

    if (remote_l == NULL)
    {
        bufferpoolReuseBuffer(client_pool, buf);
        lineUnref(l);
        return false;
    }

    sbufShiftRight(buf, (uint32_t) (3 + identity.consumed));
    const bool remote_alive = lineCallWithRefWithBuf(remote_l, tunnelNextUpStreamPayload, t, buf);

    lineUnref(l);
    return remote_alive;
}
