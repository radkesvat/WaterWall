#include "structure.h"

#include "AuthenticationClient/interface.h"

#include "loggers/network_logger.h"

enum
{
    kVlessVersion    = 0x00,
    kVlessCmdTcp     = 0x01,
    kVlessCmdUdp     = 0x02,
    kVlessAtypIpv4   = 0x01,
    kVlessAtypDomain = 0x02,
    kVlessAtypIpv6   = 0x03
};

static sbuf_t *vlessserverAllocBuffer(line_t *l, uint32_t len)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf =
        len <= bufferpoolGetSmallBufferSize(pool) ? bufferpoolGetSmallBuffer(pool) : bufferpoolGetLargeBuffer(pool);

    buf = sbufReserveSpace(buf, len);
    sbufSetLength(buf, len);
    return buf;
}

static const char *vlessserverAuthClientStateName(authenticationclient_state_t state)
{
    switch (state)
    {
    case kAuthenticationClientStateStopped:
        return "authentication client stopped";
    case kAuthenticationClientStateConnecting:
        return "authentication client connecting";
    case kAuthenticationClientStateAuthenticating:
        return "authentication client not authenticated";
    case kAuthenticationClientStateReady:
        return "authentication client ready";
    default:
        return "authentication client state unknown";
    }
}

static const vlessserver_user_t *vlessserverFindLocalUser(tunnel_t *t, line_t *l,
                                                          const uint8_t uuid[kVlessServerUuidLen])
{
    vlessserver_tstate_t     *ts      = tunnelGetState(t);
    const vlessserver_user_t *matched = NULL;

    for (uint32_t i = 0; i < ts->user_count; ++i)
    {
        if (memoryEqual(ts->users[i].uuid, uuid, kVlessServerUuidLen))
        {
            matched = &ts->users[i];
            break;
        }
    }

    if (UNLIKELY(matched == NULL && ts->verbose))
    {
        LOGW("VlessServer: rejected unknown UUID on worker %u", (unsigned int) lineGetWID(l));
    }

    return matched;
}

static bool vlessserverAuthenticateUuid(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls,
                                        const uint8_t uuid[kVlessServerUuidLen])
{
    vlessserver_tstate_t *ts = tunnelGetState(t);

    if (ts->auth_client_tunnel == NULL)
    {
        const vlessserver_user_t *matched = vlessserverFindLocalUser(t, l, uuid);
        if (matched == NULL)
        {
            return false;
        }

        // No users database in local-list mode, so there is no user handle; keep
        // the canonical UUID as the raw password so a Router can still match by it.
        if (ls->auth_password == NULL)
        {
            char uuid_password[kVlessServerCanonicalUuidStringLen + 1U] = {0};
            wwUuidToCanonicalString(uuid, uuid_password);
            if (matched->username != NULL)
            {
                ls->auth_username = stringDuplicate(matched->username);
            }
            ls->auth_password = stringDuplicate(uuid_password);
            memoryZero(uuid_password, sizeof(uuid_password));
        }
        return true;
    }

    if (userHandleIsValid(&ls->user_handle))
    {
        return true;
    }

    authenticationclient_state_t auth_state = authenticationclientGetState(ts->auth_client_tunnel);
    if (UNLIKELY(auth_state != kAuthenticationClientStateReady))
    {
        if (ts->verbose)
        {
            LOGW("VlessServer: authentication unavailable on worker %u: %s",
                 (unsigned int) lineGetWID(l),
                 vlessserverAuthClientStateName(auth_state));
        }
        return false;
    }

    user_handle_t                             handle  = userHandleEmpty();
    authenticationclient_user_profile_t       profile = {0};
    authenticationclient_user_lookup_result_t result =
        authenticationclientGetUserByUUIDWithProfile(ts->auth_client_tunnel, uuid, &handle, &profile);

    if (UNLIKELY(result != kAuthenticationClientUserLookupOk))
    {
        if (ts->verbose)
        {
            LOGW("VlessServer: rejected UUID authentication on worker %u: %s",
                 (unsigned int) lineGetWID(l),
                 authenticationclientUserLookupResultString(result));
        }
        return false;
    }

    // Keep the resolved account name/password (from the same locked lookup) on the
    // line state so a downstream Router can match by username/password. Ownership
    // of the duplicated strings is transferred from the profile to the line state.
    if (ls->auth_username != NULL)
    {
        memoryFree(ls->auth_username);
    }
    ls->auth_username = profile.name;
    if (ls->auth_password != NULL)
    {
        memoryFree(ls->auth_password);
    }
    ls->auth_password = profile.password;

    ls->user_handle = handle;
    return true;
}

static bool vlessserverLineAuthenticated(const vlessserver_lstate_t *ls)
{
    return userHandleIsValid(&ls->user_handle) || ls->auth_password != NULL;
}

static void vlessserverRecordLineUser(line_t *l, vlessserver_lstate_t *ls)
{
    if (UNLIKELY(ls->user_handle_recorded))
    {
        return;
    }

    if (userHandleIsValid(&ls->user_handle))
    {
        lineAddUser(l, &ls->user_handle, ls->auth_username, ls->auth_password);
    }
    else if (ls->auth_username != NULL || ls->auth_password != NULL)
    {
        lineAddAuthenticatedCredentials(l, ls->auth_username, ls->auth_password);
    }
    else
    {
        return;
    }

    ls->user_handle_recorded = true;
}

static int vlessserverParseDestination(const uint8_t *buf, size_t len, address_context_t *out, size_t *consumed)
{
    if (UNLIKELY(len < 3))
    {
        return 0;
    }

    uint16_t port_be = 0;
    memoryCopy(&port_be, buf, sizeof(port_be));
    uint16_t port = be16toh(port_be);
    uint8_t  atyp = buf[2];

    if (atyp == kVlessAtypIpv4)
    {
        if (UNLIKELY(len < 2 + 1 + 4))
        {
            return 0;
        }

        ip_addr_t ip = {0};
        ip.type      = IPADDR_TYPE_V4;
        memoryCopy(&ip.u_addr.ip4.addr, buf + 3, 4);
        addresscontextSetIpPort(out, &ip, port);
        *consumed = 2 + 1 + 4;
        return 1;
    }

    if (atyp == kVlessAtypIpv6)
    {
        if (UNLIKELY(len < 2 + 1 + 16))
        {
            return 0;
        }

        ip_addr_t ip = {0};
        ip.type      = IPADDR_TYPE_V6;
        memoryCopy(&ip.u_addr.ip6, buf + 3, 16);
        addresscontextSetIpPort(out, &ip, port);
        *consumed = 2 + 1 + 16;
        return 1;
    }

    if (atyp == kVlessAtypDomain)
    {
        if (UNLIKELY(len < 2 + 1 + 1))
        {
            return 0;
        }

        uint8_t domain_len = buf[3];
        if (UNLIKELY(domain_len == 0))
        {
            return -1;
        }

        if (UNLIKELY(len < (size_t) (2 + 1 + 1 + domain_len)))
        {
            return 0;
        }

        addresscontextDomainSet(out, (const char *) (buf + 4), domain_len);
        addresscontextSetPort(out, port);
        *consumed = 2 + 1 + 1 + domain_len;
        return 1;
    }

    return -1;
}

static void vlessserverApplyDestinationContext(line_t *l, const address_context_t *target, bool udp)
{
    address_context_t *dest = lineGetDestinationAddressContext(l);

    addresscontextCopy(dest, target);
    addresscontextSetOnlyProtocol(dest, udp ? IP_PROTO_UDP : IP_PROTO_TCP);
}

bool vlessserverDrainResponse(tunnel_t *t, line_t *l, bool admitted)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);
    if (ls->response_dispatching)
    {
        return true;
    }
    lineRef(l);
    ls->response_dispatching = true;
    while (admitted || ! ls->response_paused)
    {
        sbuf_t *out = NULL;
        if (! ls->response_sent)
        {
            out               = vlessserverAllocBuffer(l, kVlessServerResponseLen);
            uint8_t *bytes    = sbufGetMutablePtr(out);
            bytes[0]          = kVlessVersion;
            bytes[1]          = 0;
            ls->response_sent = true;
        }
        else
        {
            out = bufferqueuePopFront(&ls->pending_down);
            if (out == NULL)
            {
                break;
            }
        }
        tunnelPrevDownStreamPayload(t, l, out);
        if (UNLIKELY(! lineIsAlive(l)))
        {
            lineUnref(l);
            return false;
        }
        ls = lineGetState(l, t);
        if (UNLIKELY(ls->tunnel != t || ls->phase == kVlessServerPhaseClosing))
        {
            lineUnref(l);
            return false;
        }
    }
    ls->response_dispatching = false;
    lineUnref(l);
    return true;
}

bool vlessserverForwardResponse(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vlessserver_lstate_t *ls        = lineGetState(l, t);
    bool                  has_older = bufferqueueGetBufCount(&ls->pending_down) != 0;
    if (ls->response_sent && ! ls->response_dispatching && ! has_older)
    {
        return lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, buf);
    }
    if (UNLIKELY(! bufferqueueTryPushBack(&ls->pending_down, &buf)))
    {
        lineReuseBuffer(l, buf);
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }
    /* A newly admitted reply can include its required response header. A
     * preexisting delayed FIFO remains an independent Pause-aware drain. */
    return vlessserverDrainResponse(t, l, ! has_older);
}

static bool vlessserverForwardInitial(tunnel_t *t, line_t *l)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);
    if (! vlessserverRetainActiveHead(ls) || ! bufferqueueTryAttachBudget(&ls->pending_up, &ls->upstream_budget))
    {
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }
    ls->input_bytes         = 0;
    ls->phase               = kVlessServerPhaseTcpConnecting;
    ls->branch_initializing = true;
    if (! lineCallWithRef(l, tunnelNextUpStreamInit, t))
        return false;
    ls = lineGetState(l, t);
    if (ls->tunnel != t)
        return false;
    ls->branch_initializing = false;
    if (ls->response_paused && ! lineCallWithRef(l, tunnelNextUpStreamPause, t))
        return false;
    while (ls->tunnel == t && ls->phase != kVlessServerPhaseClosing)
    {
        sbuf_t *out = bufferqueuePopFront(&ls->pending_up);
        if (out == NULL)
            return true;
        if (! lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, out))
            return false;
    }
    return false;
}

static void vlessserverDetachRemoteFromClient(vlessserver_lstate_t *remote_ls)
{
    line_t *client_line = remote_ls->client_line;

    if (client_line != NULL && remote_ls->client_line_ref_held)
    {
        if (lineIsAlive(client_line))
        {
            vlessserver_lstate_t *client_ls = lineGetState(client_line, remote_ls->tunnel);
            if (client_ls->udp_remote_line == remote_ls->line)
            {
                client_ls->udp_remote_line = NULL;
            }
        }

        lineUnref(client_line);
    }

    remote_ls->client_line          = NULL;
    remote_ls->client_line_ref_held = false;
}

static line_t *vlessserverGetOrCreateUdpRemoteLine(tunnel_t *t, line_t *client_l, vlessserver_lstate_t *client_ls)
{
    if (client_ls->udp_remote_line != NULL && lineIsAlive(client_ls->udp_remote_line))
    {
        return client_ls->udp_remote_line;
    }

    if (UNLIKELY(! addresscontextHasPort(&client_ls->udp_target)))
    {
        return NULL;
    }

    line_t               *remote_l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(client_l));
    vlessserver_lstate_t *remote_ls = lineGetState(remote_l, t);

    vlessserverLinestateInitialize(remote_ls, t, remote_l, kVlessServerLineKindUdpRemote);
    remote_ls->client_line          = client_l;
    remote_ls->client_line_ref_held = true;
    remote_ls->user_handle          = client_ls->user_handle;
    remote_ls->phase                = kVlessServerPhaseUdpConnecting;

    lineRef(client_l);

    lineGetRoutingContext(remote_l)->local_listener_port = lineGetRoutingContext(client_l)->local_listener_port;
    lineCopyUsers(remote_l, client_l);
    vlessserverApplyDestinationContext(remote_l, &client_ls->udp_target, true);
    client_ls->udp_remote_line = remote_l;

    if (UNLIKELY(! lineCallWithRef(remote_l, tunnelNextUpStreamInit, t)))
    {
        return NULL;
    }
    /* The caller holds client_l throughout Init; callbacks can replace or
     * close either exact association. Replay existing receiver pressure onto
     * the newly initialized backend before it becomes an independent source. */
    if (UNLIKELY(! lineIsAlive(client_l)))
    {
        return NULL;
    }
    client_ls = lineGetState(client_l, t);
    if (UNLIKELY(client_ls->udp_remote_line != remote_l))
    {
        return NULL;
    }
    if (UNLIKELY(client_ls->response_paused && ! lineCallWithRef(remote_l, tunnelNextUpStreamPause, t)))
    {
        return NULL;
    }
    if (! lineIsAlive(client_l) || client_ls->tunnel != t || client_ls->udp_remote_line != remote_l)
        return NULL;
    return remote_l;
}

static bool vlessserverInitialCommandIsAllowed(tunnel_t *t, uint8_t cmd)
{
    vlessserver_tstate_t *ts = tunnelGetState(t);

    if (cmd == kVlessCmdTcp)
    {
        return ts->allow_connect;
    }

    if (cmd == kVlessCmdUdp)
    {
        return ts->allow_udp;
    }

    return false;
}

static bool vlessserverStartTcpBranch(tunnel_t *t, line_t *l, const address_context_t *target)
{
    vlessserverApplyDestinationContext(l, target, false);
    return vlessserverForwardInitial(t, l);
}

static bool vlessserverStartUdpBranch(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, const address_context_t *target)
{
    addresscontextCopy(&ls->udp_target, target);
    ls->phase = kVlessServerPhaseUdpConnecting;

    lineRef(l);
    line_t *remote_l     = vlessserverGetOrCreateUdpRemoteLine(t, l, ls);
    bool    client_alive = lineIsAlive(l);
    lineUnref(l);

    if (UNLIKELY(! client_alive || ls->tunnel != t))
    {
        return false;
    }

    if (UNLIKELY(remote_l == NULL))
    {
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }

    return true;
}

static bool vlessserverHandleInitialRequest(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls,
                                            bool reject_short_password)
{
    if (reject_short_password)
    {
        LOGW("VlessServer: rejected segmented UUID authentication on worker %u", (unsigned int) lineGetWID(l));
        return vlessserverStartFallback(t, l);
    }
    if (! vlessserverGatherHeader(ls, 1))
        return true;
    if (ls->header[0] != kVlessVersion)
        return vlessserverStartFallback(t, l);
    if (! vlessserverGatherHeader(ls, 17))
        return true;
    if (! vlessserverLineAuthenticated(ls) && ! vlessserverAuthenticateUuid(t, l, ls, ls->header + 1))
        return vlessserverStartFallback(t, l);
    if (! vlessserverGatherHeader(ls, 18))
        return true;
    uint8_t addons = ls->header[17];
    if (! vlessserverGatherHeader(ls, 18U + addons))
        return true;
    if (addons != 0)
        goto malformed;
    if (! vlessserverGatherHeader(ls, 19))
        return true;
    uint8_t cmd = ls->header[18];
    if (! vlessserverInitialCommandIsAllowed(t, cmd))
        goto malformed;
    if (! vlessserverGatherHeader(ls, 22))
        return true;
    uint16_t needed;
    switch (ls->header[21])
    {
    case kVlessAtypIpv4:
        needed = 26;
        break;
    case kVlessAtypIpv6:
        needed = 38;
        break;
    case kVlessAtypDomain:
        if (! vlessserverGatherHeader(ls, 23))
            return true;
        if (ls->header[22] == 0)
            goto malformed;
        needed = 23U + ls->header[22];
        break;
    default:
        goto malformed;
    }
    if (! vlessserverGatherHeader(ls, needed))
        return true;
    address_context_t target   = {0};
    size_t            dest_len = 0;
    int               parsed   = vlessserverParseDestination(ls->header + 19, needed - 19, &target, &dest_len);
    if (parsed != 1 || ! addresscontextHasPort(&target))
    {
        addresscontextReset(&target);
        goto malformed;
    }
    ls->input_bytes -= ls->header_filled;
    ls->header_filled = 0;

    vlessserverRecordLineUser(l, ls);

    bool ok =
        cmd == kVlessCmdTcp ? vlessserverStartTcpBranch(t, l, &target) : vlessserverStartUdpBranch(t, l, ls, &target);
    addresscontextReset(&target);
    return ok;
malformed:
    vlessserverCloseLineBidirectional(t, l);
    return false;
}

static bool vlessserverDrainUdpPackets(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls)
{
    while (ls->input_bytes != 0)
    {
        if (! vlessserverGatherHeader(ls, 2))
            return true;
        uint16_t packet_size = ((uint16_t) ls->header[0] << 8U) | ls->header[1];
        if (packet_size == 0)
        {
            vlessserverCloseLineBidirectional(t, l);
            return false;
        }
        if (ls->input_bytes - 2U < packet_size)
            return true;
        buffer_pool_t *pool   = lineGetBufferPool(l);
        sbuf_t        *packet = vlessserverExtractUdpBody(ls, packet_size);

        lineRef(l);
        line_t *remote_l     = vlessserverGetOrCreateUdpRemoteLine(t, l, ls);
        bool    client_alive = lineIsAlive(l);
        lineUnref(l);

        if (UNLIKELY(! client_alive || ls->tunnel != t))
        {
            bufferpoolReuseBuffer(pool, packet);
            return false;
        }

        if (UNLIKELY(remote_l == NULL))
        {
            bufferpoolReuseBuffer(pool, packet);
            vlessserverCloseLineBidirectional(t, l);
            return false;
        }

        if (ls->phase == kVlessServerPhaseUdpWaitPacket)
        {
            ls->phase = kVlessServerPhaseUdpConnecting;
        }

        lineRef(l);
        bool remote_alive = lineCallWithRefWithBuf(remote_l, tunnelNextUpStreamPayload, t, packet);
        client_alive      = lineIsAlive(l);
        lineUnref(l);

        if (UNLIKELY(! client_alive || ls->tunnel != t))
        {
            return false;
        }

        if (UNLIKELY(! remote_alive))
        {
            continue;
        }
    }

    return true;
}

bool vlessserverDrainInput(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, bool reject_short_password)
{
    if (ls->phase == kVlessServerPhaseWaitInitial)
    {
        if (! vlessserverHandleInitialRequest(t, l, ls, reject_short_password))
            return false;
        if (ls->phase == kVlessServerPhaseWaitInitial && ls->input_bytes > kVlessServerMaxInitialBytes)
        {
            vlessserverCloseLineBidirectional(t, l);
            return false;
        }
    }

    if (ls->phase == kVlessServerPhaseUdpWaitPacket || ls->phase == kVlessServerPhaseUdpConnecting ||
        ls->phase == kVlessServerPhaseUdpEstablished)
    {
        return vlessserverDrainUdpPackets(t, l, ls);
    }

    return true;
}

static bool vlessserverHasTcpUpstreamPeer(const vlessserver_lstate_t *ls)
{
    return ls->line_kind == kVlessServerLineKindClient &&
           (ls->phase == kVlessServerPhaseFallback || ls->phase == kVlessServerPhaseTcpConnecting ||
            ls->phase == kVlessServerPhaseTcpEstablished);
}

static void vlessserverCloseUdpRemoteLineInternal(tunnel_t *t, line_t *remote_l, bool close_next)
{
    vlessserver_lstate_t *remote_ls = lineGetState(remote_l, t);

    if (UNLIKELY(remote_ls->phase == kVlessServerPhaseClosing))
    {
        return;
    }

    remote_ls->phase = kVlessServerPhaseClosing;
    lineRef(remote_l);

    vlessserverDetachRemoteFromClient(remote_ls);
    vlessserverLinestateDestroy(remote_ls);

    if (close_next && LIKELY(lineIsAlive(remote_l)))
    {
        tunnelNextUpStreamFinish(t, remote_l);
    }

    if (LIKELY(lineIsAlive(remote_l)))
    {
        lineDestroy(remote_l);
    }

    lineUnref(remote_l);
}

static void vlessserverCloseOwnedUdpRemoteLine(tunnel_t *t, vlessserver_lstate_t *client_ls, bool close_next)
{
    line_t *remote_l = client_ls->udp_remote_line;

    if (remote_l == NULL || ! lineIsAlive(remote_l))
    {
        return;
    }

    vlessserverCloseUdpRemoteLineInternal(t, remote_l, close_next);
}

static void vlessserverCloseLine(tunnel_t *t, line_t *l, vlessserver_close_origin_t origin)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->line_kind == kVlessServerLineKindUdpRemote))
    {
        vlessserverCloseUdpRemoteLineInternal(t, l, origin != kVlessServerCloseFromNext);
        return;
    }

    if (UNLIKELY(ls->phase == kVlessServerPhaseClosing))
    {
        return;
    }

    bool      close_next = origin != kVlessServerCloseFromNext && vlessserverHasTcpUpstreamPeer(ls);
    bool      close_prev = origin != kVlessServerCloseFromPrev;
    bool      use_target = ls->phase == kVlessServerPhaseFallback;
    tunnel_t *target     = use_target ? ((vlessserver_tstate_t *) tunnelGetState(t))->fallback_tunnel : NULL;

    if (origin == kVlessServerCloseFromPrev && use_target && target != NULL)
    {
        vlessserverCloseFallbackFromUpstream(t, l, ls, target);
        return;
    }

    ls->phase = kVlessServerPhaseClosing;
    lineRef(l);

    vlessserverCloseOwnedUdpRemoteLine(t, ls, origin != kVlessServerCloseFromNext);
    vlessserverLinestateDestroy(ls);

    if (close_next && LIKELY(lineIsAlive(l)))
    {
        if (use_target && target != NULL)
        {
            tunnelUpStreamFin(target, l);
        }
        else
        {
            tunnelNextUpStreamFinish(t, l);
        }
    }

    if (close_prev && LIKELY(lineIsAlive(l)))
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnref(l);
}

void vlessserverCloseLineFromUpstream(tunnel_t *t, line_t *l)
{
    vlessserverCloseLine(t, l, kVlessServerCloseFromPrev);
}

void vlessserverCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    vlessserverCloseLine(t, l, kVlessServerCloseFromNext);
}

void vlessserverCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    vlessserverCloseLine(t, l, kVlessServerCloseInternal);
}

void vlessserverOnSelectedEstablished(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls)
{
    line_t *client = l;
    if (ls->line_kind == kVlessServerLineKindUdpRemote)
    {
        ls->phase = kVlessServerPhaseUdpEstablished;
        client    = ls->client_line;
        if (UNLIKELY(client == NULL || ! lineIsAlive(client)))
        {
            vlessserverCloseLineBidirectional(t, l);
            return;
        }
    }
    lineRef(l);
    lineRef(client);
    vlessserver_lstate_t *client_ls = lineGetState(client, t);
    client_ls->phase                = client == l ? kVlessServerPhaseTcpEstablished : kVlessServerPhaseUdpEstablished;
    if (! client_ls->transport_est_sent)
    {
        bool was_dispatching            = client_ls->response_dispatching;
        client_ls->transport_est_sent   = true;
        client_ls->response_dispatching = true;
        tunnelPrevDownStreamEst(t, client);
        /* An owned UDP backend may finish while the client association survives.
         * Its death must not strand the client's response-ordering guard. */
        if (lineIsAlive(client))
        {
            client_ls = lineGetState(client, t);
            if (client_ls->tunnel == t && client_ls->phase != kVlessServerPhaseClosing)
            {
                client_ls->response_dispatching = was_dispatching;
                discard vlessserverDrainResponse(t, client, false);
            }
        }
    }
    lineUnref(client);
    lineUnref(l);
}

bool vlessserverWrapUdpPayload(line_t *l, sbuf_t **buf_io)
{
    sbuf_t  *buf     = *buf_io;
    uint32_t payload = sbufGetLength(buf);

    if (UNLIKELY(payload == 0 || payload > kVlessServerUdpMaxPacket))
    {
        return false;
    }

    if (UNLIKELY(sbufGetLeftCapacity(buf) < kVlessServerUdpHeaderLen))
    {
        buffer_pool_t *pool    = lineGetBufferPool(l);
        uint16_t       padding = max(bufferpoolGetLargeBufferPadding(pool), kVlessServerUdpHeaderLen);
        sbuf_t        *wrapped = sbufIsSplice(buf) ? bufferpoolGetSpliceBuffer(pool) : NULL;
        if (wrapped != NULL && sbufGetLeftCapacity(wrapped) < padding)
        {
            bufferpoolReuseBuffer(pool, wrapped);
            wrapped = NULL;
        }
        wrapped = sbufMoveRangeTo(pool, buf, wrapped, payload, payload, padding);
        lineReuseBuffer(l, buf);
        buf = wrapped;
    }
    sbufShiftLeft(buf, kVlessServerUdpHeaderLen);

    *buf_io = buf;

    uint8_t *ptr    = sbufGetMutablePtr(buf);
    uint16_t len_be = htobe16((uint16_t) payload);
    memoryCopy(ptr, &len_be, sizeof(len_be));
    return true;
}

void vlessserverTunnelstateDestroy(vlessserver_tstate_t *ts)
{
    if (ts->user_controller_tunnel != NULL)
    {
        tunnelOwnedChildDestroy(ts->user_controller_tunnel);
        ts->user_controller_tunnel = NULL;
    }

    ts->user_controller_node.instance = NULL;
    memoryFree(ts->user_controller_node.name);
    memoryFree(ts->user_controller_node.type);
    memoryFree(ts->user_controller_node.next);
    memoryZero(&ts->user_controller_node, sizeof(ts->user_controller_node));

    for (uint32_t i = 0; i < ts->user_count; ++i)
    {
        memoryFree(ts->users[i].username);
    }
    memoryFree(ts->users);
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}
