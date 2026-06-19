#include "structure.h"

#include "AuthenticationClient/interface.h"
#include "loggers/network_logger.h"

enum
{
    kTrojanCmdConnect      = 0x01,
    kTrojanCmdUdpAssociate = 0x03,
    kTrojanAtypIpv4        = 0x01,
    kTrojanAtypDomain      = 0x03,
    kTrojanAtypIpv6        = 0x04
};

static sbuf_t *trojanserverAllocBuffer(line_t *l, uint32_t len)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf =
        len <= bufferpoolGetSmallBufferSize(pool) ? bufferpoolGetSmallBuffer(pool) : bufferpoolGetLargeBuffer(pool);
    buf = sbufReserveSpace(buf, len);
    sbufSetLength(buf, len);
    return buf;
}

static int trojanserverHexValue(uint8_t ch)
{
    if (ch >= '0' && ch <= '9')
    {
        return (int) (ch - '0');
    }
    if (ch >= 'a' && ch <= 'f')
    {
        return (int) (ch - 'a') + 10;
    }
    if (ch >= 'A' && ch <= 'F')
    {
        return (int) (ch - 'A') + 10;
    }
    return -1;
}

static bool trojanserverDecodeSha224Hex(const uint8_t hex[kTrojanServerPasswordHexLen], uint8_t out[SHA224_DIGEST_SIZE])
{
    for (size_t i = 0; i < SHA224_DIGEST_SIZE; ++i)
    {
        int hi = trojanserverHexValue(hex[i * 2U]);
        int lo = trojanserverHexValue(hex[i * 2U + 1U]);
        if (UNLIKELY(hi < 0 || lo < 0))
        {
            memoryZero(out, SHA224_DIGEST_SIZE);
            return false;
        }
        out[i] = (uint8_t) ((hi << 4) | lo);
    }

    return true;
}

static bool trojanserverAvailablePasswordPrefixCanBeTrojan(buffer_stream_t *stream)
{
    size_t available = bufferstreamGetBufLen(stream);
    size_t inspect   = min(available, (size_t) kTrojanServerPasswordHexLen);

    for (size_t i = 0; i < inspect; ++i)
    {
        if (UNLIKELY(trojanserverHexValue(bufferstreamViewByteAt(stream, i)) < 0))
        {
            return false;
        }
    }

    if (UNLIKELY(available > kTrojanServerPasswordHexLen &&
                 bufferstreamViewByteAt(stream, kTrojanServerPasswordHexLen) != '\r'))
    {
        return false;
    }

    if (UNLIKELY(available > kTrojanServerPasswordHexLen + 1U &&
                 bufferstreamViewByteAt(stream, kTrojanServerPasswordHexLen + 1U) != '\n'))
    {
        return false;
    }

    return true;
}

static int trojanserverParseAddressBytes(const uint8_t *buf, size_t len, address_context_t *out, size_t *consumed)
{
    if (UNLIKELY(len < 1))
    {
        return 0;
    }

    uint8_t atyp = buf[0];
    if (atyp == kTrojanAtypIpv4)
    {
        if (UNLIKELY(len < 1 + 4 + 2))
        {
            return 0;
        }

        ip_addr_t ip      = {0};
        uint16_t  port_be = 0;
        ip.type           = IPADDR_TYPE_V4;
        memoryCopy(&ip.u_addr.ip4.addr, buf + 1, 4);
        memoryCopy(&port_be, buf + 5, sizeof(port_be));
        addresscontextSetIpPort(out, &ip, be16toh(port_be));
        *consumed = 1 + 4 + 2;
        return 1;
    }

    if (atyp == kTrojanAtypIpv6)
    {
        if (UNLIKELY(len < 1 + 16 + 2))
        {
            return 0;
        }

        ip_addr_t ip      = {0};
        uint16_t  port_be = 0;
        ip.type           = IPADDR_TYPE_V6;
        memoryCopy(&ip.u_addr.ip6, buf + 1, 16);
        memoryCopy(&port_be, buf + 17, sizeof(port_be));
        addresscontextSetIpPort(out, &ip, be16toh(port_be));
        *consumed = 1 + 16 + 2;
        return 1;
    }

    if (atyp == kTrojanAtypDomain)
    {
        if (UNLIKELY(len < 2))
        {
            return 0;
        }

        uint8_t domain_len = buf[1];
        if (UNLIKELY(domain_len == 0))
        {
            return -1;
        }

        if (UNLIKELY(len < (size_t) (2 + domain_len + 2)))
        {
            return 0;
        }

        addresscontextDomainSet(out, (const char *) (buf + 2), domain_len);
        uint16_t port_be = 0;
        memoryCopy(&port_be, buf + 2 + domain_len, sizeof(port_be));
        out->port = be16toh(port_be);
        *consumed = 2 + domain_len + 2;
        return 1;
    }

    return -1;
}

static hash_t trojanserverCalcAddressHash(const address_context_t *ctx)
{
    if (addresscontextIsIp(ctx))
    {
        struct
        {
            uint16_t   port;
            uint8_t    ip_type;
            uint8_t    padding[5];
            ip4_addr_t ip4;
            ip6_addr_t ip6;
        } key = {0};

        key.port    = ctx->port;
        key.ip_type = ctx->ip_address.type;

        if (ctx->ip_address.type == IPADDR_TYPE_V4)
        {
            key.ip4 = ctx->ip_address.u_addr.ip4;
        }
        else
        {
            key.ip6 = ctx->ip_address.u_addr.ip6;
        }

        return calcHashBytes(&key, sizeof(key));
    }

    struct
    {
        uint16_t port;
        uint8_t  len;
        uint8_t  bytes[UINT8_MAX];
    } key = {0};

    key.port = ctx->port;
    key.len  = ctx->domain_len;
    memoryCopy(key.bytes, ctx->domain, ctx->domain_len);
    return calcHashBytes(&key, sizeof(key.port) + sizeof(key.len) + ctx->domain_len);
}

static void trojanserverApplyDestinationContext(line_t *l, const address_context_t *target, bool udp)
{
    address_context_t *dest  = lineGetDestinationAddressContext(l);
    routing_context_t *route = lineGetRoutingContext(l);

    addresscontextAddrCopy(dest, target);
    addresscontextSetOnlyProtocol(dest, udp ? IP_PROTO_UDP : IP_PROTO_TCP);
    route->network_type = udp ? WIO_TYPE_UDP : WIO_TYPE_TCP;
}

static bool trojanserverWriteAddress(uint8_t *ptr, const address_context_t *ctx, size_t *offset)
{
    if (addresscontextIsIpType(ctx))
    {
        if (addresscontextIsIpv4(ctx))
        {
            ptr[(*offset)++] = kTrojanAtypIpv4;
            memoryCopy(ptr + *offset, &ctx->ip_address.u_addr.ip4.addr, 4);
            *offset += 4;
        }
        else if (addresscontextIsIpv6(ctx))
        {
            ptr[(*offset)++] = kTrojanAtypIpv6;
            memoryCopy(ptr + *offset, &ctx->ip_address.u_addr.ip6, 16);
            *offset += 16;
        }
        else
        {
            return false;
        }
    }
    else if (addresscontextIsDomain(ctx))
    {
        ptr[(*offset)++] = kTrojanAtypDomain;
        ptr[(*offset)++] = ctx->domain_len;
        memoryCopy(ptr + *offset, ctx->domain, ctx->domain_len);
        *offset += ctx->domain_len;
    }
    else
    {
        return false;
    }

    uint16_t port_be = htobe16(ctx->port);
    memoryCopy(ptr + *offset, &port_be, sizeof(port_be));
    *offset += sizeof(port_be);
    return true;
}

static const char *trojanserverAuthClientStateName(authenticationclient_state_t state)
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

static bool trojanserverAuthenticateHash(tunnel_t *t, line_t *l, const uint8_t sha224[SHA224_DIGEST_SIZE],
                                         user_handle_t *user_handle_out)
{
    trojanserver_tstate_t *ts = tunnelGetState(t);

    if (UNLIKELY(user_handle_out == NULL))
    {
        return false;
    }

    if (ts->auth_client_tunnel == NULL)
    {
        trojanserver_lstate_t      *ls      = lineGetState(l, t);
        const trojanserver_user_t  *matched = NULL;

        for (uint32_t i = 0; i < ts->user_count; ++i)
        {
            if (wCryptoEqual(ts->users[i].sha224, sha224, SHA224_DIGEST_SIZE))
            {
                matched = &ts->users[i];
                break;
            }
        }

        if (UNLIKELY(matched == NULL))
        {
            if (ts->verbose)
            {
                LOGW("TrojanServer: rejected local password authentication on worker %u", (unsigned int) lineGetWID(l));
            }
            return false;
        }

        if (ls->auth_username != NULL)
        {
            memoryFree(ls->auth_username);
        }
        ls->auth_username = matched->username != NULL ? stringDuplicate(matched->username) : NULL;
        if (ls->auth_password != NULL)
        {
            memoryFree(ls->auth_password);
        }
        ls->auth_password = stringDuplicate(matched->password);
        *user_handle_out  = userHandleEmpty();
        return true;
    }

    authenticationclient_state_t auth_state = authenticationclientGetState(ts->auth_client_tunnel);
    if (UNLIKELY(auth_state != kAuthenticationClientStateReady))
    {
        if (ts->verbose)
        {
            LOGW("TrojanServer: authentication unavailable on worker %u: %s",
                 (unsigned int) lineGetWID(l),
                 trojanserverAuthClientStateName(auth_state));
        }
        return false;
    }

    user_handle_t                       handle  = userHandleEmpty();
    authenticationclient_user_profile_t profile = {0};
    if (UNLIKELY(! authenticationclientGetUserBySHA224WithProfile(ts->auth_client_tunnel, sha224, &handle, &profile)))
    {
        if (ts->verbose)
        {
            LOGW("TrojanServer: rejected authentication on worker %u", (unsigned int) lineGetWID(l));
        }
        return false;
    }

    // Resolve the account name/password in the same locked lookup that produced
    // the handle and keep them on the line state so a downstream Router can match
    // by username/password without re-querying the auth client. Ownership of the
    // duplicated strings is transferred from the profile to the line state.
    trojanserver_lstate_t *ls = lineGetState(l, t);
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

    *user_handle_out = handle;
    return true;
}

static bool trojanserverLineAuthenticated(const trojanserver_lstate_t *ls)
{
    return userHandleIsValid(&ls->user_handle) || ls->auth_password != NULL;
}

static void trojanserverRecordLineUser(line_t *l, trojanserver_lstate_t *ls, const user_handle_t *user_handle)
{
    if (UNLIKELY(ls->user_handle_recorded))
    {
        return;
    }

    if (userHandleIsValid(user_handle))
    {
        lineAddUser(l, user_handle, ls->auth_username, ls->auth_password);
    }
    else if (ls->auth_username != NULL || ls->auth_password != NULL)
    {
        lineSetAuthenticatedCredentials(l, ls->auth_username, ls->auth_password);
    }
    else
    {
        return;
    }

    ls->user_handle_recorded = true;
}

static bool trojanserverFlushQueueToPrev(tunnel_t *t, line_t *l, buffer_queue_t *queue)
{
    while (bufferqueueGetBufCount(queue) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(queue);
        if (UNLIKELY(! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf)))
        {
            bufferqueueDestroy(queue);
            return false;
        }
    }

    bufferqueueDestroy(queue);
    return true;
}

static void trojanserverDetachRemoteFromClient(trojanserver_lstate_t *remote_ls)
{
    line_t *client_line = remote_ls->client_line;

    if (client_line != NULL && remote_ls->client_line_locked)
    {
        if (lineIsAlive(client_line))
        {
            trojanserver_lstate_t         *client_ls = lineGetState(client_line, remote_ls->tunnel);
            trojanserver_remote_map_t_iter it =
                trojanserver_remote_map_t_find(&client_ls->udp_remote_lines, remote_ls->remote_key);
            if (it.ref != trojanserver_remote_map_t_end(&client_ls->udp_remote_lines).ref &&
                it.ref->second == remote_ls->line)
            {
                trojanserver_remote_map_t_erase_at(&client_ls->udp_remote_lines, it);
            }
        }

        lineUnlock(client_line);
    }

    remote_ls->client_line        = NULL;
    remote_ls->client_line_locked = false;
}

static line_t *trojanserverGetOrCreateUdpRemoteLine(tunnel_t *t, line_t *client_l, trojanserver_lstate_t *client_ls,
                                                    const address_context_t *target)
{
    hash_t remote_key = trojanserverCalcAddressHash(target);

    trojanserver_remote_map_t_iter it = trojanserver_remote_map_t_find(&client_ls->udp_remote_lines, remote_key);
    if (it.ref != trojanserver_remote_map_t_end(&client_ls->udp_remote_lines).ref)
    {
        return it.ref->second;
    }

    line_t                *remote_l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(client_l));
    trojanserver_lstate_t *remote_ls = lineGetState(remote_l, t);

    trojanserverLinestateInitialize(remote_ls, t, remote_l, kTrojanServerLineKindUdpRemote);
    remote_ls->client_line        = client_l;
    remote_ls->client_line_locked = true;
    remote_ls->remote_key         = remote_key;
    remote_ls->user_handle        = client_ls->user_handle;
    remote_ls->branch             = kTrojanServerBranchTrojan;
    remote_ls->phase              = kTrojanServerPhaseUdpConnecting;

    lineLock(client_l);

    lineGetRoutingContext(remote_l)->local_listener_port = lineGetRoutingContext(client_l)->local_listener_port;
    trojanserverApplyDestinationContext(remote_l, target, true);

    // Carry the resolved credentials from the client line so the backend UDP line
    // also surfaces them for downstream username/password routing.
    if (client_ls->auth_username != NULL)
    {
        remote_ls->auth_username = stringDuplicate(client_ls->auth_username);
    }
    if (client_ls->auth_password != NULL)
    {
        remote_ls->auth_password = stringDuplicate(client_ls->auth_password);
    }
    trojanserverRecordLineUser(remote_l, remote_ls, &remote_ls->user_handle);

    trojanserver_remote_map_t_insert(&client_ls->udp_remote_lines, remote_key, remote_l);

    if (UNLIKELY(! withLineLocked(remote_l, tunnelNextUpStreamInit, t)))
    {
        return NULL;
    }

    return remote_l;
}

static tunnel_t *trojanserverSelectedUpstream(tunnel_t *t, const trojanserver_lstate_t *ls)
{
    trojanserver_tstate_t *ts = tunnelGetState(t);

    if (ls->branch == kTrojanServerBranchFallback)
    {
        return ts->fallback_tunnel;
    }

    return NULL;
}

static size_t trojanserverFallbackPendingCount(const trojanserver_lstate_t *ls)
{
    return ls->fallback_pending_up != NULL ? bufferqueueGetBufCount(ls->fallback_pending_up) : 0;
}

static buffer_queue_t *trojanserverEnsureFallbackPendingQueue(trojanserver_lstate_t *ls)
{
    if (ls->fallback_pending_up == NULL)
    {
        ls->fallback_pending_up  = memoryAllocate(sizeof(*ls->fallback_pending_up));
        *ls->fallback_pending_up = bufferqueueCreate(kTrojanServerBufferQueueCap);
    }

    return ls->fallback_pending_up;
}

static uint32_t trojanserverFallbackDelayWithJitter(const trojanserver_tstate_t *ts)
{
    uint32_t delay_ms  = ts->fallback_intentional_delay_ms;
    uint32_t jitter_ms = ts->fallback_intentional_delay_jitter_ms;

    if (delay_ms == 0 || jitter_ms == 0)
    {
        return delay_ms;
    }

    uint32_t lower = jitter_ms >= delay_ms ? 0 : delay_ms - jitter_ms;
    uint32_t upper = UINT32_MAX - delay_ms < jitter_ms ? UINT32_MAX : delay_ms + jitter_ms;
    uint64_t span  = (uint64_t) upper - (uint64_t) lower + 1ULL;

    return lower + (uint32_t) (fastRand64() % span);
}

static void trojanserverForwardPendingFallbackFinish(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    tunnel_t *fallback = trojanserverSelectedUpstream(t, ls);

    if (! ls->fallback_up_finish_pending || trojanserverFallbackPendingCount(ls) > 0 || fallback == NULL ||
        ls->fallback_up_finished)
    {
        return;
    }

    ls->fallback_up_finished = true;
    ls->phase                = kTrojanServerPhaseClosing;
    trojanserverLinestateDestroy(ls);
    tunnelUpStreamFin(fallback, l);
}

static void trojanserverDelayedFallbackPayloadTask(tunnel_t *t, line_t *l)
{
    trojanserver_tstate_t *ts = tunnelGetState(t);
    trojanserver_lstate_t *ls = lineGetState(l, t);

    ls->fallback_delay_scheduled = false;

    size_t queued = trojanserverFallbackPendingCount(ls);
    while (queued > 0)
    {
        queued -= 1;

        sbuf_t   *buf      = bufferqueuePopFront(ls->fallback_pending_up);
        tunnel_t *fallback = trojanserverSelectedUpstream(t, ls);
        if (fallback == NULL || ls->branch != kTrojanServerBranchFallback || ls->fallback_up_finished)
        {
            lineReuseBuffer(l, buf);
        }
        else
        {
            tunnelUpStreamPayload(fallback, l, buf);
        }

        if (! lineIsAlive(l))
        {
            return;
        }

        ls = lineGetState(l, t);
    }

    if (trojanserverFallbackPendingCount(ls) > 0 && ! ls->fallback_delay_scheduled)
    {
        ls->fallback_delay_scheduled = true;
        lineScheduleDelayedTask(l, trojanserverDelayedFallbackPayloadTask, trojanserverFallbackDelayWithJitter(ts), t);
        return;
    }

    trojanserverForwardPendingFallbackFinish(t, l, ls);
}

bool trojanserverSendFallbackPayload(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, sbuf_t *buf)
{
    trojanserver_tstate_t *ts       = tunnelGetState(t);
    tunnel_t             *fallback = trojanserverSelectedUpstream(t, ls);

    if (fallback == NULL || ls->branch != kTrojanServerBranchFallback || ls->fallback_up_finished ||
        ls->fallback_up_finish_pending)
    {
        lineReuseBuffer(l, buf);
        return false;
    }

    if (ts->fallback_intentional_delay_ms == 0)
    {
        tunnelUpStreamPayload(fallback, l, buf);
        return lineIsAlive(l);
    }

    buffer_queue_t *pending = trojanserverEnsureFallbackPendingQueue(ls);
    bufferqueuePushBack(pending, buf);
    if (UNLIKELY(bufferqueueGetBufLen(pending) > kTrojanServerMaxPendingBytes))
    {
        LOGE("TrojanServer: fallback payload queue overflow, size=%zu limit=%u",
             bufferqueueGetBufLen(pending),
             (unsigned int) kTrojanServerMaxPendingBytes);
        trojanserverCloseLineBidirectional(t, l);
        return false;
    }

    if (! ls->fallback_delay_scheduled)
    {
        ls->fallback_delay_scheduled = true;
        lineScheduleDelayedTask(l, trojanserverDelayedFallbackPayloadTask, trojanserverFallbackDelayWithJitter(ts), t);
    }

    return true;
}

static bool trojanserverForwardSelectedPayload(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, sbuf_t *buf)
{
    if (ls->branch == kTrojanServerBranchFallback)
    {
        return trojanserverSendFallbackPayload(t, l, ls, buf);
    }

    if (ls->branch == kTrojanServerBranchTrojan)
    {
        return withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf);
    }

    lineReuseBuffer(l, buf);
    return false;
}

static bool trojanserverStartTrojanBranch(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls,
                                          trojanserver_phase_t connecting_phase)
{
    ls->branch = kTrojanServerBranchTrojan;
    ls->phase  = connecting_phase;

    return withLineLocked(l, tunnelNextUpStreamInit, t);
}

static bool trojanserverStartFallback(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    trojanserver_tstate_t *ts = tunnelGetState(t);

    if (UNLIKELY(ts->fallback_tunnel == NULL))
    {
        trojanserverCloseLineBidirectional(t, l);
        return false;
    }

    sbuf_t *first = bufferstreamFullRead(&ls->in_stream);

    lineLock(l);

    ls->branch = kTrojanServerBranchFallback;
    ls->phase  = kTrojanServerPhaseFallback;
    tunnelUpStreamInit(ts->fallback_tunnel, l);

    if (lineIsAlive(l) && first != NULL)
    {
        discard trojanserverSendFallbackPayload(t, l, ls, first);
        first = NULL;
    }

    if (first != NULL)
    {
        lineReuseBuffer(l, first);
    }

    bool alive = lineIsAlive(l);
    lineUnlock(l);
    return alive;
}

static bool trojanserverInitialCommandIsAllowed(tunnel_t *t, uint8_t cmd)
{
    trojanserver_tstate_t *ts = tunnelGetState(t);

    if (cmd == kTrojanCmdConnect)
    {
        return ts->allow_connect;
    }

    if (cmd == kTrojanCmdUdpAssociate)
    {
        return ts->allow_udp;
    }

    return false;
}

static bool trojanserverForwardBufferedTcpPayload(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    while (! bufferstreamIsEmpty(&ls->in_stream))
    {
        sbuf_t *buf = bufferstreamIdealRead(&ls->in_stream);
        if (UNLIKELY(! trojanserverForwardSelectedPayload(t, l, ls, buf)))
        {
            return false;
        }
    }

    return true;
}

static bool trojanserverUdpPacketHeaderLength(buffer_stream_t *stream, uint16_t *packet_size, uint16_t *full_len)
{
    if (UNLIKELY(bufferstreamGetBufLen(stream) <= 0))
    {
        return true;
    }

    uint8_t  atyp       = bufferstreamViewByteAt(stream, 0);
    uint16_t header_len = 0;

    switch (atyp)
    {
    case kTrojanAtypIpv4:
        header_len = 1 + 4 + 2 + 2 + 2;
        if (UNLIKELY(bufferstreamGetBufLen(stream) < header_len))
        {
            return true;
        }
        *packet_size = ((uint16_t) bufferstreamViewByteAt(stream, 1 + 4 + 2) << 8U) |
                       bufferstreamViewByteAt(stream, 1 + 4 + 2 + 1);
        break;

    case kTrojanAtypDomain:
        if (UNLIKELY(bufferstreamGetBufLen(stream) < 1 + 1))
        {
            return true;
        }
        {
            uint8_t domain_len = bufferstreamViewByteAt(stream, 1);
            if (UNLIKELY(domain_len == 0))
            {
                return false;
            }
            header_len = (uint16_t) (1 + 1 + domain_len + 2 + 2 + 2);
            if (UNLIKELY(bufferstreamGetBufLen(stream) < header_len))
            {
                return true;
            }
            *packet_size = ((uint16_t) bufferstreamViewByteAt(stream, 1 + 1 + domain_len + 2) << 8U) |
                           bufferstreamViewByteAt(stream, 1 + 1 + domain_len + 2 + 1);
        }
        break;

    case kTrojanAtypIpv6:
        header_len = 1 + 16 + 2 + 2 + 2;
        if (UNLIKELY(bufferstreamGetBufLen(stream) < header_len))
        {
            return true;
        }
        *packet_size = ((uint16_t) bufferstreamViewByteAt(stream, 1 + 16 + 2) << 8U) |
                       bufferstreamViewByteAt(stream, 1 + 16 + 2 + 1);
        break;

    default:
        return false;
    }

    if (UNLIKELY(*packet_size > kTrojanServerUdpMaxPacket))
    {
        return false;
    }

    if (UNLIKELY(bufferstreamViewByteAt(stream, (size_t) header_len - 2U) != '\r' ||
                 bufferstreamViewByteAt(stream, (size_t) header_len - 1U) != '\n'))
    {
        return false;
    }

    *full_len = (uint16_t) (header_len + *packet_size);
    return true;
}

static bool trojanserverParseUdpPacketTarget(sbuf_t *packet, address_context_t *target, uint16_t *header_len,
                                             uint16_t *packet_size)
{
    const uint8_t *raw      = sbufGetRawPtr(packet);
    size_t         len      = sbufGetLength(packet);
    size_t         addr_len = 0;

    int parse_res = trojanserverParseAddressBytes(raw, len, target, &addr_len);
    if (UNLIKELY(parse_res != 1 || len < addr_len + 4U))
    {
        return false;
    }

    uint16_t size_be = 0;
    memoryCopy(&size_be, raw + addr_len, sizeof(size_be));
    *packet_size = be16toh(size_be);

    if (UNLIKELY(*packet_size > kTrojanServerUdpMaxPacket || raw[addr_len + 2U] != '\r' || raw[addr_len + 3U] != '\n' ||
                 len != addr_len + 4U + *packet_size))
    {
        return false;
    }

    *header_len = (uint16_t) (addr_len + 4U);
    return true;
}

static bool trojanserverDrainUdpPackets(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    while (! bufferstreamIsEmpty(&ls->in_stream))
    {
        uint16_t packet_size = 0;
        uint16_t full_len    = 0;

        if (UNLIKELY(! trojanserverUdpPacketHeaderLength(&ls->in_stream, &packet_size, &full_len)))
        {
            trojanserverCloseLineBidirectional(t, l);
            return false;
        }

        if (UNLIKELY(bufferstreamGetBufLen(&ls->in_stream) < full_len))
        {
            return true;
        }

        sbuf_t           *packet             = bufferstreamReadExact(&ls->in_stream, full_len);
        address_context_t target             = {0};
        uint16_t          header_len         = 0;
        uint16_t          parsed_packet_size = 0;

        if (UNLIKELY(! trojanserverParseUdpPacketTarget(packet, &target, &header_len, &parsed_packet_size) ||
                     parsed_packet_size != packet_size))
        {
            addresscontextReset(&target);
            lineReuseBuffer(l, packet);
            trojanserverCloseLineBidirectional(t, l);
            return false;
        }

        if (UNLIKELY(! addresscontextHasPort(&target)))
        {
            addresscontextReset(&target);
            lineReuseBuffer(l, packet);
            trojanserverCloseLineBidirectional(t, l);
            return false;
        }

        buffer_pool_t *pool     = lineGetBufferPool(l);
        line_t        *remote_l = trojanserverGetOrCreateUdpRemoteLine(t, l, ls, &target);
        addresscontextReset(&target);
        sbufShiftRight(packet, header_len);

        if (UNLIKELY(remote_l == NULL))
        {
            bufferpoolReuseBuffer(pool, packet);
            return false;
        }

        ls->phase = kTrojanServerPhaseUdpEstablished;
        // Sending to a backend UDP line can synchronously close that backend. Hold the
        // Trojan client line too, so we can safely decide whether to keep draining.
        lineLock(l);
        bool remote_alive = withLineLockedWithBuf(remote_l, tunnelNextUpStreamPayload, t, packet);
        bool client_alive = lineIsAlive(l);
        lineUnlock(l);

        if (UNLIKELY(! client_alive))
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

static bool trojanserverHandleInitialRequest(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls,
                                             bool reject_short_password)
{
    size_t available = bufferstreamGetBufLen(&ls->in_stream);

    if (UNLIKELY(! trojanserverAvailablePasswordPrefixCanBeTrojan(&ls->in_stream)))
    {
        if (trojanserverLineAuthenticated(ls))
        {
            trojanserverCloseLineBidirectional(t, l);
            return false;
        }
        return trojanserverStartFallback(t, l, ls);
    }

    if (UNLIKELY(available < kTrojanServerPasswordHexLen))
    {
        if (UNLIKELY(reject_short_password))
        {
            // Not verbose-gated by design: a split credential in the very first payload is a
            // probe-resistance/hardening signal we always surface, unlike the per-attempt
            // auth-failure logs (see description.md).
            LOGW("TrojanServer: rejected segmented password authentication on worker %u",
                 (unsigned int) lineGetWID(l));
            return trojanserverStartFallback(t, l, ls);
        }
        return true;
    }

    if (! trojanserverLineAuthenticated(ls))
    {
        uint8_t sha224[SHA224_DIGEST_SIZE] = {0};
        uint8_t password_hex[kTrojanServerPasswordHexLen] = {0};
        bufferstreamViewBytesAt(&ls->in_stream, 0, password_hex, sizeof(password_hex));
        if (UNLIKELY(! trojanserverDecodeSha224Hex(password_hex, sha224)))
        {
            memoryZero(password_hex, sizeof(password_hex));
            return trojanserverStartFallback(t, l, ls);
        }
        memoryZero(password_hex, sizeof(password_hex));

        user_handle_t user_handle = userHandleEmpty();
        if (UNLIKELY(! trojanserverAuthenticateHash(t, l, sha224, &user_handle)))
        {
            memoryZero(sha224, sizeof(sha224));
            return trojanserverStartFallback(t, l, ls);
        }
        memoryZero(sha224, sizeof(sha224));

        ls->user_handle = user_handle;
    }

    if (UNLIKELY(available < kTrojanServerPasswordHexLen + kTrojanServerCrlfLen))
    {
        return true;
    }

    uint8_t password_head[kTrojanServerPasswordHexLen + kTrojanServerCrlfLen] = {0};
    bufferstreamViewBytesAt(&ls->in_stream, 0, password_head, sizeof(password_head));
    if (UNLIKELY(password_head[kTrojanServerPasswordHexLen] != '\r' ||
                 password_head[kTrojanServerPasswordHexLen + 1U] != '\n'))
    {
        return trojanserverStartFallback(t, l, ls);
    }

    if (UNLIKELY(available < kTrojanServerPasswordHexLen + kTrojanServerCrlfLen + 1U))
    {
        return true;
    }

    uint8_t request_buf[kTrojanServerInitialMaxReqLen] = {0};
    size_t  request_available = available - (kTrojanServerPasswordHexLen + kTrojanServerCrlfLen);
    size_t  copy_len          = min(sizeof(request_buf), request_available);
    bufferstreamViewBytesAt(&ls->in_stream, kTrojanServerPasswordHexLen + kTrojanServerCrlfLen, request_buf, copy_len);

    uint8_t cmd = request_buf[0];
    if (UNLIKELY(! trojanserverInitialCommandIsAllowed(t, cmd)))
    {
        trojanserverCloseLineBidirectional(t, l);
        return false;
    }

    address_context_t target   = {0};
    size_t            addr_len = 0;
    int               parse_res =
        trojanserverParseAddressBytes(request_buf + 1U, copy_len > 1U ? copy_len - 1U : 0U, &target, &addr_len);
    if (UNLIKELY(parse_res == 0))
    {
        addresscontextReset(&target);
        if (UNLIKELY(available > kTrojanServerMaxInitialBytes))
        {
            trojanserverCloseLineBidirectional(t, l);
            return false;
        }
        return true;
    }

    if (UNLIKELY(parse_res < 0))
    {
        addresscontextReset(&target);
        trojanserverCloseLineBidirectional(t, l);
        return false;
    }

    size_t request_len = 1U + addr_len + kTrojanServerCrlfLen;
    if (UNLIKELY(request_available < request_len))
    {
        addresscontextReset(&target);
        if (UNLIKELY(available > kTrojanServerMaxInitialBytes))
        {
            trojanserverCloseLineBidirectional(t, l);
            return false;
        }
        return true;
    }

    if (UNLIKELY(request_buf[1U + addr_len] != '\r' || request_buf[1U + addr_len + 1U] != '\n'))
    {
        addresscontextReset(&target);
        trojanserverCloseLineBidirectional(t, l);
        return false;
    }

    lineReuseBuffer(
        l, bufferstreamReadExact(&ls->in_stream, kTrojanServerPasswordHexLen + kTrojanServerCrlfLen + request_len));

    trojanserverRecordLineUser(l, ls, &ls->user_handle);

    if (cmd == kTrojanCmdConnect)
    {
        if (UNLIKELY(! addresscontextHasPort(&target)))
        {
            addresscontextReset(&target);
            trojanserverCloseLineBidirectional(t, l);
            return false;
        }

        trojanserverApplyDestinationContext(l, &target, false);
        addresscontextReset(&target);

        if (UNLIKELY(! trojanserverStartTrojanBranch(t, l, ls, kTrojanServerPhaseTcpConnecting)))
        {
            return false;
        }

        return trojanserverForwardBufferedTcpPayload(t, l, ls);
    }

    // The address in a Trojan UDP ASSOCIATE request is only the associate request address.
    // The real UDP target is carried by each subsequent Trojan UDP packet.
    addresscontextReset(&target);
    ls->branch = kTrojanServerBranchTrojan;
    ls->phase  = kTrojanServerPhaseUdpWaitPacket;
    return trojanserverDrainUdpPackets(t, l, ls);
}

bool trojanserverDrainInput(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, bool reject_short_password)
{
    if (ls->phase == kTrojanServerPhaseWaitInitial)
    {
        return trojanserverHandleInitialRequest(t, l, ls, reject_short_password);
    }

    if (ls->phase == kTrojanServerPhaseUdpWaitPacket || ls->phase == kTrojanServerPhaseUdpConnecting ||
        ls->phase == kTrojanServerPhaseUdpEstablished)
    {
        return trojanserverDrainUdpPackets(t, l, ls);
    }

    return true;
}

static bool trojanserverHasUpstreamPeer(const trojanserver_lstate_t *ls)
{
    return ls->branch == kTrojanServerBranchFallback || ls->phase == kTrojanServerPhaseTcpConnecting ||
           ls->phase == kTrojanServerPhaseTcpEstablished;
}

static void trojanserverCloseUdpRemoteLineInternal(tunnel_t *t, line_t *remote_l, bool close_next)
{
    trojanserver_lstate_t *remote_ls = lineGetState(remote_l, t);

    if (UNLIKELY(remote_ls->phase == kTrojanServerPhaseClosing))
    {
        return;
    }

    remote_ls->phase = kTrojanServerPhaseClosing;
    lineLock(remote_l);

    trojanserverDetachRemoteFromClient(remote_ls);
    trojanserverLinestateDestroy(remote_ls);

    if (close_next && LIKELY(lineIsAlive(remote_l)))
    {
        tunnelNextUpStreamFinish(t, remote_l);
    }

    if (LIKELY(lineIsAlive(remote_l)))
    {
        lineDestroy(remote_l);
    }

    lineUnlock(remote_l);
}

static void trojanserverCloseUdpRemoteLines(tunnel_t *t, trojanserver_lstate_t *client_ls)
{
    size_t line_count = trojanserver_remote_map_t_size(&client_ls->udp_remote_lines);
    if (LIKELY(line_count == 0))
    {
        return;
    }

    line_t **remote_lines = memoryAllocate(sizeof(*remote_lines) * line_count);
    size_t   index        = 0;

    c_foreach(it, trojanserver_remote_map_t, client_ls->udp_remote_lines)
    {
        remote_lines[index++] = it.ref->second;
    }

    for (size_t i = 0; i < index; ++i)
    {
        line_t *remote_l = remote_lines[i];
        if (LIKELY(lineIsAlive(remote_l)))
        {
            trojanserverCloseUdpRemoteLineInternal(t, remote_l, true);
        }
    }

    memoryFree(remote_lines);
}

static void trojanserverCloseLine(tunnel_t *t, line_t *l, trojanserver_close_origin_t origin)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->line_kind == kTrojanServerLineKindUdpRemote))
    {
        trojanserverCloseUdpRemoteLineInternal(t, l, origin != kTrojanServerCloseFromNext);
        return;
    }

    if (UNLIKELY(ls->phase == kTrojanServerPhaseClosing))
    {
        return;
    }

    bool      has_peer   = trojanserverHasUpstreamPeer(ls);
    bool      close_next = origin != kTrojanServerCloseFromNext && has_peer;
    bool      close_prev = origin != kTrojanServerCloseFromPrev;
    bool      use_target = ls->branch == kTrojanServerBranchFallback;
    tunnel_t *target     = use_target ? trojanserverSelectedUpstream(t, ls) : NULL;

    if (origin == kTrojanServerCloseFromPrev && use_target && target != NULL &&
        trojanserverFallbackPendingCount(ls) > 0)
    {
        ls->fallback_up_finish_pending = true;
        return;
    }

    ls->phase = kTrojanServerPhaseClosing;
    lineLock(l);
    trojanserverCloseUdpRemoteLines(t, ls);
    trojanserverLinestateDestroy(ls);

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

    lineUnlock(l);
}

void trojanserverCloseLineFromUpstream(tunnel_t *t, line_t *l)
{
    trojanserverCloseLine(t, l, kTrojanServerCloseFromPrev);
}

void trojanserverCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    trojanserverCloseLine(t, l, kTrojanServerCloseFromNext);
}

void trojanserverCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    trojanserverCloseLine(t, l, kTrojanServerCloseInternal);
}

void trojanserverOnSelectedEstablished(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    buffer_queue_t down_local = bufferqueueCreate(kTrojanServerBufferQueueCap);

    while (bufferqueueGetBufCount(&ls->pending_down) > 0)
    {
        bufferqueuePushBack(&down_local, bufferqueuePopFront(&ls->pending_down));
    }

    if (UNLIKELY(ls->line_kind == kTrojanServerLineKindUdpRemote))
    {
        if (ls->phase == kTrojanServerPhaseUdpConnecting)
        {
            ls->phase = kTrojanServerPhaseUdpEstablished;
        }

        line_t *client_l = ls->client_line;
        if (UNLIKELY(client_l == NULL || ! lineIsAlive(client_l)))
        {
            bufferqueueDestroy(&down_local);
            trojanserverCloseLineBidirectional(t, l);
            return;
        }

        trojanserverFlushQueueToPrev(t, client_l, &down_local);
        return;
    }

    if (ls->branch == kTrojanServerBranchTrojan)
    {
        if (ls->phase == kTrojanServerPhaseTcpConnecting)
        {
            ls->phase = kTrojanServerPhaseTcpEstablished;
        }
        else if (ls->phase == kTrojanServerPhaseUdpConnecting)
        {
            ls->phase = kTrojanServerPhaseUdpEstablished;
        }
    }

    if (UNLIKELY(! withLineLocked(l, tunnelPrevDownStreamEst, t)))
    {
        bufferqueueDestroy(&down_local);
        return;
    }

    trojanserverFlushQueueToPrev(t, l, &down_local);
}

bool trojanserverWrapUdpPayload(line_t *l, sbuf_t **buf_io)
{
    address_context_t *addr_ctx = lineGetDestinationAddressContext(l);
    sbuf_t            *buf      = *buf_io;
    uint32_t           payload  = sbufGetLength(buf);
    size_t             addr_len = 0;

    if (UNLIKELY(payload > UINT16_MAX))
    {
        return false;
    }

    if (addresscontextIsIpType(addr_ctx))
    {
        addr_len = addresscontextIsIpv6(addr_ctx) ? (size_t) 1 + 16 + 2 : (size_t) 1 + 4 + 2;
    }
    else if (addresscontextIsDomain(addr_ctx))
    {
        addr_len = (size_t) 1 + 1 + addr_ctx->domain_len + 2;
    }
    else
    {
        return false;
    }

    size_t header_len = addr_len + 2U + kTrojanServerCrlfLen;
    if (UNLIKELY(sbufGetLeftCapacity(buf) < header_len))
    {
        sbuf_t  *wrapped = trojanserverAllocBuffer(l, (uint32_t) (payload + header_len));
        uint8_t *dst     = sbufGetMutablePtr(wrapped);
        memoryCopy(dst + header_len, sbufGetRawPtr(buf), payload);
        lineReuseBuffer(l, buf);
        buf = wrapped;
    }
    else
    {
        sbufShiftLeft(buf, (uint32_t) header_len);
    }

    *buf_io = buf;

    uint8_t *ptr = sbufGetMutablePtr(buf);
    size_t   off = 0;
    if (UNLIKELY(! trojanserverWriteAddress(ptr, addr_ctx, &off)))
    {
        return false;
    }

    uint16_t payload_be = htobe16((uint16_t) payload);
    memoryCopy(ptr + off, &payload_be, sizeof(payload_be));
    off += sizeof(payload_be);
    ptr[off++] = '\r';
    ptr[off++] = '\n';
    assert(off == header_len);
    return true;
}

void trojanserverTunnelstateDestroy(trojanserver_tstate_t *ts)
{
    if (ts->user_controller_tunnel != NULL)
    {
        ts->user_controller_tunnel->onDestroy(ts->user_controller_tunnel);
        ts->user_controller_tunnel = NULL;
    }

    ts->user_controller_node.instance = NULL;
    memoryFree(ts->user_controller_node.name);
    memoryFree(ts->user_controller_node.type);
    memoryFree(ts->user_controller_node.next);
    memorySet(&ts->user_controller_node, 0, sizeof(ts->user_controller_node));

    for (uint32_t i = 0; i < ts->user_count; ++i)
    {
        wCryptoZero(ts->users[i].sha224, sizeof(ts->users[i].sha224));
        memoryFree(ts->users[i].username);
        memoryFree(ts->users[i].password);
    }
    memoryFree(ts->users);

    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}
