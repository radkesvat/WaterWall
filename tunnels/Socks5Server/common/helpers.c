#include "structure.h"

#include "AuthenticationClient/interface.h"
#include "loggers/network_logger.h"

enum
{
    kSocks5Version               = 0x05,
    kSocks5NoAuthMethod          = 0x00,
    kSocks5UserPassMethod        = 0x02,
    kSocks5NoAcceptable          = 0xFF,
    kSocks5CommandConnect        = 0x01,
    kSocks5CommandBind           = 0x02,
    kSocks5CommandUdpAssoc       = 0x03,
    kSocks5AddrTypeIpv4          = 0x01,
    kSocks5AddrTypeDomain        = 0x03,
    kSocks5AddrTypeIpv6          = 0x04,
    kSocks5AuthVersion           = 0x01,
    kSocks5ReplySucceeded        = 0x00,
    kSocks5ReplyGeneralFailure   = 0x01,
    kSocks5ReplyCmdNotSupported  = 0x07,
    kSocks5ReplyAddrNotSupported = 0x08
};

static uint16_t socks5serverGetLocalPort(const line_t *l)
{
    const routing_context_t *route = lineGetRoutingContext((line_t *) l);
    if (route->local_listener_port != 0)
    {
        return route->local_listener_port;
    }

    return lineGetSourceAddressContext((line_t *) l)->port;
}

static hash_t socks5serverCalcAddressHash(const address_context_t *ctx)
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

static sbuf_t *socks5serverAllocBuffer(line_t *l, uint32_t len)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf =
        len <= bufferpoolGetSmallBufferSize(pool) ? bufferpoolGetSmallBuffer(pool) : bufferpoolGetLargeBuffer(pool);
    buf = sbufReserveSpace(buf, len);
    sbufSetLength(buf, len);
    return buf;
}

static bool socks5serverFlushQueueToNext(tunnel_t *t, line_t *l, buffer_queue_t *queue)
{
    while (bufferqueueGetBufCount(queue) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(queue);
        if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf))
        {
            bufferqueueDestroy(queue);
            return false;
        }
    }

    bufferqueueDestroy(queue);
    return true;
}

static bool socks5serverFlushQueueToPrev(tunnel_t *t, line_t *l, buffer_queue_t *queue)
{
    while (bufferqueueGetBufCount(queue) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(queue);
        if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf))
        {
            bufferqueueDestroy(queue);
            return false;
        }
    }

    bufferqueueDestroy(queue);
    return true;
}

static bool socks5serverWriteAddress(uint8_t *ptr, const address_context_t *ctx, size_t *offset)
{
    if (addresscontextIsIpType(ctx))
    {
        if (addresscontextIsIpv4(ctx))
        {
            ptr[(*offset)++] = kSocks5AddrTypeIpv4;
            memoryCopy(ptr + *offset, &ctx->ip_address.u_addr.ip4.addr, 4);
            *offset += 4;
        }
        else if (addresscontextIsIpv6(ctx))
        {
            ptr[(*offset)++] = kSocks5AddrTypeIpv6;
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
        ptr[(*offset)++] = kSocks5AddrTypeDomain;
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

static sbuf_t *socks5serverCreateMethodReply(line_t *l, uint8_t method)
{
    sbuf_t  *buf = socks5serverAllocBuffer(l, 2);
    uint8_t *ptr = sbufGetMutablePtr(buf);
    ptr[0]       = kSocks5Version;
    ptr[1]       = method;
    return buf;
}

static sbuf_t *socks5serverCreateAuthReply(line_t *l, uint8_t status)
{
    sbuf_t  *buf = socks5serverAllocBuffer(l, 2);
    uint8_t *ptr = sbufGetMutablePtr(buf);
    ptr[0]       = kSocks5AuthVersion;
    ptr[1]       = status;
    return buf;
}

sbuf_t *socks5serverCreateCommandReply(line_t *l, uint8_t rep, const address_context_t *ctx)
{
    address_context_t        zero_addr  = {0};
    const address_context_t *reply_addr = ctx;

    if (reply_addr == NULL)
    {
        addresscontextSetIpAddressPort(&zero_addr, "0.0.0.0", 0);
        reply_addr = &zero_addr;
    }

    size_t addr_len = 1 + 4 + 2;
    if (addresscontextIsIp(reply_addr))
    {
        addr_len = reply_addr->ip_address.type == IPADDR_TYPE_V6 ? (1 + 16 + 2) : (1 + 4 + 2);
    }
    else if (addresscontextIsDomain(reply_addr))
    {
        addr_len = (size_t) 1 + 1 + reply_addr->domain_len + 2;
    }

    sbuf_t  *buf = socks5serverAllocBuffer(l, (uint32_t) (3 + addr_len));
    uint8_t *ptr = sbufGetMutablePtr(buf);
    size_t   off = 0;

    ptr[off++] = kSocks5Version;
    ptr[off++] = rep;
    ptr[off++] = 0;
    if (! socks5serverWriteAddress(ptr, reply_addr, &off))
    {
        lineReuseBuffer(l, buf);
        return NULL;
    }

    return buf;
}

static int socks5serverParseAddressBytes(const uint8_t *buf, size_t len, address_context_t *out, size_t *consumed)
{
    if (len < 1)
    {
        return 0;
    }

    uint8_t atyp = buf[0];
    if (atyp == kSocks5AddrTypeIpv4)
    {
        if (len < 1 + 4 + 2)
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

    if (atyp == kSocks5AddrTypeIpv6)
    {
        if (len < 1 + 16 + 2)
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

    if (atyp == kSocks5AddrTypeDomain)
    {
        if (len < 2)
        {
            return 0;
        }

        uint8_t domain_len = buf[1];
        if (len < (size_t) (2 + domain_len + 2) || domain_len == 0)
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

static void socks5serverApplyDestinationContext(line_t *l, const address_context_t *target, bool udp)
{
    address_context_t *dest = lineGetDestinationAddressContext(l);

    addresscontextCopy(dest, target);
    addresscontextSetOnlyProtocol(dest, udp ? IP_PROTO_UDP : IP_PROTO_TCP);
}

static bool socks5serverFieldHasNul(const uint8_t *field, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        if (field[i] == '\0')
        {
            return true;
        }
    }
    return false;
}

static const char *socks5serverAuthClientStateName(authenticationclient_state_t state)
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

static void socks5serverSanitizeUsername(const uint8_t *username, uint8_t username_len, char out[UINT8_MAX + 1U])
{
    if (username == NULL || username_len == 0)
    {
        out[0] = '\0';
        return;
    }

    for (uint8_t i = 0; i < username_len; ++i)
    {
        uint8_t ch = username[i];
        out[i]     = (ch >= 0x20U && ch <= 0x7EU && ch != '"') ? (char) ch : '?';
    }
    out[username_len] = '\0';
}

static void socks5serverLogAuthRejected(tunnel_t *t, line_t *l, const uint8_t *username, uint8_t username_len,
                                        const char *reason)
{
    socks5server_tstate_t *ts = tunnelGetState(t);

    if (ts->verbose && username != NULL && username_len > 0)
    {
        char username_text[UINT8_MAX + 1U];
        socks5serverSanitizeUsername(username, username_len, username_text);
        LOGW("Socks5Server: rejected SOCKS5 authentication for user \"%s\" on worker %d: %s",
             username_text,
             workerWIDForLog(l != NULL ? lineGetWID(l) : getWID()),
             reason != NULL ? reason : "unknown");
        return;
    }

    LOGW("Socks5Server: rejected SOCKS5 authentication: %s", reason != NULL ? reason : "unknown");
}

static bool socks5serverAuthUserFromClient(tunnel_t *t, line_t *l, const uint8_t *username, uint8_t username_len,
                                           const uint8_t *password, uint8_t password_len,
                                           user_handle_t *user_handle_out)
{
    socks5server_tstate_t *ts            = tunnelGetState(t);
    size_t                 username_size = username_len;
    size_t                 password_size = password_len;
    assert(user_handle_out != NULL);
    if (username_len == 0)
    {
        socks5serverLogAuthRejected(t, l, NULL, 0, "empty username");
        return false;
    }
    if (password_len == 0)
    {
        socks5serverLogAuthRejected(t, l, username, username_len, "empty password");
        return false;
    }
    if (ts->auth_client_tunnel == NULL)
    {
        socks5serverLogAuthRejected(t, l, username, username_len, "authentication client unavailable");
        return false;
    }
    if (socks5serverFieldHasNul(username, username_size))
    {
        socks5serverLogAuthRejected(t, l, username, username_len, "username contains NUL byte");
        return false;
    }
    if (socks5serverFieldHasNul(password, password_size))
    {
        socks5serverLogAuthRejected(t, l, username, username_len, "password contains NUL byte");
        return false;
    }

    authenticationclient_state_t auth_state = authenticationclientGetState(ts->auth_client_tunnel);
    if (auth_state != kAuthenticationClientStateReady)
    {
        socks5serverLogAuthRejected(t, l, username, username_len, socks5serverAuthClientStateName(auth_state));
        return false;
    }

    char auth_password_buf[(UINT8_MAX * 2U) + 2U] = {0};
    memoryCopy(auth_password_buf, username, username_size);
    auth_password_buf[username_size] = ':';
    memoryCopy(auth_password_buf + username_size + 1U, password, password_size);

    user_handle_t                             handle = userHandleEmpty();
    authenticationclient_user_lookup_result_t result =
        authenticationclientGetUserByPasswordWithResult(ts->auth_client_tunnel, auth_password_buf, &handle);
    memoryZero(auth_password_buf, sizeof(auth_password_buf));

    if (result == kAuthenticationClientUserLookupOk)
    {
        *user_handle_out = handle;
        return true;
    }

    socks5serverLogAuthRejected(t, l, username, username_len, authenticationclientUserLookupResultString(result));
    return false;
}

static bool socks5serverStoreAuthCredentials(socks5server_lstate_t *ls, const uint8_t *username, uint8_t username_len,
                                             const uint8_t *password, uint8_t password_len)
{
    char *new_username = memoryAllocate((size_t) username_len + 1U);
    char *new_password = memoryAllocate((size_t) password_len + 1U);
    if (UNLIKELY(new_username == NULL || new_password == NULL))
    {
        memoryFree(new_username);
        memoryFree(new_password);
        return false;
    }

    if (username_len > 0)
    {
        memoryCopy(new_username, username, username_len);
    }
    new_username[username_len] = '\0';

    if (password_len > 0)
    {
        memoryCopy(new_password, password, password_len);
    }
    new_password[password_len] = '\0';

    memoryFree(ls->auth_username);
    memoryFree(ls->auth_password);
    ls->auth_username = new_username;
    ls->auth_password = new_password;
    return true;
}

void socks5serverRecordLineUser(line_t *l, socks5server_lstate_t *ls, const user_handle_t *user_handle)
{
    if (ls->user_handle_recorded)
    {
        return;
    }

    lineAddUser(l, user_handle, ls->auth_username, ls->auth_password);
    ls->user_handle_recorded = true;
}

void socks5serverAssocEntryFreeCreds(socks5server_assoc_entry_t *entry)
{
    if (entry->auth_username != NULL)
    {
        memoryFree(entry->auth_username);
        entry->auth_username = NULL;
    }
    if (entry->auth_password != NULL)
    {
        memoryFree(entry->auth_password);
        entry->auth_password = NULL;
    }
}

void socks5serverRequireCurrentLineWorker(const line_t *l, const char *callback_name)
{
    if (UNLIKELY(l == NULL || ! lineIsOnCurrentEventWorker(l)))
    {
        LOGF("Socks5Server: %s arrived outside its line owner worker",
             callback_name != NULL ? callback_name : "flow callback");
        abortProgramNow(1);
    }
}

socks5server_assoc_entry_t *socks5serverFindWorkerAssociation(tunnel_t *t, wid_t wid, uint64_t generation)
{
    if (t == NULL || generation == 0)
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
    if (t == NULL || l == NULL || ls == NULL || ! lineIsOnCurrentEventWorker(l))
    {
        return false;
    }

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

static bool socks5serverRegisterUdpAssociation(tunnel_t *t, line_t *l, const user_handle_t *user_handle,
                                               const address_context_t *udp_peer_hint, uint16_t *assigned_port_out)
{
    socks5server_tstate_t *ts  = tunnelGetState(t);
    wid_t                  wid = lineGetWID(l);

    if (assigned_port_out == NULL || ts->worker_associations == NULL || wid >= ts->workers_count ||
        ! currentThreadIsEventWorkerWID(wid) || ! lineIsAuthenticated(l) || ! lineIsAlive(l))
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

static void socks5serverDestroyInternalUserController(socks5server_tstate_t *ts)
{
    if (ts->user_controller_tunnel != NULL)
    {
        tunnelOwnedChildDestroy(ts->user_controller_tunnel);
        ts->user_controller_tunnel = NULL;
    }

    ts->user_controller_node.instance = NULL;
}

static void socks5serverClearInternalNode(node_t *node)
{
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
    memoryZero(node, sizeof(*node));
}

void socks5serverDetachRemoteFromClient(socks5server_lstate_t *remote_ls)
{
    line_t *client_line = remote_ls->client_line;

    if (client_line != NULL && remote_ls->client_line_locked)
    {
        if (lineIsAlive(client_line))
        {
            socks5server_lstate_t         *client_ls = lineGetState(client_line, remote_ls->tunnel);
            socks5server_remote_map_t_iter it =
                socks5server_remote_map_t_find(&client_ls->udp_remote_lines, remote_ls->remote_key);
            if (it.ref != socks5server_remote_map_t_end(&client_ls->udp_remote_lines).ref &&
                it.ref->second == remote_ls->line)
            {
                socks5server_remote_map_t_erase_at(&client_ls->udp_remote_lines, it);
            }
        }

        lineUnlock(client_line);
    }

    remote_ls->client_line        = NULL;
    remote_ls->client_line_locked = false;
}

static line_t *socks5serverGetOrCreateUdpRemoteLine(tunnel_t *t, line_t *client_l, socks5server_lstate_t *client_ls,
                                                    const address_context_t *target, const user_handle_t *user_handle)
{
    hash_t remote_key = socks5serverCalcAddressHash(target);

    socks5server_remote_map_t_iter it = socks5server_remote_map_t_find(&client_ls->udp_remote_lines, remote_key);
    if (it.ref != socks5server_remote_map_t_end(&client_ls->udp_remote_lines).ref)
    {
        return it.ref->second;
    }

    line_t                *remote_l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(client_l));
    socks5server_lstate_t *remote_ls = lineGetState(remote_l, t);

    socks5serverLinestateInitialize(remote_ls, t, remote_l, kSocks5ServerLineKindUdpRemote);
    remote_ls->client_line        = client_l;
    remote_ls->client_line_locked = true;
    remote_ls->remote_key         = remote_key;
    remote_ls->dynamic_handle     = client_ls->dynamic_handle;
    remote_ls->user_handle        = *user_handle;

    lineLock(client_l);

    lineGetRoutingContext(remote_l)->local_listener_port = socks5serverGetLocalPort(client_l);
    socks5serverApplyDestinationContext(remote_l, target, true);

    if (client_ls->auth_username != NULL)
    {
        remote_ls->auth_username = stringDuplicate(client_ls->auth_username);
    }
    if (client_ls->auth_password != NULL)
    {
        remote_ls->auth_password = stringDuplicate(client_ls->auth_password);
    }
    socks5serverRecordLineUser(remote_l, remote_ls, user_handle);

    socks5server_remote_map_t_insert(&client_ls->udp_remote_lines, remote_key, remote_l);

    if (! withLineLocked(remote_l, tunnelNextUpStreamInit, t))
    {
        return NULL;
    }

    return remote_l;
}

void socks5serverTunnelstateDestroy(socks5server_tstate_t *ts)
{
    socks5serverDestroyInternalUserController(ts);
    socks5serverClearInternalNode(&ts->user_controller_node);

    if (ts->worker_associations != NULL)
    {
        for (wid_t wid = 0; wid < ts->workers_count; ++wid)
        {
            assert(socks5server_assoc_map_t_size(&ts->worker_associations[wid]) == 0);
            c_foreach(it, socks5server_assoc_map_t, ts->worker_associations[wid])
            {
                socks5serverAssocEntryFreeCreds(&it.ref->second);
            }
            socks5server_assoc_map_t_drop(&ts->worker_associations[wid]);
        }
        memoryFree(ts->worker_associations);
        ts->worker_associations = NULL;
    }

    if (ts->udp_reply_ipv4 != NULL)
    {
        memoryFree(ts->udp_reply_ipv4);
        ts->udp_reply_ipv4 = NULL;
    }

    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

static bool socks5serverControlHasUpstreamPeer(const socks5server_lstate_t *ls)
{
    return ls->phase == kSocks5ServerPhaseConnectWaitEst || ls->phase == kSocks5ServerPhaseTcpEstablished;
}

static void socks5serverMarkControlFinishedSide(socks5server_lstate_t *ls, socks5server_close_origin_t origin)
{
    if (origin == kSocks5ServerCloseFromPrev)
    {
        ls->prev_finished = true;
    }
    else if (origin == kSocks5ServerCloseFromNext)
    {
        ls->next_finished = true;
    }
}

static void socks5serverCloseControlLine(tunnel_t *t, line_t *l, socks5server_close_origin_t origin, int reply_code)
{
    socks5serverRequireCurrentLineWorker(l, "control close");
    socks5server_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kSocks5ServerPhaseClosing)
    {
        socks5serverMarkControlFinishedSide(ls, origin);
        return;
    }

    bool has_peer   = socks5serverControlHasUpstreamPeer(ls);
    bool pre_est    = ls->phase == kSocks5ServerPhaseConnectWaitEst;
    bool close_next = origin != kSocks5ServerCloseFromNext && has_peer;
    bool close_prev = origin != kSocks5ServerCloseFromPrev;
    bool send_reply = close_prev && reply_code >= 0 && ! ls->connect_reply_sent && (pre_est || ! has_peer);

    socks5serverMarkControlFinishedSide(ls, origin);

    ls->phase = kSocks5ServerPhaseClosing;
    lineLock(l);

    socks5serverUnregisterUdpAssociation(t, ls);

    if (send_reply)
    {
        sbuf_t *reply = socks5serverCreateCommandReply(l, (uint8_t) reply_code, NULL);
        if (reply != NULL)
        {
            ls->connect_reply_sent = true;
            tunnelPrevDownStreamPayload(t, l, reply);
        }
    }

    bool send_next_finish = close_next && ! ls->next_finished;
    bool send_prev_finish = close_prev && ! ls->prev_finished;

    socks5serverLinestateDestroy(ls);

    if (send_next_finish && lineIsAlive(l))
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (send_prev_finish && lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnlock(l);
}

void socks5serverCloseControlLineFromUpstream(tunnel_t *t, line_t *l)
{
    socks5serverCloseControlLine(t, l, kSocks5ServerCloseFromPrev, -1);
}

void socks5serverCloseControlLineFromDownstream(tunnel_t *t, line_t *l)
{
    socks5serverCloseControlLine(t, l, kSocks5ServerCloseFromNext, kSocks5ReplyGeneralFailure);
}

void socks5serverCloseControlLineBidirectional(tunnel_t *t, line_t *l)
{
    socks5serverCloseControlLine(t, l, kSocks5ServerCloseInternal, -1);
}

/*
 * Returns true only while @p client_l remains logically alive and its Socks5
 * line state is still owned by the caller.  A remote Finish can synchronously
 * close the provider endpoint, which in turn destroys this UDP client line.
 * Keep a separate client reference for the complete drain: the per-remote
 * client reference is deliberately released before its Finish callback.
 */
static bool socks5serverDrainUdpClientRemoteLines(tunnel_t *t, line_t *client_l, socks5server_lstate_t *client_ls)
{
    if (UNLIKELY(client_l == NULL || client_ls == NULL || ! lineIsAlive(client_l)))
    {
        return false;
    }

    lineLock(client_l);

    while (true)
    {
        if (! lineIsAlive(client_l))
        {
            lineUnlock(client_l);
            return false;
        }

        /* Re-read after every potentially re-entrant remote callback. */
        client_ls = lineGetState(client_l, t);
        if (socks5server_remote_map_t_size(&client_ls->udp_remote_lines) == 0)
        {
            lineUnlock(client_l);
            return true;
        }

        line_t *remote_l = NULL;
        c_foreach(it, socks5server_remote_map_t, client_ls->udp_remote_lines)
        {
            remote_l = it.ref->second;
            break;
        }

        if (UNLIKELY(remote_l == NULL || ! lineIsAlive(remote_l)))
        {
            LOGF("Socks5Server: UDP remote registry contains a dead or null line during client teardown");
            abortProgramNow(1);
        }

        socks5server_lstate_t *remote_ls = lineGetState(remote_l, t);
        if (UNLIKELY(remote_ls->client_line != client_l || ! remote_ls->client_line_locked))
        {
            LOGF("Socks5Server: UDP remote registry contains a line without its client ownership link");
            abortProgramNow(1);
        }

        lineLock(remote_l);
        socks5serverDetachRemoteFromClient(remote_ls);
        socks5serverLinestateDestroy(remote_ls);
        tunnelNextUpStreamFinish(t, remote_l);
        if (UNLIKELY(! lineIsAlive(remote_l)))
        {
            LOGF("Socks5Server: next/upstream tunnel destroyed a Socks5Server-owned UDP remote during Finish");
            abortProgramNow(1);
        }
        lineDestroy(remote_l);
        lineUnlock(remote_l);

        if (! lineIsAlive(client_l))
        {
            lineUnlock(client_l);
            return false;
        }
    }
}

void socks5serverRejectUdpClientLine(tunnel_t *t, line_t *client_l)
{
    socks5serverRequireCurrentLineWorker(client_l, "UDP client rejection");

    socks5server_lstate_t *client_ls = lineGetState(client_l, t);
    if (client_ls->kind != kSocks5ServerLineKindUdpClient)
    {
        return;
    }

    if (! socks5serverDrainUdpClientRemoteLines(t, client_l, client_ls))
    {
        return;
    }

    socks5serverLinestateDestroy(client_ls);
    socks5serverLinestateInitialize(lineGetState(client_l, t), t, client_l, kSocks5ServerLineKindRejected);
}

static void socks5serverCloseUdpClientLineInternal(tunnel_t *t, line_t *client_l, bool close_prev)
{
    socks5serverRequireCurrentLineWorker(client_l, "UDP client close");

    socks5server_lstate_t *client_ls = lineGetState(client_l, t);

    if (! socks5serverDrainUdpClientRemoteLines(t, client_l, client_ls))
    {
        return;
    }

    socks5serverLinestateDestroy(client_ls);
    if (close_prev)
    {
        tunnelPrevDownStreamFinish(t, client_l);
    }
}

void socks5serverCloseUdpClientLineFromUpstream(tunnel_t *t, line_t *client_l)
{
    socks5serverCloseUdpClientLineInternal(t, client_l, false);
}

void socks5serverCloseUdpClientLine(tunnel_t *t, line_t *client_l)
{
    socks5serverCloseUdpClientLineInternal(t, client_l, true);
}

void socks5serverCloseUdpRemoteLine(tunnel_t *t, line_t *remote_l)
{
    socks5serverRequireCurrentLineWorker(remote_l, "UDP remote close");
    socks5server_lstate_t *remote_ls = lineGetState(remote_l, t);

    lineLock(remote_l);
    socks5serverDetachRemoteFromClient(remote_ls);
    socks5serverLinestateDestroy(remote_ls);
    tunnelNextUpStreamFinish(t, remote_l);
    if (UNLIKELY(! lineIsAlive(remote_l)))
    {
        LOGF("Socks5Server: next/upstream tunnel destroyed a Socks5Server-owned UDP remote during Finish");
        abortProgramNow(1);
    }
    lineDestroy(remote_l);
    lineUnlock(remote_l);
}

void socks5serverOnControlEstablished(tunnel_t *t, line_t *l, socks5server_lstate_t *ls)
{
    buffer_queue_t up_local   = bufferqueueCreate(kSocks5ServerBufferQueueCap);
    buffer_queue_t down_local = bufferqueueCreate(kSocks5ServerBufferQueueCap);
    sbuf_t        *reply      = socks5serverCreateCommandReply(l, kSocks5ReplySucceeded, NULL);

    if (reply == NULL)
    {
        bufferqueueDestroy(&up_local);
        bufferqueueDestroy(&down_local);
        socks5serverCloseControlLineBidirectional(t, l);
        return;
    }

    while (! bufferstreamIsEmpty(&ls->in_stream))
    {
        bufferqueuePushBack(&up_local, bufferstreamIdealRead(&ls->in_stream));
    }

    while (bufferqueueGetBufCount(&ls->pending_up) > 0)
    {
        bufferqueuePushBack(&up_local, bufferqueuePopFront(&ls->pending_up));
    }

    while (bufferqueueGetBufCount(&ls->pending_down) > 0)
    {
        bufferqueuePushBack(&down_local, bufferqueuePopFront(&ls->pending_down));
    }

    ls->phase              = kSocks5ServerPhaseTcpEstablished;
    ls->connect_reply_sent = true;

    if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, reply))
    {
        bufferqueueDestroy(&up_local);
        bufferqueueDestroy(&down_local);
        return;
    }

    if (! withLineLocked(l, tunnelPrevDownStreamEst, t))
    {
        bufferqueueDestroy(&up_local);
        bufferqueueDestroy(&down_local);
        return;
    }

    if (! socks5serverFlushQueueToNext(t, l, &up_local))
    {
        bufferqueueDestroy(&down_local);
        return;
    }

    socks5serverFlushQueueToPrev(t, l, &down_local);
}

bool socks5serverWrapUdpPayloadForClient(line_t *l, sbuf_t **buf_io, const address_context_t *addr_ctx)
{
    sbuf_t  *buf     = *buf_io;
    uint32_t payload = sbufGetLength(buf);
    size_t   header_len;

    if (addresscontextIsIpType(addr_ctx))
    {
        header_len = addresscontextIsIpv6(addr_ctx) ? (size_t) 4 + 16 + 2 : (size_t) 4 + 4 + 2;
    }
    else if (addresscontextIsDomain(addr_ctx))
    {
        header_len = (size_t) 4 + 1 + addr_ctx->domain_len + 2;
    }
    else
    {
        return false;
    }

    if (sbufGetLeftCapacity(buf) < header_len)
    {
        sbuf_t  *wrapped = socks5serverAllocBuffer(l, (uint32_t) (payload + header_len));
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

    ptr[off++] = 0;
    ptr[off++] = 0;
    ptr[off++] = 0;
    if (! socks5serverWriteAddress(ptr, addr_ctx, &off))
    {
        return false;
    }
    return true;
}

bool socks5serverHandleUdpClientPayload(tunnel_t *t, line_t *l, socks5server_lstate_t *ls, sbuf_t *buf)
{
    socks5serverRequireCurrentLineWorker(l, "UDP client payload");

    /* A remote Init/Payload can close the provider endpoint and therefore this
     * different line.  Keep the allocation and pool identity independent of
     * that callback before touching any remote-line helper. */
    buffer_pool_t *const client_pool = lineGetBufferPool(l);
    lineLock(l);
    ls = lineGetState(l, t);

    const bool first_payload     = ! ls->udp_first_payload_validated;
    const bool association_valid = socks5serverValidateUdpClientAssociation(t, l, ls, first_payload);
    if (! lineIsAlive(l))
    {
        bufferpoolReuseBuffer(client_pool, buf);
        lineUnlock(l);
        return false;
    }

    if (! association_valid)
    {
        bufferpoolReuseBuffer(client_pool, buf);
        socks5serverRejectUdpClientLine(t, l);
        lineUnlock(l);
        return false;
    }
    ls->udp_first_payload_validated = true;

    const uint8_t *raw = sbufGetRawPtr(buf);
    size_t         len = sbufGetLength(buf);

    if (len < 4 || raw[0] != 0 || raw[1] != 0)
    {
        bufferpoolReuseBuffer(client_pool, buf);
        socks5serverCloseUdpClientLine(t, l);
        lineUnlock(l);
        return false;
    }

    if (raw[2] != 0)
    {
        bufferpoolReuseBuffer(client_pool, buf);
        lineUnlock(l);
        return true;
    }

    address_context_t target    = {0};
    size_t            addr_len  = 0;
    int               parse_res = socks5serverParseAddressBytes(raw + 3, len - 3, &target, &addr_len);
    if (parse_res <= 0 || len < (size_t) (3 + addr_len))
    {
        bufferpoolReuseBuffer(client_pool, buf);
        if (parse_res < 0)
        {
            socks5serverCloseUdpClientLine(t, l);
            lineUnlock(l);
            return false;
        }
        lineUnlock(l);
        return true;
    }

    line_t *remote_l = socks5serverGetOrCreateUdpRemoteLine(t, l, ls, &target, &ls->user_handle);
    addresscontextReset(&target);
    if (! lineIsAlive(l))
    {
        bufferpoolReuseBuffer(client_pool, buf);
        lineUnlock(l);
        return false;
    }

    if (remote_l == NULL)
    {
        bufferpoolReuseBuffer(client_pool, buf);
        lineUnlock(l);
        return false;
    }

    sbufShiftRight(buf, (uint32_t) (3 + addr_len));
    const bool remote_alive = withLineLockedWithBuf(remote_l, tunnelNextUpStreamPayload, t, buf);

    lineUnlock(l);
    return remote_alive;
}

static bool socks5serverSendReplyAndClose(tunnel_t *t, line_t *l, uint8_t rep)
{
    socks5serverCloseControlLine(t, l, kSocks5ServerCloseInternal, rep);
    return false;
}

bool socks5serverControlDrainInput(tunnel_t *t, line_t *l, socks5server_lstate_t *ls)
{
    socks5server_tstate_t *ts = tunnelGetState(t);

    while (true)
    {
        if (ls->phase == kSocks5ServerPhaseWaitMethod)
        {
            if (bufferstreamGetBufLen(&ls->in_stream) < 2)
            {
                return true;
            }

            uint8_t head[2];
            bufferstreamViewBytesAt(&ls->in_stream, 0, head, sizeof(head));
            if (head[0] != kSocks5Version)
            {
                socks5serverCloseControlLineBidirectional(t, l);
                return false;
            }

            size_t total = (size_t) 2 + head[1];
            if (bufferstreamGetBufLen(&ls->in_stream) < total)
            {
                return true;
            }

            sbuf_t        *method_buf      = bufferstreamReadExact(&ls->in_stream, total);
            const uint8_t *methods         = sbufGetRawPtr(method_buf);
            bool           offers_noauth   = false;
            bool           offers_userpass = false;

            for (uint8_t i = 0; i < head[1]; ++i)
            {
                offers_noauth |= methods[2 + i] == kSocks5NoAuthMethod;
                offers_userpass |= methods[2 + i] == kSocks5UserPassMethod;
            }
            lineReuseBuffer(l, method_buf);

            uint8_t selected = kSocks5NoAcceptable;
            if (ts->no_auth && offers_noauth)
            {
                selected = kSocks5NoAuthMethod;
            }
            else if (! ts->no_auth && offers_userpass)
            {
                selected = kSocks5UserPassMethod;
            }

            sbuf_t *reply = socks5serverCreateMethodReply(l, selected);
            if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, reply))
            {
                return false;
            }

            if (selected == kSocks5NoAcceptable)
            {
                const char *reason =
                    ts->no_auth ? "no-auth method not offered" : "username-password method not offered";
                socks5serverLogAuthRejected(t, l, NULL, 0, reason);
                socks5serverCloseControlLineBidirectional(t, l);
                return false;
            }

            if (selected == kSocks5NoAuthMethod)
            {
                ls->user_handle = userHandleEmpty();
                ls->phase       = kSocks5ServerPhaseWaitRequest;
                socks5serverRecordLineUser(l, ls, &ls->user_handle);
                continue;
            }

            ls->phase = kSocks5ServerPhaseWaitAuth;
            continue;
        }

        if (ls->phase == kSocks5ServerPhaseWaitAuth)
        {
            if (bufferstreamGetBufLen(&ls->in_stream) < 2)
            {
                return true;
            }

            uint8_t head[2];
            bufferstreamViewBytesAt(&ls->in_stream, 0, head, sizeof(head));
            if (head[0] != kSocks5AuthVersion)
            {
                socks5serverLogAuthRejected(t, l, NULL, 0, "invalid username-password auth version");
                socks5serverCloseControlLineBidirectional(t, l);
                return false;
            }

            size_t required = (size_t) 2 + head[1] + 1;
            if (bufferstreamGetBufLen(&ls->in_stream) < required)
            {
                return true;
            }

            uint8_t plen = bufferstreamViewByteAt(&ls->in_stream, 2 + head[1]);
            required += plen;
            if (bufferstreamGetBufLen(&ls->in_stream) < required)
            {
                return true;
            }

            sbuf_t        *auth_buf    = bufferstreamReadExact(&ls->in_stream, required);
            const uint8_t *raw         = sbufGetRawPtr(auth_buf);
            user_handle_t  user_handle = userHandleEmpty();
            bool           authenticated =
                socks5serverAuthUserFromClient(t, l, raw + 2, head[1], raw + 3 + head[1], plen, &user_handle);
            if (authenticated && ! socks5serverStoreAuthCredentials(ls, raw + 2, head[1], raw + 3 + head[1], plen))
            {
                socks5serverLogAuthRejected(t, l, raw + 2, head[1], "failed to retain authenticated credentials");
                authenticated = false;
            }
            lineReuseBuffer(l, auth_buf);

            sbuf_t *reply = socks5serverCreateAuthReply(l, authenticated ? 0x00 : 0x01);
            if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, reply))
            {
                return false;
            }

            if (! authenticated)
            {
                socks5serverCloseControlLineBidirectional(t, l);
                return false;
            }

            ls->user_handle = user_handle;
            ls->phase       = kSocks5ServerPhaseWaitRequest;
            socks5serverRecordLineUser(l, ls, &ls->user_handle);
            continue;
        }

        if (ls->phase == kSocks5ServerPhaseWaitRequest)
        {
            if (bufferstreamGetBufLen(&ls->in_stream) < 4)
            {
                return true;
            }

            uint8_t head[4];
            bufferstreamViewBytesAt(&ls->in_stream, 0, head, sizeof(head));
            if (head[0] != kSocks5Version || head[2] != 0)
            {
                return socks5serverSendReplyAndClose(t, l, kSocks5ReplyGeneralFailure);
            }

            uint8_t           request_buf[sizeof(head) + 1 + 16 + 2 + UINT8_MAX] = {0};
            size_t            available = bufferstreamGetBufLen(&ls->in_stream);
            size_t            copy_len  = min((size_t) sizeof(request_buf), available);
            address_context_t target    = {0};
            size_t            consumed  = 0;

            bufferstreamViewBytesAt(&ls->in_stream, 0, request_buf, copy_len);
            int parse_res = socks5serverParseAddressBytes(request_buf + 3, copy_len - 3, &target, &consumed);
            if (parse_res == 0)
            {
                return true;
            }

            if (parse_res < 0)
            {
                return socks5serverSendReplyAndClose(t, l, kSocks5ReplyAddrNotSupported);
            }

            lineReuseBuffer(l, bufferstreamReadExact(&ls->in_stream, 3 + consumed));

            if (head[1] == kSocks5CommandBind)
            {
                addresscontextReset(&target);
                return socks5serverSendReplyAndClose(t, l, kSocks5ReplyCmdNotSupported);
            }

            if (head[1] == kSocks5CommandConnect)
            {
                if (! ts->allow_connect)
                {
                    addresscontextReset(&target);
                    return socks5serverSendReplyAndClose(t, l, kSocks5ReplyCmdNotSupported);
                }
                if (! addresscontextHasPort(&target))
                {
                    if (ts->verbose)
                    {
                        LOGW("Socks5Server: rejected CONNECT request with zero destination port");
                    }
                    addresscontextReset(&target);
                    return socks5serverSendReplyAndClose(t, l, kSocks5ReplyAddrNotSupported);
                }

                socks5serverApplyDestinationContext(l, &target, false);
                addresscontextReset(&target);
                ls->phase = kSocks5ServerPhaseConnectWaitEst;
                if (! withLineLocked(l, tunnelNextUpStreamInit, t))
                {
                    return false;
                }
                return true;
            }

            if (head[1] == kSocks5CommandUdpAssoc)
            {
                address_context_t bind_ctx      = {0};
                uint16_t          assigned_port = 0;

                if (! ts->allow_udp)
                {
                    addresscontextReset(&target);
                    return socks5serverSendReplyAndClose(t, l, kSocks5ReplyCmdNotSupported);
                }

                if (! socks5serverRegisterUdpAssociation(t, l, &ls->user_handle, &target, &assigned_port))
                {
                    LOGW("Socks5Server: failed to create a dynamic UDP association");
                    addresscontextReset(&target);
                    return socks5serverSendReplyAndClose(t, l, kSocks5ReplyGeneralFailure);
                }

                LOGD("Socks5Server: opened dynamic UDP association endpoint on worker %u port %u",
                     (unsigned int) lineGetWID(l),
                     (unsigned int) assigned_port);

                addresscontextSetIpPort(&bind_ctx, &ts->udp_reply_ip, assigned_port);
                sbuf_t *reply = socks5serverCreateCommandReply(l, kSocks5ReplySucceeded, &bind_ctx);
                addresscontextReset(&bind_ctx);
                addresscontextReset(&target);
                if (reply == NULL)
                {
                    socks5serverUnregisterUdpAssociation(t, ls);
                    return socks5serverSendReplyAndClose(t, l, kSocks5ReplyGeneralFailure);
                }
                if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, reply))
                {
                    return false;
                }

                ls->phase              = kSocks5ServerPhaseUdpControl;
                ls->connect_reply_sent = true;
                return true;
            }

            addresscontextReset(&target);
            return socks5serverSendReplyAndClose(t, l, kSocks5ReplyCmdNotSupported);
        }

        return true;
    }
}
