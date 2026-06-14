#include "structure.h"

#include "AuthenticationClient/interface.h"
#include "loggers/network_logger.h"
#include "wmutex.h"

typedef struct socks5server_assoc_entry_s
{
    line_t        *control_line;
    user_handle_t  user_handle;
    hash_t         key;
} socks5server_assoc_entry_t;

#define i_type socks5server_assoc_map_t     // NOLINT
#define i_key  hash_t                       // NOLINT
#define i_val  socks5server_assoc_entry_t * // NOLINT
#include "stc/hmap.h"

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

static socks5server_assoc_map_t g_socks5server_assoc_map;
static wmutex_t                 g_socks5server_assoc_mutex;
static wonce_t                  g_socks5server_assoc_once = WONCE_INIT;

static void socks5serverInitAssocRegistry(void)
{
    mutexInit(&g_socks5server_assoc_mutex);
    g_socks5server_assoc_map = socks5server_assoc_map_t_with_capacity(64);
}

static uint16_t socks5serverGetLocalPort(const line_t *l)
{
    const routing_context_t *route = lineGetRoutingContext((line_t *) l);
    if (route->local_listener_port != 0)
    {
        return route->local_listener_port;
    }

    return lineGetSourceAddressContext((line_t *) l)->port;
}

static hash_t socks5serverCalcAssociationKey(const ip_addr_t *ip, uint16_t udp_port, uint16_t local_port)
{
    struct
    {
        uint16_t   listener_port;
        uint16_t   client_port;
        uint8_t    ip_type;
        uint8_t    padding[5];
        ip4_addr_t ip4;
        ip6_addr_t ip6;
    } key = {0};

    key.listener_port = local_port;
    key.client_port   = udp_port;
    key.ip_type       = ip->type;

    if (ip->type == IPADDR_TYPE_V4)
    {
        key.ip4 = ip->u_addr.ip4;
    }
    else
    {
        key.ip6 = ip->u_addr.ip6;
    }

    return calcHashBytes(&key, sizeof(key));
}

static hash_t socks5serverCalcAddressHash(const address_context_t *ctx)
{
    if (addresscontextIsIp(ctx))
    {
        return socks5serverCalcAssociationKey(&ctx->ip_address, ctx->port, 0);
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
    address_context_t *dest  = lineGetDestinationAddressContext(l);
    routing_context_t *route = lineGetRoutingContext(l);

    addresscontextAddrCopy(dest, target);
    addresscontextSetOnlyProtocol(dest, udp ? IP_PROTO_UDP : IP_PROTO_TCP);
    route->network_type = udp ? WIO_TYPE_UDP : WIO_TYPE_TCP;
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

static bool socks5serverAuthUserFromClient(tunnel_t *t, const uint8_t *username, uint8_t username_len,
                                           const uint8_t *password, uint8_t password_len,
                                           user_handle_t *user_handle_out)
{
    socks5server_tstate_t *ts = tunnelGetState(t);
    size_t                 username_size = username_len;
    size_t                 password_size = password_len;
    if (username_len == 0 || password_len == 0 || ts->auth_client_tunnel == NULL ||
        socks5serverFieldHasNul(username, username_size) || socks5serverFieldHasNul(password, password_size))
    {
        return false;
    }

    if (! authenticationclientIsReady(ts->auth_client_tunnel))
    {
        LOGW("Socks5Server: AuthenticationClient node \"%s\" is not ready",
             ts->auth_client_node != NULL ? ts->auth_client_node->name : "(null)");
        return false;
    }

    char auth_password_buf[(UINT8_MAX * 2U) + 2U] = {0};
    memoryCopy(auth_password_buf, username, username_size);
    auth_password_buf[username_size] = ':';
    memoryCopy(auth_password_buf + username_size + 1U, password, password_size);

    user_handle_t handle = {0};
    bool found = authenticationclientGetUserByPassword(ts->auth_client_tunnel, auth_password_buf, &handle);
    memoryZero(auth_password_buf, sizeof(auth_password_buf));

    if (found)
    {
        *user_handle_out = handle;
    }
    return found;
}

static bool socks5serverRegisterUdpAssociation(line_t *l, const user_handle_t *user_handle,
                                               const address_context_t *udp_peer_hint, hash_t *out_key)
{
    const address_context_t *src_ctx    = lineGetSourceAddressContext(l);
    uint16_t                 local_port = socks5serverGetLocalPort(l);
    ip_addr_t                key_ip     = src_ctx->ip_address;
    uint16_t                 key_port   = 0;

    wonce(&g_socks5server_assoc_once, socks5serverInitAssocRegistry);

    if (! addresscontextIsIp(src_ctx) || local_port == 0 || ! lineIsAuthenticated(l) || ! lineIsAlive(l))
    {
        return false;
    }

    if (udp_peer_hint != NULL && addresscontextIsIp(udp_peer_hint) && udp_peer_hint->port > 0)
    {
        key_ip   = ipAddrIsAny(&udp_peer_hint->ip_address) ? src_ctx->ip_address : udp_peer_hint->ip_address;
        key_port = udp_peer_hint->port;
    }

    hash_t                      key   = socks5serverCalcAssociationKey(&key_ip, key_port, local_port);
    socks5server_assoc_entry_t *entry = memoryAllocate(sizeof(*entry));
    *entry = (socks5server_assoc_entry_t) {.control_line = l, .user_handle = *user_handle, .key = key};
    lineLock(l);

    socks5server_assoc_entry_t *old_entry = NULL;

    mutexLock(&g_socks5server_assoc_mutex);
    socks5server_assoc_map_t_iter it = socks5server_assoc_map_t_find(&g_socks5server_assoc_map, key);
    if (it.ref != socks5server_assoc_map_t_end(&g_socks5server_assoc_map).ref)
    {
        old_entry = it.ref->second;
        socks5server_assoc_map_t_erase_at(&g_socks5server_assoc_map, it);
    }
    socks5server_assoc_map_t_insert(&g_socks5server_assoc_map, key, entry);
    mutexUnlock(&g_socks5server_assoc_mutex);

    if (old_entry != NULL)
    {
        lineUnlock(old_entry->control_line);
        memoryFree(old_entry);
    }

    *out_key = key;
    return true;
}

void socks5serverUnregisterUdpAssociation(socks5server_lstate_t *ls)
{
    if (ls->association_key == 0)
    {
        return;
    }

    wonce(&g_socks5server_assoc_once, socks5serverInitAssocRegistry);

    socks5server_assoc_entry_t *entry = NULL;

    mutexLock(&g_socks5server_assoc_mutex);
    socks5server_assoc_map_t_iter it = socks5server_assoc_map_t_find(&g_socks5server_assoc_map, ls->association_key);
    if (it.ref != socks5server_assoc_map_t_end(&g_socks5server_assoc_map).ref &&
        it.ref->second->control_line == ls->line)
    {
        entry = it.ref->second;
        socks5server_assoc_map_t_erase_at(&g_socks5server_assoc_map, it);
    }
    mutexUnlock(&g_socks5server_assoc_mutex);

    if (entry != NULL)
    {
        lineUnlock(entry->control_line);
        memoryFree(entry);
    }

    ls->association_key = 0;
}

bool socks5serverLookupUdpAssociation(line_t *l, user_handle_t *user_handle_out, hash_t *key_out)
{
    const address_context_t          *src_ctx      = lineGetSourceAddressContext(l);
    uint16_t                          local_port   = socks5serverGetLocalPort(l);
    line_t                           *control_line = NULL;
    user_handle_t                     user_handle  = {0};
    hash_t                            key          = 0;

    wonce(&g_socks5server_assoc_once, socks5serverInitAssocRegistry);

    if (! addresscontextIsIp(src_ctx) || local_port == 0)
    {
        return false;
    }

    hash_t exact_key    = socks5serverCalcAssociationKey(&src_ctx->ip_address, src_ctx->port, local_port);
    hash_t fallback_key = socks5serverCalcAssociationKey(&src_ctx->ip_address, 0, local_port);

    mutexLock(&g_socks5server_assoc_mutex);
    socks5server_assoc_map_t_iter it = socks5server_assoc_map_t_find(&g_socks5server_assoc_map, exact_key);
    if (it.ref == socks5server_assoc_map_t_end(&g_socks5server_assoc_map).ref)
    {
        it = socks5server_assoc_map_t_find(&g_socks5server_assoc_map, fallback_key);
    }

    if (it.ref != socks5server_assoc_map_t_end(&g_socks5server_assoc_map).ref)
    {
        socks5server_assoc_entry_t *entry = it.ref->second;
        control_line                      = entry->control_line;
        user_handle                       = entry->user_handle;
        key                               = entry->key;
        lineLock(control_line);
    }
    mutexUnlock(&g_socks5server_assoc_mutex);

    if (control_line == NULL)
    {
        return false;
    }

    bool authenticated = lineIsAlive(control_line) && lineIsAuthenticated(control_line);
    lineUnlock(control_line);

    if (! authenticated)
    {
        return false;
    }

    *user_handle_out = user_handle;
    *key_out         = key;
    return true;
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
                                                    const address_context_t *target,
                                                    const user_handle_t *user_handle, hash_t assoc_key)
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
    remote_ls->association_key    = assoc_key;
    remote_ls->user_handle        = *user_handle;

    lineLock(client_l);

    lineGetRoutingContext(remote_l)->local_listener_port = socks5serverGetLocalPort(client_l);
    socks5serverApplyDestinationContext(remote_l, target, true);

    socks5server_remote_map_t_insert(&client_ls->udp_remote_lines, remote_key, remote_l);

    if (! withLineLocked(remote_l, tunnelNextUpStreamInit, t))
    {
        return NULL;
    }

    return remote_l;
}

void socks5serverTunnelstateDestroy(socks5server_tstate_t *ts)
{
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

static void socks5serverCloseControlLineInternal(tunnel_t *t, line_t *l, bool close_prev)
{
    socks5server_lstate_t *ls         = lineGetState(l, t);
    bool                   close_next = socks5serverControlHasUpstreamPeer(ls);
    socks5serverUnregisterUdpAssociation(ls);

    socks5serverLinestateDestroy(ls);

    if (close_next)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (lineIsAlive(l) && close_prev)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
}

void socks5serverCloseControlLineFromUpstream(tunnel_t *t, line_t *l)
{
    socks5serverCloseControlLineInternal(t, l, false);
}

void socks5serverCloseControlLineBidirectional(tunnel_t *t, line_t *l)
{
    socks5serverCloseControlLineInternal(t, l, true);
}

static void socks5serverCloseUdpClientLineInternal(tunnel_t *t, line_t *client_l, bool close_prev)
{
    socks5server_lstate_t *client_ls = lineGetState(client_l, t);

    size_t line_count = socks5server_remote_map_t_size(&client_ls->udp_remote_lines);
    if (line_count > 0)
    {
        line_t **remote_lines = memoryAllocate(sizeof(*remote_lines) * line_count);
        size_t   index        = 0;

        c_foreach(it, socks5server_remote_map_t, client_ls->udp_remote_lines)
        {
            remote_lines[index++] = it.ref->second;
        }

        for (size_t i = 0; i < index; ++i)
        {
            line_t *remote_l = remote_lines[i];
            if (! lineIsAlive(remote_l))
            {
                continue;
            }

            socks5server_lstate_t *remote_ls = lineGetState(remote_l, t);
            socks5serverDetachRemoteFromClient(remote_ls);
            socks5serverLinestateDestroy(remote_ls);
            tunnelNextUpStreamFinish(t, remote_l);
            if (lineIsAlive(remote_l))
            {
                lineDestroy(remote_l);
            }
        }

        memoryFree(remote_lines);
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
    socks5server_lstate_t *remote_ls = lineGetState(remote_l, t);

    socks5serverDetachRemoteFromClient(remote_ls);
    socks5serverLinestateDestroy(remote_ls);
    tunnelNextUpStreamFinish(t, remote_l);
    if (lineIsAlive(remote_l))
    {
        lineDestroy(remote_l);
    }
}

void socks5serverOnControlEstablished(tunnel_t *t, line_t *l, socks5server_lstate_t *ls)
{
    buffer_queue_t up_local   = bufferqueueCreate(kSocks5ServerBufferQueueCap);
    buffer_queue_t down_local = bufferqueueCreate(kSocks5ServerBufferQueueCap);
    sbuf_t        *reply      = socks5serverCreateCommandReply(l, kSocks5ReplySucceeded, NULL);

    if (reply == NULL)
    {
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
    if (! lineIsAuthenticated(l))
    {
        lineAuthenticate(l);
    }

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
    user_handle_t     user_handle = {0};
    hash_t            assoc_key   = 0;
    address_context_t target      = {0};
    size_t            addr_len    = 0;
    const uint8_t    *raw         = sbufGetRawPtr(buf);
    size_t            len         = sbufGetLength(buf);

    if (! socks5serverLookupUdpAssociation(l, &user_handle, &assoc_key))
    {
        lineReuseBuffer(l, buf);
        socks5serverCloseUdpClientLine(t, l);
        return false;
    }

    if (len < 4 || raw[0] != 0 || raw[1] != 0)
    {
        lineReuseBuffer(l, buf);
        socks5serverCloseUdpClientLine(t, l);
        return false;
    }

    if (raw[2] != 0)
    {
        lineReuseBuffer(l, buf);
        return true;
    }

    int parse_res = socks5serverParseAddressBytes(raw + 3, len - 3, &target, &addr_len);
    if (parse_res <= 0 || len < (size_t) (3 + addr_len))
    {
        lineReuseBuffer(l, buf);
        if (parse_res < 0)
        {
            socks5serverCloseUdpClientLine(t, l);
            return false;
        }
        return true;
    }

    if (! lineIsAuthenticated(l))
    {
        lineAuthenticate(l);
    }

    ls->user_handle     = user_handle;
    ls->association_key = assoc_key;

    line_t *remote_l = socks5serverGetOrCreateUdpRemoteLine(t, l, ls, &target, &ls->user_handle, assoc_key);
    addresscontextReset(&target);
    if (remote_l == NULL)
    {
        lineReuseBuffer(l, buf);
        return false;
    }

    sbufShiftRight(buf, (uint32_t) (3 + addr_len));
    if (! withLineLockedWithBuf(remote_l, tunnelNextUpStreamPayload, t, buf))
    {
        return false;
    }

    return true;
}

static bool socks5serverSendReplyAndClose(tunnel_t *t, line_t *l, uint8_t rep, const address_context_t *ctx)
{
    sbuf_t *reply = socks5serverCreateCommandReply(l, rep, ctx);
    if (reply == NULL)
    {
        socks5serverCloseControlLineBidirectional(t, l);
        return false;
    }

    if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, reply))
    {
        return false;
    }

    socks5serverCloseControlLineBidirectional(t, l);
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
            bool           offers_userpass = false;

            for (uint8_t i = 0; i < head[1]; ++i)
            {
                offers_userpass |= methods[2 + i] == kSocks5UserPassMethod;
            }
            lineReuseBuffer(l, method_buf);

            uint8_t selected = offers_userpass ? kSocks5UserPassMethod : kSocks5NoAcceptable;

            sbuf_t *reply = socks5serverCreateMethodReply(l, selected);
            if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, reply))
            {
                return false;
            }

            if (selected == kSocks5NoAcceptable)
            {
                socks5serverCloseControlLineBidirectional(t, l);
                return false;
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
            user_handle_t  user_handle = {0};
            bool authenticated =
                socks5serverAuthUserFromClient(t, raw + 2, head[1], raw + 3 + head[1], plen, &user_handle);
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
            if (! lineIsAuthenticated(l))
            {
                lineAuthenticate(l);
            }
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
                return socks5serverSendReplyAndClose(t, l, kSocks5ReplyGeneralFailure, NULL);
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
                return socks5serverSendReplyAndClose(t, l, kSocks5ReplyAddrNotSupported, NULL);
            }

            lineReuseBuffer(l, bufferstreamReadExact(&ls->in_stream, 3 + consumed));

            if (head[1] == kSocks5CommandBind)
            {
                addresscontextReset(&target);
                return socks5serverSendReplyAndClose(t, l, kSocks5ReplyCmdNotSupported, NULL);
            }

            if (head[1] == kSocks5CommandConnect)
            {
                if (! ts->allow_connect)
                {
                    addresscontextReset(&target);
                    return socks5serverSendReplyAndClose(t, l, kSocks5ReplyCmdNotSupported, NULL);
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
                address_context_t bind_ctx   = {0};
                uint16_t          local_port = socks5serverGetLocalPort(l);

                if (! ts->allow_udp)
                {
                    addresscontextReset(&target);
                    return socks5serverSendReplyAndClose(t, l, kSocks5ReplyCmdNotSupported, NULL);
                }

                addresscontextSetIpPort(&bind_ctx, &ts->udp_reply_ip, local_port);
                if (! socks5serverRegisterUdpAssociation(l, &ls->user_handle, &target, &ls->association_key))
                {
                    addresscontextReset(&bind_ctx);
                    addresscontextReset(&target);
                    return socks5serverSendReplyAndClose(t, l, kSocks5ReplyGeneralFailure, NULL);
                }

                sbuf_t *reply = socks5serverCreateCommandReply(l, kSocks5ReplySucceeded, &bind_ctx);
                addresscontextReset(&bind_ctx);
                addresscontextReset(&target);
                if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, reply))
                {
                    return false;
                }

                ls->phase              = kSocks5ServerPhaseUdpControl;
                ls->connect_reply_sent = true;
                if (! lineIsAuthenticated(l))
                {
                    lineAuthenticate(l);
                }
                return true;
            }

            addresscontextReset(&target);
            return socks5serverSendReplyAndClose(t, l, kSocks5ReplyCmdNotSupported, NULL);
        }

        return true;
    }
}
