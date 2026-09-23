#include "structure.h"

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

void trojanserverCloseUdpRemoteLineInternal(tunnel_t *t, line_t *remote_l, bool close_next)
{
    trojanserver_lstate_t *remote = lineGetState(remote_l, t);
    if (remote->phase == kTrojanServerPhaseClosing)
        return;
    lineRef(remote_l);
    line_t *client_l = remote->client_line; // Persistent association reference remains held through cleanup.
    trojanserver_lstate_t *client           = lineGetState(client_l, t);
    bool                   next_initialized = remote->next_initialized;
    remote->phase                           = kTrojanServerPhaseClosing;
    trojanserver_remote_map_t_erase(&client->udp_remote_lines, remote->remote_key);
    if (remote->next_paused)
    {
        assert(client->paused_remotes != 0);
        --client->paused_remotes;
    }
    if (client->selected_remote == remote_l)
        client->selected_remote = NULL;
    remote->client_line = NULL;
    trojanserverLinestateDestroy(remote);
    if (close_next && next_initialized)
        tunnelNextUpStreamFinish(t, remote_l);
    if (lineIsAlive(remote_l))
        lineDestroy(remote_l);
    /* Pump admission suppresses restart during whole-association teardown. */
    if (lineIsAlive(client_l))
        trojanserverPump(t, client_l);
    lineUnref(client_l);
    lineUnref(remote_l);
}

void trojanserverCloseUdpRemoteLines(tunnel_t *t, trojanserver_lstate_t *client)
{
    /* Removal happens before callbacks. Restart from the authoritative map:
     * nested cleanup may remove any sibling, so no raw snapshot survives. */
    while (trojanserver_remote_map_t_size(&client->udp_remote_lines) != 0)
    {
        line_t *remote = trojanserver_remote_map_t_begin(&client->udp_remote_lines).ref->second;
        trojanserverCloseUdpRemoteLineInternal(t, remote, true);
    }
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
        buffer_pool_t *pool    = lineGetBufferPool(l);
        uint16_t       padding = max(bufferpoolGetLargeBufferPadding(pool), kTrojanServerUdpHeaderMaxLen);
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
    sbufShiftLeft(buf, (uint32_t) header_len);

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

line_t *trojanserverGetOrCreateUdpRemoteLine(tunnel_t *t, line_t *client_l, trojanserver_lstate_t *client,
                                             const address_context_t *target)
{
    hash_t                         key = trojanserverCalcAddressHash(target);
    trojanserver_remote_map_t_iter it  = trojanserver_remote_map_t_find(&client->udp_remote_lines, key);
    if (it.ref != NULL)
        return it.ref->second;
    line_t                *line   = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(client_l));
    trojanserver_lstate_t *remote = lineGetState(line, t);
    trojanserverLinestateInitialize(remote, t, line, kTrojanServerLineKindUdpRemote);
    remote->client_line = client_l;
    remote->remote_key  = key;
    remote->user_handle = client->user_handle;
    remote->branch      = kTrojanServerBranchTrojan;
    remote->phase       = kTrojanServerPhaseUdpConnecting;
    lineRef(client_l);
    lineGetRoutingContext(line)->local_listener_port = lineGetRoutingContext(client_l)->local_listener_port;
    trojanserverApplyDestinationContext(line, target, true);
    remote->auth_username = client->auth_username != NULL ? stringDuplicate(client->auth_username) : NULL;
    remote->auth_password = client->auth_password != NULL ? stringDuplicate(client->auth_password) : NULL;
    trojanserverRecordLineUser(line, remote, &remote->user_handle);
    trojanserver_remote_map_t_result result = trojanserver_remote_map_t_insert(&client->udp_remote_lines, key, line);
    if (UNLIKELY(result.ref == NULL))
    {
        trojanserverLinestateDestroy(remote);
        lineDestroy(line);
        lineUnref(client_l);
        trojanserverCloseLineBidirectional(t, client_l);
        return NULL;
    }
    client->selected_remote = line;
    lineRef(line);
    remote->next_initialized = true;
    tunnelNextUpStreamInit(t, line);
    bool alive = lineIsAlive(line) && lineIsAlive(client_l);
    assert(! alive || remote->client_line == client_l);
    lineUnref(line);
    return alive ? line : NULL;
}

/* Restart traversal after every callback: no iterator or unretained sibling
 * pointer survives notifications, which may close or create other backends. */
bool trojanserverNotifyRemotePermission(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    line_t *notify = NULL;
    c_foreach(i, trojanserver_remote_map_t, ls->udp_remote_lines)
    {
        trojanserver_lstate_t *remote = lineGetState(i.ref->second, t);
        if (remote->next_initialized && remote->next_pause_sent != ls->prev_paused)
        {
            notify = i.ref->second;
            break;
        }
    }
    if (notify == NULL)
        return false;
    lineRef(notify);
    trojanserver_lstate_t *remote = lineGetState(notify, t);
    remote->next_pause_sent       = ls->prev_paused;
    if (ls->prev_paused)
        tunnelNextUpStreamPause(t, notify);
    else
        tunnelNextUpStreamResume(t, notify);
    lineUnref(notify);
    discard l; // The association pump retains l across this callback.
    return true;
}
