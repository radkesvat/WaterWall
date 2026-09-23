#include "structure.h"

#include "loggers/network_logger.h"

static bool trojanserverDecodeSha224Hex(const uint8_t hex[kTrojanServerPasswordHexLen], uint8_t out[SHA224_DIGEST_SIZE])
{
    if (! asciiHexDecodeBytes(hex, kTrojanServerPasswordHexLen, out, SHA224_DIGEST_SIZE))
    {
        memoryZero(out, SHA224_DIGEST_SIZE);
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

static bool trojanserverLineAuthenticated(const trojanserver_lstate_t *ls)
{
    return userHandleIsValid(&ls->user_handle) || ls->auth_password != NULL;
}

static sbuf_t *trojanserverInputHead(trojanserver_lstate_t *ls)
{
    if (ls->input_head == NULL)
        ls->input_head = bufferqueuePopFront(&ls->pending_up);
    return ls->input_head;
}

static void trojanserverRecycleInputHead(trojanserver_lstate_t *ls)
{
    if (ls->input_head != NULL && sbufGetLength(ls->input_head) == 0)
    {
        lineReuseBuffer(ls->line, ls->input_head);
        ls->input_head = NULL;
    }
}

static bool trojanserverGatherHeader(trojanserver_lstate_t *ls, uint16_t needed)
{
    assert(needed <= sizeof(ls->header));
    ls->header_needed = needed;
    while (ls->header_filled < needed)
    {
        sbuf_t *head = trojanserverInputHead(ls);
        if (head == NULL)
            return false;
        uint32_t n = min(needed - ls->header_filled, sbufGetLength(head));
        sbufReadRangeToMemory(head, ls->header + ls->header_filled, n);
        ls->header_filled += n;
        trojanserverRecycleInputHead(ls);
    }
    return true;
}

/* Incomplete (0) is separate from invalid (-1) and complete (1). */
static int trojanserverGatherAddress(trojanserver_lstate_t *ls, uint16_t base, uint16_t trailer)
{
    if (! trojanserverGatherHeader(ls, base + 1))
        return 0;
    uint16_t length;
    switch (ls->header[base])
    {
    case kTrojanAtypIpv4:
        length = 7;
        break;
    case kTrojanAtypIpv6:
        length = 19;
        break;
    case kTrojanAtypDomain:
        if (! trojanserverGatherHeader(ls, base + 2))
            return 0;
        if (ls->header[base + 1] == 0)
            return -1;
        length = 4U + ls->header[base + 1];
        break;
    default:
        return -1;
    }
    if (! trojanserverGatherHeader(ls, base + length + trailer))
        return 0;
    size_t consumed = 0;
    return trojanserverParseAddressBytes(ls->header + base, length, &ls->frame_target, &consumed);
}

void trojanserverResetHeader(trojanserver_lstate_t *ls)
{
    ls->header_filled   = 0;
    ls->header_needed   = 1;
    ls->body_length     = 0;
    ls->frame_ready     = false;
    ls->frame_selected  = false;
    ls->selected_remote = NULL;
    addresscontextReset(&ls->frame_target);
}

bool trojanserverRetainActiveHead(trojanserver_lstate_t *ls)
{
    if (ls->input_head != NULL)
    {
        if (UNLIKELY(! bufferqueueTryPushFront(&ls->pending_up, &ls->input_head)))
            return false;
        ls->input_head = NULL;
    }
    return true;
}

void trojanserverParseInitial(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    /* Final replay during drain may reach a server whose branch is still unopened. */
    if (UNLIKELY(! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(l)))))
    {
        trojanserverCloseLineBidirectional(t, l);
        return;
    }
    if (ls->short_password)
    {
        LOGW("TrojanServer: rejected segmented password authentication on worker %u", (unsigned int) lineGetWID(l));
        trojanserverStartFallback(t, l, ls);
        return;
    }
    uint16_t prefix = (uint16_t) min(ls->input_bytes, (size_t) 58);
    if (! trojanserverGatherHeader(ls, prefix))
        return;
    bool valid = true;
    for (uint16_t i = 0; i < min(prefix, 56); ++i)
        valid &= asciiHexValue(ls->header[i]) >= 0;
    valid &= prefix <= 56 || ls->header[56] == '\r';
    valid &= prefix <= 57 || ls->header[57] == '\n';
    if (! valid)
    {
        if (trojanserverLineAuthenticated(ls))
            trojanserverCloseLineBidirectional(t, l);
        else
            trojanserverStartFallback(t, l, ls);
        return;
    }
    /* Short first deliveries already took fallback; cached input stays charged. */
    assert(prefix >= kTrojanServerPasswordHexLen);
    if (! trojanserverLineAuthenticated(ls))
    {
        uint8_t digest[SHA224_DIGEST_SIZE] = {0};
        bool    authenticated              = trojanserverDecodeSha224Hex(ls->header, digest) &&
                             trojanserverAuthenticateHash(t, l, digest, &ls->user_handle);
        memoryZero(digest, sizeof(digest));
        if (! authenticated)
        {
            trojanserverStartFallback(t, l, ls);
            return;
        }
    }
    if (! trojanserverGatherHeader(ls, 59))
        return;
    uint8_t                command = ls->header[58];
    trojanserver_tstate_t *ts      = tunnelGetState(t);
    if (! ((command == kTrojanCmdConnect && ts->allow_connect) || (command == kTrojanCmdUdpAssociate && ts->allow_udp)))
    {
        trojanserverCloseLineBidirectional(t, l);
        return;
    }
    int parsed = trojanserverGatherAddress(ls, 59, 2);
    if (parsed == 0)
    {
        if (ls->input_bytes > kTrojanServerMaxInitialBytes)
            trojanserverCloseLineBidirectional(t, l);
        return;
    }
    if (parsed < 0 || ls->header[ls->header_needed - 2] != '\r' || ls->header[ls->header_needed - 1] != '\n' ||
        (command == kTrojanCmdConnect && ! addresscontextHasPort(&ls->frame_target)))
    {
        trojanserverCloseLineBidirectional(t, l);
        return;
    }
    trojanserverRecordLineUser(l, ls, &ls->user_handle);
    ls->input_bytes -= ls->header_filled;
    if (command == kTrojanCmdUdpAssociate)
    {
        ls->branch = kTrojanServerBranchTrojan;
        ls->phase = kTrojanServerPhaseUdpWaitPacket;
        trojanserverResetHeader(ls);
        return;
    }
    trojanserverApplyDestinationContext(l, &ls->frame_target, false);
    trojanserverResetHeader(ls);
    if (! trojanserverRetainActiveHead(ls) || ls->input_bytes > kTrojanServerMaxPendingBytes ||
        ! bufferqueueTryAttachBudget(&ls->pending_up, &ls->output_budget))
    {
        trojanserverCloseLineBidirectional(t, l);
        return;
    }
    ls->branch              = kTrojanServerBranchTrojan;
    ls->input_bytes         = 0;
    ls->phase               = kTrojanServerPhaseTcpConnecting;
    ls->next_initialized    = true;
    ls->branch_initializing = true;
    tunnelNextUpStreamInit(t, l);
    if (lineIsAlive(l))
        ls->branch_initializing = false;
}

static sbuf_t *trojanserverExtractBody(trojanserver_lstate_t *ls)
{
    buffer_pool_t *pool    = lineGetBufferPool(ls->line);
    uint16_t       padding = bufferpoolGetLargeBufferPadding(pool);
    uint32_t       bytes   = ls->body_length;
    sbuf_t        *head    = trojanserverInputHead(ls);
    sbuf_t        *result  = NULL;
    if (bytes != 0 && head != NULL && sbufGetLength(head) == bytes && sbufGetLeftCapacity(head) >= padding)
    {
        result         = head;
        ls->input_head = NULL;
    }
    else
    {
        bool   has_pipe = head != NULL && sbufIsSplice(head);
        size_t range    = head == NULL ? 0 : sbufGetLength(head);
        c_foreach(i, ww_sbuffer_queue_t, ls->pending_up.q)
        {
            if (range >= bytes)
                break;
            has_pipe |= sbufIsSplice(*i.ref);
            range += sbufGetLength(*i.ref);
        }
        if (bytes != 0 && has_pipe)
            result = bufferpoolGetSpliceBuffer(pool);
        if (result != NULL && sbufGetLeftCapacity(result) < padding)
        {
            bufferpoolReuseBuffer(pool, result);
            result = NULL;
        }
        if (result == NULL)
            result = bufferpoolGetBestFit(pool, bytes, padding);
        uint32_t left = bytes;
        while (left != 0)
        {
            head           = trojanserverInputHead(ls);
            uint32_t count = min(left, sbufGetLength(head));
            result         = sbufMoveRangeTo(pool, head, result, count, bytes, padding);
            left -= count;
            trojanserverRecycleInputHead(ls);
        }
    }
    ls->input_bytes -= ls->header_filled + bytes;
    trojanserverResetHeader(ls);
    return result;
}

bool trojanserverDecodeUdp(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    if (! ls->frame_ready)
    {
        int parsed = trojanserverGatherAddress(ls, 0, 4);
        if (parsed == 0)
            return false;
        if (parsed < 0 || ! addresscontextHasPort(&ls->frame_target) || ls->header[ls->header_needed - 2] != '\r' ||
            ls->header[ls->header_needed - 1] != '\n')
        {
            trojanserverCloseLineBidirectional(t, l);
            return false;
        }
        uint16_t n      = ls->header_needed;
        ls->body_length = ((uint16_t) ls->header[n - 4] << 8U) | ls->header[n - 3];
        if (ls->body_length > kTrojanServerUdpMaxPacket)
        {
            trojanserverCloseLineBidirectional(t, l);
            return false;
        }
        ls->frame_ready = true;
    }
    if (ls->input_bytes - ls->header_filled < ls->body_length)
        return false;
    if (! ls->frame_selected)
    {
        ls->frame_selected = true;
        line_t *remote     = trojanserverGetOrCreateUdpRemoteLine(t, l, ls, &ls->frame_target);
        if (UNLIKELY(! lineIsAlive(l)))
            return false;
        if (UNLIKELY(remote == NULL))
        {
            /* The current datagram was never transferred. Losing its backend
             * during Init cannot silently discard it and continue this batch. */
            trojanserverCloseLineBidirectional(t, l);
            return false;
        }
        ls->selected_remote = remote;
        return true; // Reconcile newly initialized backend permission first.
    }
    line_t *remote = ls->selected_remote;
    if (UNLIKELY(remote == NULL))
    {
        trojanserverCloseLineBidirectional(t, l);
        return false;
    }
    lineRef(remote);
    sbuf_t *body = trojanserverExtractBody(ls);
    ls->phase    = kTrojanServerPhaseUdpEstablished;
    tunnelNextUpStreamPayload(t, remote, body);
    bool remote_alive = lineIsAlive(remote);
    lineUnref(remote);
    if (UNLIKELY(lineIsAlive(l) && ! remote_alive))
    {
        trojanserverCloseLineBidirectional(t, l);
        return false;
    }
    return true;
}
