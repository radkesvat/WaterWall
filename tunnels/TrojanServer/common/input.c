#include "internal.h"

#include "buffer_queue_range.h"
#include "loggers/network_logger.h"

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
static int trojanserverGatherAddress(trojanserver_lstate_t *ls, uint16_t base, uint16_t trailer,
                                     trojanserver_address_t *target)
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
    return trojanserverAddressDecode(ls->header + base, length, target);
}

void trojanserverResetHeader(trojanserver_lstate_t *ls)
{
    ls->header_filled   = 0;
    ls->header_needed   = 1;
    ls->body_length     = 0;
    ls->frame_ready     = false;
    ls->frame_selected  = false;
    ls->selected_remote = NULL;
}

void trojanserverRetainActiveHead(trojanserver_lstate_t *ls)
{
    if (ls->input_head != NULL)
    {
        /* Initial parsing only consumes this admitted head; no callback or new
         * admission intervenes before restoring it to the still-unbound queue. */
        assert(ls->pending_up.budget == NULL);
        bufferqueuePushFront(&ls->pending_up, ls->input_head);
        ls->input_head = NULL;
    }
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
    bool     gathered = trojanserverGatherHeader(ls, prefix);
    assert(gathered);
    discard gathered;
    /* Short first deliveries already took fallback; cached input stays charged. */
    assert(prefix >= kTrojanServerPasswordHexLen);
    if ((prefix > 56 && ls->header[56] != '\r') || (prefix > 57 && ls->header[57] != '\n'))
    {
        if (trojanserverLineAuthenticated(ls))
            trojanserverCloseLineBidirectional(t, l);
        else
            trojanserverStartFallback(t, l, ls);
        return;
    }
    if (! trojanserverLineAuthenticated(ls))
    {
        uint8_t digest[SHA224_DIGEST_SIZE] = {0};
        bool    valid_hash = asciiHexDecodeBytes(ls->header, kTrojanServerPasswordHexLen, digest, sizeof(digest));
        trojanserver_auth_result_t result =
            valid_hash ? trojanserverAuthenticateHash(t, l, digest, &ls->user_handle) : kTrojanServerAuthRejected;
        memoryZero(digest, sizeof(digest));
        if (result != kTrojanServerAuthAccepted)
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
    trojanserver_address_t target;
    int                    parsed = trojanserverGatherAddress(ls, 59, 2, &target);
    if (parsed == 0)
        return;
    if (parsed < 0 || ls->header[ls->header_needed - 2] != '\r' || ls->header[ls->header_needed - 1] != '\n' ||
        (command == kTrojanCmdConnect && target.port == 0))
    {
        trojanserverCloseLineBidirectional(t, l);
        return;
    }
    trojanserverRecordLineUser(l, ls, &ls->user_handle);
    ls->input_bytes -= ls->header_filled;
    if (command == kTrojanCmdUdpAssociate)
    {
        ls->branch = kTrojanServerBranchTrojan;
        ls->phase  = kTrojanServerPhaseUdpWaitPacket;
        trojanserverResetHeader(ls);
        return;
    }
    trojanserverApplyDestinationContext(l, &target, false);
    trojanserverResetHeader(ls);
    trojanserverRetainActiveHead(ls);
    if (ls->input_bytes > kTrojanServerMaxPendingBytes ||
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
    {
        ls->branch_initializing = false;
        if (ls->prev_paused && ! ls->next_pause_sent)
            tunnelUpStreamPause(t, l);
    }
}

static sbuf_t *trojanserverExtractBody(trojanserver_lstate_t *ls)
{
    uint32_t bytes  = ls->body_length;
    sbuf_t  *result = bufferRangeTakeExact(lineGetBufferPool(ls->line), &ls->input_head, &ls->pending_up, bytes);
    ls->input_bytes -= ls->header_filled + bytes;
    trojanserverResetHeader(ls);
    return result;
}

bool trojanserverDecodeUdp(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    if (! ls->frame_ready)
    {
        trojanserver_address_t target;
        int                    parsed = trojanserverGatherAddress(ls, 0, 4, &target);
        if (parsed == 0)
            return false;
        if (parsed < 0 || target.port == 0 || ls->header[ls->header_needed - 2] != '\r' ||
            ls->header[ls->header_needed - 1] != '\n')
        {
            trojanserverCloseLineBidirectional(t, l);
            return false;
        }
        uint16_t n      = ls->header_needed;
        ls->body_length = ((uint16_t) ls->header[n - 4] << 8U) | ls->header[n - 3];
        ls->frame_ready = true;
    }
    if (ls->input_bytes - ls->header_filled < ls->body_length)
        return false;
    if (! ls->frame_selected)
    {
        ls->frame_selected = true;
        /* Cached wire metadata outlives partial-body input without owning a domain. */
        trojanserver_address_t        target;
        trojanserver_address_result_t decoded = trojanserverAddressDecode(ls->header, ls->header_filled, &target);
        assert(decoded == kTrojanServerAddressComplete);
        discard decoded;
        line_t *remote = trojanserverGetOrCreateUdpRemoteLine(t, l, ls, &target);
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

void trojanserverApplyDestinationContext(line_t *l, const trojanserver_address_t *target, bool udp)
{
    address_context_t *dest = lineGetDestinationAddressContext(l);
    if (target->kind == kTrojanServerAddressDomain)
    {
        char *domain = memoryAllocate((size_t) target->length + 1);
        memoryCopy(domain, target->bytes, target->length);
        domain[target->length] = '\0';
        addresscontextReset(dest);
        dest->domain     = domain;
        dest->domain_len = (uint8_t) target->length;
        dest->type_ip    = kCCTypeDomain;
        dest->port       = target->port;
    }
    else
    {
        ip_addr_t ip = {0};
        ip.type      = target->kind == kTrojanServerAddressIpv4 ? IPADDR_TYPE_V4 : IPADDR_TYPE_V6;
        if (ip.type == IPADDR_TYPE_V4)
            memoryCopy(&ip.u_addr.ip4.addr, target->bytes, 4);
        else
            memoryCopy(&ip.u_addr.ip6, target->bytes, 16);
        addresscontextSetIpPort(dest, &ip, target->port);
    }
    addresscontextSetOnlyProtocol(dest, udp ? IP_PROTO_UDP : IP_PROTO_TCP);
}
