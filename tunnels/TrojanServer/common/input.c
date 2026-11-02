#include "internal.h"

#include "TrojanCommon/input.h"
#include "loggers/network_logger.h"

static bool trojanserverLineAuthenticated(const trojanserver_lstate_t *ls)
{
    return userHandleIsValid(&ls->user_handle) || ls->auth_password != NULL;
}

void trojanserverResetHeader(trojanserver_lstate_t *ls)
{
    ls->body_length     = 0;
    ls->frame_ready     = false;
    ls->frame_selected  = false;
    ls->selected_remote = NULL;
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
    uint16_t prefix   = (uint16_t) min(bufferreaderLength(&ls->reader), (size_t) 58);
    bool     gathered = bufferreaderGather(&ls->reader, prefix);
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
    if (! bufferreaderGather(&ls->reader, 59))
        return;
    uint8_t                command = ls->header[58];
    trojanserver_tstate_t *ts      = tunnelGetState(t);
    if (! ((command == kTrojanCmdConnect && ts->allow_connect) || (command == kTrojanCmdUdpAssociate && ts->allow_udp)))
    {
        trojanserverCloseLineBidirectional(t, l);
        return;
    }
    socks_address_t        target;
    int                    parsed = trojanGatherAddress(&ls->reader, 59, 2, &target);
    if (parsed == 0)
        return;
    const uint16_t header_length = bufferreaderHeaderLength(&ls->reader);
    if (parsed < 0 || ls->header[header_length - 2] != '\r' || ls->header[header_length - 1] != '\n' ||
        (command == kTrojanCmdConnect && target.port == 0))
    {
        trojanserverCloseLineBidirectional(t, l);
        return;
    }
    trojanserverRecordLineUser(l, ls, &ls->user_handle);
    bufferreaderConsumeHeader(&ls->reader);
    if (command == kTrojanCmdUdpAssociate)
    {
        ls->branch = kTrojanServerBranchTrojan;
        ls->phase  = kTrojanServerPhaseUdpWaitPacket;
        trojanserverResetHeader(ls);
        return;
    }
    trojanserverApplyDestinationContext(l, &target, false);
    trojanserverResetHeader(ls);
    if (bufferreaderLength(&ls->reader) > kTrojanServerMaxPendingBytes ||
        ! bufferreaderMoveToQueue(&ls->reader, &ls->pending_up, false) ||
        ! bufferqueueTryAttachBudget(&ls->pending_up, &ls->output_budget))
    {
        trojanserverCloseLineBidirectional(t, l);
        return;
    }
    ls->branch              = kTrojanServerBranchTrojan;
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
    sbuf_t *result = bufferreaderTakeBody(&ls->reader, ls->body_length);
    trojanserverResetHeader(ls);
    return result;
}

bool trojanserverDecodeUdp(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    if (! ls->frame_ready)
    {
        const socks_address_result_t parsed = trojanReadUdpHeader(&ls->reader, &ls->body_length);
        if (parsed == 0)
            return false;
        if (parsed < 0)
        {
            trojanserverCloseLineBidirectional(t, l);
            return false;
        }
        ls->frame_ready = true;
    }
    if (! bufferreaderBodyReady(&ls->reader, ls->body_length))
    {
        if (! bufferreaderSettle(&ls->reader, kTrojanServerMaxInputCharge))
            trojanserverCloseLineBidirectional(t, l);
        return false;
    }
    if (! ls->frame_selected)
    {
        ls->frame_selected = true;
        /* Cached wire metadata outlives partial-body input without owning a domain. */
        socks_address_t        target;
        socks_address_result_t decoded = socksAddressDecode(ls->header, bufferreaderHeaderLength(&ls->reader), &target);
        assert(decoded == kSocksAddressComplete);
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

void trojanserverApplyDestinationContext(line_t *l, const socks_address_t *target, bool udp)
{
    address_context_t *dest = lineGetDestinationAddressContext(l);
    if (target->kind == kSocksAddressDomain)
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
        ip.type      = target->kind == kSocksAddressIpv4 ? IPADDR_TYPE_V4 : IPADDR_TYPE_V6;
        if (ip.type == IPADDR_TYPE_V4)
            memoryCopy(&ip.u_addr.ip4.addr, target->bytes, 4);
        else
            memoryCopy(&ip.u_addr.ip6, target->bytes, 16);
        addresscontextSetIpPort(dest, &ip, target->port);
    }
    addresscontextSetOnlyProtocol(dest, udp ? IP_PROTO_UDP : IP_PROTO_TCP);
}
