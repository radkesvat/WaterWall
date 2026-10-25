#include "auth.h"
#include "internal.h"

void vmessserverApplyDestinationContext(line_t *line, const address_context_t *target, bool udp)
{
    addresscontextCopy(lineGetDestinationAddressContext(line), target);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(line), udp ? IP_PROTO_UDP : IP_PROTO_TCP);
}

static void decodeDestination(const vmess_request_header_t *request, address_context_t *target)
{
    if (request->address_type == kVmessAtypDomain)
    {
        addresscontextDomainSet(target, (const char *) request->address, request->address_length);
        addresscontextSetPort(target, request->port);
        return;
    }
    ip_addr_t address = {0};
    if (request->address_type == kVmessAtypIpv4)
    {
        address.type = IPADDR_TYPE_V4;
        memoryCopy(&address.u_addr.ip4.addr, request->address, 4);
    }
    else
    {
        address.type = IPADDR_TYPE_V6;
        memoryCopy(&address.u_addr.ip6, request->address, 16);
    }
    addresscontextSetIpPort(target, &address, request->port);
}

static bool initializeCrypto(vmessserver_lstate_t *ls)
{
    vmessserver_tstate_t   *ts               = tunnelGetState(ls->tunnel);
    uint8_t                 response_key[16] = {0}, response_iv[16] = {0};
    vmess_request_header_t *request = &ls->request;
    bool                    ok =
        vmessResponseKeys(request->key, request->iv, response_key, response_iv) == kWCryptoOk &&
        vmessResponseHeaderSeal(response_key, response_iv, request->response, ls->response_header) == kWCryptoOk &&
        vmessBodyInit(&ls->input_crypto,
                      request->key,
                      request->iv,
                      request->security,
                      request->options,
                      request->command,
                      false,
                      ts->counter_policy) == kWCryptoOk &&
        vmessBodyInit(&ls->output_crypto,
                      response_key,
                      response_iv,
                      request->security,
                      request->options,
                      request->command,
                      true,
                      ts->counter_policy) == kWCryptoOk;
    if (ok && (request->options & VMESS_OPTION_AUTH_LENGTH) != 0)
    {
        ok = vmessBodySetLengthMaterial(&ls->output_crypto, request->key, request->iv) == kWCryptoOk;
    }
    memorySecureZero(response_key, sizeof(response_key));
    memorySecureZero(response_iv, sizeof(response_iv));
    return ok;
}

bool vmessserverHandleInitialRequest(tunnel_t *t, line_t *line, vmessserver_lstate_t *ls)
{
    vmessserver_tstate_t *ts = tunnelGetState(t);
    if (! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(line))))
        goto failed;
    if (! vmessserverGatherHeader(ls, 16))
        return true;
    if (ls->auth_result == 0)
    {
        vmessserverAuthSchedule(ls);
        return true;
    }
    if (ls->auth_result == 2)
    {
        vmessserverReason(ls, kVmessServerReasonAuthMismatch);
        return vmessserverStartFallback(t, line);
    }
    if (ls->auth_result != 1)
        goto failed;
    if (! vmessserverGatherHeader(ls, VMESS_REQUEST_PREFIX_SIZE))
        return true;
    if (ls->request_length == 0 &&
        vmessRequestLengthOpen(
            ls->auth_key.cmd_key, ls->header, ls->header + 16, ls->header + 34, &ls->request_length) != kWCryptoOk)
        goto failed;
    if (ls->request_length == 0 || ls->request_length > VMESS_REQUEST_HEADER_MAX)
        goto failed;
    uint16_t total = VMESS_REQUEST_PREFIX_SIZE + ls->request_length + 16;
    if (! vmessserverGatherHeader(ls, total))
        return true;
    if (vmessRequestHeaderOpen(ls->auth_key.cmd_key,
                               ls->header,
                               ls->header + 34,
                               ls->header + VMESS_REQUEST_PREFIX_SIZE,
                               ls->request_length + 16,
                               &ls->request) != kWCryptoOk)
        goto failed;
    if ((ls->request.command == kVmessCmdTcp && ! ts->allow_connect) ||
        (ls->request.command == kVmessCmdUdp && ! ts->allow_udp))
    {
        vmessserverReason(ls, kVmessServerReasonCommandDenied);
        goto failed;
    }
    uint8_t mode = ls->request.security == VMESS_SECURITY_AES128_GCM          ? 0
                   : ls->request.security == VMESS_SECURITY_CHACHA20_POLY1305 ? 1
                   : (ls->request.options & VMESS_OPTION_CHUNK) != 0          ? 2
                                                                              : 3;
    if ((ts->allowed_security & (1U << mode)) == 0)
    {
        vmessserverReason(ls, kVmessServerReasonSecurityDenied);
        goto failed;
    }
    ls->packetaddr = vmessRequestIsPacketAddr(&ls->request);
    if (ls->packetaddr && ! ts->packetaddr)
    {
        vmessserverReason(ls, kVmessServerReasonCommandDenied);
        goto failed;
    }
    if (! initializeCrypto(ls))
        goto failed;
    if (! vmessserverAuthResolve(ls))
    {
        vmessserverReason(ls, kVmessServerReasonAuthUnavailable);
        goto failed;
    }
    if (! vmessReplayAdmit(ts->replay,
                           ls->header,
                           ls->candidate.uuid,
                           ls->request.key,
                           ls->request.iv,
                           ls->auth_timestamp,
                           getTimeOfDayMS() / 1000,
                           getHRTimeUs() / 1000))
    {
        vmessserverReason(ls, kVmessServerReasonReplayOrCapacity);
        goto failed;
    }
    ls->input_bytes -= total;
    ls->header_filled = 0;
    ls->crypto_ready  = true;
    atomicAddU64(&ts->stats.applications, 1);
    vmessserverAuthLineDetach(ls);
    memorySecureZero(ls->auth_key.cmd_key, sizeof(ls->auth_key.cmd_key));
    memorySecureZero(ls->auth_key.auth_key, sizeof(ls->auth_key.auth_key));
    vmessserverRecordLineUser(line, ls);
    if (ls->packetaddr)
    {
        ls->udp_destinations = memoryAllocateZero((size_t) ts->packetaddr_max_destinations * sizeof(line_t *));
        ls->phase            = kVmessServerPhaseUdpConnecting;
        /* The authenticated carrier itself is the local UDP association endpoint.
         * No magic address is ever published to a resolver or connector. */
        ls->transport_est_sent = true;
        if (! lineCallWithRef(line, tunnelPrevDownStreamEst, t))
            return false;
        return ((vmessserver_lstate_t *) lineGetState(line, t))->tunnel == t;
    }
    address_context_t target = {0};
    decodeDestination(&ls->request, &target);
    if (ls->request.command == kVmessCmdUdp)
    {
        bool ok = vmessserverStartUdpBranch(t, line, ls, &target);
        addresscontextReset(&target);
        return ok;
    }
    vmessserverApplyDestinationContext(line, &target, false);
    addresscontextReset(&target);
    ls->phase               = kVmessServerPhaseTcpConnecting;
    ls->branch_initializing = true;
    if (! lineCallWithRef(line, tunnelNextUpStreamInit, t))
        return false;
    ls = lineGetState(line, t);
    if (ls->tunnel != t)
        return false;
    ls->branch_initializing = false;
    if (ls->response_paused && ! lineCallWithRef(line, tunnelNextUpStreamPause, t))
        return false;
    return ls->tunnel == t;
failed:
    vmessserverReason(ls, kVmessServerReasonHeader);
    vmessserverCloseLineBidirectional(t, line);
    return false;
}
