#include "internal.h"

#include "loggers/network_logger.h"

/* The caller has gathered and validated the complete destination header. */
static void vlessserverDecodeDestination(const uint8_t *buf, address_context_t *out)
{
    uint16_t port_be = 0;
    memoryCopy(&port_be, buf, sizeof(port_be));
    uint16_t port = be16toh(port_be);
    uint8_t  atyp = buf[2];

    if (atyp == kVlessAtypIpv4)
    {
        ip_addr_t ip = {0};
        ip.type      = IPADDR_TYPE_V4;
        memoryCopy(&ip.u_addr.ip4.addr, buf + 3, 4);
        addresscontextSetIpPort(out, &ip, port);
        return;
    }

    if (atyp == kVlessAtypIpv6)
    {
        ip_addr_t ip = {0};
        ip.type      = IPADDR_TYPE_V6;
        memoryCopy(&ip.u_addr.ip6, buf + 3, 16);
        addresscontextSetIpPort(out, &ip, port);
        return;
    }

    assert(atyp == kVlessAtypDomain && buf[3] != 0);
    addresscontextDomainSet(out, (const char *) (buf + 4), buf[3]);
    addresscontextSetPort(out, port);
}

void vlessserverApplyDestinationContext(line_t *l, const address_context_t *target, bool udp)
{
    address_context_t *dest = lineGetDestinationAddressContext(l);

    addresscontextCopy(dest, target);
    addresscontextSetOnlyProtocol(dest, udp ? IP_PROTO_UDP : IP_PROTO_TCP);
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

bool vlessserverHandleInitialRequest(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, bool reject_short_uuid)
{
    /* Final replay during drain may reach a server whose branch is still unopened. */
    if (UNLIKELY(! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(l)))))
    {
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }
    if (reject_short_uuid)
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
    if (! vlessserverLineAuthenticated(ls))
    {
        vlessserver_auth_result_t result = vlessserverAuthenticateUuid(t, l, ls, ls->header + 1);
        if (result == kVlessServerAuthRejected)
            return vlessserverStartFallback(t, l);
    }
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
    address_context_t target = {0};
    vlessserverDecodeDestination(ls->header + 19, &target);
    if (! addresscontextHasPort(&target))
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
