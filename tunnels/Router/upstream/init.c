#include "structure.h"

#include "loggers/network_logger.h"
#include "modules/protocol/protocol.h"

static bool routerCanCommitRouteDuringInit(const router_tstate_t *ts, const router_lstate_t *ls)
{
    /* Protocol, attribute, and configured domain sniffing rules need the
     * first payload window. Every remaining matcher is fully determined by
     * line metadata already present at Init. Datagram-only protocols (dns)
     * can never be sniffed on a stream line, so they must not hold one. */
    uint32_t needed_protocols = ts->needed_protocols;
    if (! ls->datagram_input)
    {
        needed_protocols &= ~routerProtocolDatagramOnlyMask();
    }
    return needed_protocols == 0 && ts->sniffing_modes == 0 && ! ts->needs_http_upgrade_attribute;
}

void routerTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    router_tstate_t *ts = tunnelGetState(t);
    router_lstate_t *ls = lineGetState(l, t);

    routerLinestateInitialize(ls);
    const address_context_t *dest = lineGetDestinationAddressContext(l);
    ls->datagram_input            = dest->proto_udp && ! dest->proto_tcp && ! dest->proto_icmp && ! dest->proto_packet;
    addresscontextClearDetectedProtocols(lineGetDestinationAddressContext(l));

    /* A resolver-origin DNS query line never waits for payload sniffing: it
     * commits here even when other rules need the first payload window. */
    if (! addresscontextIsResolverOrigin(dest) && ! routerCanCommitRouteDuringInit(ts, ls))
    {
        return;
    }

    router_match_ctx_t mctx = {
        .router_state = ts,
        .line         = l,
        .line_state   = ls,
        .payload      = NULL,
        .payload_len  = 0,
    };
    const router_match_t match = routerClassify(ts, &mctx);
    if (match.result == kRouterClassifyError)
    {
        LOGE("Router: static rule evaluation failed during Init, closing this line");
        routerLinestateDestroy(l, ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    /* Metadata-only rules, and resolver-origin lines that skip sniffing, cannot request payload. */
    assert(match.result != kRouterClassifyNeedMore);

    routerCommitRoute(t, l, ls, match.result == kRouterClassifyTarget ? match.target : NULL, NULL);
}
