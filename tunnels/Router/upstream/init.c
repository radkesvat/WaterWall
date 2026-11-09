#include "structure.h"

#include "loggers/network_logger.h"

void routerTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    router_tstate_t *ts = tunnelGetState(t);
    router_lstate_t *ls = lineGetState(l, t);

    routerLinestateInitialize(ls);
    const address_context_t *dest = lineGetDestinationAddressContext(l);
    ls->datagram_input            = dest->proto_udp && ! dest->proto_tcp && ! dest->proto_icmp && ! dest->proto_packet;
    addresscontextClearDetectedProtocols(lineGetDestinationAddressContext(l));

    router_match_ctx_t mctx = {
        .router_state = ts,
        .line         = l,
        .line_state   = ls,
        .payload      = NULL,
        .payload_len  = 0,
    };
    const router_match_t match = routerClassifyDuringInit(ts, &mctx);
    if (match.result == kRouterClassifyNeedMore)
    {
        return;
    }
    if (match.result == kRouterClassifyError)
    {
        LOGE("Router: static rule evaluation failed during Init, closing this line");
        routerLinestateDestroy(l, ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    routerCommitRoute(t, l, ls, match.result == kRouterClassifyTarget ? match.target : NULL, NULL);
}
