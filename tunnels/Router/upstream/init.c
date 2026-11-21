#include "structure.h"

#include "loggers/network_logger.h"

void routerTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    router_tstate_t *ts = tunnelGetState(t);
    router_lstate_t *ls = lineGetState(l, t);

    address_context_t *dest = lineGetDestinationAddressContext(l);
    routerLinestateInitialize(ls, dest);
    if (ls->network_offer == 0)
    {
        LOGE("Router: invalid destination transport offer, closing this line");
        routerLinestateDestroy(l, ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    addresscontextClearDetectedProtocols(dest);

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

    routerCommitRoute(t, l, ls, match, NULL);
}
