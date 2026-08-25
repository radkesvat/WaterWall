#include "structure.h"

#include "loggers/network_logger.h"

static bool routerCanCommitRouteDuringInit(const router_tstate_t *ts)
{
    /* Protocol, attribute, and configured domain sniffing rules need the
     * first payload window. Every remaining matcher is fully determined by
     * line metadata already present at Init. */
    return ts->needed_protocols == 0 && ts->sniffing_modes == 0 && ! ts->needs_http_upgrade_attribute;
}

static void routerCommitInitialRoute(tunnel_t *t, line_t *l, router_lstate_t *ls, const router_match_t *match)
{
    lineRef(l);

    if (match->result == kRouterClassifyTarget)
    {
        ls->target = match->target;
        ls->route  = kRouterRouteTarget;
        tunnelUpStreamInit(match->target, l);
    }
    else
    {
        ls->target = NULL;
        ls->route  = kRouterRouteDefault;
        tunnelNextUpStreamInit(t, l);
    }

    lineUnref(l);
}

void routerTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    router_tstate_t *ts = tunnelGetState(t);
    router_lstate_t *ls = lineGetState(l, t);

    routerLinestateInitialize(ls);
    addresscontextClearDetectedProtocols(lineGetDestinationAddressContext(l));

    if (! routerCanCommitRouteDuringInit(ts))
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

    if (match.result == kRouterClassifyNeedMore)
    {
        /* Defensive: routerCanCommitRouteDuringInit() excludes every current
         * payload consumer, but keep the lazy contract if a future matcher
         * introduces one. */
        return;
    }

    routerCommitInitialRoute(t, l, ls, &match);

    /*
     * Payload-dependent routing remains intentionally lazy so content-based
     * matchers retain their first-payload window. Static routing commits above
     * so handshake clients can receive their downstream establishment before
     * producing a first upstream payload.
     */
}
