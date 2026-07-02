#include "structure.h"

static void routerClassifyPrepareGeositeHost(router_tstate_t *ts, router_match_ctx_t *mctx)
{
    if (ts->geosite_lists_count == 0)
    {
        return;
    }

    const address_context_t *dest = lineGetDestinationAddressContext(mctx->line);
    routerGeositeHostCachePrepare(&mctx->geosite_host, (const uint8_t *) dest->domain, (uint32_t) dest->domain_len);
}

/*
 * Evaluate the configured rules against one connection. Rules are tested in JSON
 * order; the first rule whose conditions ALL match (logical AND, implemented by
 * routerRuleMatches) selects that rule's target tunnel. If no rule matches, the
 * connection uses the default route (the node's top-level "next").
 */
router_match_t routerClassify(router_tstate_t *ts, router_match_ctx_t *mctx)
{
    router_match_t match = {
        .result = kRouterClassifyDefault,
        .target = NULL,
    };

    if (routerSniffRun(ts, mctx) == kRouterSniffNeedMore)
    {
        match.result = kRouterClassifyNeedMore;
        return match;
    }

    if (ts->rules_count == 0)
    {
        return match;
    }

    routerClassifyPrepareGeositeHost(ts, mctx);

    for (uint32_t ri = 0; ri < ts->rules_count; ++ri)
    {
        router_rule_t *rule = &ts->rules[ri];

        if (routerRuleMatches(rule, mctx))
        {
            match.result = kRouterClassifyTarget;
            match.target = rule->target_tunnel;
            return match;
        }
    }

    return match;
}
