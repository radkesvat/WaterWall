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

static router_match_t routerClassifyRules(router_tstate_t *ts, router_match_ctx_t *mctx, bool during_init)
{
    router_match_t match = {
        .result = kRouterClassifyDefault,
        .target = NULL,
    };

    routerClassifyPrepareGeositeHost(ts, mctx);

    for (uint32_t ri = 0; ri < ts->rules_count; ++ri)
    {
        router_rule_t *rule = &ts->rules[ri];

        /* A later payload condition must not delay a conclusive earlier rule.
         * Stop at the first rule requiring payload rather than treating absent
         * sniff observations as a mismatch and incorrectly skipping that rule. */
        if (during_init && (rule->protocol.present || rule->attributes.present))
        {
            match.result = kRouterClassifyNeedMore;
            return match;
        }

        if (routerRuleMatches(rule, mctx))
        {
            match.result = kRouterClassifyTarget;
            match.target = rule->target_tunnel;
            return match;
        }

        if (UNLIKELY(mctx->evaluation_failed))
        {
            // stop at the first evaluation error: neither a later rule nor the default route may be selected
            // on facts we could not establish
            match.result = kRouterClassifyError;
            match.target = NULL;
            return match;
        }
    }

    return match;
}

router_match_t routerClassifyDuringInit(router_tstate_t *ts, router_match_ctx_t *mctx)
{
    /* Explicit domain sniffing also prepares the destination for the selected
     * target. Preserve that work even when its rules use only known metadata. */
    if (ts->sniffing_modes != 0)
        return (router_match_t) {.result = kRouterClassifyNeedMore};

    return routerClassifyRules(ts, mctx, true);
}

/* First matching rule wins; once payload inspection has completed, every rule
 * can be evaluated and exhausting the table selects the ordinary next path. */
router_match_t routerClassify(router_tstate_t *ts, router_match_ctx_t *mctx)
{
    if (routerSniffRun(ts, mctx) == kRouterSniffNeedMore)
        return (router_match_t) {.result = kRouterClassifyNeedMore};

    return routerClassifyRules(ts, mctx, false);
}
