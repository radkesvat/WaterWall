#include "structure.h"

#include "loggers/network_logger.h"

static bool routerDeferUntilPrevious(tunnel_t *t, tunnel_chain_t *chain)
{
    if (t->prev != NULL)
    {
        return false;
    }

    if (chain->tunnels.len != 0)
    {
        LOGF("Router: cannot defer internal DomainResolver insertion on a non-empty chain");
        terminateProgram(1);
    }

    tunnelchainDestroy(chain);
    return true;
}

static void routerInsertDomainResolverBeforeSelf(tunnel_t *t, tunnel_chain_t *chain)
{
    router_tstate_t *ts       = tunnelGetState(t);
    tunnel_t        *resolver = ts->domain_resolver_tunnel;
    tunnel_t        *prev     = t->prev;

    if (resolver == NULL)
    {
        LOGF("Router: internal DomainResolver tunnel was not created");
        terminateProgram(1);
    }

    if (resolver->prev != NULL || resolver->next != NULL)
    {
        LOGF("Router: internal DomainResolver tunnel is already bound");
        terminateProgram(1);
    }

    if (prev->next == t)
    {
        prev->next = resolver;
    }

    resolver->prev = prev;
    resolver->next = t;
    t->prev        = resolver;

    tunnelchainInsert(chain, resolver);
}

static tunnel_t *routerFindRouteEntry(tunnel_t *router, tunnel_t *target)
{
    tunnel_t *entry = target;
    for (uint16_t i = 0; i < kMaxChainLen && entry != NULL; ++i)
    {
        if (entry->prev == router)
        {
            return entry;
        }

        entry = entry->prev;
    }

    return NULL;
}

static void routerSetRuleTargetEntry(tunnel_t *t, router_rule_t *rule, tunnel_t *target)
{
    tunnel_t *entry = routerFindRouteEntry(t, target);
    if (entry == NULL)
    {
        LOGF("Router: rule target node \"%s\" is not reachable from the router", target->node->name);
        terminateProgram(1);
    }

    rule->target_tunnel = entry;
}

// Fold a rule's target node into this router's chain so the target gets a
// per-line state slot and its downstream traffic returns through the router.
// If the target inserts internal tunnels before itself, store that branch entry
// as the callable route. The same target may be referenced by several rules.
static void routerBindRuleTarget(tunnel_t *t, tunnel_chain_t *chain, router_rule_t *rule)
{
    tunnel_t *target = rule->target_node->instance;
    if (target == NULL)
    {
        LOGF("Router: referenced target tunnel \"%s\" is not available", rule->target_node->name);
        terminateProgram(1);
    }

    if (target == t)
    {
        LOGF("Router: rule target must be different from the router");
        terminateProgram(1);
    }

    if (target->chain == chain)
    {
        routerSetRuleTargetEntry(t, rule, target);
        return;
    }

    if (target->prev != NULL && target->prev != t)
    {
        LOGF("Router: rule target node \"%s\" is already bound to previous node \"%s\"",
             target->node->name,
             target->prev->node->name);
        terminateProgram(1);
    }

    if (target->prev == NULL)
    {
        tunnelBindDown(t, target);
    }

    if (target->chain != NULL)
    {
        tunnelchainCombine(chain, target->chain);
    }
    else
    {
        target->onChain(target, chain);
    }

    routerSetRuleTargetEntry(t, rule, target);
}

void routerTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    router_tstate_t *ts = tunnelGetState(t);

    if (ts->resolve_domains)
    {
        if (routerDeferUntilPrevious(t, chain))
        {
            return;
        }

        routerInsertDomainResolverBeforeSelf(t, chain);
    }

    tunnelDefaultOnChain(t, chain);
    chain = tunnelGetChain(t);

    for (uint32_t i = 0; i < ts->rules_count; ++i)
    {
        routerBindRuleTarget(t, chain, &ts->rules[i]);
    }
}
