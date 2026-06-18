#include "structure.h"

#include "loggers/network_logger.h"

// Fold a rule's target node into this router's chain so the target gets a
// per-line state slot and its downstream traffic returns through the router.
// Mirrors SniffRouter's route binding; the same target may be referenced by
// several rules (it is bound only once).
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

    rule->target_tunnel = target;

    if (target == t->next)
    {
        return;
    }

    if (target->prev != NULL && target->prev != t)
    {
        LOGF("Router: rule target node \"%s\" is already bound to previous node \"%s\"",
             target->node->name,
             target->prev->node->name);
        terminateProgram(1);
    }

    if (target->chain == chain)
    {
        if (target->prev == t)
        {
            return;
        }

        LOGF("Router: rule target node \"%s\" is already in the router chain", target->node->name);
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
}

void routerTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    router_tstate_t *ts = tunnelGetState(t);

    tunnelDefaultOnChain(t, chain);
    chain = tunnelGetChain(t);

    for (uint32_t i = 0; i < ts->rules_count; ++i)
    {
        routerBindRuleTarget(t, chain, &ts->rules[i]);
    }
}
