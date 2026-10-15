/*
 * Covers: router chain ownership; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: replacement-chain ownership, duplicate direct/helper targets, configured-default
 * targets with helpers, and rejection of targets owned by nested/configured branches.
 * Checks: Assertion labels include: replacement chain was not installed; SniffRouter chain construction
 * unexpectedly failed startup; SniffRouter did not retain the replacement chain; SniffRouter did not
 * combine both route branches
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.router_chain_ownership_unit
 */
#include "Router/structure.h"
#include "loggers/network_logger.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "SniffRouter/structure.h"

static tunnel_chain_t *replacement_chain;
static tunnel_t       *target_helpers[2];

static node_t testNode(const char *name, const char *type)
{
    return (node_t) {
        .name        = (char *) name,
        .type        = (char *) type,
        .hash_name   = calcHashBytes(name, stringLength(name)),
        .layer_group = kNodeLayer4,
    };
}

static tunnel_t *testTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, 0, 0);
    require(t != NULL, "failed to create test tunnel");
    node->instance = t;
    return t;
}

static void replaceCurrentChainOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    require(replacement_chain != NULL, "replacement chain was not installed");

    tunnelchainInsert(chain, t);
    tunnelchainCombine(replacement_chain, chain);
}

static void testSniffRouterRefreshesChainBetweenRoutes(void)
{
    node_t router_node      = testNode("sniff-router", "SniffRouter");
    node_t replacement_node = testNode("sniff-replacement", "TestTunnel");
    node_t replacing_node   = testNode("sniff-replacing-route", "TestTunnel");
    node_t following_node   = testNode("sniff-following-route", "TestTunnel");

    tunnel_t *router      = tunnelCreate(&router_node, sizeof(sniffrouter_tstate_t), 0);
    tunnel_t *replacement = testTunnelCreate(&replacement_node);
    tunnel_t *replacing   = testTunnelCreate(&replacing_node);
    tunnel_t *following   = testTunnelCreate(&following_node);
    require(router != NULL, "failed to create SniffRouter test tunnel");
    router_node.instance = router;
    replacing->onChain   = replaceCurrentChainOnChain;

    sniffrouter_route_t routes[2] = {
        {.node = &replacing_node},
        {.node = &following_node},
    };
    sniffrouter_tstate_t *state = tunnelGetState(router);
    state->routes               = routes;
    state->routes_count         = 2;

    replacement_chain = tunnelchainCreate(0);
    tunnelchainInsert(replacement_chain, replacement);

    tunnel_chain_t *following_chain = tunnelchainCreate(0);
    tunnelchainInsert(following_chain, following);

    tunnel_chain_t      *initial_chain = tunnelchainCreate(0);
    ww_startup_context_t startup       = {0};
    wwStartupContextBegin(&startup);
    sniffrouterTunnelOnChain(router, initial_chain);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(wwStartupSucceeded(result), "SniffRouter chain construction unexpectedly failed startup");
    require(tunnelGetChain(router) == replacement_chain, "SniffRouter did not retain the replacement chain");
    require(replacement_chain->tunnels.len == 4, "SniffRouter did not combine both route branches");
    require(routes[0].tunnel == replacing, "SniffRouter lost the replacing route entry");
    require(routes[1].tunnel == following, "SniffRouter lost the following route entry");

    tunnelchainDestroy(replacement_chain);
    replacement_chain = NULL;
    tunnelDestroy(following);
    tunnelDestroy(replacing);
    tunnelDestroy(replacement);
    tunnelDestroy(router);
}

static void testRouterRefreshesChainBetweenRules(void)
{
    node_t router_node      = testNode("router", "Router");
    node_t replacement_node = testNode("router-replacement", "TestTunnel");
    node_t replacing_node   = testNode("router-replacing-rule", "TestTunnel");
    node_t following_node   = testNode("router-following-rule", "TestTunnel");

    tunnel_t *router      = tunnelCreate(&router_node, sizeof(router_tstate_t), 0);
    tunnel_t *replacement = testTunnelCreate(&replacement_node);
    tunnel_t *replacing   = testTunnelCreate(&replacing_node);
    tunnel_t *following   = testTunnelCreate(&following_node);
    require(router != NULL, "failed to create Router test tunnel");
    router_node.instance = router;
    replacing->onChain   = replaceCurrentChainOnChain;

    router_rule_t rules[2] = {
        {.target_node = &replacing_node},
        {.target_node = &following_node},
    };
    router_tstate_t *state = tunnelGetState(router);
    state->rules           = rules;
    state->rules_count     = 2;

    replacement_chain = tunnelchainCreate(0);
    tunnelchainInsert(replacement_chain, replacement);

    tunnel_chain_t *following_chain = tunnelchainCreate(0);
    tunnelchainInsert(following_chain, following);

    tunnel_chain_t      *initial_chain = tunnelchainCreate(0);
    ww_startup_context_t startup       = {0};
    wwStartupContextBegin(&startup);
    routerTunnelOnChain(router, initial_chain);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(wwStartupSucceeded(result), "Router chain construction unexpectedly failed startup");
    require(tunnelGetChain(router) == replacement_chain, "Router did not retain the replacement chain");
    require(replacement_chain->tunnels.len == 4, "Router did not combine both rule branches");
    require(rules[0].target_tunnel == replacing, "Router lost the replacing rule entry");
    require(rules[1].target_tunnel == following, "Router lost the following rule entry");

    tunnelchainDestroy(replacement_chain);
    replacement_chain = NULL;
    tunnelDestroy(following);
    tunnelDestroy(replacing);
    tunnelDestroy(replacement);
    tunnelDestroy(router);
}

static void insertTargetHelpersOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    for (size_t i = 0; i < sizeof(target_helpers) / sizeof(target_helpers[0]); ++i)
    {
        if (! tunnelInsertBefore(t, target_helpers[i], chain))
        {
            return;
        }
    }
    tunnelDefaultOnChain(t, chain);
}

#if WW_ROUTER_LOOKUP_WRAP_TEST
static node_t *configured_nodes[2];

node_t *__wrap_nodemanagerGetConfigNodeByHash(node_manager_config_t *config, hash_t hash);
node_t *__wrap_nodemanagerGetConfigNodeByHash(node_manager_config_t *config, hash_t hash)
{
    require(config == NULL, "unexpected node-manager config");
    for (size_t i = 0; i < sizeof(configured_nodes) / sizeof(configured_nodes[0]); ++i)
    {
        if (configured_nodes[i] != NULL && configured_nodes[i]->hash_name == hash)
        {
            return configured_nodes[i];
        }
    }
    require(false, "unexpected configured-node lookup");
    return NULL;
}
#endif

static void testRepeatedTarget(bool sniffrouter, bool with_helpers, bool default_target)
{
    testCaseSet(sniffrouter ? "SniffRouter target reuse" : "Router target reuse");
    node_t router_node     = testNode("router", sniffrouter ? "SniffRouter" : "Router");
    node_t target_node     = testNode("target", "TestTunnel");
    node_t helper_nodes[2] = {
        testNode("target.prepare", "TestTunnel"),
        testNode("target.resolve", "TestTunnel"),
    };
    tunnel_t *router =
        tunnelCreate(&router_node, sniffrouter ? sizeof(sniffrouter_tstate_t) : sizeof(router_tstate_t), 0);
    tunnel_t *target = testTunnelCreate(&target_node);
    require(router != NULL, "failed to create Router");
    if (with_helpers)
    {
        for (size_t i = 0; i < sizeof(target_helpers) / sizeof(target_helpers[0]); ++i)
        {
            target_helpers[i] = testTunnelCreate(&helper_nodes[i]);
        }
        target->onChain = insertTargetHelpersOnChain;
    }
    if (default_target)
    {
#if WW_ROUTER_LOOKUP_WRAP_TEST
        router_node.next      = target_node.name;
        router_node.hash_next = target_node.hash_name;
        configured_nodes[0]   = &target_node;
#else
        require(false, "default-target fixture requires node lookup wrapping");
#endif
    }
    router_rule_t rules[2] = {
        {.target_node = &target_node},
        {.target_node = &target_node},
    };
    sniffrouter_route_t routes[2] = {
        {.node = &target_node},
        {.node = &target_node},
    };
    if (sniffrouter)
    {
        sniffrouter_tstate_t *state = tunnelGetState(router);
        state->routes               = routes;
        state->routes_count         = 2;
        router->onChain             = sniffrouterTunnelOnChain;
    }
    else
    {
        router_tstate_t *state = tunnelGetState(router);
        state->rules           = rules;
        state->rules_count     = 2;
        router->onChain        = routerTunnelOnChain;
    }

    tunnel_chain_t      *chain   = tunnelchainCreate(0);
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    router->onChain(router, chain);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(wwStartupSucceeded(result), "Router rejected its own branch target");
    tunnel_t *entry = with_helpers ? target_helpers[0] : target;
    require(sniffrouter ? routes[0].tunnel == entry && routes[1].tunnel == entry
                        : rules[0].target_tunnel == entry && rules[1].target_tunnel == entry,
            "router did not retain the same callable entry for repeated targets");
    require(entry->prev == router, "target entry lost its Router predecessor");
    require(chain->tunnels.len == (with_helpers ? 4 : 2), "Router inserted a repeated target twice");
    if (default_target)
    {
        require(router->next == entry, "default target did not retain its inserted helpers");
    }
    else
    {
        require(router->next == NULL, "alternate target changed the default link");
    }

    tunnelchainDestroy(chain);
    if (with_helpers)
    {
        for (size_t i = 0; i < sizeof(target_helpers) / sizeof(target_helpers[0]); ++i)
        {
            tunnelDestroy(target_helpers[i]);
            target_helpers[i] = NULL;
        }
    }
#if WW_ROUTER_LOOKUP_WRAP_TEST
    configured_nodes[0] = NULL;
#endif
    tunnelDestroy(target);
    tunnelDestroy(router);
}

static void testRejectsNestedTarget(bool sniffrouter)
{
    testCaseSet(sniffrouter ? "SniffRouter rejects another Router's target" : "Router rejects another Router's target");
    node_t    router_node = testNode("router", sniffrouter ? "SniffRouter" : "Router");
    node_t    nested_node = testNode("nested", "Router");
    node_t    target_node = testNode("target", "TestTunnel");
    node_t    later_node  = testNode("later", "TestTunnel");
    tunnel_t *router =
        tunnelCreate(&router_node, sniffrouter ? sizeof(sniffrouter_tstate_t) : sizeof(router_tstate_t), 0);
    tunnel_t *nested = tunnelCreate(&nested_node, sizeof(router_tstate_t), 0);
    tunnel_t *target = testTunnelCreate(&target_node);
    tunnel_t *later  = testTunnelCreate(&later_node);
    require(router != NULL && nested != NULL, "failed to create Routers");
    nested_node.instance = nested;
    nested->onChain      = routerTunnelOnChain;

    router_rule_t rules[3] = {
        {.target_node = &nested_node},
        {.target_node = &target_node},
        {.target_node = &later_node},
    };
    sniffrouter_route_t routes[3] = {
        {.node = &nested_node},
        {.node = &target_node},
        {.node = &later_node},
    };
    if (sniffrouter)
    {
        sniffrouter_tstate_t *state = tunnelGetState(router);
        state->routes               = routes;
        state->routes_count         = 3;
        router->onChain             = sniffrouterTunnelOnChain;
    }
    else
    {
        router_tstate_t *state = tunnelGetState(router);
        state->rules           = rules;
        state->rules_count     = 3;
        router->onChain        = routerTunnelOnChain;
    }
    router_rule_t    nested_rule  = {.target_node = &target_node};
    router_tstate_t *nested_state = tunnelGetState(nested);
    nested_state->rules           = &nested_rule;
    nested_state->rules_count     = 1;

    tunnel_chain_t      *chain   = tunnelchainCreate(0);
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    router->onChain(router, chain);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(! wwStartupSucceeded(result), "Router accepted a target belonging to another Router");
    require((sniffrouter ? routes[0].tunnel : rules[0].target_tunnel) == nested && nested_rule.target_tunnel == target,
            "Router rejected or changed a valid nested branch");
    require((sniffrouter ? routes[1].tunnel : rules[1].target_tunnel) == NULL,
            "router published an incompatible target");
    require(target->prev == nested, "rejected rule changed the target's predecessor");
    require(later->chain == NULL && later->prev == NULL &&
                (sniffrouter ? routes[2].tunnel : rules[2].target_tunnel) == NULL,
            "router continued binding targets after a rejected route");

    tunnelchainDestroy(chain);
    tunnelDestroy(later);
    tunnelDestroy(target);
    tunnelDestroy(nested);
    tunnelDestroy(router);
}

#if WW_ROUTER_LOOKUP_WRAP_TEST
static void testRejectsDefaultDescendant(bool sniffrouter)
{
    testCaseSet(sniffrouter ? "SniffRouter rejects a default descendant" : "Router rejects a default descendant");
    node_t router_node    = testNode("router", sniffrouter ? "SniffRouter" : "Router");
    node_t middle_node    = testNode("middle", "TestTunnel");
    node_t target_node    = testNode("target", "TestTunnel");
    router_node.next      = middle_node.name;
    router_node.hash_next = middle_node.hash_name;
    middle_node.next      = target_node.name;
    middle_node.hash_next = target_node.hash_name;
    configured_nodes[0]   = &middle_node;
    configured_nodes[1]   = &target_node;
    tunnel_t *router =
        tunnelCreate(&router_node, sniffrouter ? sizeof(sniffrouter_tstate_t) : sizeof(router_tstate_t), 0);
    tunnel_t *middle = testTunnelCreate(&middle_node);
    tunnel_t *target = testTunnelCreate(&target_node);
    require(router != NULL, "failed to create Router");
    router_rule_t       rule  = {.target_node = &target_node};
    sniffrouter_route_t route = {.node = &target_node};
    if (sniffrouter)
    {
        sniffrouter_tstate_t *state = tunnelGetState(router);
        state->routes               = &route;
        state->routes_count         = 1;
        router->onChain             = sniffrouterTunnelOnChain;
    }
    else
    {
        router_tstate_t *state = tunnelGetState(router);
        state->rules           = &rule;
        state->rules_count     = 1;
        router->onChain        = routerTunnelOnChain;
    }

    tunnel_chain_t      *chain   = tunnelchainCreate(0);
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    router->onChain(router, chain);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(! wwStartupSucceeded(result), "Router accepted a target below another configured node");
    require((sniffrouter ? route.tunnel : rule.target_tunnel) == NULL, "router published an incompatible target");
    require(router->next == middle && target->prev == middle, "rejected rule rewired the default branch");

    configured_nodes[0] = configured_nodes[1] = NULL;
    tunnelchainDestroy(chain);
    tunnelDestroy(target);
    tunnelDestroy(middle);
    tunnelDestroy(router);
}
#endif

int main(void)
{
    testCaseSet("router_chain_ownership_test");
    logger_t *logger = loggerCreate();
    require(logger != NULL, "failed to create network logger");
    setNetworkLogger(logger);
    testSniffRouterRefreshesChainBetweenRoutes();
    testRouterRefreshesChainBetweenRules();
    for (unsigned sniffrouter = 0; sniffrouter < 2; ++sniffrouter)
    {
        testRepeatedTarget(sniffrouter != 0, false, false);
        testRepeatedTarget(sniffrouter != 0, true, false);
        testRejectsNestedTarget(sniffrouter != 0);
#if WW_ROUTER_LOOKUP_WRAP_TEST
        testRepeatedTarget(sniffrouter != 0, false, true);
        testRepeatedTarget(sniffrouter != 0, true, true);
        testRejectsDefaultDescendant(sniffrouter != 0);
#endif
    }
    networkloggerDestroy();
    return 0;
}
