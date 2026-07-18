#include "Router/structure.h"
#include "SniffRouter/structure.h"

#include <stdio.h>
#include <stdlib.h>

static tunnel_chain_t *replacement_chain;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static node_t testNode(const char *name, const char *type)
{
    return (node_t) {
        .name        = (char *) name,
        .type        = (char *) type,
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

    tunnel_chain_t *initial_chain = tunnelchainCreate(0);
    sniffrouterTunnelOnChain(router, initial_chain);

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

    tunnel_chain_t *initial_chain = tunnelchainCreate(0);
    routerTunnelOnChain(router, initial_chain);

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

int main(void)
{
    testSniffRouterRefreshesChainBetweenRoutes();
    testRouterRefreshesChainBetweenRules();
    return 0;
}
