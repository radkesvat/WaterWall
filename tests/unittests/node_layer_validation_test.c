/*
 * Tests strict node capability and layer group validation rules in NodeManager,
 * along with the bounded monotonic edge-domain constraint solver.
 */

#include "wwapi.h"

#include "managers/node_manager.c" // NOLINT: exercises private validateTunnelChains and initializePacketTunnels

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void bindTunnels(tunnel_t *from, tunnel_t *to)
{
    from->next = to;
    to->prev   = from;
}

/* ========================================================================= */
/* 1. Valid Chain Solving Tests (Direct Solver)                             */
/* ========================================================================= */

static void testValidL4Chain(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TcpListener",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayer4,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_mid = {
        .name                  = (char *) "mid",
        .type                  = (char *) "TlsClient",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayer4,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "TcpConnector",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_mid  = {.node = &n_mid};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_mid);
    bindTunnels(&t_mid, &t_tail);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_head);
    tunnelarrayInsert(&chain.tunnels, &t_mid);
    tunnelarrayInsert(&chain.tunnels, &t_tail);
    t_head.chain = &chain;
    t_mid.chain  = &chain;
    t_tail.chain = &chain;

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(&chain, &status), "Valid L4 chain was rejected");
    require(chain.layer_solution_ready, "layer_solution_ready not set");
    require(! chain.contains_packet_node, "L4 chain marked as packet chain");
    require(chain.resolved_next_layer[0] == kLayerDomainL4, "head next layer not L4");
    require(chain.resolved_prev_layer[1] == kLayerDomainL4, "mid prev layer not L4");
    require(chain.resolved_next_layer[1] == kLayerDomainL4, "mid next layer not L4");
    require(chain.resolved_prev_layer[2] == kLayerDomainL4, "tail prev layer not L4");
}

static void testValidTransparentMiddleChainL4(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TcpListener",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayer4,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_mid = {
        .name                  = (char *) "mid",
        .type                  = (char *) "ObfuscatorClient",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerSameAsPrev,
        .layer_group_prev_node = kNodeLayerSameAsNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "TcpConnector",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_mid  = {.node = &n_mid};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_mid);
    bindTunnels(&t_mid, &t_tail);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_head);
    tunnelarrayInsert(&chain.tunnels, &t_mid);
    tunnelarrayInsert(&chain.tunnels, &t_tail);
    t_head.chain = &chain;
    t_mid.chain  = &chain;
    t_tail.chain = &chain;

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(&chain, &status), "Valid L4 transparent middle chain was rejected");
    require(chain.resolved_next_layer[0] == kLayerDomainL4, "head next layer not L4");
    require(chain.resolved_prev_layer[1] == kLayerDomainL4, "mid prev layer not L4");
    require(chain.resolved_next_layer[1] == kLayerDomainL4, "mid next layer not L4");
    require(chain.resolved_prev_layer[2] == kLayerDomainL4, "tail prev layer not L4");
}

static void testValidTransparentMiddleChainL3(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TunDevice",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_mid = {
        .name                  = (char *) "mid",
        .type                  = (char *) "ObfuscatorClient",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerSameAsPrev,
        .layer_group_prev_node = kNodeLayerSameAsNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "PingServer",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer3,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_mid  = {.node = &n_mid};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_mid);
    bindTunnels(&t_mid, &t_tail);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_head);
    tunnelarrayInsert(&chain.tunnels, &t_mid);
    tunnelarrayInsert(&chain.tunnels, &t_tail);
    t_head.chain = &chain;
    t_mid.chain  = &chain;
    t_tail.chain = &chain;

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(&chain, &status), "Valid L3 transparent middle chain was rejected");
    require(chain.contains_packet_node, "L3 chain not marked as packet chain");
    require(chain.resolved_next_layer[0] == kLayerDomainL3, "head next layer not L3");
    require(chain.resolved_prev_layer[1] == kLayerDomainL3, "mid prev layer not L3");
    require(chain.resolved_next_layer[1] == kLayerDomainL3, "mid next layer not L3");
    require(chain.resolved_prev_layer[2] == kLayerDomainL3, "tail prev layer not L3");
}

static void testValidMultiHopTransparent(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TunDevice",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_mid1 = {
        .name                  = (char *) "mid1",
        .type                  = (char *) "Disturber",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerSameAsPrev,
        .layer_group_prev_node = kNodeLayerSameAsNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_mid2 = {
        .name                  = (char *) "mid2",
        .type                  = (char *) "SpeedLimit",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerSameAsPrev,
        .layer_group_prev_node = kNodeLayerSameAsNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "PingServer",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer3,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_mid1 = {.node = &n_mid1};
    tunnel_t t_mid2 = {.node = &n_mid2};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_mid1);
    bindTunnels(&t_mid1, &t_mid2);
    bindTunnels(&t_mid2, &t_tail);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_head);
    tunnelarrayInsert(&chain.tunnels, &t_mid1);
    tunnelarrayInsert(&chain.tunnels, &t_mid2);
    tunnelarrayInsert(&chain.tunnels, &t_tail);
    t_head.chain = &chain;
    t_mid1.chain = &chain;
    t_mid2.chain = &chain;
    t_tail.chain = &chain;

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(&chain, &status), "Multi-hop transparent chain was rejected");
    require(chain.resolved_next_layer[0] == kLayerDomainL3, "head next not L3");
    require(chain.resolved_prev_layer[1] == kLayerDomainL3, "mid1 prev not L3");
    require(chain.resolved_next_layer[1] == kLayerDomainL3, "mid1 next not L3");
    require(chain.resolved_prev_layer[2] == kLayerDomainL3, "mid2 prev not L3");
    require(chain.resolved_next_layer[2] == kLayerDomainL3, "mid2 next not L3");
    require(chain.resolved_prev_layer[3] == kLayerDomainL3, "tail prev not L3");
}

static void testValidOppositeLayerChainL3toL4(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TunDevice",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_mid = {
        .name                  = (char *) "bridge",
        .type                  = (char *) "ConnectionToPackets",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerAnything | kNodeLayerOppositePrev,
        .layer_group_prev_node = kNodeLayerAnything | kNodeLayerOppositeNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "TcpConnector",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_mid  = {.node = &n_mid};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_mid);
    bindTunnels(&t_mid, &t_tail);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_head);
    tunnelarrayInsert(&chain.tunnels, &t_mid);
    tunnelarrayInsert(&chain.tunnels, &t_tail);
    t_head.chain = &chain;
    t_mid.chain  = &chain;
    t_tail.chain = &chain;

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(&chain, &status), "Valid L3->L4 opposite layer chain was rejected");
    require(chain.contains_packet_node, "L3->L4 bridge not marked as packet chain");
    require(chain.resolved_next_layer[0] == kLayerDomainL3, "head next not L3");
    require(chain.resolved_prev_layer[1] == kLayerDomainL3, "bridge prev not L3");
    require(chain.resolved_next_layer[1] == kLayerDomainL4, "bridge next not L4");
    require(chain.resolved_prev_layer[2] == kLayerDomainL4, "tail prev not L4");
}

static void testValidOppositeLayerChainL4toL3(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TcpListener",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayer4,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_mid = {
        .name                  = (char *) "bridge",
        .type                  = (char *) "PacketsToStream",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerAnything | kNodeLayerOppositePrev,
        .layer_group_prev_node = kNodeLayerAnything | kNodeLayerOppositeNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "PingServer",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer3,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_mid  = {.node = &n_mid};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_mid);
    bindTunnels(&t_mid, &t_tail);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_head);
    tunnelarrayInsert(&chain.tunnels, &t_mid);
    tunnelarrayInsert(&chain.tunnels, &t_tail);
    t_head.chain = &chain;
    t_mid.chain  = &chain;
    t_tail.chain = &chain;

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(&chain, &status), "Valid L4->L3 opposite layer chain was rejected");
    require(chain.contains_packet_node, "L4->L3 bridge not marked as packet chain");
    require(chain.resolved_next_layer[0] == kLayerDomainL4, "head next not L4");
    require(chain.resolved_prev_layer[1] == kLayerDomainL4, "bridge prev not L4");
    require(chain.resolved_next_layer[1] == kLayerDomainL3, "bridge next not L3");
    require(chain.resolved_prev_layer[2] == kLayerDomainL3, "tail prev not L3");
}

/* ========================================================================= */
/* 2. Finding 1: Bridge Pair Logical Relation Tests                          */
/* ========================================================================= */

static void testValidBridgeSameLayerL3(void)
{
    node_t n_tun = {
        .name                  = (char *) "tun",
        .type                  = (char *) "TunDevice",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_br_a = {
        .name                  = (char *) "bridge-a",
        .type                  = (char *) "Bridge",
        .flags                 = kNodeFlagChainHead | kNodeFlagChainEnd,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_ping = {
        .name                  = (char *) "ping",
        .type                  = (char *) "PingServer",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_br_b = {
        .name                  = (char *) "bridge-b",
        .type                  = (char *) "Bridge",
        .flags                 = kNodeFlagChainHead | kNodeFlagChainEnd,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };

    tunnel_t t_tun  = {.node = &n_tun};
    tunnel_t t_br_a = {.node = &n_br_a};
    tunnel_t t_ping = {.node = &n_ping};
    tunnel_t t_br_b = {.node = &n_br_b};

    bindTunnels(&t_tun, &t_br_a);
    bindTunnels(&t_ping, &t_br_b);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_tun);
    tunnelarrayInsert(&chain.tunnels, &t_br_a);
    tunnelarrayInsert(&chain.tunnels, &t_ping);
    tunnelarrayInsert(&chain.tunnels, &t_br_b);
    t_tun.chain  = &chain;
    t_br_a.chain = &chain;
    t_ping.chain = &chain;
    t_br_b.chain = &chain;

    require(tunnelchainRegisterLayerRelation(&chain, &t_br_a, kTunnelLayerSidePrev,
                                            &t_br_b, kTunnelLayerSidePrev,
                                            kTunnelLayerRelationSame),
            "failed to register Bridge prev relation");

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(&chain, &status), "L3-L3 Bridge pair was rejected");
    require(chain.resolved_next_layer[0] == kLayerDomainL3, "tun next not L3");
    require(chain.resolved_prev_layer[1] == kLayerDomainL3, "bridge-a prev not L3");
    require(chain.resolved_next_layer[2] == kLayerDomainL3, "ping next not L3");
    require(chain.resolved_prev_layer[3] == kLayerDomainL3, "bridge-b prev not L3");
}

static void testValidBridgeSameLayerL4(void)
{
    node_t n_tcp_in = {
        .name                  = (char *) "tcp-in",
        .type                  = (char *) "TcpListener",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayer4,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_br_a = {
        .name                  = (char *) "bridge-a",
        .type                  = (char *) "Bridge",
        .flags                 = kNodeFlagChainHead | kNodeFlagChainEnd,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tcp_out = {
        .name                  = (char *) "tcp-out",
        .type                  = (char *) "TcpConnector",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = false,
        .can_have_prev         = true,
    };
    node_t n_br_b = {
        .name                  = (char *) "bridge-b",
        .type                  = (char *) "Bridge",
        .flags                 = kNodeFlagChainHead | kNodeFlagChainEnd,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };

    tunnel_t t_tcp_in  = {.node = &n_tcp_in};
    tunnel_t t_br_a    = {.node = &n_br_a};
    tunnel_t t_br_b    = {.node = &n_br_b};
    tunnel_t t_tcp_out = {.node = &n_tcp_out};

    bindTunnels(&t_tcp_in, &t_br_a);
    bindTunnels(&t_br_b, &t_tcp_out);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_tcp_in);
    tunnelarrayInsert(&chain.tunnels, &t_br_a);
    tunnelarrayInsert(&chain.tunnels, &t_br_b);
    tunnelarrayInsert(&chain.tunnels, &t_tcp_out);
    t_tcp_in.chain  = &chain;
    t_br_a.chain    = &chain;
    t_br_b.chain    = &chain;
    t_tcp_out.chain = &chain;

    require(tunnelchainRegisterLayerRelation(&chain, &t_br_a, kTunnelLayerSidePrev,
                                            &t_br_b, kTunnelLayerSideNext,
                                            kTunnelLayerRelationSame),
            "failed to register Bridge relation");

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(&chain, &status), "L4-L4 Bridge pair was rejected");
    require(! chain.contains_packet_node, "L4 Bridge pair marked as packet chain");
    require(chain.resolved_next_layer[0] == kLayerDomainL4, "tcp-in next not L4");
    require(chain.resolved_prev_layer[1] == kLayerDomainL4, "bridge-a prev not L4");
    require(chain.resolved_next_layer[2] == kLayerDomainL4, "bridge-b next not L4");
    require(chain.resolved_prev_layer[3] == kLayerDomainL4, "tcp-out prev not L4");
}

static void testRejectBridgeMixedLayerL3L4(void)
{
    node_t n_tun = {
        .name                  = (char *) "tun-in",
        .type                  = (char *) "TunDevice",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_br_a = {
        .name                  = (char *) "bridge-a",
        .type                  = (char *) "Bridge",
        .flags                 = kNodeFlagChainHead | kNodeFlagChainEnd,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tcp = {
        .name                  = (char *) "tcp-in",
        .type                  = (char *) "TcpListener",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayer4,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_br_b = {
        .name                  = (char *) "bridge-b",
        .type                  = (char *) "Bridge",
        .flags                 = kNodeFlagChainHead | kNodeFlagChainEnd,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };

    tunnel_t t_tun  = {.node = &n_tun};
    tunnel_t t_br_a = {.node = &n_br_a};
    tunnel_t t_tcp  = {.node = &n_tcp};
    tunnel_t t_br_b = {.node = &n_br_b};

    bindTunnels(&t_tun, &t_br_a);
    bindTunnels(&t_tcp, &t_br_b);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_tun);
    tunnelarrayInsert(&chain.tunnels, &t_br_a);
    tunnelarrayInsert(&chain.tunnels, &t_tcp);
    tunnelarrayInsert(&chain.tunnels, &t_br_b);
    t_tun.chain  = &chain;
    t_br_a.chain = &chain;
    t_tcp.chain  = &chain;
    t_br_b.chain = &chain;

    require(tunnelchainRegisterLayerRelation(&chain, &t_br_a, kTunnelLayerSidePrev,
                                            &t_br_b, kTunnelLayerSidePrev,
                                            kTunnelLayerRelationSame),
            "failed to register Bridge relation");

    node_layer_solver_status_t status = {0};
    require(! nodeLayerSolveChain(&chain, &status), "Mixed L3/L4 Bridge pair was accepted");
    require(status.code == kNodeLayerSolverErrConflict, "Wrong solver error code for Bridge conflict");
    require(strstr(status.message, "bridge-a") != NULL, "Diagnostic does not mention bridge-a");
    require(strstr(status.message, "bridge-b") != NULL, "Diagnostic does not mention bridge-b");
}

static void testRejectBridgeMixedLayerAcrossTransparent(void)
{
    node_t n_tun = {
        .name                  = (char *) "tun-in",
        .type                  = (char *) "TunDevice",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_obf1 = {
        .name                  = (char *) "obf1",
        .type                  = (char *) "ObfuscatorClient",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerSameAsPrev,
        .layer_group_prev_node = kNodeLayerSameAsNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_br_a = {
        .name                  = (char *) "bridge-a",
        .type                  = (char *) "Bridge",
        .flags                 = kNodeFlagChainHead | kNodeFlagChainEnd,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tcp = {
        .name                  = (char *) "tcp-in",
        .type                  = (char *) "TcpListener",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayer4,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_obf2 = {
        .name                  = (char *) "obf2",
        .type                  = (char *) "ObfuscatorServer",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerSameAsPrev,
        .layer_group_prev_node = kNodeLayerSameAsNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_br_b = {
        .name                  = (char *) "bridge-b",
        .type                  = (char *) "Bridge",
        .flags                 = kNodeFlagChainHead | kNodeFlagChainEnd,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };

    tunnel_t t_tun  = {.node = &n_tun};
    tunnel_t t_obf1 = {.node = &n_obf1};
    tunnel_t t_br_a = {.node = &n_br_a};
    tunnel_t t_tcp  = {.node = &n_tcp};
    tunnel_t t_obf2 = {.node = &n_obf2};
    tunnel_t t_br_b = {.node = &n_br_b};

    bindTunnels(&t_tun, &t_obf1);
    bindTunnels(&t_obf1, &t_br_a);

    bindTunnels(&t_tcp, &t_obf2);
    bindTunnels(&t_obf2, &t_br_b);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_tun);
    tunnelarrayInsert(&chain.tunnels, &t_obf1);
    tunnelarrayInsert(&chain.tunnels, &t_br_a);
    tunnelarrayInsert(&chain.tunnels, &t_tcp);
    tunnelarrayInsert(&chain.tunnels, &t_obf2);
    tunnelarrayInsert(&chain.tunnels, &t_br_b);
    t_tun.chain  = &chain;
    t_obf1.chain = &chain;
    t_br_a.chain = &chain;
    t_tcp.chain  = &chain;
    t_obf2.chain = &chain;
    t_br_b.chain = &chain;

    require(tunnelchainRegisterLayerRelation(&chain, &t_br_a, kTunnelLayerSidePrev,
                                            &t_br_b, kTunnelLayerSidePrev,
                                            kTunnelLayerRelationSame),
            "failed to register Bridge relation");

    node_layer_solver_status_t status = {0};
    require(! nodeLayerSolveChain(&chain, &status), "Transparent run before mixed Bridge pair did not fail");
    require(status.code == kNodeLayerSolverErrConflict, "Wrong error code for transparent Bridge conflict");
}

static void testBridgeRelationsSurviveChainCombine(void)
{
    node_t n_tun = {
        .name                  = (char *) "tun-in",
        .type                  = (char *) "TunDevice",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_br_a = {
        .name                  = (char *) "bridge-a",
        .type                  = (char *) "Bridge",
        .flags                 = kNodeFlagChainHead | kNodeFlagChainEnd,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_ping = {
        .name                  = (char *) "ping-in",
        .type                  = (char *) "PingClient",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_br_b = {
        .name                  = (char *) "bridge-b",
        .type                  = (char *) "Bridge",
        .flags                 = kNodeFlagChainHead | kNodeFlagChainEnd,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };

    tunnel_t t_tun  = {.node = &n_tun};
    tunnel_t t_br_a = {.node = &n_br_a};
    tunnel_t t_ping = {.node = &n_ping};
    tunnel_t t_br_b = {.node = &n_br_b};

    bindTunnels(&t_tun, &t_br_a);
    bindTunnels(&t_ping, &t_br_b);

    tunnel_chain_t *dest = tunnelchainCreate(0);
    tunnel_chain_t *src  = tunnelchainCreate(0);

    tunnelchainInsert(dest, &t_tun);
    tunnelchainInsert(dest, &t_br_a);

    tunnelchainInsert(src, &t_ping);
    tunnelchainInsert(src, &t_br_b);

    // Register on src chain before combine
    require(tunnelchainRegisterLayerRelation(src, &t_br_a, kTunnelLayerSidePrev,
                                            &t_br_b, kTunnelLayerSidePrev,
                                            kTunnelLayerRelationSame),
            "failed to register relation on source chain");

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    tunnelchainCombine(dest, src);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(wwStartupSucceeded(result), "valid chain combination unexpectedly failed startup");
    require(dest->layer_relations_count == 1, "Layer relation was not transferred during combine");

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(dest, &status), "Combined chain solve failed");
    require(dest->resolved_next_layer[0] == kLayerDomainL3, "tun next layer not L3");

    tunnelchainDestroy(dest);
}

/* ========================================================================= */
/* 3. Finding 2: Conditional SameAs and LoggerTunnel Tests                  */
/* ========================================================================= */

static node_t makeLoggerTunnelNode(const char *name)
{
    node_t node = {
        .name                  = (char *) name,
        .type                  = (char *) "LoggerTunnel",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerSameAsPrev,
        .layer_group_prev_node = kNodeLayerSameAsNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    return node;
}

static node_t makeOptionalTransparentNode(const char *name)
{
    node_t node = makeLoggerTunnelNode(name);
    node.type   = (char *) "OptionalTransparent";
    node.flags  = kNodeFlagChainHead | kNodeFlagChainEnd | kNodeFlagNoChain;
    return node;
}

static node_t makeDisturberNode(const char *name)
{
    node_t node = {
        .name                  = (char *) name,
        .type                  = (char *) "Disturber",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerSameAsPrev,
        .layer_group_prev_node = kNodeLayerSameAsNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    return node;
}

static node_t makeDomainResolverNode(const char *name)
{
    node_t node = {
        .name                  = (char *) name,
        .type                  = (char *) "DomainResolver",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerSameAsPrev,
        .layer_group_prev_node = kNodeLayerSameAsNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    return node;
}

static void testValidLoggerTunnelL3toL3(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TunDevice",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_log = makeLoggerTunnelNode("logger");
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "PingServer",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer3,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_log  = {.node = &n_log};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_log);
    bindTunnels(&t_log, &t_tail);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_head);
    tunnelarrayInsert(&chain.tunnels, &t_log);
    tunnelarrayInsert(&chain.tunnels, &t_tail);
    t_head.chain = &chain;
    t_log.chain  = &chain;
    t_tail.chain = &chain;

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(&chain, &status), "LoggerTunnel in L3 chain was rejected");
    require(chain.resolved_next_layer[0] == kLayerDomainL3, "head next not L3");
    require(chain.resolved_prev_layer[1] == kLayerDomainL3, "logger prev not L3");
    require(chain.resolved_next_layer[1] == kLayerDomainL3, "logger next not L3");
    require(chain.resolved_prev_layer[2] == kLayerDomainL3, "tail prev not L3");
}

static void testValidLoggerTunnelL4toL4(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TcpListener",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayer4,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_log = makeLoggerTunnelNode("logger");
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "TcpConnector",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_log  = {.node = &n_log};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_log);
    bindTunnels(&t_log, &t_tail);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_head);
    tunnelarrayInsert(&chain.tunnels, &t_log);
    tunnelarrayInsert(&chain.tunnels, &t_tail);
    t_head.chain = &chain;
    t_log.chain  = &chain;
    t_tail.chain = &chain;

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(&chain, &status), "LoggerTunnel in L4 chain was rejected");
    require(chain.resolved_next_layer[0] == kLayerDomainL4, "head next not L4");
    require(chain.resolved_prev_layer[1] == kLayerDomainL4, "logger prev not L4");
    require(chain.resolved_next_layer[1] == kLayerDomainL4, "logger next not L4");
    require(chain.resolved_prev_layer[2] == kLayerDomainL4, "tail prev not L4");
}

static void testRejectLoggerTunnelL3toL4(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TunDevice",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_log = makeLoggerTunnelNode("logger");
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "TcpConnector",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_log  = {.node = &n_log};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_log);
    bindTunnels(&t_log, &t_tail);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_head);
    tunnelarrayInsert(&chain.tunnels, &t_log);
    tunnelarrayInsert(&chain.tunnels, &t_tail);
    t_head.chain = &chain;
    t_log.chain  = &chain;
    t_tail.chain = &chain;

    node_layer_solver_status_t status = {0};
    require(! nodeLayerSolveChain(&chain, &status), "L3 -> LoggerTunnel -> L4 conflict was accepted");
    require(status.code == kNodeLayerSolverErrConflict, "Wrong solver error code for LoggerTunnel mismatch");
}

static void testValidConditionalSameAsStandalone(void)
{
    node_t n_log = makeOptionalTransparentNode("standalone-optional");

    tunnel_t t_log = {.node = &n_log};

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_log);
    t_log.chain = &chain;

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(&chain, &status), "Standalone optional SameAs node was rejected");
}

static void testValidConditionalSameAsHead(void)
{
    node_t n_log = makeOptionalTransparentNode("head-optional");
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "TcpConnector",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_log  = {.node = &n_log};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_log, &t_tail);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_log);
    tunnelarrayInsert(&chain.tunnels, &t_tail);
    t_log.chain  = &chain;
    t_tail.chain = &chain;

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(&chain, &status), "Optional SameAs node as chain head was rejected");
    require(chain.resolved_next_layer[0] == kLayerDomainL4, "optional head next not L4");
}

static void testValidConditionalSameAsTail(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TcpListener",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayer4,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_log = makeOptionalTransparentNode("tail-optional");

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_log  = {.node = &n_log};

    bindTunnels(&t_head, &t_log);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_head);
    tunnelarrayInsert(&chain.tunnels, &t_log);
    t_head.chain = &chain;
    t_log.chain  = &chain;

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(&chain, &status), "Optional SameAs node as chain tail was rejected");
    require(chain.resolved_prev_layer[1] == kLayerDomainL4, "optional tail prev not L4");
}

static void testRejectMiddleNodesAtBoundaries(void)
{
    // 1. Disturber placed as chain head (flags = kNodeFlagNone)
    node_t n_dist = makeDisturberNode("disturber-head");
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "TcpConnector",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_dist = {.node = &n_dist};
    tunnel_t t_tail = {.node = &n_tail};
    bindTunnels(&t_dist, &t_tail);

    tunnel_chain_t chain1 = {0};
    tunnelarrayInsert(&chain1.tunnels, &t_dist);
    tunnelarrayInsert(&chain1.tunnels, &t_tail);
    t_dist.chain = &chain1;
    t_tail.chain = &chain1;

    node_layer_solver_status_t status1 = {0};
    require(! nodeLayerSolveChain(&chain1, &status1), "Disturber at chain head without flag was accepted");

    // 2. DomainResolver placed as chain head (flags = kNodeFlagNone)
    node_t n_dr = makeDomainResolverNode("dr-head");

    tunnel_t t_dr = {.node = &n_dr};
    bindTunnels(&t_dr, &t_tail);

    tunnel_chain_t chain2 = {0};
    tunnelarrayInsert(&chain2.tunnels, &t_dr);
    tunnelarrayInsert(&chain2.tunnels, &t_tail);
    t_dr.chain   = &chain2;
    t_tail.chain = &chain2;

    node_layer_solver_status_t status2 = {0};
    require(! nodeLayerSolveChain(&chain2, &status2), "DomainResolver at chain head without flag was accepted");

    // 3. LoggerTunnel is a transparent observer, not a line source or sink.
    node_t n_logger = makeLoggerTunnelNode("logger-head");

    tunnel_t t_logger = {.node = &n_logger};
    bindTunnels(&t_logger, &t_tail);

    tunnel_chain_t chain3 = {0};
    tunnelarrayInsert(&chain3.tunnels, &t_logger);
    tunnelarrayInsert(&chain3.tunnels, &t_tail);
    t_logger.chain = &chain3;
    t_tail.chain   = &chain3;

    node_layer_solver_status_t status3 = {0};
    require(! nodeLayerSolveChain(&chain3, &status3), "LoggerTunnel at chain head without flag was accepted");

    node_t         n_logger_standalone = makeLoggerTunnelNode("logger-standalone");
    tunnel_t       t_logger_standalone = {.node = &n_logger_standalone};
    tunnel_chain_t chain4 = {0};
    tunnelarrayInsert(&chain4.tunnels, &t_logger_standalone);
    t_logger_standalone.chain = &chain4;

    node_layer_solver_status_t status4 = {0};
    require(! nodeLayerSolveChain(&chain4, &status4), "Standalone LoggerTunnel without flag was accepted");

    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TcpListener",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayer4,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t   n_logger_tail = makeLoggerTunnelNode("logger-tail");
    tunnel_t t_head        = {.node = &n_head};
    tunnel_t t_logger_tail = {.node = &n_logger_tail};
    bindTunnels(&t_head, &t_logger_tail);

    tunnel_chain_t chain5 = {0};
    tunnelarrayInsert(&chain5.tunnels, &t_head);
    tunnelarrayInsert(&chain5.tunnels, &t_logger_tail);
    t_head.chain        = &chain5;
    t_logger_tail.chain = &chain5;

    node_layer_solver_status_t status5 = {0};
    require(! nodeLayerSolveChain(&chain5, &status5), "LoggerTunnel at chain tail without flag was accepted");
}

static void testRejectOppositeMissingSide(void)
{
    // Opposite on head node with no previous side must be strictly rejected
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "CustomBridge",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayer3 | kNodeLayerOppositePrev, // requires prev
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "TcpConnector",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_tail = {.node = &n_tail};
    bindTunnels(&t_head, &t_tail);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_head);
    tunnelarrayInsert(&chain.tunnels, &t_tail);
    t_head.chain = &chain;
    t_tail.chain = &chain;

    node_layer_solver_status_t status = {0};
    require(! nodeLayerSolveChain(&chain, &status), "OppositePrev on head without prev was accepted");
    require(status.code == kNodeLayerSolverErrRelativeMissingSide, "Wrong error code for missing Opposite side");
}

/* ========================================================================= */
/* 4. Finding 3: Malformed Metadata Matrix Tests                            */
/* ========================================================================= */

static void testMalformedMetadataMatrix(void)
{
    node_layer_solver_status_t status = {0};

    // 1. Valid base node
    node_t base = {
        .name                  = (char *) "base",
        .type                  = (char *) "TcpConnector",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = false,
        .can_have_prev         = true,
    };
    require(nodeLayerValidateNodeMetadata(&base, &status), "base metadata validation failed");

    // 2. Unknown bits in layer_group
    node_t bad_lg = base;
    bad_lg.layer_group = 0x80;
    require(! nodeLayerValidateNodeMetadata(&bad_lg, &status), "Unknown bits in layer_group did not fail");
    require(status.code == kNodeLayerSolverErrMetadataShape, "Wrong error code for bad layer_group");

    // 3. None combined with other bits in layer_group
    node_t bad_lg_none = base;
    bad_lg_none.layer_group = kNodeLayerNone | kNodeLayer3;
    require(! nodeLayerValidateNodeMetadata(&bad_lg_none, &status), "None combined with layer3 in layer_group did not fail");

    // 4. Multiple relation bits in layer_group_next_node
    node_t bad_multi_rel = base;
    bad_multi_rel.can_have_next         = true;
    bad_multi_rel.layer_group_next_node = kNodeLayerSameAsPrev | kNodeLayerOppositePrev;
    require(! nodeLayerValidateNodeMetadata(&bad_multi_rel, &status), "Multiple relation bits did not fail");

    // 5. Base bits combined with SameAs in layer_group_next_node
    node_t bad_base_same = base;
    bad_base_same.can_have_next         = true;
    bad_base_same.layer_group_next_node = kNodeLayer3 | kNodeLayerSameAsPrev;
    require(! nodeLayerValidateNodeMetadata(&bad_base_same, &status), "Base plus SameAs did not fail");

    // 6. Wrong-direction relative flag (SameAsNext in next_node)
    node_t bad_dir_next = base;
    bad_dir_next.can_have_next         = true;
    bad_dir_next.layer_group_next_node = kNodeLayerSameAsNext;
    require(! nodeLayerValidateNodeMetadata(&bad_dir_next, &status), "Forward-referencing relative flag in next_node did not fail");

    // 7. Wrong-direction relative flag (SameAsPrev in prev_node)
    node_t bad_dir_prev = base;
    bad_dir_prev.layer_group_prev_node = kNodeLayerSameAsPrev;
    require(! nodeLayerValidateNodeMetadata(&bad_dir_prev, &status), "Backward-referencing relative flag in prev_node did not fail");

    // 8. Bare Opposite without base layer in next_node
    node_t bad_bare_opp = base;
    bad_bare_opp.can_have_next         = true;
    bad_bare_opp.layer_group_next_node = kNodeLayerOppositePrev;
    require(! nodeLayerValidateNodeMetadata(&bad_bare_opp, &status), "Bare Opposite without base layer did not fail");

    // 9. can_have_next = false with non-None next_node
    node_t bad_can_next = base;
    bad_can_next.can_have_next         = false;
    bad_can_next.layer_group_next_node = kNodeLayer4;
    require(! nodeLayerValidateNodeMetadata(&bad_can_next, &status), "can_have_next = false with non-None did not fail");

    // 10. can_have_prev = false with non-None prev_node
    node_t bad_can_prev = base;
    bad_can_prev.can_have_prev         = false;
    bad_can_prev.layer_group_prev_node = kNodeLayer4;
    require(! nodeLayerValidateNodeMetadata(&bad_can_prev, &status), "can_have_prev = false with non-None did not fail");
}

/* ========================================================================= */
/* 5. Finding 3: Packet Line Execution & Initialization Tests               */
/* ========================================================================= */

typedef struct test_packet_lstate_s
{
    uint32_t magic;
    uint32_t init_count;
    uint32_t payload_count;

} test_packet_lstate_t;

static void fakePacketMiddleInitU(tunnel_t *t, line_t *l)
{
    test_packet_lstate_t *ls = lineGetState(l, t);
    ls->magic = 0xCAFEBABE;
    ls->init_count++;
    tunnelNextUpStreamInit(t, l);
}

static void fakePacketMiddlePayloadU(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    test_packet_lstate_t *ls = lineGetState(l, t);
    require(ls->magic == 0xCAFEBABE, "Payload observed zero/uninitialized line state!");
    ls->payload_count++;
    tunnelNextUpStreamPayload(t, l, buf);
}

static void fakePacketTailInitU(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
}

static void fakePacketTailPayloadU(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    (void) t;
    (void) l;
    (void) buf;
}

static void testPacketLineInitAndPayloadExecution(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "UdpStatelessSocket",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_mid = {
        .name                  = (char *) "test-mid",
        .type                  = (char *) "TestMid",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerSameAsPrev,
        .layer_group_prev_node = kNodeLayerSameAsNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "RawSocket",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer3,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head, .fnInitU = tunnelNextUpStreamInit, .fnPayloadU = tunnelNextUpStreamPayload};
    tunnel_t t_mid  = {
        .node         = &n_mid,
        .lstate_size  = sizeof(test_packet_lstate_t),
        .fnInitU      = fakePacketMiddleInitU,
        .fnPayloadU   = fakePacketMiddlePayloadU,
    };
    tunnel_t t_tail = {.node = &n_tail, .fnInitU = fakePacketTailInitU, .fnPayloadU = fakePacketTailPayloadU};

    bindTunnels(&t_head, &t_mid);
    bindTunnels(&t_mid, &t_tail);

    tunnel_chain_t *chain = tunnelchainCreate(1);
    tunnelchainInsert(chain, &t_head);
    tunnelchainInsert(chain, &t_mid);
    tunnelchainInsert(chain, &t_tail);

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(chain, &status), "Failed to solve test packet chain");
    require(chain->contains_packet_node, "Packet chain not classified as packet chain");

    tunnelchainFinalize(chain);
    require(chain->packet_lines != NULL, "Finalize did not allocate packet lines for packet chain");

    line_t *pkt_line = tunnelchainGetWorkerPacketLine(chain, 0);
    require(pkt_line != NULL, "Worker 0 packet line is NULL");

    // 1. Initial line state before Init is zeroed
    test_packet_lstate_t *ls = lineGetState(pkt_line, &t_mid);
    require(ls->magic == 0, "Line state was non-zero before Init");

    // 2. Execute Init callback on worker packet line
    t_head.fnInitU(&t_head, pkt_line);
    require(ls->init_count == 1, "Init callback did not run exactly once");
    require(ls->magic == 0xCAFEBABE, "Init callback did not initialize line state magic");

    // 3. Execute Payload callback on worker packet line
    sbuf_t dummy_buf = {0};
    t_head.fnPayloadU(&t_head, pkt_line, &dummy_buf);
    require(ls->payload_count == 1, "Payload callback did not run");

    // 4. Assert topological head is chosen regardless of chain array order
    tunnel_chain_t rev_chain = {0};
    tunnelarrayInsert(&rev_chain.tunnels, &t_tail);
    tunnelarrayInsert(&rev_chain.tunnels, &t_mid);
    tunnelarrayInsert(&rev_chain.tunnels, &t_head);
    t_head.chain = &rev_chain;
    t_mid.chain  = &rev_chain;
    t_tail.chain = &rev_chain;

    require(nodeLayerSolveChain(&rev_chain, &status), "Failed to solve reverse packet chain");
    require(tunnelIsManagerPacketInitHead(&rev_chain, 2), "Topological head was not chosen in reverse array order");
    require(! tunnelIsManagerPacketInitHead(&rev_chain, 0), "Tail was incorrectly chosen as Init head");

    // The chain owns the persistent packet line, but each tunnel still owns and
    // must settle its exact line-state slot before chain teardown.
    memoryZero(ls, t_mid.lstate_size);
    tunnelchainDestroy(chain);
}

/* ========================================================================= */
/* 6. Finding 3: NodeManager Seam & Cleanup Tests                            */
/* ========================================================================= */

static tunnel_t *g_layer_expansion_tunnel;
static uint32_t  g_solved_topology_calls;

static bool insertTransparentTunnelAfterSolvedLayers(tunnel_t *owner, tunnel_chain_t *chain)
{
    g_solved_topology_calls++;
    require(chain->layer_solution_ready, "solved-topology callback ran before the chain was solved");

    if (g_layer_expansion_tunnel->chain == chain)
    {
        return false;
    }

    uint16_t owner_index = 0;
    while (owner_index < chain->tunnels.len && chain->tunnels.tuns[owner_index] != owner)
    {
        owner_index++;
    }
    require(owner_index < chain->tunnels.len, "layer callback owner was absent from its chain");

    tunnel_t *next = owner->next;
    require(next != NULL, "layer callback owner had no next tunnel");

    tunnelchainInsertAt(chain, g_layer_expansion_tunnel, (uint16_t) (owner_index + 1U));
    require(g_layer_expansion_tunnel->chain == chain, "layer-dependent tunnel insertion failed");

    owner->next                         = g_layer_expansion_tunnel;
    g_layer_expansion_tunnel->prev      = owner;
    g_layer_expansion_tunnel->next      = next;
    next->prev                          = g_layer_expansion_tunnel;
    return true;
}

static void testSolvedTopologyExpansionIsRevalidated(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "PacketHead",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_inserted = {
        .name                  = (char *) "inserted",
        .type                  = (char *) "Transparent",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerSameAsPrev,
        .layer_group_prev_node = kNodeLayerSameAsNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "PacketTail",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer3,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_head     = {.node = &n_head, .onSolvedTopology = insertTransparentTunnelAfterSolvedLayers};
    tunnel_t t_inserted = {.node = &n_inserted};
    tunnel_t t_tail     = {.node = &n_tail};
    bindTunnels(&t_head, &t_tail);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_head);
    tunnelarrayInsert(&chain.tunnels, &t_tail);
    t_head.chain = &chain;
    t_tail.chain = &chain;

    g_layer_expansion_tunnel = &t_inserted;
    g_solved_topology_calls  = 0;
    tunnel_t *t_array[2]     = {&t_head, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 2);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(wwStartupSucceeded(result), "valid layer-dependent topology expansion failed");
    require(g_solved_topology_calls == 2,
            "solved-topology callback was not rerun against the final solved topology");
    require(chain.tunnels.len == 3 && chain.tunnels.tuns[1] == &t_inserted,
            "layer-dependent tunnel was not inserted in topological order");
    require(chain.layer_solution_ready, "expanded chain did not retain its final layer solution");
    require(chain.resolved_prev_layer[1] == kLayerDomainL3 &&
                chain.resolved_next_layer[1] == kLayerDomainL3,
            "expanded transparent tunnel did not resolve to L3");
}

static void testNodeManagerPreFinalizationChainCleanup(void)
{
    // Test that an invalid chain caught during validation records startup failure
    // and can be cleanly torn down without leaks.
    node_t n_head = {
        .name                  = (char *) "head-l3",
        .type                  = (char *) "TunDevice",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    node_t n_tail = {
        .name                  = (char *) "tail-l4",
        .type                  = (char *) "TcpConnector",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_tail = {.node = &n_tail};
    bindTunnels(&t_head, &t_tail);

    tunnel_t *t_array[2] = {&t_head, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &t_head);
    tunnelarrayInsert(&chain.tunnels, &t_tail);
    t_head.chain = &chain;
    t_tail.chain = &chain;

    validateTunnelChains(t_array, 2);

    const ww_startup_result_t result = wwStartupContextEnd(&startup);
    require(result.exit_code == 1, "Validation failure was not recorded in startup context");
    require(! chain.layer_solution_ready, "Failed chain has layer_solution_ready = true");
}

int main(void)
{
    testValidL4Chain();
    testValidTransparentMiddleChainL4();
    testValidTransparentMiddleChainL3();
    testValidMultiHopTransparent();
    testValidOppositeLayerChainL3toL4();
    testValidOppositeLayerChainL4toL3();
    testValidBridgeSameLayerL3();
    testValidBridgeSameLayerL4();
    testRejectBridgeMixedLayerL3L4();
    testRejectBridgeMixedLayerAcrossTransparent();
    testBridgeRelationsSurviveChainCombine();
    testValidLoggerTunnelL3toL3();
    testValidLoggerTunnelL4toL4();
    testRejectLoggerTunnelL3toL4();
    testValidConditionalSameAsStandalone();
    testValidConditionalSameAsHead();
    testValidConditionalSameAsTail();
    testRejectMiddleNodesAtBoundaries();
    testRejectOppositeMissingSide();
    testMalformedMetadataMatrix();
    testPacketLineInitAndPayloadExecution();
    testSolvedTopologyExpansionIsRevalidated();
    testNodeManagerPreFinalizationChainCleanup();

    printf("ALL node_layer_validation unit tests passed successfully!\n");
    return 0;
}
