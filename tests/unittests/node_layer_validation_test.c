/*
 * Tests strict node capability and layer group validation rules in NodeManager.
 */

#include "wwapi.h"

#include "managers/node_manager.c" // NOLINT: exercises private validateTunnelChains

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

    tunnel_t *t_array[3] = {&t_head, &t_mid, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 3);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(result.exit_code == 0, "Valid L4 chain was rejected");
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

    tunnel_t *t_array[3] = {&t_head, &t_mid, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 3);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(result.exit_code == 0, "Valid transparent middle chain on L4 was rejected");
}

static void testValidTransparentMiddleChainL3(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TunDevice",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayer3,
        .can_have_next         = true,
        .can_have_prev         = true,
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
        .type                  = (char *) "RawSocket",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayer3,
        .can_have_next         = true,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_mid  = {.node = &n_mid};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_mid);
    bindTunnels(&t_mid, &t_tail);

    tunnel_t *t_array[3] = {&t_head, &t_mid, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 3);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(result.exit_code == 0, "Valid transparent middle chain on L3 was rejected");
}

static void testValidMultiHopTransparent(void)
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
    node_t n_mid1 = {
        .name                  = (char *) "mid1",
        .type                  = (char *) "ObfuscatorClient",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerSameAsPrev,
        .layer_group_prev_node = kNodeLayerSameAsNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_mid2 = {
        .name                  = (char *) "mid2",
        .type                  = (char *) "EncryptionClient",
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
    tunnel_t t_mid1 = {.node = &n_mid1};
    tunnel_t t_mid2 = {.node = &n_mid2};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_mid1);
    bindTunnels(&t_mid1, &t_mid2);
    bindTunnels(&t_mid2, &t_tail);

    tunnel_t *t_array[4] = {&t_head, &t_mid1, &t_mid2, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 4);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(result.exit_code == 0, "Valid multi-hop transparent chain was rejected");
}

static void testValidBridgeChain(void)
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
    node_t n_bridge = {
        .name                  = (char *) "bridge",
        .type                  = (char *) "ConnectionToPackets",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayer3 | kNodeLayer4,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "PingServer",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayer3,
        .can_have_next         = true,
        .can_have_prev         = true,
    };

    tunnel_t t_head   = {.node = &n_head};
    tunnel_t t_bridge = {.node = &n_bridge};
    tunnel_t t_tail   = {.node = &n_tail};

    bindTunnels(&t_head, &t_bridge);
    bindTunnels(&t_bridge, &t_tail);

    tunnel_t *t_array[3] = {&t_head, &t_bridge, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 3);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(result.exit_code == 0, "Valid bridge chain was rejected");
}

static void testRejectForbiddenSameAsInLayerGroup(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TcpListener",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayerSameAsNext,
        .layer_group_next_node = kNodeLayer4,
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

    tunnel_t *t_array[2] = {&t_head, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 2);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(result.exit_code == 1, "Forbidden SameAs in layer_group was not rejected");
}

static void testRejectTransparentBridgeMismatch(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TunDevice",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayer3,
        .can_have_next         = true,
        .can_have_prev         = true,
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

    tunnel_t *t_array[3] = {&t_head, &t_mid, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 3);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(result.exit_code == 1, "Transparent bridge mismatch L3->Obfuscator->L4 was not rejected");
}

static void testRejectAdjacentLayerMismatch(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TcpListener",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "TunDevice",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_tail);

    tunnel_t *t_array[2] = {&t_head, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 2);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(result.exit_code == 1, "Direct L4->L3 adjacent mismatch was not rejected");
}

static void testRejectNextNodeLayerMismatch(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "Bgp4Client",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayer4,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "PingServer",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayer3,
        .can_have_next         = true,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_tail);

    tunnel_t *t_array[2] = {&t_head, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 2);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(result.exit_code == 1, "Next-node layer mismatch was not rejected");
}

static void testRejectCanHaveNextViolation(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "BlackHole",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = false,
        .can_have_prev         = true,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "TcpConnector",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_tail);

    tunnel_t *t_array[2] = {&t_head, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 2);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(result.exit_code == 1, "can_have_next=false violation was not rejected");
}

static void testRejectCanHavePrevViolation(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "TcpListener",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "PacketSender",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = false,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_tail);

    tunnel_t *t_array[2] = {&t_head, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 2);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(result.exit_code == 1, "can_have_prev=false violation was not rejected");
}

static void testRejectSameAsPrevOnHead(void)
{
    node_t n_head = {
        .name                  = (char *) "head",
        .type                  = (char *) "BadHead",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerSameAsPrev,
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

    tunnel_t *t_array[2] = {&t_head, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 2);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(result.exit_code == 1, "SameAsPrev on chain head was not rejected");
}

static void testRejectSameAsNextOnTail(void)
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
    node_t n_tail = {
        .name                  = (char *) "tail",
        .type                  = (char *) "BadTail",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayerSameAsNext,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    tunnel_t t_head = {.node = &n_head};
    tunnel_t t_tail = {.node = &n_tail};

    bindTunnels(&t_head, &t_tail);

    tunnel_t *t_array[2] = {&t_head, &t_tail};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 2);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(result.exit_code == 1, "SameAsNext on chain tail was not rejected");
}

static void testRejectNoChainWithLinks(void)
{
    node_t n_node = {
        .name                  = (char *) "standalone",
        .type                  = (char *) "StandaloneNode",
        .flags                 = kNodeFlagNoChain,
        .layer_group           = kNodeLayerNone,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = false,
        .can_have_prev         = false,
    };
    node_t n_other = {
        .name                  = (char *) "other",
        .type                  = (char *) "OtherNode",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };

    tunnel_t t_node  = {.node = &n_node};
    tunnel_t t_other = {.node = &n_other};

    bindTunnels(&t_node, &t_other);

    tunnel_t *t_array[2] = {&t_node, &t_other};

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    validateTunnelChains(t_array, 2);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(result.exit_code == 1, "kNodeFlagNoChain with links was not rejected");
}

int main(void)
{
    testValidL4Chain();
    testValidTransparentMiddleChainL4();
    testValidTransparentMiddleChainL3();
    testValidMultiHopTransparent();
    testValidBridgeChain();
    testRejectForbiddenSameAsInLayerGroup();
    testRejectTransparentBridgeMismatch();
    testRejectAdjacentLayerMismatch();
    testRejectNextNodeLayerMismatch();
    testRejectCanHaveNextViolation();
    testRejectCanHavePrevViolation();
    testRejectSameAsPrevOnHead();
    testRejectSameAsNextOnTail();
    testRejectNoChainWithLinks();
    return 0;
}
