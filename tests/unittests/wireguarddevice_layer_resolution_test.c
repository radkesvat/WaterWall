#include "WireGuardDevice/structure.h"

#include "net/node_layer_solver.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

typedef struct layer_fixture_s
{
    node_t          prev_node;
    node_t          wireguard_node;
    node_t          next_node;
    tunnel_t       *prev;
    tunnel_t       *wireguard;
    tunnel_t       *next;
    tunnel_chain_t *chain;
} layer_fixture_t;

static void layerFixtureCreate(layer_fixture_t *fixture, enum node_layer_group prev_layer,
                               enum node_layer_group next_layer)
{
    memoryZero(fixture, sizeof(*fixture));
    fixture->prev_node = (node_t) {
        .name                  = (char *) "prev",
        .type                  = (char *) "PrevNode",
        .flags                 = kNodeFlagChainHead,
        .layer_group           = prev_layer,
        .layer_group_next_node = prev_layer,
        .layer_group_prev_node = kNodeLayerNone,
        .can_have_next         = true,
        .can_have_prev         = false,
    };
    fixture->wireguard_node = (node_t) {
        .name                  = (char *) "wireguard",
        .type                  = (char *) "WireGuardDevice",
        .flags                 = kNodeFlagNone,
        .layer_group           = kNodeLayerAnything,
        .layer_group_next_node = kNodeLayerAnything | kNodeLayerOppositePrev,
        .layer_group_prev_node = kNodeLayerAnything | kNodeLayerOppositeNext,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    fixture->next_node = (node_t) {
        .name                  = (char *) "next",
        .type                  = (char *) "NextNode",
        .flags                 = kNodeFlagChainEnd,
        .layer_group           = next_layer,
        .layer_group_next_node = kNodeLayerNone,
        .layer_group_prev_node = next_layer,
        .can_have_next         = false,
        .can_have_prev         = true,
    };

    fixture->prev      = tunnelCreate(&fixture->prev_node, 0, 0);
    fixture->wireguard = tunnelCreate(&fixture->wireguard_node, sizeof(wgd_tstate_t), 0);
    fixture->next      = tunnelCreate(&fixture->next_node, 0, 0);
    fixture->chain     = tunnelchainCreate(0);
    require(fixture->prev != NULL && fixture->wireguard != NULL && fixture->next != NULL && fixture->chain != NULL,
            "failed to create WireGuard layer fixture");

    tunnelBind(fixture->prev, fixture->wireguard);
    tunnelBind(fixture->wireguard, fixture->next);
    tunnelchainInsert(fixture->chain, fixture->prev);
    tunnelchainInsert(fixture->chain, fixture->wireguard);
    tunnelchainInsert(fixture->chain, fixture->next);

    wgd_tstate_t *state = tunnelGetState(fixture->wireguard);
    state->tunnel       = fixture->wireguard;
}

static tunnel_t *layerFixtureAddController(layer_fixture_t *fixture)
{
    wgd_tstate_t *state = tunnelGetState(fixture->wireguard);
    node_t       *node  = &state->user_controller_node;

    node->name                  = stringDuplicate("wireguard.user-controller");
    node->type                  = stringDuplicate("UserController");
    node->hash_name             = calcHashBytes(node->name, stringLength(node->name));
    node->hash_type             = calcHashBytes(node->type, stringLength(node->type));
    node->flags                 = kNodeFlagNone;
    node->layer_group           = kNodeLayer4;
    node->layer_group_next_node = kNodeLayer4;
    node->layer_group_prev_node = kNodeLayer4;
    node->can_have_next         = true;
    node->can_have_prev         = true;
    require(node->name != NULL && node->type != NULL, "failed to configure synthetic UserController node");

    state->user_controller_tunnel = tunnelCreate(node, 0, 0);
    require(state->user_controller_tunnel != NULL, "failed to create synthetic UserController tunnel");
    node->instance = state->user_controller_tunnel;
    return state->user_controller_tunnel;
}

static void layerFixtureDestroy(layer_fixture_t *fixture)
{
    wgd_tstate_t *state = tunnelGetState(fixture->wireguard);

    tunnelchainDestroy(fixture->chain);
    if (state->user_controller_tunnel != NULL)
    {
        tunnelDestroy(state->user_controller_tunnel);
        state->user_controller_tunnel = NULL;
    }
    memoryFree(state->user_controller_node.next);
    memoryFree(state->user_controller_node.name);
    memoryFree(state->user_controller_node.type);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->wireguard);
    tunnelDestroy(fixture->prev);
    memoryZero(fixture, sizeof(*fixture));
}

static void requireSolved(layer_fixture_t *fixture)
{
    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(fixture->chain, &status), status.message);
}

static bool runSuccessfulSolvedTopologyHook(layer_fixture_t *fixture)
{
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    const bool                changed = wireguarddeviceTunnelOnSolvedTopology(fixture->wireguard, fixture->chain);
    const ww_startup_result_t result  = wwStartupContextEnd(&startup);
    require(wwStartupSucceeded(result), "valid WireGuard topology hook unexpectedly failed startup");
    return changed;
}

static void testDirectionComesFromAdjacentSolvedLayers(void)
{
    layer_fixture_t packet_prev;
    layerFixtureCreate(&packet_prev, kNodeLayer3, kNodeLayer4);
    requireSolved(&packet_prev);
    require(! runSuccessfulSolvedTopologyHook(&packet_prev),
            "WireGuard without a private controller reported a topology change");
    wgd_tstate_t *prev_state = tunnelGetState(packet_prev.wireguard);
    require(prev_state->transport_side_resolved && prev_state->transport_side_is_next,
            "WireGuard did not select its solved next L4 edge as transport");
    layerFixtureDestroy(&packet_prev);

    layer_fixture_t packet_next;
    layerFixtureCreate(&packet_next, kNodeLayer4, kNodeLayer3);
    requireSolved(&packet_next);
    require(! runSuccessfulSolvedTopologyHook(&packet_next),
            "WireGuard without a private controller reported a topology change");
    wgd_tstate_t *next_state = tunnelGetState(packet_next.wireguard);
    require(next_state->transport_side_resolved && ! next_state->transport_side_is_next,
            "WireGuard did not select its solved previous L4 edge as transport");
    layerFixtureDestroy(&packet_next);
}

static void testControllerIsInsertedOnSolvedTransportSide(void)
{
    layer_fixture_t next_transport;
    layerFixtureCreate(&next_transport, kNodeLayer3, kNodeLayer4);
    tunnel_t *next_controller = layerFixtureAddController(&next_transport);
    requireSolved(&next_transport);
    require(runSuccessfulSolvedTopologyHook(&next_transport),
            "WireGuard did not report next-side controller insertion");
    require(next_transport.wireguard->next == next_controller && next_controller->next == next_transport.next &&
                next_transport.chain->tunnels.tuns[2] == next_controller,
            "WireGuard inserted its controller outside the solved next L4 edge");
    requireSolved(&next_transport);
    require(! runSuccessfulSolvedTopologyHook(&next_transport),
            "WireGuard inserted its next-side controller more than once");
    layerFixtureDestroy(&next_transport);

    layer_fixture_t prev_transport;
    layerFixtureCreate(&prev_transport, kNodeLayer4, kNodeLayer3);
    tunnel_t *prev_controller = layerFixtureAddController(&prev_transport);
    requireSolved(&prev_transport);
    require(runSuccessfulSolvedTopologyHook(&prev_transport),
            "WireGuard did not report previous-side controller insertion");
    require(prev_transport.prev->next == prev_controller && prev_controller->next == prev_transport.wireguard &&
                prev_transport.chain->tunnels.tuns[1] == prev_controller,
            "WireGuard inserted its controller outside the solved previous L4 edge");
    requireSolved(&prev_transport);
    require(! runSuccessfulSolvedTopologyHook(&prev_transport),
            "WireGuard inserted its previous-side controller more than once");
    layerFixtureDestroy(&prev_transport);
}

static void testAmbiguousLayersFailInsteadOfDefaultingOrScanning(void)
{
    layer_fixture_t fixture;
    layerFixtureCreate(&fixture, kNodeLayerAnything, kNodeLayerAnything);
    requireSolved(&fixture);

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    require(! wireguarddeviceTunnelOnSolvedTopology(fixture.wireguard, fixture.chain),
            "ambiguous WireGuard layers reported a topology change");
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(! wwStartupSucceeded(result), "ambiguous WireGuard layers did not fail startup");
    require(! ((wgd_tstate_t *) tunnelGetState(fixture.wireguard))->transport_side_resolved,
            "ambiguous WireGuard layers selected a transport side");
    layerFixtureDestroy(&fixture);
}

int main(void)
{
    testDirectionComesFromAdjacentSolvedLayers();
    testControllerIsInsertedOnSolvedTransportSide();
    testAmbiguousLayersFailInsteadOfDefaultingOrScanning();

    printf("wireguarddevice_layer_resolution_test: all cases passed\n");
    return 0;
}
