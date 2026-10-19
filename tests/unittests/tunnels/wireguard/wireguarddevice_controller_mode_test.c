/* Covers the real WireGuard-created UserController and its saved datagram mode.
 * Both solved transport orientations use WireGuard-owned normal transport lines
 * with initially unset destination metadata, plus fixture-owned peer lines with
 * contradictory TCP metadata. UserController borrows every line. Real constructors,
 * Init/Finish and child destruction run; only configuration lookup is substituted.
 * No WireGuard handshake, authentication integration or network I/O is exercised.
 * CTest: waterwall.wireguarddevice_controller_mode_unit. */
#define kTunnelStateSize kWireGuardTestTunnelStateSize
#define kLineStateSize   kWireGuardTestLineStateSize
#include "WireGuardDevice/structure.h"
#undef kTunnelStateSize
#undef kLineStateSize
#include "UserController/structure.h"
#include "WireGuardDevice/interface.h"
#include "net/node_layer_solver.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static node_t    auth_node;
static tunnel_t *observed_controller;
static unsigned  transport_inits, transport_finishes;

node_t *__wrap_nodemanagerGetConfigNodeByName(node_manager_config_t *config, const char *name);
node_t *__wrap_nodemanagerGetConfigNodeByName(node_manager_config_t *config, const char *name)
{
    discard config;
    return stringCompare(name, "auth-client") == 0 ? &auth_node : NULL;
}

static void requireDatagram(line_t *line, bool from_next)
{
    const usercontroller_lstate_t *ls = lineGetState(line, observed_controller);
    require(ls->payload_mode == kUserControllerPayloadDatagram && ls->started_from_next == from_next,
            "WireGuard controller saved the wrong mode or Init orientation");
    require(ls->directions[0].shaper.mode == kTrafficShaperDatagram &&
                ls->directions[1].shaper.mode == kTrafficShaperDatagram,
            "WireGuard controller did not initialize both shapers for whole datagrams");
}

static void transportInit(tunnel_t *t, line_t *line)
{
    requireDatagram(line, observed_controller->prev == t);
    address_context_t *dest = lineGetDestinationAddressContext(line);
    require(! dest->proto_tcp && ! dest->proto_udp, "owned transport line already had destination protocol metadata");
    dest->proto_tcp = true;
    ++transport_inits;
}

static void transportFinish(tunnel_t *t, line_t *line)
{
    discard                        t;
    const usercontroller_lstate_t *ls = lineGetState(line, observed_controller);
    require(ls->payload_mode == 0, "controller state was not destroyed before forwarding Finish");
    ++transport_finishes;
}

static node_t endpointNode(const char *name, bool head, enum node_layer_group layer)
{
    return (node_t) {.name                  = (char *) name,
                     .type                  = (char *) "FixtureEndpoint",
                     .flags                 = head ? kNodeFlagChainHead : kNodeFlagChainEnd,
                     .layer_group           = layer,
                     .layer_group_next_node = head ? layer : kNodeLayerNone,
                     .layer_group_prev_node = head ? kNodeLayerNone : layer,
                     .can_have_next         = head,
                     .can_have_prev         = ! head};
}

static void testControllerMode(bool transport_next)
{
    testCaseSet(transport_next ? "wireguard_next_transport_mode" : "wireguard_prev_transport_mode");
    node_t prev_node        = endpointNode("prev", true, transport_next ? kNodeLayer3 : kNodeLayer4);
    node_t next_node        = endpointNode("next", false, transport_next ? kNodeLayer4 : kNodeLayer3);
    node_t node             = nodeWireGuardDeviceGet();
    node.name               = (char *) "wireguard";
    node.hash_name          = calcHashBytes(node.name, stringLength(node.name));
    node.node_settings_json = cJSON_Parse("{\"auth-client-node-name\":\"auth-client\","
                                          "\"privatekey\":\"0MHoX6RogAEFxKF7c5E84tA1Qy3l9u8IzJfgcVt4B2Y=\","
                                          "\"peers\":[{\"publickey\":\"GnRcOavdc180YrXak138cZxWlMoEUZL0Mg/ZyWhLBgo=\","
                                          "\"allowedips\":\"0.0.0.0/0\",\"endpoint\":\"127.0.0.1:26762\"}]}");
    require(node.node_settings_json != NULL, "parse WireGuard settings");
    tunnel_t *prev = tunnelCreate(&prev_node, 0, 0);
    tunnel_t *next = tunnelCreate(&next_node, 0, 0);
    tunnel_t *wg   = wireguarddeviceTunnelCreate(&node);
    require(prev != NULL && next != NULL && wg != NULL, "construct real WireGuard controller fixture");
    wgd_tstate_t *state = tunnelGetState(wg);
    observed_controller = state->user_controller_tunnel;
    require(observed_controller != NULL, "WireGuard did not create its private controller");
    const usercontroller_tstate_t *controller_state = tunnelGetState(observed_controller);
    require(controller_state->payload_mode_resolver != NULL && controller_state->payload_mode_owner == wg,
            "WireGuard constructor did not bind its own mode resolver");

    prev->fnInitD = next->fnInitU = transportInit;
    prev->fnFinD = next->fnFinU = transportFinish;
    tunnelBind(prev, wg);
    tunnelBind(wg, next);
    tunnel_chain_t *chain = tunnelchainCreate(1);
    tunnelchainInsert(chain, prev);
    tunnelchainInsert(chain, wg);
    tunnelchainInsert(chain, next);
    node_layer_solver_status_t status  = {0};
    ww_startup_context_t       startup = {0};
    wwStartupContextBegin(&startup);
    require(nodeLayerSolveChain(chain, &status), status.message);
    require(wireguarddeviceTunnelOnSolvedTopology(wg, chain), "real controller was not inserted");
    require(nodeLayerSolveChain(chain, &status), status.message);
    require(! wireguarddeviceTunnelOnSolvedTopology(wg, chain), "controller insertion was not stable");
    require(transport_next ? wg->next == observed_controller : wg->prev == observed_controller,
            "controller was inserted on the packet side");
    uint32_t offset = 0;
    for (uint16_t i = 0; i < chain->tunnels.len; ++i)
    {
        tunnel_t *t = chain->tunnels.tuns[i];
        t->onIndex(t, i, &offset);
        t->onPrepare(t);
    }
    tunnelchainFinalize(chain);
    require(wwStartupSucceeded(wwStartupContextEnd(&startup)), "prepare/finalize real controller topology");
    state->transport_lines = memoryAllocateZero(sizeof(*state->transport_lines));

    transport_inits = transport_finishes = 0;
    line_t *owned                        = wireguarddeviceEnsureTransportLine(state, 0);
    require(owned != NULL && transport_inits == 1, "real transport-line creation did not reach controller and sink");
    requireDatagram(owned, ! transport_next);
    require(lineGetDestinationAddressContext(owned)->proto_tcp, "neighbor did not rewrite destination metadata");
    lineRef(owned);
    wireguarddeviceCloseTransportLine(wg, 0);
    require(! lineIsAlive(owned) && state->transport_lines[0] == NULL && transport_finishes == 1,
            "owned transport close did not settle controller and line");
    lineUnref(owned);

    /* The fixture now stands in for the transport adapter, which owns this peer
     * line. WireGuard receives Init/Finish on a borrowed normal line. */
    line_t *peer                                      = lineCreate(tunnelchainGetLinePools(chain), 0);
    lineGetDestinationAddressContext(peer)->proto_tcp = true;
    lineRef(peer);
    if (transport_next)
        tunnelPrevDownStreamInit(next, peer);
    else
        tunnelNextUpStreamInit(prev, peer);
    require(lineIsAlive(peer), "peer Init unexpectedly closed the fixture-owned line");
    requireDatagram(peer, transport_next);
    if (transport_next)
        tunnelPrevDownStreamFinish(next, peer);
    else
        tunnelNextUpStreamFinish(prev, peer);
    require(lineIsAlive(peer), "borrower destroyed the peer line");
    require(((usercontroller_lstate_t *) lineGetState(peer, observed_controller))->payload_mode == 0,
            "peer Finish did not destroy controller line state");
    lineDestroy(peer);
    lineUnref(peer);

    /* Real parent destruction also runs the real child's destructor, including
     * its empty-registry/timer checks, while the line pools still exist. */
    wireguarddeviceTunnelDestroy(wg, wwLifecycleStartupRollback());
    observed_controller = NULL;
    tunnelDestroy(prev);
    tunnelDestroy(next);
    tunnelchainDestroy(chain);
    cJSON_Delete(node.node_settings_json);
    memoryFree(node.type);
}

int main(void)
{
    testCaseSet("wireguarddevice_controller_mode_test");
    static char            off[]        = "OFF";
    ww_construction_data_t data         = {0};
    data.workers_count                  = 1;
    data.ram_profile                    = kRamProfileS1Memory;
    data.mtu_size                       = 1500;
    data.internal_logger_data.log_level = data.core_logger_data.log_level = off;
    data.network_logger_data.log_level = data.dns_logger_data.log_level = off;
    require(wwStartupSucceeded(createGlobalState(data)), "initialize runtime");
    auth_node = (node_t) {.name = (char *) "auth-client", .hash_type = calcHashBytes("AuthenticationClient", 20)};
    auth_node.instance = tunnelCreate(NULL, 0, 0);
    require(auth_node.instance != NULL, "authentication metadata fixture");
    testControllerMode(true);
    testControllerMode(false);
    tunnelDestroy(auth_node.instance);
    worker_t                     *worker  = getWorker(0);
    const ww_lifecycle_context_t *context = wwLifecycleProcessShutdown();
    require(workerInstallApplicationQuiesceRequest(worker, context) != kWorkerQuiesceRequestUnavailable, "quiesce");
    workerPerformQuiesce(worker, context);
    require(workerRequestDrain(worker), "request drain");
    workerPerformDrain(worker, context);
    require(workerRequestTeardown(worker), "request teardown");
    workerPerformTeardown(worker);
    destroyGlobalState();
    puts("WireGuard-created UserController modes passed in both transport orientations");
    return 0;
}
