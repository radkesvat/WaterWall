/*
 * Runtime proof that the audited Category-D sites really do end the process
 * through abortProgramNow(1).
 *
 * The executable runs one named case per invocation and never owns a
 * subprocess: run_tunnels_abort_runtime_test.cmake provides the process
 * boundary and requires the exact hard-abort result of 1.
 *
 * Every case is compiled in only when its tunnel target exists, so an optional
 * or platform-specific tunnel removes its own case and nothing else.
 */
#include "wwapi.h"

#include "tunnels_abort_runtime_cases.h"

#include "adapter.h"
#include "worker_registry_fixture.h"

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

// Category-D callbacks under test. They are declared here rather than pulled in
// through their owning tunnel's structure.h so this translation unit stays free
// of per-tunnel state-size enumerators.
#if defined(WATERWALL_ABORT_TEST_HAS_AUTHENTICATIONCLIENT)
void authenticationclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
#endif
#if defined(WATERWALL_ABORT_TEST_HAS_TESTERCLIENT)
void testerclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
#endif

static tunnel_t *createGuardedAdapter(node_t *node, adapter_edge_t edge)
{
    static char adapter_name[] = "AdapterGuardTest";

    memset(node, 0, sizeof(*node));
    node->name = adapter_name;
    return adapterCreate(node, 0, 0, edge);
}

static int caseAdapterChainHeadFinish(void)
{
    node_t    node;
    tunnel_t *adapter = createGuardedAdapter(&node, kAdapterChainHead);
    adapter->fnFinU(adapter, NULL);
    return 0;
}

static int caseAdapterChainHeadPayload(void)
{
    node_t    node;
    tunnel_t *adapter = createGuardedAdapter(&node, kAdapterChainHead);
    adapter->fnPayloadU(adapter, NULL, NULL);
    return 0;
}

static int caseAdapterChainEndFinish(void)
{
    node_t    node;
    tunnel_t *adapter = createGuardedAdapter(&node, kAdapterChainEnd);
    adapter->fnFinD(adapter, NULL);
    return 0;
}

static int caseAdapterChainEndPayload(void)
{
    node_t    node;
    tunnel_t *adapter = createGuardedAdapter(&node, kAdapterChainEnd);
    adapter->fnPayloadD(adapter, NULL, NULL);
    return 0;
}

#if defined(WATERWALL_ABORT_TEST_HAS_AUTHENTICATIONCLIENT)
// The callback discards both arguments before aborting, so NULL is intentional.
static int caseAuthenticationClientDisabledDownstreamInit(void)
{
    authenticationclientTunnelDownStreamInit(NULL, NULL);
    return 0;
}
#endif

static int casePacketLifecycleAnchorFinish(bool upstream)
{
    line_t line;
    memset(&line, 0, sizeof(line));
    line.wid = 0;

    tunnel_t *anchor = packettunnelCreate(NULL, sizeof(packet_lifecycle_anchor_t), 0);
    if (anchor == NULL ||
        ! packettunnelConfigureLifecycleAnchor(
            anchor, "PacketAnchorTest", tunnelDefaultUpStreamPayload, kPacketLifecycleAnchorPublishUpstream))
    {
        return kAbortCaseAllocationFailed;
    }

    if (upstream)
    {
        anchor->fnFinU(anchor, &line);
    }
    else
    {
        anchor->fnFinD(anchor, &line);
    }
    return 0;
}

static int casePacketLifecycleAnchorUpstreamFinish(void)
{
    return casePacketLifecycleAnchorFinish(true);
}

static int casePacketLifecycleAnchorDownstreamFinish(void)
{
    return casePacketLifecycleAnchorFinish(false);
}

#if defined(WATERWALL_ABORT_TEST_HAS_TESTERCLIENT)
// TesterClient is a chain head, so no previous tunnel can invoke this callback.
// The callback discards both arguments before aborting.
static int caseTesterClientDisabledUpstreamFinish(void)
{
    testerclientTunnelUpStreamFinish(NULL, NULL);
    return 0;
}
#endif

typedef struct abort_case_s
{
    const char *name;
    int (*run)(void);

} abort_case_t;

static const abort_case_t kAbortCases[] = {
    {"adapter_chain_head_finish", caseAdapterChainHeadFinish},
    {"adapter_chain_head_payload", caseAdapterChainHeadPayload},
    {"adapter_chain_end_finish", caseAdapterChainEndFinish},
    {"adapter_chain_end_payload", caseAdapterChainEndPayload},
#if defined(WATERWALL_ABORT_TEST_HAS_AUTHENTICATIONCLIENT)
    {"authenticationclient_disabled_downstream_init", caseAuthenticationClientDisabledDownstreamInit},
#endif
    {"packet_lifecycle_anchor_upstream_finish", casePacketLifecycleAnchorUpstreamFinish},
    {"packet_lifecycle_anchor_downstream_finish", casePacketLifecycleAnchorDownstreamFinish},
#if defined(WATERWALL_ABORT_TEST_HAS_TESTERCLIENT)
    {"testerclient_disabled_upstream_finish", caseTesterClientDisabledUpstreamFinish},
#endif
#if defined(WATERWALL_ABORT_TEST_HAS_UDPSTATELESSSOCKET)
    {"udpstatelesssocket_active_worker_idle_table_destroy", tunnelsAbortUdpStatelessSocketDestroyCase},
#endif
#if defined(WATERWALL_ABORT_TEST_HAS_TCPOVERUDPCLIENT)
    {"tcpoverudpclient_impossible_kcp_mtu_rejection", tunnelsAbortTcpOverUdpClientMtuCase},
#endif
#if defined(WATERWALL_ABORT_TEST_HAS_TCPOVERUDPSERVER)
    {"tcpoverudpserver_impossible_kcp_mtu_rejection", tunnelsAbortTcpOverUdpServerMtuCase},
#endif
#if defined(WATERWALL_ABORT_TEST_HAS_ROUTER)
    {"router_geoip_rule_without_open_database", tunnelsAbortRouterGeoipUnopenedDatabaseCase},
#endif
};

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s <case-name>\n", (argc > 0) ? argv[0] : "tunnels_abort_runtime_test");
        return kAbortCaseUsageError;
    }

    // None of these fixtures start a runtime; the worker count is the only
    // global the production invariants below read. Two total workers leave
    // exactly one event-loop worker.
    GSTATE.workers_count = 2;
    testWorkerRegistryInstall(&g_test_worker_registry);

    for (size_t i = 0; i < (sizeof(kAbortCases) / sizeof(kAbortCases[0])); ++i)
    {
        if (strcmp(argv[1], kAbortCases[i].name) == 0)
        {
            return kAbortCases[i].run();
        }
    }

    fprintf(stderr, "unknown abort case: %s\n", argv[1]);
    return kAbortCaseUnknownName;
}
