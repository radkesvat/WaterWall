/*
 * Runtime proof that the audited Category-D sites really do end the process
 * through abortProgramNow(1).
 *
 * The executable runs one named case per invocation and never owns a
 * subprocess: run_tunnels_abort_runtime_test.cmake provides the process
 * boundary and requires an exact result of 1 plus the immediate-abort
 * diagnostic, so a crash can no longer masquerade as a hard abort.
 *
 * Every case is compiled in only when its tunnel target exists, so an optional
 * or platform-specific tunnel removes its own case and nothing else.
 */
#include "wwapi.h"

#include "tunnels_abort_runtime_cases.h"

#include "adapter.h"

// Category-D callbacks under test. They are declared here rather than pulled in
// through their owning tunnel's structure.h so this translation unit stays free
// of per-tunnel state-size enumerators.
#if defined(WATERWALL_ABORT_TEST_HAS_AUTHENTICATIONCLIENT)
void authenticationclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
#endif
#if defined(WATERWALL_ABORT_TEST_HAS_PINGCLIENT)
void pingclientUpStreamInit(tunnel_t *t, line_t *l);
#endif
#if defined(WATERWALL_ABORT_TEST_HAS_RAWSOCKET)
void rawsocketUpStreamFinish(tunnel_t *t, line_t *l);
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

#if defined(WATERWALL_ABORT_TEST_HAS_PINGCLIENT)
// Same contract: the packet-tunnel interface replaced this stream callback and
// the stub discards its arguments.
static int casePingClientImpossiblePacketUpstreamInit(void)
{
    pingclientUpStreamInit(NULL, NULL);
    return 0;
}
#endif

#if defined(WATERWALL_ABORT_TEST_HAS_RAWSOCKET)
// RawSocket reads the line worker id for its diagnostic, so this one needs a
// real zero-initialized line.
static int caseRawSocketWorkerPacketLineUpstreamFinish(void)
{
    line_t line;
    memset(&line, 0, sizeof(line));
    line.wid = 0;

    rawsocketUpStreamFinish(NULL, &line);
    return 0;
}
#endif

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
#if defined(WATERWALL_ABORT_TEST_HAS_PINGCLIENT)
    {"pingclient_impossible_packet_upstream_init", casePingClientImpossiblePacketUpstreamInit},
#endif
#if defined(WATERWALL_ABORT_TEST_HAS_RAWSOCKET)
    {"rawsocket_worker_packet_line_upstream_finish", caseRawSocketWorkerPacketLineUpstreamFinish},
#endif
#if defined(WATERWALL_ABORT_TEST_HAS_TESTERCLIENT)
    {"testerclient_disabled_upstream_finish", caseTesterClientDisabledUpstreamFinish},
#endif
#if defined(WATERWALL_ABORT_TEST_HAS_REVERSECLIENT)
    {"reverseclient_live_idle_handle_linestate_destroy", tunnelsAbortReverseClientLinestateCase},
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
