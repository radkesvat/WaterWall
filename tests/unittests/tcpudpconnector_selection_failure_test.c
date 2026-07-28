/*
 * TcpUdpConnector selection failure injection.
 *
 * Unsupported or ambiguous protocol flags describe one line's metadata, not a broken process. The connector is
 * selected before any line state is committed, so a rejected line must close only its previous side and never
 * reach tunnelUpStreamInit() on a connector branch.
 */
#include "TcpUdpConnector/structure.h"

#include "tunnel_line_failure_harness.h"

enum
{
    kTestLargeBufferSize = 4096,
    // Generous stand-in for tcpconnector_tstate_t / udpconnector_tstate_t. The entry-tunnel accessors only read
    // their domain_resolver_tunnel field, which stays NULL in this zeroed state, so each fake connector resolves
    // to itself.
    kFakeConnectorStateSize = 8192
};

static uint32_t g_tcp_connector_inits = 0;
static uint32_t g_udp_connector_inits = 0;

static void fakeTcpConnectorInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++g_tcp_connector_inits;
}

static void fakeUdpConnectorInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++g_udp_connector_inits;
}

typedef struct tcpudpconnector_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *connector;
    tunnel_t        *tcp_connector;
    tunnel_t        *udp_connector;
} tcpudpconnector_fixture_t;

static void fixtureSetup(tcpudpconnector_fixture_t *fixture)
{
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    g_tcp_connector_inits = 0;
    g_udp_connector_inits = 0;

    fixture->prev      = twfCreatePrevTunnel(&fixture->trace);
    fixture->connector = tunnelCreate(NULL, sizeof(tcpudpconnector_tstate_t), sizeof(tcpudpconnector_lstate_t));
    twfRequire(fixture->connector != NULL, "failed to create the TcpUdpConnector tunnel");

    fixture->tcp_connector = tunnelCreate(NULL, kFakeConnectorStateSize, 0);
    fixture->udp_connector = tunnelCreate(NULL, kFakeConnectorStateSize, 0);
    twfRequire(fixture->tcp_connector != NULL && fixture->udp_connector != NULL,
               "failed to create the fake connector branches");

    fixture->tcp_connector->fnInitU = fakeTcpConnectorInit;
    fixture->udp_connector->fnInitU = fakeUdpConnectorInit;

    tunnelBind(fixture->prev, fixture->connector);

    fixture->connector->fnInitU = &tcpudpconnectorTunnelUpStreamInit;

    tcpudpconnector_tstate_t *ts = tunnelGetState(fixture->connector);
    ts->tcp_connector            = fixture->tcp_connector;
    ts->udp_connector            = fixture->udp_connector;
}

static void fixtureTeardown(tcpudpconnector_fixture_t *fixture)
{
    twfRequireNoLeakedBuffers();
    memoryFree(fixture->prev);
    memoryFree(fixture->connector);
    memoryFree(fixture->tcp_connector);
    memoryFree(fixture->udp_connector);
}

typedef struct protocol_flags_s
{
    bool tcp;
    bool udp;
    bool icmp;
    bool packet;
} protocol_flags_t;

static void applyFlags(address_context_t *ctx, protocol_flags_t flags)
{
    ctx->proto_tcp    = flags.tcp;
    ctx->proto_udp    = flags.udp;
    ctx->proto_icmp   = flags.icmp;
    ctx->proto_packet = flags.packet;
}

static void requireRejected(const char *case_name, protocol_flags_t destination, protocol_flags_t source)
{
    twfSetCase(case_name);

    tcpudpconnector_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t        *l             = twfLineCreate(fixture.connector->lstate_size);
    const uint32_t refc_at_start = twfLineRefCount(l);

    applyFlags(&l->routing_context.dest_ctx, destination);
    applyFlags(&l->routing_context.src_ctx, source);

    tcpudpconnectorTunnelUpStreamInit(fixture.connector, l);

    twfRequireEqualText(fixture.trace.seq, "f", "the rejected line did not close exactly the previous side");
    twfRequireEqualU32(g_tcp_connector_inits, 0, "the TCP connector branch was initialized for a rejected line");
    twfRequireEqualU32(g_udp_connector_inits, 0, "the UDP connector branch was initialized for a rejected line");
    twfRequireLineStateZeroed(l, fixture.connector, "the rejected line state was not zeroed");
    twfRequireEqualU32(twfLineRefCount(l), refc_at_start, "the line reference count did not return to its start");

    twfLineDestroy(l);
    fixtureTeardown(&fixture);
}

static void requireSelected(const char *case_name, protocol_flags_t destination, protocol_flags_t source,
                            bool expect_tcp)
{
    twfSetCase(case_name);

    tcpudpconnector_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t *l = twfLineCreate(fixture.connector->lstate_size);

    applyFlags(&l->routing_context.dest_ctx, destination);
    applyFlags(&l->routing_context.src_ctx, source);

    tcpudpconnectorTunnelUpStreamInit(fixture.connector, l);

    twfRequireEqualU32(fixture.trace.prev_finish, 0, "a valid line was closed instead of connected");
    twfRequireEqualU32(g_tcp_connector_inits, expect_tcp ? 1U : 0U, "the TCP connector branch selection is wrong");
    twfRequireEqualU32(g_udp_connector_inits, expect_tcp ? 0U : 1U, "the UDP connector branch selection is wrong");

    tcpudpconnector_lstate_t *ls = lineGetState(l, fixture.connector);
    twfRequire(ls->selected_connector == (expect_tcp ? fixture.tcp_connector : fixture.udp_connector),
               "the committed line state points at the wrong connector");

    twfRequire(tcpudpconnectorGetSelectedUpStreamTunnel(fixture.connector, l) == ls->selected_connector,
               "the selected connector could not be read back");

    tcpudpconnectorLinestateDestroy(ls);
    twfLineDestroy(l);
    fixtureTeardown(&fixture);
}

int main(void)
{
    const protocol_flags_t none   = {false, false, false, false};
    const protocol_flags_t tcp    = {true, false, false, false};
    const protocol_flags_t udp    = {false, true, false, false};
    const protocol_flags_t both   = {true, true, false, false};
    const protocol_flags_t icmp   = {false, false, true, false};
    const protocol_flags_t packet = {false, false, false, true};

    requireRejected("no protocol flag anywhere", none, none);
    requireRejected("destination advertises both TCP and UDP", both, tcp);
    requireRejected("destination is ICMP only", icmp, tcp);
    requireRejected("destination is packet only", packet, tcp);
    requireRejected("source advertises both TCP and UDP", none, both);

    requireSelected("destination TCP selects the TCP connector", tcp, none, true);
    requireSelected("destination UDP selects the UDP connector", udp, none, false);
    requireSelected("source TCP is the fallback when the destination has no flags", none, tcp, true);
    requireSelected("source UDP is the fallback when the destination has no flags", none, udp, false);

    printf("tcpudpconnector_selection_failure_test: all cases passed\n");
    return 0;
}
