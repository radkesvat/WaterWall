#include "Socks5Server/structure.h"
#include "TcpUdpListener/interface.h"
#include "UdpListener/interface.h"
#include "tunnel_orderly_shutdown_harness.h"

#if defined(OS_UNIX)
#include <sys/mman.h>
#endif

enum
{
    kTestLargeBuffer = 8192,
    kTestLinePoolCap = 8,
};

typedef struct dynamic_mock_provider_s
{
    uint32_t                              open_calls;
    uint32_t                              activate_calls;
    uint32_t                              close_calls;
    uint32_t                              get_line_info_calls;
    uint64_t                              next_generation;
    uint16_t                              mock_port;
    udplistener_dynamic_endpoint_handle_t last_closed_handle;
    udplistener_dynamic_line_info_t       mock_line_info;
    bool                                  mock_line_is_dynamic;
    bool                                  open_should_fail;
    bool                                  activate_should_fail;
} dynamic_mock_provider_t;

static bool mockOpen(tunnel_t *instance, wid_t worker_wid, const udplistener_dynamic_endpoint_open_request_t *request,
                     udplistener_dynamic_endpoint_open_result_t *result_out)
{
    (void) request;
    dynamic_mock_provider_t *mock = *(dynamic_mock_provider_t **) tunnelGetState(instance);
    ++mock->open_calls;
    if (mock->open_should_fail)
    {
        return false;
    }

    uint64_t gen = ++mock->next_generation;
    *result_out  = (udplistener_dynamic_endpoint_open_result_t) {
         .handle           = {.owner_wid = worker_wid, .generation = gen},
         .bound_local_port = mock->mock_port != 0 ? mock->mock_port : 25000,
    };
    twfRequire(sockaddrSetIpAddressPort(&result_out->bound_local_addr, "127.0.0.1", result_out->bound_local_port) == 0,
               "failed to build mock dynamic endpoint address");
    return true;
}

static bool mockActivate(tunnel_t *instance, udplistener_dynamic_endpoint_handle_t handle)
{
    (void) handle;
    dynamic_mock_provider_t *mock = *(dynamic_mock_provider_t **) tunnelGetState(instance);
    ++mock->activate_calls;
    return ! mock->activate_should_fail;
}

static void mockClose(tunnel_t *instance, udplistener_dynamic_endpoint_handle_t handle)
{
    dynamic_mock_provider_t *mock = *(dynamic_mock_provider_t **) tunnelGetState(instance);
    ++mock->close_calls;
    mock->last_closed_handle = handle;
}

static bool mockGetLineInfo(tunnel_t *instance, const line_t *line, udplistener_dynamic_line_info_t *info_out)
{
    (void) line;
    dynamic_mock_provider_t *mock = *(dynamic_mock_provider_t **) tunnelGetState(instance);
    ++mock->get_line_info_calls;
    if (info_out != NULL)
    {
        *info_out = mock->mock_line_info;
    }
    return mock->mock_line_is_dynamic;
}

typedef struct test_env_s
{
    twf_worker_env_t        env;
    twf_line_pool_t         lines;
    tunnel_t               *server;
    tunnel_t               *client_peer;
    tunnel_t               *mock_listener_tunnel;
    line_t                 *control_line;
    dynamic_mock_provider_t mock_provider;
    sbuf_t                 *last_received_payload;
    uint32_t                client_payload_calls;
    uint32_t                client_finish_calls;
} test_env_t;

static void clientPeerPayloadD(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    test_env_t *test = *(test_env_t **) tunnelGetState(t);
    (void) l;
    ++test->client_payload_calls;
    if (test->last_received_payload != NULL)
    {
        sbufDestroy(test->last_received_payload);
    }
    test->last_received_payload = buf;
}

static void clientPeerFinishD(tunnel_t *t, line_t *l)
{
    test_env_t *test = *(test_env_t **) tunnelGetState(t);
    (void) l;
    ++test->client_finish_calls;
}

static void setupTestEnv(test_env_t *test)
{
    memoryZero(test, sizeof(*test));
    twfWorkerEnvSetup(&test->env, kTestLargeBuffer, 0);

    test->client_peer          = tunnelCreate(NULL, sizeof(test_env_t *), 0);
    test->server               = tunnelCreate(NULL, sizeof(socks5server_tstate_t), sizeof(socks5server_lstate_t));
    test->mock_listener_tunnel = tunnelCreate(NULL, sizeof(dynamic_mock_provider_t *), 0);
    twfRequire(test->client_peer != NULL && test->server != NULL && test->mock_listener_tunnel != NULL,
               "failed to create test tunnels");

    *(test_env_t **) tunnelGetState(test->client_peer)                       = test;
    test->client_peer->fnPayloadD                                            = clientPeerPayloadD;
    test->client_peer->fnFinD                                                = clientPeerFinishD;
    *(dynamic_mock_provider_t **) tunnelGetState(test->mock_listener_tunnel) = &test->mock_provider;
    tunnelBind(test->client_peer, test->server);

    twfLinePoolSetup(&test->lines, test->server->lstate_size, kTestLinePoolCap);
    test->control_line = twfLinePoolCreateLine(&test->lines);

    socks5server_tstate_t *ts = tunnelGetState(test->server);
    ts->allow_connect         = true;
    ts->allow_udp             = true;
    ts->no_auth               = true;
    ts->workers_count         = 1;
    ts->worker_associations   = memoryAllocateZero(sizeof(socks5server_assoc_map_t) * ts->workers_count);
    for (wid_t wid = 0; wid < ts->workers_count; ++wid)
    {
        ts->worker_associations[wid] = socks5server_assoc_map_t_init();
    }
    ts->dynamic_provider = (udplistener_dynamic_provider_t) {
        .instance      = test->mock_listener_tunnel,
        .open          = mockOpen,
        .activate      = mockActivate,
        .close         = mockClose,
        .get_line_info = mockGetLineInfo,
    };
    ts->udp_reply_ip = (ip_addr_t) {.type = IPADDR_TYPE_V4, .u_addr.ip4 = {.addr = 0x0100007F}}; // 127.0.0.1

    addresscontextSetIpPortProtocol(
        lineGetSourceAddressContext(test->control_line), &ts->udp_reply_ip, 12345, IP_PROTO_TCP);
    user_handle_t empty_handle = userHandleEmpty();
    lineAddUser(test->control_line, &empty_handle, NULL, NULL);

    socks5serverTunnelUpStreamInit(test->server, test->control_line);
}

static void teardownTestEnv(test_env_t *test)
{
    if (test->last_received_payload != NULL)
    {
        sbufDestroy(test->last_received_payload);
        test->last_received_payload = NULL;
    }

    if (test->control_line != NULL && lineIsAlive(test->control_line))
    {
        socks5server_lstate_t *ls = lineGetState(test->control_line, test->server);
        socks5serverLinestateDestroy(ls);
        lineDestroy(test->control_line);
        test->control_line = NULL;
    }

    socks5server_tstate_t *ts = tunnelGetState(test->server);
    socks5serverTunnelstateDestroy(ts);

    twfLinePoolTeardown(&test->lines);
    tunnelDestroy(test->mock_listener_tunnel);
    tunnelDestroy(test->server);
    tunnelDestroy(test->client_peer);
    twfWorkerEnvTeardown(&test->env);
}

static void testUdpAssociateSuccessFlow(void)
{
    twfSetCase("socks5server UDP ASSOCIATE success flow allocates dynamic endpoint");
    test_env_t test;
    setupTestEnv(&test);

    // Method selection handshake
    const uint8_t method_req[] = {0x05, 0x01, 0x00};
    sbuf_t       *req_buf      = bufferpoolGetSmallBuffer(lineGetBufferPool(test.control_line));
    sbufSetLength(req_buf, sizeof(method_req));
    memoryCopy(sbufGetMutablePtr(req_buf), method_req, sizeof(method_req));

    socks5serverTunnelUpStreamPayload(test.server, test.control_line, req_buf);

    twfRequireEqualU32(test.client_payload_calls, 1, "method reply not received");
    twfRequire(test.last_received_payload != NULL, "method reply buffer is null");
    const uint8_t *method_rep = sbufGetRawPtr(test.last_received_payload);
    twfRequireEqualU32(method_rep[0], 0x05, "version mismatch in method reply");
    twfRequireEqualU32(method_rep[1], 0x00, "no-auth method must be accepted");

    // UDP ASSOCIATE command: 05 03 00 01 00 00 00 00 00 00
    const uint8_t assoc_req[] = {0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    req_buf                   = bufferpoolGetSmallBuffer(lineGetBufferPool(test.control_line));
    sbufSetLength(req_buf, sizeof(assoc_req));
    memoryCopy(sbufGetMutablePtr(req_buf), assoc_req, sizeof(assoc_req));

    socks5serverTunnelUpStreamPayload(test.server, test.control_line, req_buf);

    twfRequireEqualU32(test.client_payload_calls, 2, "UDP ASSOCIATE reply not received");
    twfRequireEqualU32(test.mock_provider.open_calls, 1, "provider.open was not called");
    twfRequireEqualU32(test.mock_provider.activate_calls, 1, "provider.activate was not called");

    const uint8_t *assoc_rep = sbufGetRawPtr(test.last_received_payload);
    twfRequireEqualU32(assoc_rep[0], 0x05, "version mismatch in assoc reply");
    twfRequireEqualU32(assoc_rep[1], 0x00, "REP must be 0x00 (success)");

    socks5server_lstate_t *ls = lineGetState(test.control_line, test.server);
    twfRequireEqualU32(ls->phase, kSocks5ServerPhaseUdpControl, "phase must be kSocks5ServerPhaseUdpControl");
    twfRequire(ls->dynamic_handle.generation > 0, "dynamic_handle generation must be set");

    socks5server_assoc_entry_t *entry =
        socks5serverFindWorkerAssociation(test.server, 0, ls->dynamic_handle.generation);
    twfRequire(entry != NULL, "association entry must exist in worker association map");
    twfRequire(entry->active, "association entry must be active after provider activation");
    twfRequire(udplistenerDynamicEndpointHandleEquals(entry->dynamic_handle, ls->dynamic_handle),
               "association entry handle must match control state");
    twfRequireEqualU32(entry->assigned_port, 25000, "assigned_port mismatch");

    // Close control line and verify dynamic endpoint cleanup
    line_t *closing_line = test.control_line;
    test.control_line    = NULL;
    socks5serverCloseControlLineBidirectional(test.server, closing_line);
    twfRequireEqualU32(test.mock_provider.close_calls, 1, "provider.close must be called on control line close");
    twfRequireEqualU32(
        test.mock_provider.last_closed_handle.generation, 1, "closed handle generation must match association");

    lineDestroy(closing_line);
    teardownTestEnv(&test);
}

static void testUdpClientDynamicLineValidation(void)
{
    twfSetCase("socks5server validates dynamic UDP line info against worker-local associations");
    test_env_t test;
    setupTestEnv(&test);

    // Setup an association in worker 0 map
    socks5server_tstate_t     *ts    = tunnelGetState(test.server);
    uint64_t                   gen   = 42;
    socks5server_assoc_entry_t assoc = {
        .generation     = gen,
        .owner_wid      = 0,
        .dynamic_handle = {.owner_wid = 0, .generation = gen},
        .assigned_port  = 25000,
        .user_handle    = userHandleEmpty(),
        .auth_username  = NULL,
        .auth_password  = NULL,
        .active         = true,
    };
    socks5server_assoc_map_t_insert(&ts->worker_associations[0], gen, assoc);

    // 1. Line with matching dynamic info
    line_t *valid_udp_line = twfLinePoolCreateLine(&test.lines);
    addresscontextSetIpPortProtocol(
        lineGetSourceAddressContext(valid_udp_line), &ts->udp_reply_ip, 30000, IP_PROTO_UDP);
    lineGetRoutingContext(valid_udp_line)->local_listener_port = 25000;
    test.mock_provider.mock_line_is_dynamic                    = true;
    test.mock_provider.mock_line_info                          = (udplistener_dynamic_line_info_t) {
                                 .is_dynamic       = true,
                                 .expected_wid     = 0,
                                 .generation       = gen,
                                 .handle           = {.owner_wid = 0, .generation = gen},
                                 .bound_local_port = 25000,
    };

    socks5serverTunnelUpStreamInit(test.server, valid_udp_line);
    socks5server_lstate_t *valid_ls = lineGetState(valid_udp_line, test.server);
    twfRequireEqualU32(
        valid_ls->kind, kSocks5ServerLineKindUdpClient, "valid dynamic UDP line must be accepted as UdpClient");
    twfRequireEqualU32(valid_ls->dynamic_handle.generation, gen, "dynamic handle generation must match");

    // 2. Line with unknown / rogue generation
    line_t *rogue_udp_line = twfLinePoolCreateLine(&test.lines);
    addresscontextSetIpPortProtocol(
        lineGetSourceAddressContext(rogue_udp_line), &ts->udp_reply_ip, 30001, IP_PROTO_UDP);
    test.mock_provider.mock_line_info = (udplistener_dynamic_line_info_t) {
        .is_dynamic       = true,
        .expected_wid     = 0,
        .generation       = 999, // unknown generation
        .handle           = {.owner_wid = 0, .generation = 999},
        .bound_local_port = 25000,
    };

    socks5serverTunnelUpStreamInit(test.server, rogue_udp_line);
    socks5server_lstate_t *rogue_ls = lineGetState(rogue_udp_line, test.server);
    twfRequireEqualU32(rogue_ls->kind,
                       kSocks5ServerLineKindRejected,
                       "rogue dynamic UDP line must be marked kSocks5ServerLineKindRejected");

    // Sending payload on rejected line drops safely
    sbuf_t *dummy_buf = bufferpoolGetSmallBuffer(lineGetBufferPool(rogue_udp_line));
    sbufSetLength(dummy_buf, 10);
    socks5serverTunnelUpStreamPayload(test.server, rogue_udp_line, dummy_buf);

    /* An endpoint can be syntactically dynamic yet belong to another (or an
     * unregistered) worker. This is an ordinary fail-closed association
     * mismatch, not a cross-worker control-line operation. */
    line_t *wrong_wid_udp_line = twfLinePoolCreateLine(&test.lines);
    addresscontextSetIpPortProtocol(
        lineGetSourceAddressContext(wrong_wid_udp_line), &ts->udp_reply_ip, 30002, IP_PROTO_UDP);
    lineGetRoutingContext(wrong_wid_udp_line)->local_listener_port = 25000;
    test.mock_provider.mock_line_is_dynamic                        = true;
    test.mock_provider.mock_line_info                              = (udplistener_dynamic_line_info_t) {
                                     .is_dynamic       = true,
                                     .expected_wid     = 1,
                                     .generation       = gen,
                                     .handle           = {.owner_wid = 1, .generation = gen},
                                     .bound_local_port = 25000,
    };
    socks5serverTunnelUpStreamInit(test.server, wrong_wid_udp_line);
    socks5server_lstate_t *wrong_wid_ls = lineGetState(wrong_wid_udp_line, test.server);
    twfRequireEqualU32(wrong_wid_ls->kind,
                       kSocks5ServerLineKindRejected,
                       "foreign expected WID must reject UDP without touching the control association");

    line_t *unregistered_wid_udp_line = twfLinePoolCreateLine(&test.lines);
    addresscontextSetIpPortProtocol(
        lineGetSourceAddressContext(unregistered_wid_udp_line), &ts->udp_reply_ip, 30003, IP_PROTO_UDP);
    lineGetRoutingContext(unregistered_wid_udp_line)->local_listener_port = 25000;
    test.mock_provider.mock_line_info                                     = (udplistener_dynamic_line_info_t) {
                                            .is_dynamic       = true,
                                            .expected_wid     = 2,
                                            .generation       = gen,
                                            .handle           = {.owner_wid = 2, .generation = gen},
                                            .bound_local_port = 25000,
    };
    socks5serverTunnelUpStreamInit(test.server, unregistered_wid_udp_line);
    socks5server_lstate_t *unregistered_wid_ls = lineGetState(unregistered_wid_udp_line, test.server);
    twfRequireEqualU32(unregistered_wid_ls->kind,
                       kSocks5ServerLineKindRejected,
                       "unregistered expected WID must reject UDP without indexing a foreign map");
    twfRequireEqualU32(test.mock_provider.close_calls,
                       0,
                       "ordinary expected-WID mismatch must not close or message the TCP association");
    twfRequireEqualU32(
        test.client_payload_calls, 0, "ordinary expected-WID mismatch must not access the TCP client peer");

    /* A static listener line cannot impersonate one of the dynamically bound
     * association endpoints, even when its source tuple looks plausible. */
    line_t *static_udp_line = twfLinePoolCreateLine(&test.lines);
    addresscontextSetIpPortProtocol(
        lineGetSourceAddressContext(static_udp_line), &ts->udp_reply_ip, 30004, IP_PROTO_UDP);
    lineGetRoutingContext(static_udp_line)->local_listener_port = 25000;
    test.mock_provider.mock_line_is_dynamic                     = false;
    socks5serverTunnelUpStreamInit(test.server, static_udp_line);
    socks5server_lstate_t *static_ls = lineGetState(static_udp_line, test.server);
    twfRequireEqualU32(static_ls->kind,
                       kSocks5ServerLineKindRejected,
                       "static listener metadata must not authorize a SOCKS UDP client line");
    twfRequireEqualU32(
        test.mock_provider.close_calls, 0, "static listener metadata must not close the TCP association");

    /* A line that passed Init must validate the local association again before
     * its first payload. Removing the old generation models endpoint close
     * followed by a later handle allocation on the same worker. */
    line_t *stale_udp_line = twfLinePoolCreateLine(&test.lines);
    addresscontextSetIpPortProtocol(
        lineGetSourceAddressContext(stale_udp_line), &ts->udp_reply_ip, 30005, IP_PROTO_UDP);
    lineGetRoutingContext(stale_udp_line)->local_listener_port = 25000;
    test.mock_provider.mock_line_is_dynamic                    = true;
    test.mock_provider.mock_line_info                          = (udplistener_dynamic_line_info_t) {
                                 .is_dynamic       = true,
                                 .expected_wid     = 0,
                                 .generation       = gen,
                                 .handle           = {.owner_wid = 0, .generation = gen},
                                 .bound_local_port = 25000,
    };
    socks5serverTunnelUpStreamInit(test.server, stale_udp_line);
    socks5server_lstate_t *stale_ls = lineGetState(stale_udp_line, test.server);
    twfRequireEqualU32(stale_ls->kind,
                       kSocks5ServerLineKindUdpClient,
                       "active association did not accept the stale-generation fixture line at Init");
    socks5server_assoc_map_t_erase(&ts->worker_associations[0], gen);
    dummy_buf = bufferpoolGetSmallBuffer(lineGetBufferPool(stale_udp_line));
    sbufSetLength(dummy_buf, 10);
    socks5serverTunnelUpStreamPayload(test.server, stale_udp_line, dummy_buf);
    twfRequireEqualU32(stale_ls->kind,
                       kSocks5ServerLineKindRejected,
                       "removed association generation did not reject the first UDP payload");
    twfRequireEqualU32(
        test.mock_provider.close_calls, 0, "removed association generation must not close the TCP control line");
    twfRequire(socks5server_assoc_map_t_insert(&ts->worker_associations[0], gen, assoc).inserted,
               "failed to restore the active association for the metadata-mutation case");

    /* Provider metadata is checked again on first payload. A mutable/stale
     * handle therefore rejects only this UDP line and creates no remote. */
    test.mock_provider.mock_line_is_dynamic = false;
    dummy_buf                               = bufferpoolGetSmallBuffer(lineGetBufferPool(valid_udp_line));
    sbufSetLength(dummy_buf, 10);
    socks5serverTunnelUpStreamPayload(test.server, valid_udp_line, dummy_buf);
    twfRequireEqualU32(valid_ls->kind,
                       kSocks5ServerLineKindRejected,
                       "provider metadata changed after Init must reject first UDP payload");
    twfRequireEqualU32(test.mock_provider.close_calls, 0, "stale provider metadata must not close the TCP association");

    // Teardown lines
    socks5serverLinestateDestroy(valid_ls);
    lineDestroy(valid_udp_line);

    socks5serverLinestateDestroy(rogue_ls);
    lineDestroy(rogue_udp_line);

    socks5serverLinestateDestroy(wrong_wid_ls);
    lineDestroy(wrong_wid_udp_line);

    socks5serverLinestateDestroy(unregistered_wid_ls);
    lineDestroy(unregistered_wid_udp_line);

    socks5serverLinestateDestroy(static_ls);
    lineDestroy(static_udp_line);

    socks5serverLinestateDestroy(stale_ls);
    lineDestroy(stale_udp_line);

    socks5server_assoc_map_t_erase(&ts->worker_associations[0], gen);

    teardownTestEnv(&test);
}

static void testValidUdpClientAssociationOnNonzeroWorker(void)
{
    twfSetCase("socks5server accepts a valid dynamic UDP client on its nonzero owner worker");
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, 2, kTestLargeBuffer, kTwfDefaultSmallBufferSize);

    dynamic_mock_provider_t mock   = {0};
    tunnel_t               *server = tunnelCreate(NULL, sizeof(socks5server_tstate_t), sizeof(socks5server_lstate_t));
    tunnel_t               *provider_tunnel = tunnelCreate(NULL, sizeof(dynamic_mock_provider_t *), 0);
    twfRequire(server != NULL && provider_tunnel != NULL, "failed to allocate nonzero-worker SOCKS fixture tunnels");
    *(dynamic_mock_provider_t **) tunnelGetState(provider_tunnel) = &mock;

    socks5server_tstate_t *ts = tunnelGetState(server);
    ts->workers_count         = 2;
    ts->worker_associations   = memoryAllocateZero(sizeof(socks5server_assoc_map_t) * ts->workers_count);
    twfRequire(ts->worker_associations != NULL, "failed to allocate nonzero-worker SOCKS association maps");
    for (wid_t wid = 0; wid < ts->workers_count; ++wid)
    {
        ts->worker_associations[wid] = socks5server_assoc_map_t_init();
    }
    ts->dynamic_provider = (udplistener_dynamic_provider_t) {
        .instance      = provider_tunnel,
        .open          = mockOpen,
        .activate      = mockActivate,
        .close         = mockClose,
        .get_line_info = mockGetLineInfo,
    };

    const uint64_t                   generation  = 91;
    const socks5server_assoc_entry_t association = {
        .generation     = generation,
        .owner_wid      = 1,
        .dynamic_handle = {.owner_wid = 1, .generation = generation},
        .assigned_port  = 25000,
        .user_handle    = userHandleEmpty(),
        .active         = true,
    };
    twfRequire(socks5server_assoc_map_t_insert(&ts->worker_associations[1], generation, association).inserted,
               "failed to install nonzero-worker SOCKS association");
    mock.mock_line_is_dynamic = true;
    mock.mock_line_info       = (udplistener_dynamic_line_info_t) {
              .is_dynamic       = true,
              .expected_wid     = 1,
              .generation       = generation,
              .handle           = {.owner_wid = 1, .generation = generation},
              .bound_local_port = 25000,
    };

    line_t *udp_line  = twfLineCreate(server->lstate_size);
    udp_line->wid     = 1;
    ip_addr_t peer_ip = {.type = IPADDR_TYPE_V4};
    twfRequire(ip4AddrAddressToNetwork("127.0.0.1", &peer_ip.u_addr.ip4) != 0,
               "failed to parse nonzero-worker UDP peer");
    addresscontextSetIpPortProtocol(lineGetSourceAddressContext(udp_line), &peer_ip, 34000, IP_PROTO_UDP);
    lineGetRoutingContext(udp_line)->local_listener_port = 25000;

    testWorkerBindWID(1);
    socks5serverTunnelUpStreamInit(server, udp_line);
    socks5server_lstate_t *ls = lineGetState(udp_line, server);
    twfRequireEqualU32(ls->kind,
                       kSocks5ServerLineKindUdpClient,
                       "valid nonzero-worker endpoint metadata did not authorize the UDP client line");
    twfRequireEqualU32(ls->dynamic_handle.owner_wid, 1, "UDP client line lost its nonzero owner WID");
    socks5serverLinestateDestroy(ls);
    twfLineDestroy(udp_line);

    socks5server_assoc_map_t_erase(&ts->worker_associations[1], generation);
    socks5serverTunnelstateDestroy(ts);
    tunnelDestroy(provider_tunnel);
    tunnelDestroy(server);
    testWorkerBindWID(0);
    tosWorkerEnvTeardown(&env);
}

static void testUdpAssociateRejectsForeignPeerHint(void)
{
    twfSetCase("socks5server rejects UDP ASSOCIATE with a foreign peer IP hint");
    test_env_t test;
    setupTestEnv(&test);

    const uint8_t method_req[] = {0x05, 0x01, 0x00};
    sbuf_t       *req_buf      = bufferpoolGetSmallBuffer(lineGetBufferPool(test.control_line));
    sbufSetLength(req_buf, sizeof(method_req));
    memoryCopy(sbufGetMutablePtr(req_buf), method_req, sizeof(method_req));
    socks5serverTunnelUpStreamPayload(test.server, test.control_line, req_buf);

    /* UDP ASSOCIATE 127.0.0.2:53000 from a control connection at 127.0.0.1. */
    const uint8_t assoc_req[] = {0x05, 0x03, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x02, 0xCF, 0x08};
    req_buf                   = bufferpoolGetSmallBuffer(lineGetBufferPool(test.control_line));
    sbufSetLength(req_buf, sizeof(assoc_req));
    memoryCopy(sbufGetMutablePtr(req_buf), assoc_req, sizeof(assoc_req));
    socks5serverTunnelUpStreamPayload(test.server, test.control_line, req_buf);

    twfRequireEqualU32(test.mock_provider.open_calls, 0, "foreign peer hint must not open a UDP endpoint");
    twfRequireEqualU32(test.client_payload_calls, 2, "foreign peer hint must receive a command failure reply");
    twfRequireEqualU32(
        sbufGetMutablePtr(test.last_received_payload)[1], 0x01, "foreign peer hint must receive general failure");

    lineDestroy(test.control_line);
    test.control_line = NULL;
    teardownTestEnv(&test);
}

typedef enum socks5server_wrong_worker_entry_e
{
    kSocks5ServerWrongWorkerInit,
    kSocks5ServerWrongWorkerPayload,
} socks5server_wrong_worker_entry_t;

#if defined(OS_UNIX)
static tunnel_t *makeWrongWorkerProtectedTunnel(uint32_t tstate_size, uint32_t lstate_size)
{
    const long page_size_long = sysconf(_SC_PAGESIZE);
    twfRequire(page_size_long > 0, "failed to determine page size for SOCKS wrong-worker tunnel guard test");
    const size_t page_size = (size_t) page_size_long;
    const size_t state_at  = offsetof(tunnel_t, state);
    twfRequire(state_at < page_size, "tunnel header does not fit before SOCKS wrong-worker state guard page");

    uint8_t *mapping = mmap(NULL, page_size * 2U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    twfRequire(mapping != MAP_FAILED, "failed to allocate SOCKS wrong-worker tunnel guard pages");

    tunnel_t *t    = (tunnel_t *) (mapping + page_size - state_at);
    t->tstate_size = tstate_size;
    t->lstate_size = lstate_size;
    twfRequire(mprotect(mapping + page_size, page_size, PROT_NONE) == 0,
               "failed to protect SOCKS wrong-worker tunnel state page");
    return t;
}

static line_t *makeWrongWorkerProtectedLine(void)
{
    const long page_size_long = sysconf(_SC_PAGESIZE);
    twfRequire(page_size_long > 0, "failed to determine page size for SOCKS wrong-worker guard test");
    const size_t page_size     = (size_t) page_size_long;
    const size_t line_state_at = offsetof(line_t, tunnels_line_state);
    twfRequire(line_state_at < page_size, "line header does not fit before SOCKS wrong-worker guard page");

    uint8_t *mapping = mmap(NULL, page_size * 2U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    twfRequire(mapping != MAP_FAILED, "failed to allocate SOCKS wrong-worker guard pages");

    line_t *line = (line_t *) (mapping + page_size - line_state_at);
    atomic_init(&line->refc, 1);
    line->alive = true;
    line->wid   = 0;
    twfRequire(mprotect(mapping + page_size, page_size, PROT_NONE) == 0,
               "failed to protect SOCKS wrong-worker line state page");
    return line;
}
#endif

static void wrongWorkerEntryBody(void *argument)
{
    const socks5server_wrong_worker_entry_t entry = (socks5server_wrong_worker_entry_t) (uintptr_t) argument;
    test_env_t                              test;
    setupTestEnv(&test);

#if defined(OS_UNIX)
    tunnel_t *server = makeWrongWorkerProtectedTunnel(sizeof(socks5server_tstate_t), sizeof(socks5server_lstate_t));
    line_t   *line   = makeWrongWorkerProtectedLine();
#else
    tunnel_t *server = test.server;
    line_t   *line   = twfLineCreate(server->lstate_size);
#endif

    if (entry == kSocks5ServerWrongWorkerInit)
    {
        testWorkerUnbindWID();
        socks5serverTunnelUpStreamInit(server, line);
        return;
    }

    testWorkerUnbindWID();
    socks5serverTunnelUpStreamPayload(server, line, NULL);
}

static void testWrongWorkerCallbacksAbortBeforeLineStateAccess(void)
{
    twfSetCase("socks5server rejects foreign-worker UDP callbacks before line state access");
    tosResetProcessApi(true);
    tosRequireChildExit("upstream Init from a foreign worker",
                        wrongWorkerEntryBody,
                        (void *) (uintptr_t) kSocks5ServerWrongWorkerInit,
                        kTosChildDirectAbort);
    tosRequireChildExit("upstream Payload from a foreign worker",
                        wrongWorkerEntryBody,
                        (void *) (uintptr_t) kSocks5ServerWrongWorkerPayload,
                        kTosChildDirectAbort);
    tosResetProcessApi(true);
}

int main(void)
{
    testUdpAssociateSuccessFlow();
    testUdpClientDynamicLineValidation();
    testValidUdpClientAssociationOnNonzeroWorker();
    testUdpAssociateRejectsForeignPeerHint();
    testWrongWorkerCallbacksAbortBeforeLineStateAccess();

    puts("socks5server_dynamic_provider_test: all cases passed");
    return 0;
}
