/*
 * Socks5Server UDP cross-line re-entrancy coverage.
 *
 * A remote response is forwarded on its associated client line. That client
 * Payload callback may synchronously close the client; Socks5Server then drains
 * every registered remote, including the suspended response's own line. The
 * outer remote callback must retain that line until it can observe the nested
 * owner close and return without a duplicate teardown or stale-state access.
 */
#include "Socks5Server/structure.h"

#include "tunnel_orderly_shutdown_harness.h"

enum
{
    kSocks5ServerCloseTestLargeBuffer = 8192,
    kSocks5ServerCloseTestLinePoolCap = 4,
    kSocks5ServerCloseRemoteKey       = 0x5A17,
    kSocks5ServerCloseClientPort      = 24000,
    kSocks5ServerCloseListenerPort    = 1080,
    kSocks5ServerCloseRemotePort      = 53,
};

typedef struct socks5server_close_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    tunnel_t        *prev;
    tunnel_t        *server;
    tunnel_t        *next;
    tunnel_t        *provider;
    tunnel_chain_t  *chain;
    line_t          *client;
    line_t          *remote;
    line_t          *remote_second;
    line_t          *control;
    uint32_t         client_payload_calls;
    uint32_t         upstream_finish_calls;
    uint32_t         upstream_finish_refcount;
    uint32_t         remote_init_calls;
    uint32_t         provider_close_calls;
    uint32_t         remote_registry_count_on_finish;
    bool             provider_closed;
    bool             assoc_initialized;
} socks5server_close_fixture_t;

static ip_addr_t fixtureIpv4(const char *text)
{
    ip_addr_t ip = {.type = IPADDR_TYPE_V4};
    twfRequire(ip4AddrAddressToNetwork(text, &ip.u_addr.ip4) != 0, "failed to parse fixture IPv4 address");
    return ip;
}

static void countNextFinish(tunnel_t *t, line_t *l)
{
    socks5server_close_fixture_t *fixture = *(socks5server_close_fixture_t **) tunnelGetState(t);

    twfRequire(l == fixture->remote, "Socks5Server finished the wrong UDP remote line");
    ++fixture->upstream_finish_calls;
    fixture->upstream_finish_refcount = twfLineRefCount(l);
    if (fixture->client != NULL && lineIsAlive(fixture->client))
    {
        socks5server_lstate_t *client_ls = lineGetState(fixture->client, fixture->server);
        fixture->remote_registry_count_on_finish =
            (uint32_t) socks5server_remote_map_t_size(&client_ls->udp_remote_lines);
    }
}

static void closeClientFromPrevPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    socks5server_close_fixture_t *fixture = *(socks5server_close_fixture_t **) tunnelGetState(t);

    twfRequire(l == fixture->client, "Socks5Server delivered the remote response on the wrong client line");
    ++fixture->client_payload_calls;
    lineReuseBuffer(l, buf);

    /* This is a legal local close by the client's previous-side owner. Its
     * upstream Finish re-enters Socks5Server, whose client teardown owns and
     * destroys every UDP remote before this callback returns. */
    socks5serverTunnelUpStreamFinish(fixture->server, l);
    twfRequire(lineIsAlive(l), "Socks5Server destroyed its borrowed UDP client line");
    lineDestroy(l);
}

static void illegalNextFinishDestroysRemote(tunnel_t *t, line_t *l)
{
    socks5server_close_fixture_t *fixture = *(socks5server_close_fixture_t **) tunnelGetState(t);

    twfRequire(l == fixture->remote, "Socks5Server finished the wrong UDP remote line");
    ++fixture->upstream_finish_calls;

    /* Deliberate invariant violation: next borrows this line and is forbidden
     * to destroy it. The owner close helper must diagnose this rather than
     * accepting the death as a normal re-entrant outcome. */
    lineDestroy(l);
}

static bool providerGetDynamicLineInfo(tunnel_t *t, const line_t *line, udplistener_dynamic_line_info_t *info_out)
{
    socks5server_close_fixture_t *fixture = *(socks5server_close_fixture_t **) tunnelGetState(t);

    if (line != fixture->client || ! lineIsAlive((line_t *) line))
    {
        return false;
    }

    *info_out = (udplistener_dynamic_line_info_t) {
        .handle           = {.owner_wid = 0, .generation = 1},
        .expected_wid     = 0,
        .generation       = 1,
        .bound_local_port = kSocks5ServerCloseListenerPort,
        .is_dynamic       = true,
    };
    return true;
}

static void providerCloseDynamicClient(tunnel_t *t, udplistener_dynamic_endpoint_handle_t handle)
{
    socks5server_close_fixture_t *fixture = *(socks5server_close_fixture_t **) tunnelGetState(t);

    twfRequire(udplistenerDynamicEndpointHandleEquals(
                   handle, (udplistener_dynamic_endpoint_handle_t) {.owner_wid = 0, .generation = 1}),
               "provider close received the wrong dynamic endpoint handle");
    twfRequire(! fixture->provider_closed, "provider closed the dynamic endpoint more than once");
    twfRequire(fixture->client != NULL && lineIsAlive(fixture->client), "provider close lost its UDP client line");

    fixture->provider_closed = true;
    ++fixture->provider_close_calls;

    /* This mirrors UdpListener's provider-owned line close: Socks5Server only
     * borrows the client line, then the provider makes it logically dead. */
    lineRef(fixture->client);
    socks5serverTunnelUpStreamFinish(fixture->server, fixture->client);
    twfRequire(lineIsAlive(fixture->client), "Socks5Server destroyed the provider-owned UDP client line");
    lineDestroy(fixture->client);
    lineUnref(fixture->client);
}

static void closeControlDuringRemoteInit(tunnel_t *t, line_t *l)
{
    socks5server_close_fixture_t *fixture = *(socks5server_close_fixture_t **) tunnelGetState(t);

    twfRequire(l != fixture->client, "remote Init received the UDP client line");
    fixture->remote = l;
    ++fixture->remote_init_calls;
    socks5serverCloseControlLineFromUpstream(fixture->server, fixture->control);
}

static void closeProviderDuringRemoteFinish(tunnel_t *t, line_t *l)
{
    socks5server_close_fixture_t *fixture = *(socks5server_close_fixture_t **) tunnelGetState(t);

    twfRequire(l == fixture->remote || l == fixture->remote_second,
               "client drain finished an unregistered UDP remote line");
    ++fixture->upstream_finish_calls;
    if (! fixture->provider_closed)
    {
        providerCloseDynamicClient(fixture->provider,
                                   (udplistener_dynamic_endpoint_handle_t) {.owner_wid = 0, .generation = 1});
    }
}

static void fixtureAttachSingleWorkerChain(socks5server_close_fixture_t *fixture)
{
    fixture->chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    twfRequire(fixture->chain != NULL, "failed to allocate Socks5Server test chain");
    fixture->chain->workers_count = 1;
    fixture->chain->line_pools[0] = fixture->lines.pools[0];
    fixture->server->chain        = fixture->chain;
}

static void fixtureInitializeAssociation(socks5server_close_fixture_t *fixture)
{
    const ip_addr_t client_ip = fixtureIpv4("192.0.2.10");
    const ip_addr_t remote_ip = fixtureIpv4("198.51.100.20");

    routing_context_t *client_route = lineGetRoutingContext(fixture->client);
    addresscontextSetIpPortProtocol(&client_route->src_ctx, &client_ip, kSocks5ServerCloseClientPort, IP_PROTO_UDP);
    client_route->peer_source_port    = kSocks5ServerCloseClientPort;
    client_route->local_listener_port = kSocks5ServerCloseListenerPort;

    if (fixture->remote != NULL)
    {
        addresscontextSetIpPortProtocol(
            lineGetDestinationAddressContext(fixture->remote), &remote_ip, kSocks5ServerCloseRemotePort, IP_PROTO_UDP);
    }

    socks5server_tstate_t *ts  = tunnelGetState(fixture->server);
    ts->workers_count          = 1;
    ts->worker_associations    = memoryAllocateZero(sizeof(socks5server_assoc_map_t));
    ts->worker_associations[0] = socks5server_assoc_map_t_init();
    fixture->assoc_initialized = true;

    socks5server_lstate_t *client_ls = lineGetState(fixture->client, fixture->server);
    socks5server_lstate_t *remote_ls = fixture->remote != NULL ? lineGetState(fixture->remote, fixture->server) : NULL;

    client_ls->dynamic_handle = (udplistener_dynamic_endpoint_handle_t) {.owner_wid = 0, .generation = 1};
    if (remote_ls != NULL)
    {
        remote_ls->dynamic_handle = client_ls->dynamic_handle;
    }

    socks5server_assoc_entry_t entry = {
        .generation     = 1,
        .owner_wid      = 0,
        .dynamic_handle = client_ls->dynamic_handle,
        .assigned_port  = kSocks5ServerCloseListenerPort,
        .user_handle    = userHandleEmpty(),
        .auth_username  = NULL,
        .auth_password  = NULL,
        .active         = true,
    };
    twfRequire(socks5server_assoc_map_t_insert(&ts->worker_associations[0], 1, entry).ref != NULL,
               "failed to insert the fixture UDP association");
}

static void fixtureSetup(socks5server_close_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kSocks5ServerCloseTestLargeBuffer, 0);

    fixture->prev   = tunnelCreate(NULL, sizeof(socks5server_close_fixture_t *), 0);
    fixture->server = tunnelCreate(NULL, sizeof(socks5server_tstate_t), sizeof(socks5server_lstate_t));
    fixture->next   = tunnelCreate(NULL, sizeof(socks5server_close_fixture_t *), 0);
    twfRequire(fixture->prev != NULL && fixture->server != NULL && fixture->next != NULL,
               "failed to create Socks5Server close fixture tunnels");

    *(socks5server_close_fixture_t **) tunnelGetState(fixture->prev) = fixture;
    fixture->prev->fnPayloadD                                        = closeClientFromPrevPayload;
    *(socks5server_close_fixture_t **) tunnelGetState(fixture->next) = fixture;
    fixture->next->fnFinU                                            = countNextFinish;
    tunnelBind(fixture->prev, fixture->server);
    tunnelBind(fixture->server, fixture->next);

    twfLinePoolSetup(&fixture->lines, fixture->server->lstate_size, kSocks5ServerCloseTestLinePoolCap);
    fixture->client = twfLinePoolCreateLine(&fixture->lines);
    fixture->remote = twfLinePoolCreateLine(&fixture->lines);

    socks5server_lstate_t *client_ls = lineGetState(fixture->client, fixture->server);
    socks5server_lstate_t *remote_ls = lineGetState(fixture->remote, fixture->server);
    socks5serverLinestateInitialize(client_ls, fixture->server, fixture->client, kSocks5ServerLineKindUdpClient);
    socks5serverLinestateInitialize(remote_ls, fixture->server, fixture->remote, kSocks5ServerLineKindUdpRemote);

    remote_ls->client_line          = fixture->client;
    remote_ls->client_line_ref_held = true;
    remote_ls->remote_key           = kSocks5ServerCloseRemoteKey;
    lineRef(fixture->client);
    twfRequire(
        socks5server_remote_map_t_insert(&client_ls->udp_remote_lines, remote_ls->remote_key, fixture->remote).ref !=
            NULL,
        "failed to register the fixture UDP remote");

    fixtureInitializeAssociation(fixture);
}

static void fixtureSetupRemoteInitClose(socks5server_close_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kSocks5ServerCloseTestLargeBuffer, 0);

    fixture->prev     = tunnelCreate(NULL, sizeof(socks5server_close_fixture_t *), 0);
    fixture->server   = tunnelCreate(NULL, sizeof(socks5server_tstate_t), sizeof(socks5server_lstate_t));
    fixture->next     = tunnelCreate(NULL, sizeof(socks5server_close_fixture_t *), 0);
    fixture->provider = tunnelCreate(NULL, sizeof(socks5server_close_fixture_t *), 0);
    twfRequire(fixture->prev != NULL && fixture->server != NULL && fixture->next != NULL && fixture->provider != NULL,
               "failed to create remote-Init close fixture tunnels");

    *(socks5server_close_fixture_t **) tunnelGetState(fixture->next)     = fixture;
    *(socks5server_close_fixture_t **) tunnelGetState(fixture->provider) = fixture;
    fixture->next->fnInitU                                               = closeControlDuringRemoteInit;
    fixture->next->fnFinU                                                = countNextFinish;
    tunnelBind(fixture->prev, fixture->server);
    tunnelBind(fixture->server, fixture->next);

    twfLinePoolSetup(&fixture->lines, fixture->server->lstate_size, kSocks5ServerCloseTestLinePoolCap);
    fixtureAttachSingleWorkerChain(fixture);
    fixture->client  = twfLinePoolCreateLine(&fixture->lines);
    fixture->control = twfLinePoolCreateLine(&fixture->lines);

    socks5serverLinestateInitialize(lineGetState(fixture->client, fixture->server),
                                    fixture->server,
                                    fixture->client,
                                    kSocks5ServerLineKindUdpClient);
    socks5serverLinestateInitialize(lineGetState(fixture->control, fixture->server),
                                    fixture->server,
                                    fixture->control,
                                    kSocks5ServerLineKindControlTcp);
    fixtureInitializeAssociation(fixture);

    socks5server_tstate_t *ts = tunnelGetState(fixture->server);
    ts->dynamic_provider      = (udplistener_dynamic_provider_t) {
             .instance      = fixture->provider,
             .close         = providerCloseDynamicClient,
             .get_line_info = providerGetDynamicLineInfo,
    };

    socks5server_lstate_t *client_ls  = lineGetState(fixture->client, fixture->server);
    socks5server_lstate_t *control_ls = lineGetState(fixture->control, fixture->server);
    client_ls->user_handle            = userHandleEmpty();
    control_ls->phase                 = kSocks5ServerPhaseUdpControl;
    control_ls->dynamic_handle        = client_ls->dynamic_handle;
}

static line_t *fixtureAddUdpRemote(socks5server_close_fixture_t *fixture, hash_t remote_key)
{
    line_t                *remote    = twfLinePoolCreateLine(&fixture->lines);
    socks5server_lstate_t *remote_ls = lineGetState(remote, fixture->server);
    socks5server_lstate_t *client_ls = lineGetState(fixture->client, fixture->server);
    socks5serverLinestateInitialize(remote_ls, fixture->server, remote, kSocks5ServerLineKindUdpRemote);
    remote_ls->client_line          = fixture->client;
    remote_ls->client_line_ref_held = true;
    remote_ls->remote_key           = remote_key;
    remote_ls->dynamic_handle       = client_ls->dynamic_handle;
    lineRef(fixture->client);
    twfRequire(socks5server_remote_map_t_insert(&client_ls->udp_remote_lines, remote_key, remote).ref != NULL,
               "failed to register a second fixture UDP remote");
    return remote;
}

static void fixtureTeardown(socks5server_close_fixture_t *fixture)
{
    if (fixture->remote_second != NULL)
    {
        socks5server_lstate_t *remote_ls = lineGetState(fixture->remote_second, fixture->server);
        socks5serverDetachRemoteFromClient(remote_ls);
        socks5serverLinestateDestroy(remote_ls);
        lineDestroy(fixture->remote_second);
        fixture->remote_second = NULL;
    }

    if (fixture->remote != NULL)
    {
        socks5server_lstate_t *remote_ls = lineGetState(fixture->remote, fixture->server);
        socks5serverDetachRemoteFromClient(remote_ls);
        socks5serverLinestateDestroy(remote_ls);
        lineDestroy(fixture->remote);
        fixture->remote = NULL;
    }

    if (fixture->client != NULL)
    {
        socks5serverLinestateDestroy(lineGetState(fixture->client, fixture->server));
        lineDestroy(fixture->client);
        fixture->client = NULL;
    }

    if (fixture->control != NULL)
    {
        socks5serverLinestateDestroy(lineGetState(fixture->control, fixture->server));
        lineDestroy(fixture->control);
        fixture->control = NULL;
    }

    if (fixture->assoc_initialized)
    {
        socks5server_tstate_t *ts = tunnelGetState(fixture->server);
        socks5server_assoc_map_t_drop(&ts->worker_associations[0]);
        memoryFree(ts->worker_associations);
        ts->worker_associations    = NULL;
        fixture->assoc_initialized = false;
    }

    if (fixture->chain != NULL)
    {
        fixture->server->chain = NULL;
        memoryFree(fixture->chain);
        fixture->chain = NULL;
    }

    twfLinePoolTeardown(&fixture->lines);
    if (fixture->provider != NULL)
    {
        tunnelDestroy(fixture->provider);
        fixture->provider = NULL;
    }
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->server);
    tunnelDestroy(fixture->prev);
    twfWorkerEnvTeardown(&fixture->env);
}

static void caseClientPayloadCloseDrainsCurrentRemoteSafely(void)
{
    twfSetCase("socks5server client Payload close safely drains the current UDP remote");
    tosResetProcessApi(true);

    socks5server_close_fixture_t fixture;
    fixtureSetup(&fixture);

    sbuf_t *payload = bufferpoolGetSmallBuffer(lineGetBufferPool(fixture.remote));
    sbufSetLength(payload, 1);
    sbufGetMutablePtr(payload)[0] = UINT8_C(0xA5);

    socks5serverTunnelDownStreamPayload(fixture.server, fixture.remote, payload);

    twfRequireEqualU32(fixture.client_payload_calls, 1, "the remote response did not reach the client owner");
    twfRequireEqualU32(fixture.upstream_finish_calls, 1, "nested client teardown did not finish the remote once");
    twfRequireEqualU32(fixture.upstream_finish_refcount,
                       3,
                       "the remote response frame did not retain its line across the client callback");
    twfRequireEqualU32(
        masterpoolGetCheckedOut(fixture.lines.master), 0, "nested client teardown retained a client or remote line");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    fixture.client = NULL;
    fixture.remote = NULL;
    fixtureTeardown(&fixture);
}

static void caseRemoteInitCanCloseProviderClientSafely(void)
{
    twfSetCase("socks5server remote Init can close the provider-owned UDP client safely");
    tosResetProcessApi(true);

    socks5server_close_fixture_t fixture;
    fixtureSetupRemoteInitClose(&fixture);

    const uint8_t first_datagram[] = {0x00, 0x00, 0x00, 0x01, 198, 51, 100, 20, 0x00, 0x35};
    sbuf_t       *payload          = bufferpoolGetSmallBuffer(lineGetBufferPool(fixture.client));
    sbufSetLength(payload, sizeof(first_datagram));
    memoryCopy(sbufGetMutablePtr(payload), first_datagram, sizeof(first_datagram));
    const uint32_t recycle_count_before = twfRecycleCount();

    twfRequire(! socks5serverHandleUdpClientPayload(
                   fixture.server, fixture.client, lineGetState(fixture.client, fixture.server), payload),
               "remote Init close must stop the first UDP datagram path");
    twfRequireEqualU32(fixture.remote_init_calls, 1, "the first datagram did not initialize one remote line");
    twfRequireEqualU32(fixture.provider_close_calls, 1, "the provider endpoint did not close exactly once");
    twfRequireEqualU32(fixture.upstream_finish_calls, 1, "the newly-created remote did not finish exactly once");
    twfRequireEqualU32(
        fixture.remote_registry_count_on_finish, 0, "remote Init close left the remote registered on the dead client");
    twfRequireEqualU32(twfRecycleCount(),
                       recycle_count_before + 1U,
                       "the pending first UDP datagram was not recycled exactly once through the captured pool");

    /* The handler's temporary client reference is now released, so both the
     * provider-owned client and Socks5Server-owned remote are fully reclaimed. */
    fixture.client = NULL;
    fixture.remote = NULL;
    lineDestroy(fixture.control);
    fixture.control = NULL;
    twfRequireEqualU32(masterpoolGetCheckedOut(fixture.lines.master),
                       0,
                       "remote Init close retained a client, remote, or control line reference");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();
    fixtureTeardown(&fixture);
}

static void caseMultiRemoteDrainStopsAfterProviderClose(void)
{
    twfSetCase("socks5server multi-remote client drain stops after provider close re-entry");
    tosResetProcessApi(true);

    socks5server_close_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.remote_second = fixtureAddUdpRemote(&fixture, kSocks5ServerCloseRemoteKey + 1U);
    fixture.provider      = tunnelCreate(NULL, sizeof(socks5server_close_fixture_t *), 0);
    twfRequire(fixture.provider != NULL, "failed to create a provider-close fixture tunnel");
    *(socks5server_close_fixture_t **) tunnelGetState(fixture.provider) = &fixture;

    socks5server_tstate_t *ts = tunnelGetState(fixture.server);
    ts->dynamic_provider      = (udplistener_dynamic_provider_t) {
             .instance = fixture.provider,
             .close    = providerCloseDynamicClient,
    };
    fixture.next->fnFinU = closeProviderDuringRemoteFinish;

    socks5serverCloseUdpClientLineFromUpstream(fixture.server, fixture.client);

    twfRequireEqualU32(fixture.provider_close_calls, 1, "nested provider close did not run exactly once");
    twfRequireEqualU32(fixture.upstream_finish_calls,
                       2,
                       "multi-remote drain did not finish each remote exactly once before observing client death");
    fixture.client        = NULL;
    fixture.remote        = NULL;
    fixture.remote_second = NULL;
    twfRequireEqualU32(masterpoolGetCheckedOut(fixture.lines.master),
                       0,
                       "multi-remote provider close retained a client or remote line");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();
    fixtureTeardown(&fixture);
}

static void caseInactiveAssociationReplyClosesOnlyItsRemote(void)
{
    twfSetCase("socks5server drops a late UDP remote reply after its association becomes inactive");
    tosResetProcessApi(true);

    socks5server_close_fixture_t fixture;
    fixtureSetup(&fixture);

    socks5server_tstate_t           *ts                    = tunnelGetState(fixture.server);
    const socks5server_assoc_entry_t unrelated_association = {
        .generation     = 2,
        .owner_wid      = 0,
        .dynamic_handle = {.owner_wid = 0, .generation = 2},
        .assigned_port  = kSocks5ServerCloseListenerPort + 1,
        .user_handle    = userHandleEmpty(),
        .active         = true,
    };
    twfRequire(socks5server_assoc_map_t_insert(&ts->worker_associations[0], 2, unrelated_association).inserted,
               "failed to install unrelated UDP association sentinel");

    socks5server_assoc_map_t_erase(&ts->worker_associations[0], 1);
    const uint32_t recycle_count_before = twfRecycleCount();
    sbuf_t        *payload              = bufferpoolGetSmallBuffer(lineGetBufferPool(fixture.remote));
    sbufSetLength(payload, 1);
    sbufGetMutablePtr(payload)[0] = UINT8_C(0x5A);
    socks5serverTunnelDownStreamPayload(fixture.server, fixture.remote, payload);

    twfRequireEqualU32(fixture.client_payload_calls,
                       0,
                       "late inactive-association reply emitted UDP client payload or touched its TCP control path");
    twfRequireEqualU32(fixture.upstream_finish_calls,
                       1,
                       "late inactive-association reply did not finish its Socks5Server-owned remote exactly once");
    twfRequireEqualU32(twfRecycleCount(),
                       recycle_count_before + 1U,
                       "late inactive-association reply buffer was not recycled exactly once");
    socks5server_lstate_t *client_ls = lineGetState(fixture.client, fixture.server);
    twfRequireEqualU32((uint32_t) socks5server_remote_map_t_size(&client_ls->udp_remote_lines),
                       0,
                       "late inactive-association reply left its remote registered on the client line");
    socks5server_assoc_map_t_iter unrelated = socks5server_assoc_map_t_find(&ts->worker_associations[0], 2);
    twfRequire(unrelated.ref != socks5server_assoc_map_t_end(&ts->worker_associations[0]).ref &&
                   unrelated.ref->second.active,
               "late inactive-association reply touched an unrelated live association");
    twfRequireEqualU32(masterpoolGetCheckedOut(fixture.lines.master),
                       1,
                       "late inactive-association reply retained or destroyed the wrong client/remote line");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    fixture.remote = NULL;
    fixtureTeardown(&fixture);
}

typedef enum illegal_remote_finish_case_e
{
    kIllegalRemoteFinishDirectClose,
    kIllegalRemoteFinishClientDrain,
} illegal_remote_finish_case_t;

static void illegalRemoteFinishBody(void *argument)
{
    const illegal_remote_finish_case_t close_case = (illegal_remote_finish_case_t) (uintptr_t) argument;

    socks5server_close_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.next->fnFinU = illegalNextFinishDestroysRemote;

    if (close_case == kIllegalRemoteFinishClientDrain)
    {
        socks5serverCloseUdpClientLineFromUpstream(fixture.server, fixture.client);
        return;
    }

    socks5serverCloseUdpRemoteLine(fixture.server, fixture.remote);
}

static void caseOwnerCloseRejectsNextLineDestruction(void)
{
    twfSetCase("socks5server UDP remote owner rejects next/upstream line destruction");
    tosResetProcessApi(true);

    tosRequireChildExit("next/upstream destruction during direct remote close",
                        illegalRemoteFinishBody,
                        (void *) (uintptr_t) kIllegalRemoteFinishDirectClose,
                        kTosChildDirectAbort);
    tosRequireChildExit("next/upstream destruction during client remote drain",
                        illegalRemoteFinishBody,
                        (void *) (uintptr_t) kIllegalRemoteFinishClientDrain,
                        kTosChildDirectAbort);

    tosResetProcessApi(true);
}

int main(void)
{
    caseClientPayloadCloseDrainsCurrentRemoteSafely();
    caseRemoteInitCanCloseProviderClientSafely();
    caseMultiRemoteDrainStopsAfterProviderClose();
    caseInactiveAssociationReplyClosesOnlyItsRemote();
    caseOwnerCloseRejectsNextLineDestruction();

    puts("socks5server_udp_close_reentrant_test: all cases passed");
    return 0;
}
