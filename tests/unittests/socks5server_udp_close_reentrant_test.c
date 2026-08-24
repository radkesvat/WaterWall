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
    line_t          *client;
    line_t          *remote;
    uint32_t         client_payload_calls;
    uint32_t         upstream_finish_calls;
    uint32_t         upstream_finish_refcount;
    uint32_t         assoc_shard_index;
    bool             assoc_shard_initialized;
} socks5server_close_fixture_t;

static hash_t fixtureAssociationKey(const ip_addr_t *ip, uint16_t udp_port, uint16_t local_port)
{
    struct
    {
        uint16_t   listener_port;
        uint16_t   client_port;
        uint8_t    ip_type;
        uint8_t    padding[5];
        ip4_addr_t ip4;
        ip6_addr_t ip6;
    } key = {0};

    key.listener_port = local_port;
    key.client_port   = udp_port;
    key.ip_type       = ip->type;

    if (ip->type == IPADDR_TYPE_V4)
    {
        key.ip4 = ip->u_addr.ip4;
    }
    else
    {
        key.ip6 = ip->u_addr.ip6;
    }

    return calcHashBytes(&key, sizeof(key));
}

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

static void fixtureInitializeAssociation(socks5server_close_fixture_t *fixture)
{
    const ip_addr_t client_ip = fixtureIpv4("192.0.2.10");
    const ip_addr_t remote_ip = fixtureIpv4("198.51.100.20");

    routing_context_t *client_route = lineGetRoutingContext(fixture->client);
    addresscontextSetIpPortProtocol(&client_route->src_ctx, &client_ip, kSocks5ServerCloseClientPort, IP_PROTO_UDP);
    client_route->peer_source_port    = kSocks5ServerCloseClientPort;
    client_route->local_listener_port = kSocks5ServerCloseListenerPort;

    addresscontextSetIpPortProtocol(
        lineGetDestinationAddressContext(fixture->remote), &remote_ip, kSocks5ServerCloseRemotePort, IP_PROTO_UDP);

    const hash_t key = fixtureAssociationKey(&client_ip, kSocks5ServerCloseClientPort, kSocks5ServerCloseListenerPort);
    fixture->assoc_shard_index = (uint32_t) (key & (hash_t) (kSocks5ServerAssocShardCount - 1U));

    socks5server_tstate_t      *ts    = tunnelGetState(fixture->server);
    socks5server_assoc_shard_t *shard = &ts->assoc_shards[fixture->assoc_shard_index];
    shard->map                        = socks5server_assoc_map_t_init();
    twfRequire(rwlockTryInit(&shard->lock), "failed to initialize the fixture association lock");
    fixture->assoc_shard_initialized = true;
    twfRequire(socks5server_assoc_map_t_reserve(&shard->map, 1), "failed to reserve the fixture association map");

    socks5server_assoc_entry_t entry = {
        .token       = 1,
        .owner_wid   = 0,
        .user_handle = userHandleEmpty(),
    };
    twfRequire(socks5server_assoc_map_t_insert(&shard->map, key, entry).ref != NULL,
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

    remote_ls->client_line        = fixture->client;
    remote_ls->client_line_locked = true;
    remote_ls->remote_key         = kSocks5ServerCloseRemoteKey;
    lineLock(fixture->client);
    twfRequire(
        socks5server_remote_map_t_insert(&client_ls->udp_remote_lines, remote_ls->remote_key, fixture->remote).ref !=
            NULL,
        "failed to register the fixture UDP remote");

    fixtureInitializeAssociation(fixture);
}

static void fixtureTeardown(socks5server_close_fixture_t *fixture)
{
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

    if (fixture->assoc_shard_initialized)
    {
        socks5server_tstate_t      *ts    = tunnelGetState(fixture->server);
        socks5server_assoc_shard_t *shard = &ts->assoc_shards[fixture->assoc_shard_index];
        socks5server_assoc_map_t_drop(&shard->map);
        rwlockDestroy(&shard->lock);
        fixture->assoc_shard_initialized = false;
    }

    twfLinePoolTeardown(&fixture->lines);
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
    caseOwnerCloseRejectsNextLineDestruction();

    puts("socks5server_udp_close_reentrant_test: all cases passed");
    return 0;
}
