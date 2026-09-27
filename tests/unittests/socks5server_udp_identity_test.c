#include "Socks5Server/internal.h"
#include "tunnel_line_failure_harness.h"

static tunnel_t        *server, *prev, *next;
static tunnel_chain_t  *chain;
static twf_worker_env_t env;
static line_t          *client, *remotes[128], *expected;
static unsigned         created, delivered, finished;
static bool             rewrite_destination, fail_init, close_client_in_init, close_client_in_finish;
static const uint8_t   *active_wire;
static size_t           active_length;

static void closeClient(void)
{
    socks5serverTunnelUpStreamFinish(server, client);
    lineDestroy(client);
}
static void initNext(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(created < 128, "remote capture overflow");
    remotes[created++] = l;
    lineRef(l);
    socks5server_lstate_t *ls = lineGetState(l, server);
    socks5_address_t       original;
    twfRequire(socks5AddressDecode(active_wire, active_length, &original) == kSocks5AddressComplete, "fixture vector");
    twfRequire(ls->client_line == client && ls->client_line_ref_held, "remote parent was not published before Init");
    twfRequire(ls->remote_key && ls->remote_key->address.kind == original.kind &&
                   ls->remote_key->address.port == original.port && ls->remote_key->address.length == original.length &&
                   memoryEqual(ls->remote_key->address.bytes, original.bytes, original.length),
               "immutable identity not published before Init");
    socks5server_lstate_t                 *parent = lineGetState(client, server);
    const socks5server_remote_map_t_value *entry =
        socks5server_remote_map_t_get(&parent->udp_remote_lines, ls->remote_key);
    twfRequire(entry && entry->second == l, "remote registry missing before Init");
    if (rewrite_destination)
        addresscontextSetIpAddressPort(lineGetDestinationAddressContext(l), "203.0.113.9", 444);
    if (fail_init)
        socks5serverTunnelDownStreamFinish(server, l);
    else if (close_client_in_init)
        closeClient();
}
static void payload(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    twfRequire(l == (expected ? expected : remotes[created - 1]), "datagram selected wrong colliding destination");
    twfRequire(sbufGetLength(b) == 1 && *(const uint8_t *) sbufGetRawPtr(b) == 'X', "datagram body changed");
    ++delivered;
    lineReuseBuffer(l, b);
}
static void finishNext(tunnel_t *t, line_t *l)
{
    discard                t;
    socks5server_lstate_t *ls = lineGetState(l, server);
    twfRequire(ls->kind == kSocks5ServerLineKindNone, "remote state was not destroyed before Finish");
    ++finished;
    if (close_client_in_finish && lineIsAlive(client))
    {
        close_client_in_finish = false;
        closeClient();
    }
}
static bool lineInfo(tunnel_t *t, const line_t *l, udplistener_dynamic_line_info_t *out)
{
    discard t;
    discard l;
    *out = (udplistener_dynamic_line_info_t) {.is_dynamic       = true,
                                              .expected_wid     = 0,
                                              .generation       = 1,
                                              .handle           = {.owner_wid = 0, .generation = 1},
                                              .bound_local_port = 1080};
    return true;
}
static void setup(void)
{
    twfWorkerEnvSetup(&env, 8192, 300);
    server = tunnelCreate(NULL, sizeof(socks5server_tstate_t), sizeof(socks5server_lstate_t));
    prev   = tunnelCreate(NULL, 0, 0);
    next   = tunnelCreate(NULL, 0, 0);
    tunnelBind(prev, server);
    tunnelBind(server, next);
    next->fnInitU              = initNext;
    next->fnPayloadU           = payload;
    next->fnFinU               = finishNext;
    chain                      = tunnelchainCreate(1);
    chain->sum_line_state_size = server->lstate_size;
    tunnelchainFinalize(chain);
    server->chain = chain;
    client        = lineCreate(tunnelchainGetLinePools(chain), 0);
    lineRef(client);
    addresscontextSetIpAddressPort(lineGetSourceAddressContext(client), "127.0.0.1", 1234);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(client), IP_PROTO_UDP);
    lineGetRoutingContext(client)->local_listener_port = 1080;
    socks5server_tstate_t *ts                          = tunnelGetState(server);
    ts->workers_count                                  = 1;
    ts->worker_associations                            = memoryAllocateZero(sizeof(*ts->worker_associations));
    ts->dynamic_provider             = (udplistener_dynamic_provider_t) {.instance = prev, .get_line_info = lineInfo};
    socks5server_assoc_entry_t entry = {.generation     = 1,
                                        .owner_wid      = 0,
                                        .dynamic_handle = {.owner_wid = 0, .generation = 1},
                                        .assigned_port  = 1080,
                                        .active         = true};
    twfRequire(socks5server_assoc_map_t_insert(ts->worker_associations, 1, entry).inserted, "fixture association");
    socks5serverTunnelUpStreamInit(server, client);
    created = delivered = finished = 0;
    expected                       = NULL;
    rewrite_destination = fail_init = close_client_in_init = close_client_in_finish = false;
}
static void sendDatagram(const uint8_t *address, size_t length, line_t *remote)
{
    expected      = remote;
    active_wire   = address;
    active_length = length;
    sbuf_t *b     = bufferpoolGetSmallBuffer(env.pool);
    sbufSetLength(b, (uint32_t) (length + 4));
    uint8_t *p = sbufGetMutablePtr(b);
    p[0] = p[1] = p[2] = 0;
    memoryCopy(p + 3, address, length);
    p[length + 3] = 'X';
    socks5serverTunnelUpStreamPayload(server, client, b);
}
static void teardown(void)
{
    if (lineIsAlive(client))
        closeClient();
    for (unsigned i = 0; i < created; ++i)
    {
        twfRequire(! lineIsAlive(remotes[i]) && twfLineRefCount(remotes[i]) == 1,
                   "remote death/reference settlement failed");
        lineUnref(remotes[i]);
    }
    twfRequire(twfLineRefCount(client) == 1, "parent reference leak");
    lineUnref(client);
    socks5server_tstate_t *ts = tunnelGetState(server);
    socks5server_assoc_map_t_drop(ts->worker_associations);
    memoryFree(ts->worker_associations);
    tunnelchainDestroy(chain);
    tunnelDestroy(server);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    twfWorkerEnvTeardown(&env);
}
int main(void)
{
    const uint8_t ipv4[]      = {1, 127, 0, 0, 1, 0, 80};
    const uint8_t ipv6[]      = {4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80};
    const uint8_t domain_ip[] = {3, 9, '1', '2', '7', '.', '0', '.', '0', '.', '1', 0, 80};
    const uint8_t domain_a[] = {3, 1, 'a', 0, 80}, domain_A[] = {3, 1, 'A', 0, 80},
                  domain_ab[] = {3, 2, 'a', 'b', 0, 80};
    const uint8_t *vectors[]  = {ipv4, ipv6, domain_ip, domain_a, domain_A, domain_ab};
    const size_t   lengths[]  = {
        sizeof(ipv4), sizeof(ipv6), sizeof(domain_ip), sizeof(domain_a), sizeof(domain_A), sizeof(domain_ab)};
    twfSetCase("constant-hash actual map: full identity, rewriting, rehash and exact erase");
    setup();
    rewrite_destination = true;
    for (unsigned i = 0; i < 6; ++i)
        sendDatagram(vectors[i], lengths[i], NULL);
    twfRequire(created == 6 && delivered == 6, "distinct colliding identities reused a backend");
    for (unsigned i = 0; i < 6; ++i)
        sendDatagram(vectors[i], lengths[i], remotes[i]);
    twfRequire(created == 6, "rewritten destinations lost original lookup identity");
    for (unsigned i = 0; i < 40; ++i)
    {
        uint8_t wire[7] = {1, 127, 0, 0, 1, 1, (uint8_t) i};
        sendDatagram(wire, sizeof(wire), NULL);
    }
    twfRequire(created == 46, "map growth or port identity failed");
    socks5serverCloseUdpRemoteLine(server, remotes[0]);
    socks5server_lstate_t *parent = lineGetState(client, server);
    twfRequire(socks5server_remote_map_t_size(&parent->udp_remote_lines) == 45,
               "exact erase removed sibling collision");
    for (unsigned i = 1; i < 6; ++i)
        sendDatagram(vectors[i], lengths[i], remotes[i]);
    sendDatagram(ipv4, sizeof(ipv4), NULL);
    twfRequire(created == 47, "closed identity did not recreate");
    uint8_t long_domain[259] = {3, 255};
    memset(long_domain + 2, 'd', 255);
    long_domain[257] = 0;
    long_domain[258] = 80;
    sendDatagram(long_domain, sizeof(long_domain), NULL);
    line_t *long_remote = remotes[created - 1];
    sendDatagram(long_domain, sizeof(long_domain), long_remote);
    long_domain[256] = 'e';
    sendDatagram(long_domain, sizeof(long_domain), NULL);
    twfRequire(created == 49, "maximum domain identity was truncated");
    teardown();
    twfSetCase("constant-hash synchronous Init failure detaches only its full key");
    setup();
    sendDatagram(domain_a, sizeof(domain_a), NULL);
    fail_init = true;
    sendDatagram(domain_A, sizeof(domain_A), NULL);
    fail_init = false;
    twfRequire(created == 2 && ! lineIsAlive(remotes[1]) && delivered == 1,
               "Init failure retained remote or delivered body");
    sendDatagram(domain_a, sizeof(domain_a), remotes[0]);
    teardown();
    twfSetCase("constant-hash endpoint close during Init");
    setup();
    sendDatagram(ipv4, sizeof(ipv4), NULL);
    close_client_in_init = true;
    sendDatagram(domain_a, sizeof(domain_a), NULL);
    twfRequire(! lineIsAlive(client) && delivered == 1, "Init endpoint close forwarded after death");
    teardown();
    twfSetCase("constant-hash endpoint close reenters owner drain");
    setup();
    sendDatagram(ipv4, sizeof(ipv4), NULL);
    sendDatagram(domain_a, sizeof(domain_a), NULL);
    close_client_in_finish = true;
    socks5serverRejectUdpClientLine(server, client);
    twfRequire(! lineIsAlive(client) && finished == 2, "nested provider close duplicated or lost remote cleanup");
    teardown();
    puts("SOCKS5 UDP identity collision tests passed");
    return 0;
}
