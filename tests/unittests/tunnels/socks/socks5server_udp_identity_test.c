/*
 * Covers: socks5server udp identity; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: spliceDatagrams, sendDatagram
 * Checks: Assertion labels include: private pipe population failed; remote capture overflow; remote parent
 * was not published before Init; UDP remote read preferences were not published before Init
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.socks5server_udp_identity_unit
 */
#include "Socks5Server/internal.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

static tunnel_t        *server, *prev, *next;
static tunnel_chain_t  *chain;
static twf_worker_env_t env;
static line_t          *client, *remotes[128], *expected;
static unsigned         created, delivered, finished;
static bool             rewrite_destination, fail_init, close_client_in_init, close_client_in_finish;
static bool             splice_input;
static const uint8_t   *active_wire;
static size_t           active_length;
static const uint8_t   *reply_bytes;
static size_t           reply_length;
static unsigned         replies;

static sbuf_t *spliceBytes(const void *data, size_t len, size_t prefix, bool headroom)
{
    twfRequire(prefix <= len && prefix <= 300 && (headroom || prefix == 0), "invalid splice fixture prefix");
    sbuf_t *b = headroom ? bufferpoolGetSpliceBuffer(env.pool) : twfTrackAcquired(sbufCreateSplice(0));
    twfRequire(b != NULL && (headroom || sbufSpliceInitPipe(b, 0) == 0), "private pipe allocation failed");
    const size_t body = len - prefix;
    if (body)
        twfRequire(write(sbufSpliceMetadata(b).pipefd[1], (const uint8_t *) data + prefix, body) == (ssize_t) body,
                   "private pipe population failed");
    b->capacity = b->l_pad + (uint32_t) body;
    sbufSetLength(b, (uint32_t) body);
    sbufShiftLeft(b, (uint32_t) prefix);
    if (prefix)
        sbufWrite(b, data, (uint32_t) prefix);
    return b;
}

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
    twfRequire(linePrefersOrdinaryReadUpstream(l) && linePrefersOrdinaryReadDownstream(l),
               "UDP remote read preferences were not published before Init");
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
    twfRequire(! sbufIsSplice(b), "UDP request body was not fully materialized");
    twfRequire(sbufGetLength(b) == 1 && *(const uint8_t *) sbufGetRawPtr(b) == 'X', "datagram body changed");
    ++delivered;
    lineReuseBuffer(l, b);
}
static void reply(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    twfRequire(l == client && ! sbufIsSplice(b), "UDP response did not use ordinary provider-client storage");
    twfRequire(sbufGetLength(b) == reply_length && memoryEqual(sbufGetRawPtr(b), reply_bytes, reply_length),
               "UDP response bytes changed");
    ++replies;
    lineReuseBuffer(l, b);
}
static void ownerFinish(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == client, "UDP provider finished the wrong line");
    lineDestroy(l);
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
    prev->fnPayloadD           = reply;
    prev->fnFinD               = ownerFinish;
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
    twfRequire(linePrefersOrdinaryReadUpstream(client) && linePrefersOrdinaryReadDownstream(client),
               "UDP provider-client read preferences were not published during Init");
    created = delivered = finished = 0;
    expected                       = NULL;
    rewrite_destination = fail_init = close_client_in_init = close_client_in_finish = false;
    splice_input                                                                    = false;
    replies                                                                         = 0;
    reply_bytes                                                                     = NULL;
    reply_length                                                                    = 0;
}
static void sendDatagram(const uint8_t *address, size_t length, line_t *remote)
{
    expected      = remote;
    active_wire   = address;
    active_length = length;
    uint8_t wire[kSocks5ServerUdpHeaderMaxLen + 1];
    twfRequire(length + 4 <= sizeof(wire), "datagram fixture overflow");
    uint8_t *p = wire;
    p[0] = p[1] = p[2] = 0;
    memoryCopy(p + 3, address, length);
    p[length + 3] = 'X';
    sbuf_t *b     = splice_input ? spliceBytes(wire, length + 4, 2, true) : bufferpoolGetSmallBuffer(env.pool);
    if (! splice_input)
    {
        sbufSetLength(b, (uint32_t) (length + 4));
        memoryCopy(sbufGetMutablePtr(b), wire, length + 4);
    }
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
static void spliceDatagrams(void)
{
    const uint8_t ipv4[] = {1, 127, 0, 0, 1, 0, 80};
    twfSetCase("splice UDP decode and ordinary response framing preserve full datagrams");
    setup();
    splice_input = true;
    sendDatagram(ipv4, sizeof(ipv4), NULL);
    sendDatagram(ipv4, sizeof(ipv4), remotes[0]);
    twfRequire(created == 1 && delivered == 2, "splice UDP decode changed destination identity");
    uint8_t body[3000], response[3 + sizeof(ipv4) + sizeof(body)] = {0};
    for (size_t i = 0; i < sizeof(body); ++i)
        body[i] = (uint8_t) i;
    memoryCopy(response + 3, ipv4, sizeof(ipv4));
    memoryCopy(response + 3 + sizeof(ipv4), body, sizeof(body));
    reply_bytes  = response;
    reply_length = sizeof(response);
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        sbuf_t *b;
        if (mode < 2)
            b = spliceBytes(body, sizeof(body), mode ? 0 : 17, mode == 0);
        else
        {
            b = twfTrackAcquired(sbufCreateWithPadding(sizeof(body), 0));
            sbufWrite(b, body, sizeof(body));
            sbufSetLength(b, sizeof(body));
        }
        socks5serverTunnelDownStreamPayload(server, remotes[0], b);
        twfRequire(replies == mode + 1, "UDP framed response was not delivered once");
    }
    teardown();
    twfSetCase("splice malformed UDP header closes and settles its private pipe");
    setup();
    const uint8_t invalid[] = {1, 0, 0, 1, 127, 0, 0, 1, 0, 80, 'X'};
    socks5serverTunnelUpStreamPayload(server, client, spliceBytes(invalid, sizeof(invalid), 0, true));
    twfRequire(created == 0 && delivered == 0, "malformed pipe backed datagram reached a backend");
    teardown();
    twfSetCase("splice UDP Init failure releases converted input");
    setup();
    splice_input = fail_init = true;
    sendDatagram(ipv4, sizeof(ipv4), NULL);
    twfRequire(created == 1 && ! lineIsAlive(remotes[0]) && delivered == 0,
               "splice UDP Init failure retained remote or forwarded payload");
    teardown();
}
int main(void)
{
    spliceDatagrams();
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
