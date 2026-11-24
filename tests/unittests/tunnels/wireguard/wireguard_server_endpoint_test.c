/* Real server ingress capture and authenticated endpoint publication. The normal
 * lines belong to the fixture adapter; receive consumes every input buffer.
 * CTest: waterwall.wireguard_server_endpoint_unit */
#include "../../../../../tunnels/WireGuardServer/server.c"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/user_runtime.h"

typedef struct fifo_s
{
    sbuf_t  *packets[16];
    unsigned head, count;
} fifo_t;
static fifo_t   server_output, client_output;
static unsigned delivered_count;
static uint16_t output_port;
static bool     capture(fifo_t *queue, sbuf_t *packet)
{
    twfRequire(queue->count < 16, "endpoint fixture output overflow");
    queue->packets[(queue->head + queue->count++) % 16] = packet;
    return true;
}
static sbuf_t *take(fifo_t *queue)
{
    twfRequire(queue->count != 0, "missing endpoint fixture packet");
    sbuf_t *packet = queue->packets[queue->head];
    queue->head    = (queue->head + 1) % 16;
    --queue->count;
    return packet;
}
static bool clientCapture(void *context, sbuf_t *packet, wireguard_peer_t *peer, const ip_addr_t *ip, uint16_t port)
{
    discard context;
    discard peer;
    discard ip;
    discard port;
    return capture(&client_output, packet);
}
static bool serverCapture(void *context, sbuf_t *packet, wireguard_peer_t *peer, const ip_addr_t *ip, uint16_t port)
{
    server_t *state = context;
    discard   peer;
    twfRequire(ipAddrCmp(ip, &state->binding_head->ingress->ip), "server output lost its authenticated IP");
    output_port = port;
    return capture(&server_output, packet);
}
static void delivered(void *context, sbuf_t *packet, wireguard_peer_t *peer)
{
    discard context;
    discard peer;
    ++delivered_count;
    reuseBuffer(packet);
}
static void established(tunnel_t *owner, line_t *line)
{
    discard owner;
    discard line;
}
static void receiveOn(tunnel_t *server, line_t *line, sbuf_t *packet)
{
    server_line_t *ls       = lineGetState(line, server);
    receive_t      received = {.ingress = ls->ingress};
    receive(server, packet, &received);
}
static void exchange(tunnel_t *server, line_t *line, wireguard_device_t *client)
{
    ip_addr_t server_ip;
    twfRequire(ipaddr_aton("192.0.2.2", &server_ip), "invalid server IP");
    for (unsigned i = 0; i < 16 && (server_output.count != 0 || client_output.count != 0); ++i)
    {
        while (client_output.count != 0)
            receiveOn(server, line, take(&client_output));
        while (server_output.count != 0)
            wireguardCommonReceive(client, take(&server_output), &server_ip, 26951);
    }
    twfRequire(server_output.count == 0 && client_output.count == 0, "endpoint exchange did not settle");
}
static sbuf_t *innerPacket(buffer_pool_t *pool, size_t capacity, uint8_t source, uint8_t destination)
{
    sbuf_t *packet = bufferpoolGetBestFit(pool, capacity, 32);
    sbufSetLength(packet, 20);
    sbufWriteZeros(packet, 20);
    uint8_t *bytes = sbufGetMutablePtr(packet);
    bytes[0]       = 0x45;
    bytes[3]       = 20;
    bytes[8]       = 64;
    bytes[9]       = 253;
    bytes[12]      = 10;
    bytes[15]      = source;
    bytes[16]      = 10;
    bytes[19]      = destination;
    return packet;
}
static void testPendingOnCarrierLoss(server_t *state, line_t *line, buffer_pool_t *pool, wireguard_device_t *client)
{
    wireguard_peer_t *peer            = state->engine.first_peer;
    peer->curr_keypair.keypair_millis = getTickMS() - REJECT_AFTER_TIME * 1000U;
    wtimer_t timer                    = {0};
    weventSetUserData(&timer, state);
    getCurrentWorkerLoop()->cur_hrtime = (uint64_t) (getTickMS() - 30000U) * 1000U;
    sbuf_t *oversized                  = innerPacket(pool, 256 * 1024, 2, 1);
    wireguardCommonSendInner(&state->engine, oversized);
    tick(&timer);
    twfRequire(server_output.count == 1 && ! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, oversized),
               "oversized buffer failed to wake the peer or exceeded the retention budget");
    /* Leave the initiation queued until its answer can release a held packet. */
    const uint32_t before  = getTickMS();
    sbuf_t        *pending = innerPacket(pool, 20, 2, 1);
    wireguardCommonSendInner(&state->engine, pending);
    binding_t *binding = state->binding_head;
    twfRequire(binding->pending == pending && binding->pending_since - before <= getTickMS() - before,
               "stale loop time shortened the lifetime of a newly held packet");

    binding->pending_since = getTickMS() - REKEY_ATTEMPT_TIME * 1000U;
    sbuf_t *replacement    = innerPacket(pool, 20, 2, 1);
    wireguardCommonSendInner(&state->engine, replacement);
    twfRequire(binding->pending == replacement &&
                   ! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, pending),
               "stale loop time kept an expired packet in the slot during fresh admission");

    binding->pending_since    = getTickMS() - REKEY_ATTEMPT_TIME * 1000U;
    const unsigned deliveries = delivered_count;
    client->callbacks.inner   = delivered;
    exchange(state->tunnel, line, client);
    twfRequire(wireguardCommonPeerCanSend(peer) && delivered_count == deliveries && binding->pending == NULL &&
                   ! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, replacement),
               "a fresh key released expired plaintext while the loop clock lagged");

    /* Model the interval after the sweep selected a ready packet and before final encryption. */
    pending = innerPacket(pool, 20, 2, 1);
    sendHeldInner(state, pending, binding->epoch, getTickMS() - REKEY_ATTEMPT_TIME * 1000U);
    twfRequire(server_output.count == 0 && ! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, pending),
               "final release sent plaintext after its deadline");
    peer->curr_keypair.keypair_millis = getTickMS() - REJECT_AFTER_TIME * 1000U;
    const uint32_t original_since     = getTickMS() - 10000U;
    pending                           = innerPacket(pool, 20, 2, 1);
    sendHeldInner(state, pending, binding->epoch, original_since);
    twfRequire(binding->pending == pending && binding->pending_since == original_since,
               "losing the key during release restarted the packet's retention deadline");
    finishUp(state->tunnel, line);
    peer->last_initiation_tx -= (REKEY_TIMEOUT + 1) * 1000U;
    tick(&timer);
    twfRequire(! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, pending),
               "closed ingress retained its pending packet");
    sbuf_t *late = innerPacket(pool, 20, 2, 1);
    wireguardCommonSendInner(&state->engine, late);
    twfRequire(! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, late) && server_output.count == 0,
               "closed ingress admitted new recovery work");
}

static void requireEndpoint(server_t *state, line_t *line, uint16_t port, const char *message)
{
    server_line_t *ls = lineGetState(line, state->tunnel);
    twfRequire(state->binding_head->ingress == ls->ingress && state->binding_head->usable &&
                   state->engine.first_peer->port == port && ipAddrCmp(&state->engine.first_peer->ip, &ls->ingress->ip),
               message);
}
static void addStaticPeer(cJSON *peers, unsigned id, const char *ranges)
{
    const uint8_t basepoint[32] = {9};
    uint8_t       secret[32]    = {0}, public_key[32];
    secret[1]                   = (uint8_t) id;
    secret[2]                   = (uint8_t) (id >> 8U);
    char encoded[45]            = {0};
    twfRequire(wCryptoX25519(public_key, secret, basepoint) == kWCryptoOk &&
                   wwBase64Encode(public_key, sizeof(public_key), encoded) == 44,
               "could not derive static peer key");
    cJSON *peer = cJSON_CreateObject();
    cJSON_AddStringToObject(peer, "publickey", encoded);
    cJSON_AddStringToObject(peer, "allowedips", ranges);
    cJSON_AddItemToArray(peers, peer);
}

static void testStaticPeerConfiguration(void)
{
    cJSON *settings = cJSON_CreateObject();
    cJSON_AddStringToObject(settings, "mode", "packet");
    cJSON_AddStringToObject(settings, "privatekey", "EBJOHctLU2w8uteyTE+WU0hruB09Ub0vwVS+Gt9wAls=");
    cJSON *peers = cJSON_AddArrayToObject(settings, "peers");
    for (unsigned i = 0; i < 256; ++i)
    {
        char range[32];
        snprintf(range, sizeof(range), "10.70.0.%u/32", i);
        addStaticPeer(peers, i, range);
    }
    addStaticPeer(peers, 256, "10.70.1.0/31,10.70.1.1/32,198.51.100.0/24,2001:db8::/64");
    node_t    node   = {.hash_next = 1, .node_settings_json = settings};
    tunnel_t *server = create(&node);
    twfRequire(server != NULL, "disjoint static peers or nested ranges of one peer were rejected");
    server_t         *state = tunnelGetState(server);
    wireguard_peer_t *last  = peerLookupByPeerIndex(&state->engine, 256);
    twfRequire(last != NULL && last->context != NULL && state->engine.peer_count == 257,
               "high-index static peer has no binding");
    const char *targets[] = {"10.70.1.0", "10.70.1.1", "198.51.100.42", "2001:db8::1"};
    for (unsigned i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i)
    {
        ip_addr_t target;
        twfRequire(ipaddr_aton(targets[i], &target) && wireguardCommonPeerForIp(&state->engine, &target) == last,
                   "static route did not select its high-index owner");
    }
    destroy(server, wwLifecycleStartupRollback());
    /* The last range overlaps an existing owner after the first range was inserted. */
    addStaticPeer(peers, 257, "203.0.113.128/25,10.70.1.0/24");
    twfRequire(create(&node) == NULL, "overlapping static peers survived constructor rollback");
    cJSON_Delete(settings);
}

static void testServerLimits(void)
{
    server_t state = {0};
    twfRequire(readServerLimits(&state, NULL) && state.max_unauthenticated_ingress == 1024 &&
                   state.max_pending_rekey_bytes == 4U * 1024U * 1024U,
               "server budget defaults changed");
    cJSON *settings = cJSON_Parse("{\"max-unauthenticated-ingress\":1,\"max-pending-rekey-bytes\":0}");
    twfRequire(settings != NULL && readServerLimits(&state, settings) && state.max_unauthenticated_ingress == 1 &&
                   state.max_pending_rekey_bytes == 0,
               "server ignored configured ingress or zero pending budget");
    cJSON_Delete(settings);
    const char *invalid[] = {"{\"max-unauthenticated-ingress\":0}",
                             "{\"max-unauthenticated-ingress\":1.5}",
                             "{\"max-pending-rekey-bytes\":-1}",
                             "{\"max-pending-rekey-bytes\":4294967296}"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i)
    {
        settings = cJSON_Parse(invalid[i]);
        twfRequire(settings != NULL && ! readServerLimits(&state, settings), "invalid server budget was accepted");
        cJSON_Delete(settings);
    }
}

int main(void)
{
    testServerLimits();
    testCaseSet("wireguard_server_endpoint_test");
    twfRequire(userTestRuntimeInitialize(), "crypto setup failed");
    twfRequire(createNetworkLogger(NULL, false) != NULL, "logger setup failed");
    twf_worker_env_t environment;
    twfWorkerEnvSetup(&environment, 8192, 32);
    testStaticPeerConfiguration();
    tunnel_t *owner  = tunnelCreate(NULL, 0, 0);
    owner->fnEstD    = established;
    tunnel_t *server = tunnelCreate(NULL, sizeof(server_t), sizeof(server_line_t));
    tunnelBind(owner, server);
    tunnel_chain_t *chain = tunnelchainCreate(1);
    server->chain         = chain;
    server_t *state       = tunnelGetState(server);
    state->tunnel         = server;
    mutexInit(&state->bindings_lock);
    wireguardDispatchInit(&state->dispatch);
    twfRequire(readServerLimits(state, NULL), "server default limits failed");
    state->ingress_heads      = memoryAllocateZero(sizeof(ingress_t *));
    wireguard_device_t client = {0};
    twfRequire(wireguardCommonInit(&client,
                                   "0MHoX6RogAEFxKF7c5E84tA1Qy3l9u8IzJfgcVt4B2Y=",
                                   NULL,
                                   (wireguard_callbacks_t) {.output = clientCapture}) &&
                   wireguardCommonInit(&state->engine,
                                       "EBJOHctLU2w8uteyTE+WU0hruB09Ub0vwVS+Gt9wAls=",
                                       state,
                                       (wireguard_callbacks_t) {.output          = serverCapture,
                                                                .inner           = delivered,
                                                                .authenticated   = authenticated,
                                                                .can_initiate    = canInitiate,
                                                                .key_unavailable = keyUnavailable}),
               "engine setup failed");
    cJSON *client_peer =
        cJSON_Parse("{\"publickey\":\"GnRcOavdc180YrXak138cZxWlMoEUZL0Mg/ZyWhLBgo=\",\"allowedips\":\"0.0.0.0/0\"}");
    cJSON *server_peer =
        cJSON_Parse("{\"publickey\":\"dDUfRvZSDy8jZBsB4kQflTO+iwlLbR+jgb840fumqUM=\",\"allowedips\":\"10.0.0.1/32\"}");
    size_t index;
    twfRequire(wireguardCommonAddConfiguredPeer(&client, client_peer, &index) &&
                   wireguardCommonAddConfiguredPeer(&state->engine, server_peer, &index),
               "peer setup failed");
    cJSON_Delete(client_peer);
    cJSON_Delete(server_peer);
    twfRequire(createBinding(state, peerLookupByPeerIndex(&state->engine, index), NULL) != NULL,
               "server peer binding failed");
    sbuf_t *unbound = innerPacket(environment.pool, 20, 2, 1);
    wireguardCommonSendInner(&state->engine, unbound);
    wireguardCommonLoop(&state->engine);
    twfRequire(! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, unbound) && server_output.count == 0,
               "unproven static peer admitted outbound recovery work");
    twf_line_pool_t pool;
    twfLinePoolSetup(&pool, server->lstate_size, 4);
    line_t *lines[2];
    for (unsigned i = 0; i < 2; ++i)
    {
        lines[i] = twfLinePoolCreateLine(&pool);
        lineRef(lines[i]);
        addresscontextSetIpAddressPortProtocol(lineGetSourceAddressContext(lines[i]), "192.0.2.1", 26951, 17);
        lineGetRoutingContext(lines[i])->peer_source_port = (uint16_t) (26960 + i);
        addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(lines[i]), IP_PROTO_UDP);
        initUp(server, lines[i]);
        server_line_t *ls = lineGetState(lines[i], server);
        twfRequire(ls->ingress != NULL && ls->ingress->port == 26960 + i,
                   "ingress used the local listener port instead of the remote source port");
    }
    twfRequire(wireguardifStartHandshake(&client, client.first_peer, true) == ERR_OK, "initiation failed");
    receiveOn(server, lines[0], take(&client_output));
    requireEndpoint(state, lines[0], 26960, "authenticated initiation learned the wrong endpoint");
    /* A valid cookie can cause an exact response retry, but cannot authorize the
     * different ingress from which it arrived. */
    wireguard_peer_t      *peer = state->engine.first_peer;
    message_cookie_reply_t cookie;
    uint8_t                source[6] = {192, 0, 2, 2, 0x69, 0x47};
    twfRequire(
        peer->pending_handshake.valid &&
            wireguardCreateCookieReply(
                &client, &cookie, peer->pending_handshake.mac1, peer->pending_handshake.sender, source, sizeof(source)),
        "valid response cookie setup failed");
    sbuf_t *cookie_packet = bufferpoolGetSmallBuffer(environment.pool);
    sbufSetLength(cookie_packet, sizeof(cookie));
    sbufWrite(cookie_packet, &cookie, sizeof(cookie));
    receiveOn(server, lines[1], cookie_packet);
    twfRequire(server_output.count == 2 && output_port == 26960, "valid cookie did not retry on original endpoint");
    requireEndpoint(state, lines[0], 26960, "cookie alone roamed the server binding");
    exchange(server, lines[0], &client);
    wireguardCommonSendInner(&client, innerPacket(environment.pool, 20, 1, 2));
    sbuf_t *packet = take(&client_output);
    sbuf_t *replay = sbufDuplicate(packet);
    receiveOn(server, lines[0], packet);
    twfRequire(delivered_count == 1, "authenticated packet was not delivered");
    receiveOn(server, lines[1], replay);
    requireEndpoint(state, lines[0], 26960, "replay roamed the server binding");
    twfRequire(delivered_count == 1, "replay published a packet");
    wireguardCommonSendInner(&client, innerPacket(environment.pool, 20, 1, 2));
    packet      = take(&client_output);
    sbuf_t *bad = sbufDuplicate(packet);
    sbufGetMutablePtr(bad)[sbufGetLength(bad) - 1] ^= 1;
    receiveOn(server, lines[1], bad);
    requireEndpoint(state, lines[0], 26960, "invalid authentication roamed the server binding");
    twfRequire(delivered_count == 1, "invalid authentication published a packet");
    receiveOn(server, lines[1], packet);
    requireEndpoint(state, lines[1], 26961, "fresh authenticated data failed source-port roaming");
    twfRequire(delivered_count == 2, "roaming packet was not delivered");
    wireguardifSendKeepalive(&state->engine, peer);
    twfRequire(output_port == 26961, "reply metadata retained the previous source port");
    exchange(server, lines[1], &client);
    testPendingOnCarrierLoss(state, lines[1], environment.pool, &client);
    clearBinding(state, state->binding_head);
    finishUp(server, lines[0]);
    for (unsigned i = 0; i < 2; ++i)
    {
        lineDestroy(lines[i]);
        lineUnref(lines[i]);
    }
    twfRequire(atomic_load(&state->ingress_count) == 0 && state->ingress_heads[0] == NULL,
               "borrowed ingress references did not settle");
    twfLinePoolTeardown(&pool);
    wireguardDeviceDestroy(&client);
    binding_map_t_drop(&state->epochs);
    wireguardPrefixDestroy(&state->ranges);
    wireguardDeviceDestroy(&state->engine);
    memoryFree(state->ingress_heads);
    mutexDestroy(&state->bindings_lock);
    memoryFree(chain);
    tunnelDestroy(server);
    tunnelDestroy(owner);
    twfWorkerEnvTeardown(&environment);
    networkloggerDestroy();
    userTestRuntimeCleanup();
    return 0;
}
