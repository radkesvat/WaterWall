/* Two real engines: handshake, packets, full-width replay, roaming, and fixed
 * protocol timers. A wrapped monotonic clock avoids real-time waits.
 * CTest: waterwall.wireguard_protocol_unit */
#include "WireGuardCommon/engine.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/user_runtime.h"
#include "loggers/network_logger.h"

static uint32_t now_millis;
static bool     under_load;

unsigned int __wrap_getTickMS(void);
unsigned int __wrap_getTickMS(void)
{
    return now_millis;
}

bool __wrap_isSystemUnderLoad(double threshold);
bool __wrap_isSystemUnderLoad(double threshold)
{
    discard threshold;
    return under_load;
}

typedef struct endpoint_s
{
    wireguard_device_t engine;
    sbuf_t            *packets[64];
    unsigned           head, count, delivered;
    unsigned           cookie_replies, authenticated;
    sbuf_t            *replay;
    ip_addr_t          ip;
    uint64_t           carrier_id;
} endpoint_t;
static bool capture(void *context, sbuf_t *packet, wireguard_peer_t *peer, const ip_addr_t *ip, uint16_t port)
{
    discard     peer;
    endpoint_t *endpoint = context;
    twfRequire(endpoint->count < 64, "protocol fixture output queue overflow");
    endpoint->packets[(endpoint->head + endpoint->count++) % 64] = packet;
    const uint8_t type = wireguardGetMessageType(sbufGetRawPtr(packet), sbufGetLength(packet));
    if (type == MESSAGE_COOKIE_REPLY)
    {
        ++endpoint->cookie_replies;
        if (endpoint->carrier_id != 0)
            twfRequire(ip == NULL && port == 0, "carrier cookie reply invented a network endpoint");
        else
            twfRequire(ip != NULL && port == 51820, "network cookie reply lost its source endpoint");
    }
    if (type == MESSAGE_TRANSPORT_DATA && sbufGetLength(packet) > 32 && endpoint->replay == NULL)
        endpoint->replay = sbufDuplicate(packet);
    return true;
}
static bool authenticated(void *context, wireguard_peer_t *peer)
{
    discard peer;
    ++((endpoint_t *) context)->authenticated;
    return true;
}
static void delivered(void *context, sbuf_t *packet, wireguard_peer_t *peer)
{
    discard     peer;
    endpoint_t *endpoint = context;
    twfRequire(sbufGetLength(packet) == 20, "decoded packet length differs from IPv4 length");
    ++endpoint->delivered;
    reuseBuffer(packet);
}
static void drain(endpoint_t *from, endpoint_t *to)
{
    while (from->count > 0)
    {
        sbuf_t *packet = from->packets[from->head];
        from->head     = (from->head + 1U) % 64U;
        --from->count;
        if (to->carrier_id != 0)
            wireguardCommonReceiveOnCarrier(&to->engine, packet, to->carrier_id);
        else
            wireguardCommonReceive(&to->engine, packet, &from->ip, 51820);
    }
}
static void exchange(endpoint_t *a, endpoint_t *b)
{
    for (unsigned i = 0; i < 16 && (a->count != 0 || b->count != 0); ++i)
    {
        drain(a, b);
        drain(b, a);
    }
    twfRequire(a->count == 0 && b->count == 0, "protocol exchange did not settle");
}
static sbuf_t *innerPacket(buffer_pool_t *pool, uint8_t source, uint8_t destination)
{
    sbuf_t *packet = bufferpoolGetSmallBuffer(pool);
    sbufSetLength(packet, 20);
    sbufWriteZeros(packet, 20);
    uint8_t *bytes = sbufGetMutablePtr(packet);
    bytes[0]       = 0x45;
    bytes[3]       = 20;
    bytes[8]       = 64;
    bytes[9]       = 253;
    bytes[12]      = 10;
    bytes[13]      = 1;
    bytes[15]      = source;
    bytes[16]      = 10;
    bytes[17]      = 1;
    bytes[19]      = destination;
    return packet;
}
static void setupEndpoints(endpoint_t *client, endpoint_t *server)
{
    twfRequire(ipaddr_aton("192.0.2.1", &client->ip) && ipaddr_aton("192.0.2.2", &server->ip), "endpoint parse failed");
    wireguard_callbacks_t callbacks = {.output = capture, .inner = delivered, .authenticated = authenticated};
    twfRequire(
        wireguardCommonInit(&client->engine, "0MHoX6RogAEFxKF7c5E84tA1Qy3l9u8IzJfgcVt4B2Y=", client, callbacks) &&
            wireguardCommonInit(&server->engine, "EBJOHctLU2w8uteyTE+WU0hruB09Ub0vwVS+Gt9wAls=", server, callbacks),
        "engine initialization failed");
    cJSON *client_peer =
        cJSON_Parse("{\"publickey\":\"GnRcOavdc180YrXak138cZxWlMoEUZL0Mg/ZyWhLBgo=\",\"allowedips\":\"0.0.0.0/0\"}");
    cJSON *server_peer =
        cJSON_Parse("{\"publickey\":\"dDUfRvZSDy8jZBsB4kQflTO+iwlLbR+jgb840fumqUM=\",\"allowedips\":\"10.1.0.1/32\"}");
    uint8_t index;
    twfRequire(wireguardCommonAddConfiguredPeer(&client->engine, client_peer, &index) &&
                   wireguardCommonAddConfiguredPeer(&server->engine, server_peer, &index),
               "peer setup failed");
    cJSON_Delete(client_peer);
    cJSON_Delete(server_peer);
}

static void discardOutput(endpoint_t *endpoint)
{
    while (endpoint->count > 0)
    {
        reuseBuffer(endpoint->packets[endpoint->head]);
        endpoint->head = (endpoint->head + 1U) % 64U;
        --endpoint->count;
    }
    if (endpoint->replay != NULL)
    {
        reuseBuffer(endpoint->replay);
        endpoint->replay = NULL;
    }
}

static void destroyEndpoints(endpoint_t *client, endpoint_t *server)
{
    discardOutput(client);
    discardOutput(server);
    wireguardDeviceDestroy(&client->engine);
    wireguardDeviceDestroy(&server->engine);
}

static void establish(endpoint_t *client, endpoint_t *server)
{
    twfRequire(wireguardifStartHandshake(&client->engine, &client->engine.peers[0], true) == ERR_OK,
               "initiation failed");
    exchange(client, server);
    twfRequire(client->engine.peers[0].curr_keypair.valid && server->engine.peers[0].curr_keypair.valid,
               "handshake did not establish both sessions");
}

static void testCarrierCookies(buffer_pool_t *pool)
{
    /* Exercise both roles: a carrier initiator challenges responses, while a
     * carrier responder challenges initiations. The other side retains the
     * ordinary network-address cookie and authenticated roaming behavior. */
    for (unsigned responder = 0; responder < 2; ++responder)
    {
        endpoint_t client = {0}, server = {0};
        now_millis = 1000;
        setupEndpoints(&client, &server);
        endpoint_t *carrier           = responder ? &server : &client;
        endpoint_t *network           = responder ? &client : &server;
        carrier->carrier_id           = 1;
        const ip_addr_t original_ip   = carrier->engine.peers[0].ip;
        const uint16_t  original_port = carrier->engine.peers[0].port;

        under_load = true;
        establish(&client, &server);
        twfRequire(client.cookie_replies == 1 && server.cookie_replies == 1,
                   "under-load handshake did not challenge both initiation and response");
        twfRequire(carrier->authenticated != 0 &&
                       memcmp(&carrier->engine.peers[0].ip, &original_ip, sizeof(original_ip)) == 0 &&
                       carrier->engine.peers[0].port == original_port,
                   "authenticated carrier handshake skipped admission or learned a network endpoint");
        twfRequire(ipAddrCmp(&network->engine.peers[0].ip, &carrier->ip) && network->engine.peers[0].port == 51820,
                   "network handshake stopped learning the authenticated endpoint");

        wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
        wireguardCommonSendInner(&server.engine, innerPacket(pool, 2, 1));
        exchange(&client, &server);
        twfRequire(client.delivered == 1 && server.delivered == 1,
                   "carrier handshake did not carry bidirectional authenticated packets");

        now_millis                         = 2000;
        const uint32_t prior_index         = carrier->engine.peers[0].curr_keypair.local_index;
        const unsigned prior_authenticated = carrier->authenticated;
        twfRequire(wireguardifStartHandshake(&client.engine, &client.engine.peers[0], true) == ERR_OK,
                   "carrier replacement rekey initiation failed");
        if (! responder)
            drain(&client, &server);

        /* The queued handshake has a MAC2 for generation 1. Replacing the
         * carrier must challenge it before authenticating/deriving a session. */
        carrier->carrier_id = 2;
        drain(network, carrier);
        twfRequire(carrier->cookie_replies == 2 && carrier->authenticated == prior_authenticated &&
                       carrier->engine.peers[0].curr_keypair.local_index == prior_index,
                   "old-carrier cookie authorized a handshake on the replacement carrier");

        exchange(&client, &server);
        twfRequire(client.engine.peers[0].curr_keypair.valid && server.engine.peers[0].curr_keypair.valid &&
                       carrier->engine.peers[0].curr_keypair.local_index != prior_index &&
                       carrier->authenticated > prior_authenticated,
                   "fresh replacement-carrier cookie did not complete the exact pending handshake");
        wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
        wireguardCommonSendInner(&server.engine, innerPacket(pool, 2, 1));
        exchange(&client, &server);
        twfRequire(client.delivered == 2 && server.delivered == 2 &&
                       memcmp(&carrier->engine.peers[0].ip, &original_ip, sizeof(original_ip)) == 0 &&
                       carrier->engine.peers[0].port == original_port,
                   "carrier replacement lost traffic or published a synthetic endpoint");
        under_load = false;
        destroyEndpoints(&client, &server);
    }
}

static bool allZero(const void *bytes, size_t length)
{
    const uint8_t *cursor = bytes;
    for (size_t i = 0; i < length; ++i)
        if (cursor[i] != 0)
            return false;
    return true;
}

static void requireSessionErased(const wireguard_peer_t *peer, const wireguard_peer_t *before)
{
    twfRequire(allZero(&peer->curr_keypair, sizeof(peer->curr_keypair)) &&
                   allZero(&peer->prev_keypair, sizeof(peer->prev_keypair)) &&
                   allZero(&peer->next_keypair, sizeof(peer->next_keypair)) &&
                   allZero(&peer->handshake, sizeof(peer->handshake)) &&
                   allZero(&peer->pending_handshake, sizeof(peer->pending_handshake)),
               "session erasure retained secret bytes");
    twfRequire(! peer->session_erase_armed && peer->session_erase_millis == 0,
               "session erasure retained its timer obligation");
    twfRequire(peer->valid && memcmp(peer->public_key, before->public_key, sizeof(peer->public_key)) == 0 &&
                   memcmp(peer->preshared_key, before->preshared_key, sizeof(peer->preshared_key)) == 0 &&
                   memcmp(peer->public_key_dh, before->public_key_dh, sizeof(peer->public_key_dh)) == 0 &&
                   memcmp(peer->allowed_source_ips, before->allowed_source_ips, sizeof(peer->allowed_source_ips)) ==
                       0 &&
                   memcmp(peer->greatest_timestamp, before->greatest_timestamp, sizeof(peer->greatest_timestamp)) == 0,
               "session erasure changed static configuration or initiation replay protection");
}

static void testReplayWindow(void)
{
    wireguard_keypair_t keypair = {0};
    twfRequire(wireguardCheckReplay(&keypair, 0) && wireguardCheckReplay(&keypair, 31) &&
                   wireguardCheckReplay(&keypair, UINT64_C(4294967297)) && ! wireguardCheckReplay(&keypair, 0),
               "full-width replay sequence 0,31,4294967297,0 was accepted");
    keypair = (wireguard_keypair_t) {0};
    twfRequire(wireguardCheckReplay(&keypair, 32) && wireguardCheckReplay(&keypair, 1) &&
                   ! wireguardCheckReplay(&keypair, 1) && ! wireguardCheckReplay(&keypair, 0),
               "replay window boundaries 31/32 or out-of-order duplicate differ");
    twfRequire(wireguardCheckReplay(&keypair, 64) && ! wireguardCheckReplay(&keypair, 32) &&
                   wireguardCheckReplay(&keypair, 63),
               "forward distance 32 did not reset the replay window");
    const uint64_t boundaries[] = {UINT32_MAX, UINT64_C(1) << 32, (UINT64_C(1) << 32) + 31};
    for (size_t i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); ++i)
    {
        keypair = (wireguard_keypair_t) {0};
        twfRequire(wireguardCheckReplay(&keypair, 0) && wireguardCheckReplay(&keypair, boundaries[i]) &&
                       ! wireguardCheckReplay(&keypair, 0) && wireguardCheckReplay(&keypair, boundaries[i] - 31) &&
                       ! wireguardCheckReplay(&keypair, boundaries[i] - 32),
                   "32-bit boundary narrowed a forward/backward replay distance");
    }
    uint32_t bitmap  = keypair.replay_bitmap;
    uint64_t counter = keypair.replay_counter;
    twfRequire(! wireguardCheckReplay(&keypair, UINT64_MAX) && keypair.replay_bitmap == bitmap &&
                   keypair.replay_counter == counter,
               "wrapped nonce modified the replay window");
}

static void testAuthenticatedReplayAndMessageLimit(buffer_pool_t *pool)
{
    endpoint_t client = {0}, server = {0};
    now_millis = 1000;
    setupEndpoints(&client, &server);
    twfRequire(wireguardifStartHandshake(&client.engine, &client.engine.peers[0], true) == ERR_OK,
               "replay fixture initiation failed");
    drain(&client, &server);
    drain(&server, &client);
    discardOutput(&client); // Leave the responder next-only until the first data packet.
    const uint64_t counters[] = {0, 31, UINT64_C(4294967297)};
    sbuf_t        *first      = NULL;
    for (size_t i = 0; i < sizeof(counters) / sizeof(counters[0]); ++i)
    {
        client.engine.peers[0].curr_keypair.sending_counter = counters[i];
        wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
        if (i == 0)
            first = sbufDuplicate(client.packets[client.head]);
        drain(&client, &server);
    }
    twfRequire(server.delivered == 3, "valid wide-counter packets were rejected");
    ip_addr_t foreign;
    twfRequire(ipaddr_aton("198.51.100.9", &foreign), "foreign endpoint parse failed");
    wireguard_keypair_t before = server.engine.peers[0].curr_keypair;
    wireguardCommonReceive(&server.engine, first, &foreign, 60000);
    twfRequire(server.delivered == 3 && ipAddrCmp(&server.engine.peers[0].ip, &client.ip) &&
                   server.engine.peers[0].port == 51820 &&
                   server.engine.peers[0].curr_keypair.replay_counter == before.replay_counter &&
                   server.engine.peers[0].curr_keypair.replay_bitmap == before.replay_bitmap,
               "replayed wide-distance packet published data, roamed, or changed replay state");
    const uint64_t rejected[] = {REJECT_AFTER_MESSAGES, UINT64_MAX};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i)
    {
        sbuf_t *packet = bufferpoolGetSmallBuffer(pool);
        sbufSetLength(packet, sizeof(message_transport_data_t) + WIREGUARD_AUTHTAG_LEN);
        sbufWriteZeros(packet, sbufGetLength(packet));
        message_transport_data_t *header = (message_transport_data_t *) sbufGetMutablePtr(packet);
        header->type                     = MESSAGE_TRANSPORT_DATA;
        header->receiver                 = client.engine.peers[0].curr_keypair.remote_index;
        U64TO8_LITTLE(header->counter, rejected[i]);
        wireguard_keypair_t sending = client.engine.peers[0].curr_keypair;
        sending.sending_counter     = rejected[i];
        twfRequire(wireguardEncryptPacket(header->enc_packet, WIREGUARD_AUTHTAG_LEN, NULL, 0, &sending),
                   "message-limit packet encryption failed");
        wireguardCommonReceive(&server.engine, packet, &foreign, 60000);
        twfRequire(server.delivered == 3 && ipAddrCmp(&server.engine.peers[0].ip, &client.ip) &&
                       server.engine.peers[0].port == 51820 &&
                       server.engine.peers[0].curr_keypair.replay_counter == before.replay_counter,
                   "message-limit rejection changed data, endpoint, or replay state");
    }
    client.engine.peers[0].curr_keypair.sending_counter = REJECT_AFTER_MESSAGES - 1;
    wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
    drain(&client, &server);
    twfRequire(server.delivered == 4, "last permitted transport nonce was rejected");
    // An invalid tag with a newer counter must not move the replay window.
    sbuf_t                   *bad        = sbufDuplicate(client.replay);
    message_transport_data_t *bad_header = (message_transport_data_t *) sbufGetMutablePtr(bad);
    U64TO8_LITTLE(bad_header->counter, REJECT_AFTER_MESSAGES - 2);
    before = server.engine.peers[0].curr_keypair;
    wireguardCommonReceive(&server.engine, bad, &foreign, 60000);
    twfRequire(server.delivered == 4 && ipAddrCmp(&server.engine.peers[0].ip, &client.ip) &&
                   server.engine.peers[0].curr_keypair.replay_counter == before.replay_counter &&
                   server.engine.peers[0].curr_keypair.replay_bitmap == before.replay_bitmap,
               "unauthenticated nonce mutated replay state or endpoint");
    destroyEndpoints(&client, &server);
}

static void testIndependentKeypairExpiry(buffer_pool_t *pool)
{
    endpoint_t client = {0}, server = {0};
    now_millis = 1000;
    setupEndpoints(&client, &server);
    establish(&client, &server);
    now_millis = 101000;
    establish(&client, &server);
    // Leave an unfinished handshake while the current session still works.
    now_millis = 151000;
    twfRequire(wireguardifStartHandshake(&client.engine, &client.engine.peers[0], true) == ERR_OK,
               "unconfirmed rekey initiation failed");
    discardOutput(&client);
    wireguard_peer_t *peer = &client.engine.peers[0];
    twfRequire(peer->prev_keypair.valid && peer->curr_keypair.valid, "mixed-age sessions were not established");
    const wireguard_peer_t before = *peer;
    now_millis                    = 180999;
    wireguardCommonLoop(&client.engine);
    twfRequire(memcmp(&peer->prev_keypair, &before.prev_keypair, sizeof(peer->prev_keypair)) == 0,
               "previous session erased before its rejection deadline");
    now_millis = 181000;
    wireguardCommonLoop(&client.engine);
    twfRequire(allZero(&peer->prev_keypair, sizeof(peer->prev_keypair)) &&
                   memcmp(&peer->curr_keypair, &before.curr_keypair, sizeof(peer->curr_keypair)) == 0 &&
                   memcmp(&peer->next_keypair, &before.next_keypair, sizeof(peer->next_keypair)) == 0,
               "previous expiry retained secrets or erased a fresh session");
    wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
    drain(&client, &server);
    twfRequire(server.delivered == 1, "expired previous slot interrupted the fresh current session");
    now_millis = 281000;
    wireguardCommonLoop(&client.engine);
    twfRequire(allZero(&peer->curr_keypair, sizeof(peer->curr_keypair)) && peer->session_erase_armed &&
                   peer->session_erase_millis == 101000 &&
                   memcmp(&peer->pending_handshake, &before.pending_handshake, sizeof(peer->pending_handshake)) == 0,
               "current expiry retained keys or lost pending-handshake cleanup");

    // The local message budget applies independently to every session slot.
    wireguard_keypair_t *slots[] = {&peer->curr_keypair, &peer->prev_keypair, &peer->next_keypair};
    for (size_t exhausted = 0; exhausted < 3; ++exhausted)
    {
        for (size_t i = 0; i < 3; ++i)
        {
            *slots[i]                 = before.curr_keypair;
            slots[i]->keypair_millis  = now_millis;
            slots[i]->sending_counter = REJECT_AFTER_MESSAGES - 1;
        }
        wireguardCommonLoop(&client.engine);
        twfRequire(slots[0]->valid && slots[1]->valid && slots[2]->valid,
                   "session erased before the local message limit");
        slots[exhausted]->sending_counter = REJECT_AFTER_MESSAGES;
        wireguardCommonLoop(&client.engine);
        for (size_t i = 0; i < 3; ++i)
            twfRequire(i == exhausted ? allZero(slots[i], sizeof(*slots[i])) : slots[i]->valid,
                       "local message limit failed to erase only its exhausted slot");
    }
    destroyEndpoints(&client, &server);
}

static void testSessionErasure(buffer_pool_t *pool)
{
    const uint32_t starts[] = {0, UINT32_MAX - 100000U};
    for (size_t i = 0; i < sizeof(starts) / sizeof(starts[0]); ++i)
    {
        endpoint_t     client = {0}, server = {0};
        const uint32_t start = starts[i];
        now_millis           = start;
        setupEndpoints(&client, &server);
        establish(&client, &server);
        wireguard_peer_t *peer   = &client.engine.peers[0];
        peer->keepalive_interval = 0;
        twfRequire(peer->session_erase_armed && peer->session_erase_millis == start,
                   "session derivation did not arm erasure, including clock zero");
        // A rekey leaves a previous slot; an unfinished retry leaves ephemeral/pending state.
        now_millis = start + 1000;
        twfRequire(wireguardifStartHandshake(&client.engine, peer, true) == ERR_OK, "erasure rekey initiation failed");
        exchange(&client, &server);
        twfRequire(peer->prev_keypair.valid, "successful rekey did not retain previous slot");
        const uint32_t derived = now_millis;
        now_millis             = derived + 100000;
        wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
        drain(&client, &server);
        twfRequire(wireguardifStartHandshake(&client.engine, peer, true) == ERR_OK, "unfinished initiation failed");
        discardOutput(&client);
        twfRequire(peer->session_erase_millis == derived, "data or retry postponed session erasure");
        wireguard_peer_t before = *peer;
        now_millis              = derived + 180000;
        peer->send_handshake    = false;
        wireguardCommonLoop(&client.engine);
        twfRequire(allZero(&peer->curr_keypair, sizeof(peer->curr_keypair)) &&
                       allZero(&peer->prev_keypair, sizeof(peer->prev_keypair)) && peer->handshake.valid &&
                       peer->pending_handshake.valid && peer->session_erase_armed,
                   "current expiry lost the outstanding session/handshake erasure obligation");
        now_millis = derived + 540000 - 1;
        wireguardCommonLoop(&client.engine);
        twfRequire(allZero(&peer->prev_keypair, sizeof(peer->prev_keypair)) && peer->handshake.valid,
                   "unfinished handshake erased before its deadline");
        now_millis = derived + 540000;
        wireguardCommonLoop(&client.engine);
        requireSessionErased(peer, &before);
        destroyEndpoints(&client, &server);
    }
    // An unconfirmed responder has only next keys, so current validity cannot arm cleanup.
    endpoint_t client = {0}, server = {0};
    now_millis = 0;
    setupEndpoints(&client, &server);
    twfRequire(wireguardifStartHandshake(&client.engine, &client.engine.peers[0], true) == ERR_OK,
               "next-only initiation failed");
    drain(&client, &server);
    wireguard_peer_t *peer = &server.engine.peers[0];
    twfRequire(! peer->curr_keypair.valid && peer->next_keypair.valid && peer->pending_handshake.valid &&
                   peer->session_erase_armed,
               "responder next-only session did not arm erasure");
    wireguard_peer_t before = *peer;
    now_millis              = 179999;
    wireguardCommonLoop(&server.engine);
    twfRequire(peer->next_keypair.valid, "unconfirmed responder key erased before its deadline");
    now_millis = 180000;
    wireguardCommonLoop(&server.engine);
    twfRequire(allZero(&peer->next_keypair, sizeof(peer->next_keypair)) && peer->pending_handshake.valid &&
                   peer->session_erase_armed && peer->session_erase_millis == 0,
               "unconfirmed responder expiry retained keys or lost the pending cleanup obligation");
    now_millis = 540000;
    wireguardCommonLoop(&server.engine);
    requireSessionErased(peer, &before);
    destroyEndpoints(&client, &server);
    // A peer which never derives a session must still erase its pending ephemeral state.
    client     = (endpoint_t) {0};
    server     = (endpoint_t) {0};
    now_millis = 0;
    setupEndpoints(&client, &server);
    peer = &client.engine.peers[0];
    twfRequire(wireguardifStartHandshake(&client.engine, peer, true) == ERR_OK, "pending-only initiation failed");
    discardOutput(&client);
    now_millis = 539999;
    twfRequire(wireguardifStartHandshake(&client.engine, peer, true) == ERR_OK, "pending-only retry failed");
    discardOutput(&client);
    twfRequire(peer->session_erase_armed && peer->session_erase_millis == 0, "retry extended pending-only retention");
    before     = *peer;
    now_millis = 540000;
    wireguardCommonLoop(&client.engine);
    requireSessionErased(peer, &before);
    destroyEndpoints(&client, &server);
}

static void testRekeyResetsErasure(void)
{
    endpoint_t client = {0}, server = {0};
    now_millis = 1000;
    setupEndpoints(&client, &server);
    establish(&client, &server);
    now_millis = 101000;
    twfRequire(wireguardifStartHandshake(&client.engine, &client.engine.peers[0], true) == ERR_OK,
               "resetting rekey failed");
    exchange(&client, &server);
    wireguard_peer_t *peer   = &client.engine.peers[0];
    peer->keepalive_interval = 0;
    now_millis               = 541000;
    wireguardCommonLoop(&client.engine);
    twfRequire(peer->session_erase_armed && peer->session_erase_millis == 101000 &&
                   allZero(&peer->prev_keypair, sizeof(peer->prev_keypair)),
               "old erasure deadline survived successful session derivation");
    wireguard_peer_t before = *peer;
    now_millis              = 641000;
    wireguardCommonLoop(&client.engine);
    requireSessionErased(peer, &before);
    destroyEndpoints(&client, &server);
}

static void testFixedRekeyTimers(buffer_pool_t *pool)
{
    const uint16_t intervals[] = {0, 25, 175, 180, 65535};
    for (size_t i = 0; i < sizeof(intervals) / sizeof(intervals[0]); ++i)
    {
        endpoint_t client = {0}, server = {0};
        now_millis = 1000;
        setupEndpoints(&client, &server);
        establish(&client, &server);
        wireguard_peer_t *peer   = &client.engine.peers[0];
        peer->keepalive_interval = intervals[i];
        uint32_t previous_index  = peer->curr_keypair.local_index;
        for (uint32_t elapsed = 30000; elapsed <= 150000; elapsed += 30000)
        {
            now_millis = 1000 + elapsed;
            wireguardCommonSendInner(&server.engine, innerPacket(pool, 2, 1));
            drain(&server, &client);
            twfRequire(! peer->send_handshake, "receive-only traffic requested early rekey");
        }
        now_millis = 165999;
        wireguardCommonSendInner(&server.engine, innerPacket(pool, 2, 1));
        drain(&server, &client);
        twfRequire(! peer->send_handshake, "receive-side rekey fired before 165 seconds");
        now_millis = 166000;
        wireguardCommonSendInner(&server.engine, innerPacket(pool, 2, 1));
        drain(&server, &client);
        twfRequire(peer->send_handshake, "persistent keepalive changed the fixed 165-second receive rekey");
        wireguardCommonLoop(&client.engine);
        exchange(&client, &server);
        twfRequire(peer->curr_keypair.valid && peer->curr_keypair.local_index != previous_index &&
                       peer->curr_keypair.keypair_millis == now_millis,
                   "receive-only traffic failed to renew before expiry");
        wireguardCommonSendInner(&server.engine, innerPacket(pool, 2, 1));
        exchange(&client, &server);
        twfRequire(client.delivered == 8, "receive-only traffic failed after key renewal");
        destroyEndpoints(&client, &server);

        client     = (endpoint_t) {0};
        server     = (endpoint_t) {0};
        now_millis = 1000;
        setupEndpoints(&client, &server);
        establish(&client, &server);
        peer                     = &server.engine.peers[0];
        peer->keepalive_interval = intervals[i];
        now_millis               = 170999;
        peer->last_tx            = now_millis;
        wireguardCommonLoop(&server.engine);
        twfRequire(server.count == 0, "responder initiated before its fixed deadline");
        now_millis    = 171000;
        peer->last_tx = now_millis;
        wireguardCommonLoop(&server.engine);
        twfRequire(server.count == 1 && wireguardGetMessageType(sbufGetRawPtr(server.packets[server.head]),
                                                                sbufGetLength(server.packets[server.head])) ==
                                            MESSAGE_HANDSHAKE_INITIATION,
                   "persistent keepalive changed the fixed responder rekey deadline");
        destroyEndpoints(&client, &server);
    }
}

static void testRetryAndPersistentKeepalive(void)
{
    endpoint_t client = {0}, server = {0};
    now_millis = 1000;
    setupEndpoints(&client, &server);
    wireguard_peer_t *peer = &client.engine.peers[0];
    peer->active           = true;
    twfRequire(wireguardifStartHandshake(&client.engine, peer, false) == ERR_OK, "retry initiation failed");
    discardOutput(&client);
    now_millis = 5999;
    wireguardCommonLoop(&client.engine);
    twfRequire(client.count == 0, "normal handshake retried before five seconds");
    now_millis = 6000;
    wireguardCommonLoop(&client.engine);
    twfRequire(client.count == 1 && peer->last_initiation_tx == 6000, "normal handshake did not retry at five seconds");
    destroyEndpoints(&client, &server);
    const uint16_t intervals[] = {0, 25, 175, 180, 65535};
    for (size_t i = 0; i < sizeof(intervals) / sizeof(intervals[0]); ++i)
    {
        client     = (endpoint_t) {0};
        server     = (endpoint_t) {0};
        now_millis = 1000;
        setupEndpoints(&client, &server);
        establish(&client, &server);
        peer                     = &client.engine.peers[0];
        peer->keepalive_interval = intervals[i];
        const uint32_t deadline  = 1000U + (intervals[i] ? intervals[i] : 65535U) * 1000U;
        now_millis               = deadline - 1;
        // Keep the transport key fresh without sending a packet: isolate optional keepalive scheduling.
        peer->handshake.local_index  = peer->curr_keypair.local_index;
        peer->handshake.remote_index = peer->curr_keypair.remote_index;
        memset(peer->handshake.chaining_key, 0x73, sizeof(peer->handshake.chaining_key));
        twfRequire(wireguardStartSession(peer, true), "keepalive fixture session derivation failed");
        wireguardCommonLoop(&client.engine);
        twfRequire(client.count == 0, "persistent keepalive fired before its configured interval");
        now_millis = deadline;
        wireguardCommonLoop(&client.engine);
        twfRequire(client.count == (intervals[i] ? 1U : 0U), "persistent keepalive did not follow configuration");
        if (intervals[i])
            twfRequire(wireguardGetMessageType(sbufGetRawPtr(client.packets[client.head]),
                                               sbufGetLength(client.packets[client.head])) == MESSAGE_TRANSPORT_DATA,
                       "persistent keepalive generated a handshake instead of transport");
        twfRequire(wireguardifDisconnect(&client.engine, 0) == ERR_OK && ! peer->session_erase_armed &&
                       peer->session_erase_millis == 0,
                   "disconnect retained erasure bookkeeping");
        twfRequire(wireguardifRemovePeer(&client.engine, 0) == ERR_OK && allZero(peer, sizeof(*peer)),
                   "peer removal retained secret or erasure state");
        destroyEndpoints(&client, &server);
    }
}

int main(void)
{
    testCaseSet("wireguard_protocol_test");
    twfRequire(userTestRuntimeInitialize(), "crypto setup failed");
    twfRequire(createNetworkLogger(NULL, false) != NULL, "logger setup failed");
    twf_worker_env_t environment;
    twfWorkerEnvSetup(&environment, 8192, 32);
    endpoint_t client = {0}, server = {0};
    now_millis = 1000;
    setupEndpoints(&client, &server);
    twfRequire(wireguardifStartHandshake(&client.engine, &client.engine.peers[0], true) == ERR_OK, "initiation failed");
    exchange(&client, &server);
    twfRequire(client.engine.peers[0].curr_keypair.valid && server.engine.peers[0].curr_keypair.valid,
               "bidirectional handshake did not establish session keys");
    wireguardCommonSendInner(&client.engine, innerPacket(environment.pool, 1, 2));
    exchange(&client, &server);
    twfRequire(server.delivered == 1 && client.replay != NULL, "authenticated inner packet was not published");
    ip_addr_t roaming;
    twfRequire(ipaddr_aton("198.51.100.1", &roaming), "roaming parse failed");
    wireguardCommonReceive(&server.engine, client.replay, &roaming, 51821);
    client.replay = NULL;
    twfRequire(server.delivered == 1 && ipAddrCmp(&server.engine.peers[0].ip, &client.ip),
               "replay roamed or published");
    wireguardCommonSendInner(&client.engine, innerPacket(environment.pool, 7, 2));
    exchange(&client, &server);
    twfRequire(server.delivered == 1, "peer injected another inner source");
    client.ip = roaming;
    wireguardCommonSendInner(&client.engine, innerPacket(environment.pool, 1, 2));
    exchange(&client, &server);
    twfRequire(server.delivered == 2 && ipAddrCmp(&server.engine.peers[0].ip, &roaming),
               "authenticated roaming failed");
    wireguardCommonSendInner(&server.engine, innerPacket(environment.pool, 2, 1));
    exchange(&client, &server);
    twfRequire(client.delivered == 1, "return routing/decryption failed");
    if (client.replay)
        reuseBuffer(client.replay);
    if (server.replay)
        reuseBuffer(server.replay);
    wireguardDeviceDestroy(&client.engine);
    wireguardDeviceDestroy(&server.engine);
    testCarrierCookies(environment.pool);
    testReplayWindow();
    testAuthenticatedReplayAndMessageLimit(environment.pool);
    testIndependentKeypairExpiry(environment.pool);
    testSessionErasure(environment.pool);
    testRekeyResetsErasure();
    testFixedRekeyTimers(environment.pool);
    testRetryAndPersistentKeepalive();
    twfWorkerEnvTeardown(&environment);
    networkloggerDestroy();
    userTestRuntimeCleanup();
    return 0;
}
