/* Two real engines: handshake, packets, full-width replay, roaming, and fixed
 * protocol timers. A wrapped monotonic clock avoids real-time waits.
 * CTest: waterwall.wireguard_protocol_unit */
#include "WireGuardCommon/engine.h"
#include "WireGuardCommon/prefix.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/user_runtime.h"
#include "loggers/network_logger.h"

static uint32_t now_millis;
static bool     under_load;

static void testPeerPrefixes(void)
{
    wireguard_prefix_table_t table = {0};
    int                      owner[3];
    /* The same path covers roots, internal branches, nested reservations and equal prefixes. */
    const char *ranges[][4] = {{"0.0.0.0/0", "192.0.2.0/24", "192.0.2.19/32", "198.51.100.1/32"},
                               {"::/0", "2001:db8::/64", "2001:db8::19/128", "2001:db8:1::1/128"}};
    for (unsigned family = 0; family < 2; ++family)
    {
        ip_addr_t ip[4], mask[4];
        for (unsigned i = 0; i < 4; ++i)
            twfRequire(parseIPWithSubnetMask(ranges[family][i], &ip[i], &mask[i]) != ERR_ARG, "CIDR parse failed");
        twfRequire(wireguardPrefixInsert(&table, &ip[2], &mask[2], 3, &owner[2], true) &&
                       wireguardPrefixInsert(&table, &ip[3], &mask[3], 2, &owner[1], true),
                   "disjoint host prefixes collided");
        twfRequire(! wireguardPrefixInsert(&table, &ip[1], &mask[1], 1, &owner[0], true) &&
                       ! wireguardPrefixInsert(&table, &ip[0], &mask[0], 1, &owner[0], true),
                   "an exclusive range overlapped an existing descendant");
        twfRequire(wireguardPrefixInsert(&table, &ip[1], &mask[1], 3, &owner[2], true) &&
                       wireguardPrefixInsert(&table, &ip[0], &mask[0], 1, &owner[0], false) &&
                       wireguardPrefixInsert(&table, &ip[1], &mask[1], 2, &owner[1], false),
                   "overlapping routing prefixes failed");
        twfRequire(wireguardPrefixLookup(&table, &ip[1]) == &owner[1] &&
                       wireguardPrefixLookup(&table, &ip[2]) == &owner[2] &&
                       wireguardPrefixLookup(&table, &ip[0]) == &owner[0],
                   "longest prefix or equal-prefix precedence failed");
        wireguardPrefixRemove(&table, &ip[2], &mask[2], 3);
        twfRequire(! wireguardPrefixInsert(&table, &ip[2], &mask[2], 3, &owner[2], true) &&
                       wireguardPrefixLookup(&table, &ip[2]) == &owner[1],
                   "a parent reservation failed to protect a removed host");
        wireguardPrefixRemove(&table, &ip[1], &mask[1], 2);
        twfRequire(wireguardPrefixLookup(&table, &ip[2]) == &owner[2], "removal lost an equal-prefix owner");
        wireguardPrefixRemove(&table, &ip[1], &mask[1], 3);
        twfRequire(wireguardPrefixLookup(&table, &ip[2]) == &owner[0] &&
                       wireguardPrefixLookup(&table, &ip[3]) == &owner[1],
                   "branch pruning lost the fallback route or sibling");
    }
    wireguardPrefixDestroy(&table);
}

/* Tests drive callbacks directly, so advance the worker cache alongside the fresh clock. */
static void setTime(uint32_t millis)
{
    getCurrentWorkerLoop()->cur_hrtime = (uint64_t) millis * 1000U;
    now_millis                         = millis;
}

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
    sbuf_t            *receive_during_output;
    const sbuf_t      *expected_plaintext;
    bool               refuse_next_output;
    ip_addr_t          ip;
    uint64_t           carrier_id;
} endpoint_t;
static bool capture(void *context, sbuf_t *packet, wireguard_peer_t *peer, const ip_addr_t *ip, uint16_t port)
{
    discard     peer;
    endpoint_t *endpoint = context;
    if (endpoint->refuse_next_output)
    {
        endpoint->refuse_next_output = false;
        reuseBuffer(packet);
        return false;
    }
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
    if (endpoint->receive_during_output != NULL)
    {
        sbuf_t *reply                   = endpoint->receive_during_output;
        endpoint->receive_during_output = NULL;
        wireguardCommonReceive(&endpoint->engine, reply, ip, port);
    }
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
    const sbuf_t *expected = endpoint->expected_plaintext;
    twfRequireEqualU32(sbufGetLength(packet),
                       expected != NULL ? sbufGetLength(expected) : 20,
                       "decoded packet length differs from IPv4 length");
    if (expected != NULL)
        twfRequire(memoryEqual(sbufGetRawPtr(packet), sbufGetRawPtr(expected), sbufGetLength(expected)),
                   "transport padding changed the delivered inner packet");
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
    size_t index;
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
    twfRequire(wireguardifStartHandshake(&client->engine, client->engine.first_peer, true) == ERR_OK,
               "initiation failed");
    exchange(client, server);
    twfRequire(client->engine.first_peer->curr_keypair.valid && server->engine.first_peer->curr_keypair.valid,
               "handshake did not establish both sessions");
}

static bool onlyMessage(const endpoint_t *endpoint, uint8_t type)
{
    if (endpoint->count != 1)
        return false;
    const sbuf_t *packet = endpoint->packets[endpoint->head];
    return wireguardGetMessageType(sbufGetRawPtr(packet), sbufGetLength(packet)) == type;
}

static void checkTransportPadding(endpoint_t *client, endpoint_t *server, buffer_pool_t *pool, uint16_t inner_length,
                                  uint16_t padded_length)
{
    sbuf_t *inner = sbufReserveSpace(innerPacket(pool, 1, 2), inner_length);
    sbufSetLength(inner, inner_length);
    uint8_t *bytes = sbufGetMutablePtr(inner);
    PUT_BE16(bytes + 2, inner_length);
    for (uint16_t i = 20; i < inner_length; ++i)
        bytes[i] = (uint8_t) (i + 1U);

    const unsigned before      = server->delivered;
    server->expected_plaintext = inner;
    wireguardCommonSendInner(&client->engine, sbufDuplicate(inner));
    twfRequire(onlyMessage(client, MESSAGE_TRANSPORT_DATA), "expected one encrypted transport datagram");
    twfRequireEqualU32(sbufGetLength(client->packets[client->head]),
                       (uint32_t) sizeof(message_transport_data_t) + padded_length + WIREGUARD_AUTHTAG_LEN,
                       "transport datagram has unexpected padding");
    drain(client, server);
    twfRequire(server->delivered == before + 1, "padded transport datagram failed to deliver");
    server->expected_plaintext = NULL;
    reuseBuffer(inner);
}

static void testTransportPadding(buffer_pool_t *pool)
{
    endpoint_t client = {0}, server = {0};
    setTime(1000);
    setupEndpoints(&client, &server);
    establish(&client, &server);

    checkTransportPadding(&client, &server, pool, 1407, 1408);
    checkTransportPadding(&client, &server, pool, 1408, 1408);
    checkTransportPadding(&client, &server, pool, 1409, 1420);
    checkTransportPadding(&client, &server, pool, 1419, 1420);
    checkTransportPadding(&client, &server, pool, 1420, 1420);
    checkTransportPadding(&client, &server, pool, 1421, 1421);
    client.engine.padding_mtu = 1500;
    checkTransportPadding(&client, &server, pool, 1420, 1424);
    checkTransportPadding(&client, &server, pool, 1499, 1500);
    destroyEndpoints(&client, &server);
}

static void testCarrierCookies(buffer_pool_t *pool)
{
    /* Exercise both roles: a carrier initiator challenges responses, while a
     * carrier responder challenges initiations. The other side retains the
     * ordinary network-address cookie and authenticated roaming behavior. */
    for (unsigned responder = 0; responder < 2; ++responder)
    {
        endpoint_t client = {0}, server = {0};
        setTime(1000);
        setupEndpoints(&client, &server);
        endpoint_t *carrier           = responder ? &server : &client;
        endpoint_t *network           = responder ? &client : &server;
        carrier->carrier_id           = 1;
        const ip_addr_t original_ip   = carrier->engine.first_peer->ip;
        const uint16_t  original_port = carrier->engine.first_peer->port;

        under_load = true;
        establish(&client, &server);
        twfRequire(client.cookie_replies == 1 && server.cookie_replies == 1,
                   "under-load handshake did not challenge both initiation and response");
        twfRequire(carrier->authenticated != 0 &&
                       memcmp(&carrier->engine.first_peer->ip, &original_ip, sizeof(original_ip)) == 0 &&
                       carrier->engine.first_peer->port == original_port,
                   "authenticated carrier handshake skipped admission or learned a network endpoint");
        twfRequire(ipAddrCmp(&network->engine.first_peer->ip, &carrier->ip) &&
                       network->engine.first_peer->port == 51820,
                   "network handshake stopped learning the authenticated endpoint");

        wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
        wireguardCommonSendInner(&server.engine, innerPacket(pool, 2, 1));
        exchange(&client, &server);
        twfRequire(client.delivered == 1 && server.delivered == 1,
                   "carrier handshake did not carry bidirectional authenticated packets");

        setTime(2000);
        const uint32_t prior_index         = carrier->engine.first_peer->curr_keypair.local_index;
        const unsigned prior_authenticated = carrier->authenticated;
        twfRequire(wireguardifStartHandshake(&client.engine, client.engine.first_peer, true) == ERR_OK,
                   "carrier replacement rekey initiation failed");
        if (! responder)
            drain(&client, &server);

        /* The queued handshake has a MAC2 for generation 1. Replacing the
         * carrier must challenge it before authenticating/deriving a session. */
        carrier->carrier_id = 2;
        drain(network, carrier);
        twfRequire(carrier->cookie_replies == 2 && carrier->authenticated == prior_authenticated &&
                       carrier->engine.first_peer->curr_keypair.local_index == prior_index,
                   "old-carrier cookie authorized a handshake on the replacement carrier");

        exchange(&client, &server);
        twfRequire(client.engine.first_peer->curr_keypair.valid && server.engine.first_peer->curr_keypair.valid &&
                       carrier->engine.first_peer->curr_keypair.local_index != prior_index &&
                       carrier->authenticated > prior_authenticated,
                   "fresh replacement-carrier cookie did not complete the exact pending handshake");
        wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
        wireguardCommonSendInner(&server.engine, innerPacket(pool, 2, 1));
        exchange(&client, &server);
        twfRequire(client.delivered == 2 && server.delivered == 2 &&
                       memcmp(&carrier->engine.first_peer->ip, &original_ip, sizeof(original_ip)) == 0 &&
                       carrier->engine.first_peer->port == original_port,
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
    setTime(1000);
    setupEndpoints(&client, &server);
    twfRequire(wireguardifStartHandshake(&client.engine, client.engine.first_peer, true) == ERR_OK,
               "replay fixture initiation failed");
    drain(&client, &server);
    drain(&server, &client);
    discardOutput(&client); // Leave the responder next-only until the first data packet.
    const uint64_t counters[] = {0, 31, UINT64_C(4294967297)};
    sbuf_t        *first      = NULL;
    for (size_t i = 0; i < sizeof(counters) / sizeof(counters[0]); ++i)
    {
        client.engine.first_peer->curr_keypair.sending_counter = counters[i];
        wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
        if (i == 0)
            first = sbufDuplicate(client.packets[client.head]);
        drain(&client, &server);
    }
    twfRequire(server.delivered == 3, "valid wide-counter packets were rejected");
    ip_addr_t foreign;
    twfRequire(ipaddr_aton("198.51.100.9", &foreign), "foreign endpoint parse failed");
    wireguard_keypair_t before = server.engine.first_peer->curr_keypair;
    wireguardCommonReceive(&server.engine, first, &foreign, 60000);
    twfRequire(server.delivered == 3 && ipAddrCmp(&server.engine.first_peer->ip, &client.ip) &&
                   server.engine.first_peer->port == 51820 &&
                   server.engine.first_peer->curr_keypair.replay_counter == before.replay_counter &&
                   server.engine.first_peer->curr_keypair.replay_bitmap == before.replay_bitmap,
               "replayed wide-distance packet published data, roamed, or changed replay state");
    const uint64_t rejected[] = {REJECT_AFTER_MESSAGES, UINT64_MAX};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i)
    {
        sbuf_t *packet = bufferpoolGetSmallBuffer(pool);
        sbufSetLength(packet, sizeof(message_transport_data_t) + WIREGUARD_AUTHTAG_LEN);
        sbufWriteZeros(packet, sbufGetLength(packet));
        message_transport_data_t *header = (message_transport_data_t *) sbufGetMutablePtr(packet);
        header->type                     = MESSAGE_TRANSPORT_DATA;
        header->receiver                 = client.engine.first_peer->curr_keypair.remote_index;
        U64TO8_LITTLE(header->counter, rejected[i]);
        wireguard_keypair_t sending = client.engine.first_peer->curr_keypair;
        sending.sending_counter     = rejected[i];
        twfRequire(wireguardEncryptPacket(header->enc_packet, WIREGUARD_AUTHTAG_LEN, NULL, 0, &sending),
                   "message-limit packet encryption failed");
        wireguardCommonReceive(&server.engine, packet, &foreign, 60000);
        twfRequire(server.delivered == 3 && ipAddrCmp(&server.engine.first_peer->ip, &client.ip) &&
                       server.engine.first_peer->port == 51820 &&
                       server.engine.first_peer->curr_keypair.replay_counter == before.replay_counter,
                   "message-limit rejection changed data, endpoint, or replay state");
    }
    client.engine.first_peer->curr_keypair.sending_counter = REJECT_AFTER_MESSAGES - 1;
    wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
    drain(&client, &server);
    twfRequire(server.delivered == 4, "last permitted transport nonce was rejected");
    // An invalid tag with a newer counter must not move the replay window.
    sbuf_t                   *bad        = sbufDuplicate(client.replay);
    message_transport_data_t *bad_header = (message_transport_data_t *) sbufGetMutablePtr(bad);
    U64TO8_LITTLE(bad_header->counter, REJECT_AFTER_MESSAGES - 2);
    before = server.engine.first_peer->curr_keypair;
    wireguardCommonReceive(&server.engine, bad, &foreign, 60000);
    twfRequire(server.delivered == 4 && ipAddrCmp(&server.engine.first_peer->ip, &client.ip) &&
                   server.engine.first_peer->curr_keypair.replay_counter == before.replay_counter &&
                   server.engine.first_peer->curr_keypair.replay_bitmap == before.replay_bitmap,
               "unauthenticated nonce mutated replay state or endpoint");
    destroyEndpoints(&client, &server);
}

static void testIndependentKeypairExpiry(buffer_pool_t *pool)
{
    endpoint_t client = {0}, server = {0};
    setTime(1000);
    setupEndpoints(&client, &server);
    establish(&client, &server);
    setTime(101000);
    establish(&client, &server);
    wireguard_peer_t *peer = client.engine.first_peer;
    twfRequire(peer->prev_keypair.valid && peer->curr_keypair.valid, "mixed-age sessions were not established");
    const wireguard_peer_t before = *peer;
    setTime(180999);
    wireguardCommonLoop(&client.engine);
    twfRequire(memcmp(&peer->prev_keypair, &before.prev_keypair, sizeof(peer->prev_keypair)) == 0,
               "previous session erased before its rejection deadline");
    setTime(181000);
    wireguardCommonLoop(&client.engine);
    twfRequire(allZero(&peer->prev_keypair, sizeof(peer->prev_keypair)) &&
                   memcmp(&peer->curr_keypair, &before.curr_keypair, sizeof(peer->curr_keypair)) == 0 &&
                   memcmp(&peer->next_keypair, &before.next_keypair, sizeof(peer->next_keypair)) == 0,
               "previous expiry retained secrets or erased a fresh session");
    wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
    drain(&client, &server);
    twfRequire(server.delivered == 1, "expired previous slot interrupted the fresh current session");
    // Isolate key expiry from the independent retry and unanswered-data deadlines.
    wireguardifSendKeepalive(&server.engine, server.engine.first_peer);
    drain(&server, &client);
    setTime(280000);
    twfRequire(wireguardifStartHandshake(&client.engine, peer, true) == ERR_OK, "unconfirmed rekey initiation failed");
    discardOutput(&client);
    const wireguard_pending_handshake_t pending = peer->pending_handshake;
    setTime(281000);
    wireguardCommonLoop(&client.engine);
    twfRequire(allZero(&peer->curr_keypair, sizeof(peer->curr_keypair)) && peer->session_erase_armed &&
                   peer->session_erase_millis == 101000 && pending.valid &&
                   memcmp(&peer->pending_handshake, &pending, sizeof(pending)) == 0,
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
        setTime(start);
        setupEndpoints(&client, &server);
        establish(&client, &server);
        wireguard_peer_t *peer   = client.engine.first_peer;
        peer->keepalive_interval = 0;
        twfRequire(peer->session_erase_armed && peer->session_erase_millis == start,
                   "session derivation did not arm erasure, including clock zero");
        // A rekey leaves a previous slot; an unfinished retry leaves ephemeral/pending state.
        setTime(start + 1000);
        twfRequire(wireguardifStartHandshake(&client.engine, peer, true) == ERR_OK, "erasure rekey initiation failed");
        exchange(&client, &server);
        twfRequire(peer->prev_keypair.valid, "successful rekey did not retain previous slot");
        const uint32_t derived = now_millis;
        setTime(derived + 100000);
        wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
        drain(&client, &server);
        twfRequire(wireguardifStartHandshake(&client.engine, peer, true) == ERR_OK, "unfinished initiation failed");
        discardOutput(&client);
        twfRequire(peer->session_erase_millis == derived, "data or retry postponed session erasure");
        wireguard_peer_t before = *peer;
        setTime(derived + 180000);
        peer->send_handshake    = false;
        wireguardCommonLoop(&client.engine);
        twfRequire(allZero(&peer->curr_keypair, sizeof(peer->curr_keypair)) &&
                       allZero(&peer->prev_keypair, sizeof(peer->prev_keypair)) && peer->handshake.valid &&
                       peer->pending_handshake.valid && peer->session_erase_armed,
                   "current expiry lost the outstanding session/handshake erasure obligation");
        setTime(derived + 540000 - 1);
        wireguardCommonLoop(&client.engine);
        twfRequire(allZero(&peer->prev_keypair, sizeof(peer->prev_keypair)) && peer->handshake.valid,
                   "unfinished handshake erased before its deadline");
        setTime(derived + 540000);
        wireguardCommonLoop(&client.engine);
        requireSessionErased(peer, &before);
        destroyEndpoints(&client, &server);
    }
    // An unconfirmed responder has only next keys, so current validity cannot arm cleanup.
    endpoint_t client = {0}, server = {0};
    setTime(0);
    setupEndpoints(&client, &server);
    twfRequire(wireguardifStartHandshake(&client.engine, client.engine.first_peer, true) == ERR_OK,
               "next-only initiation failed");
    drain(&client, &server);
    wireguard_peer_t *peer = server.engine.first_peer;
    twfRequire(! peer->curr_keypair.valid && peer->next_keypair.valid && peer->pending_handshake.valid &&
                   peer->session_erase_armed,
               "responder next-only session did not arm erasure");
    wireguard_peer_t before = *peer;
    setTime(179999);
    wireguardCommonLoop(&server.engine);
    twfRequire(peer->next_keypair.valid, "unconfirmed responder key erased before its deadline");
    setTime(180000);
    wireguardCommonLoop(&server.engine);
    twfRequire(allZero(&peer->next_keypair, sizeof(peer->next_keypair)) && peer->pending_handshake.valid &&
                   peer->session_erase_armed && peer->session_erase_millis == 0,
               "unconfirmed responder expiry retained keys or lost the pending cleanup obligation");
    setTime(540000);
    wireguardCommonLoop(&server.engine);
    requireSessionErased(peer, &before);
    destroyEndpoints(&client, &server);
    // A peer which never derives a session must still erase its pending ephemeral state.
    client     = (endpoint_t) {0};
    server     = (endpoint_t) {0};
    setTime(0);
    setupEndpoints(&client, &server);
    peer = client.engine.first_peer;
    twfRequire(wireguardifStartHandshake(&client.engine, peer, true) == ERR_OK, "pending-only initiation failed");
    discardOutput(&client);
    setTime(539999);
    twfRequire(wireguardifStartHandshake(&client.engine, peer, true) == ERR_OK, "pending-only retry failed");
    discardOutput(&client);
    twfRequire(peer->session_erase_armed && peer->session_erase_millis == 0, "retry extended pending-only retention");
    before     = *peer;
    setTime(540000);
    wireguardCommonLoop(&client.engine);
    requireSessionErased(peer, &before);
    destroyEndpoints(&client, &server);
}

static void testRekeyResetsErasure(void)
{
    endpoint_t client = {0}, server = {0};
    setTime(1000);
    setupEndpoints(&client, &server);
    establish(&client, &server);
    setTime(101000);
    twfRequire(wireguardifStartHandshake(&client.engine, client.engine.first_peer, true) == ERR_OK,
               "resetting rekey failed");
    exchange(&client, &server);
    wireguard_peer_t *peer   = client.engine.first_peer;
    peer->keepalive_interval = 0;
    setTime(541000);
    wireguardCommonLoop(&client.engine);
    twfRequire(peer->session_erase_armed && peer->session_erase_millis == 101000 &&
                   allZero(&peer->prev_keypair, sizeof(peer->prev_keypair)),
               "old erasure deadline survived successful session derivation");
    wireguard_peer_t before = *peer;
    setTime(641000);
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
        setTime(1000);
        setupEndpoints(&client, &server);
        establish(&client, &server);
        wireguard_peer_t *peer   = client.engine.first_peer;
        peer->keepalive_interval = intervals[i];
        uint32_t previous_index  = peer->curr_keypair.local_index;
        for (uint32_t elapsed = 30000; elapsed <= 150000; elapsed += 30000)
        {
            setTime(1000 + elapsed);
            wireguardCommonSendInner(&server.engine, innerPacket(pool, 2, 1));
            drain(&server, &client);
            twfRequire(! peer->send_handshake, "receive-only traffic requested early rekey");
        }
        setTime(165999);
        wireguardCommonSendInner(&server.engine, innerPacket(pool, 2, 1));
        drain(&server, &client);
        twfRequire(! peer->send_handshake, "receive-side rekey fired before 165 seconds");
        setTime(166000);
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
        setTime(1000);
        setupEndpoints(&client, &server);
        establish(&client, &server);
        peer                     = server.engine.first_peer;
        peer->keepalive_interval = intervals[i];
        setTime(170999);
        peer->last_tx            = now_millis;
        wireguardCommonLoop(&server.engine);
        twfRequire(server.count == 0, "responder initiated before its fixed deadline");
        setTime(171000);
        peer->last_tx = now_millis;
        wireguardCommonLoop(&server.engine);
        twfRequire(server.count == 1 && wireguardGetMessageType(sbufGetRawPtr(server.packets[server.head]),
                                                                sbufGetLength(server.packets[server.head])) ==
                                            MESSAGE_HANDSHAKE_INITIATION,
                   "persistent keepalive changed the fixed responder rekey deadline");
        destroyEndpoints(&client, &server);
    }
}

static void testPassiveKeepalive(buffer_pool_t *pool, uint16_t interval)
{
    endpoint_t client = {0}, server = {0};
    setTime(1000);
    setupEndpoints(&client, &server);
    establish(&client, &server);
    client.engine.first_peer->keepalive_interval = interval;
    server.engine.first_peer->keepalive_interval = interval;
    wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
    drain(&client, &server);
    setTime(10999);
    wireguardCommonLoop(&server.engine);
    twfRequire(server.delivered == 1 && server.count == 0, "one-way receiver replied before ten seconds");
    setTime(11000);
    wireguardCommonLoop(&server.engine);
    twfRequire(onlyMessage(&server, MESSAGE_TRANSPORT_DATA) &&
                   sbufGetLength(server.packets[server.head]) ==
                       sizeof(message_transport_data_t) + WIREGUARD_AUTHTAG_LEN,
               "one-way receiver did not send an empty keepalive at ten seconds");
    drain(&server, &client);
    setTime(27000);
    wireguardCommonLoop(&client.engine);
    wireguardCommonLoop(&server.engine);
    twfRequire(client.count == 0 && server.count == 0,
               "passive keepalive failed to cancel unanswered-data recovery or triggered another probe");

    wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
    drain(&client, &server);
    setTime(now_millis + 1000);
    wireguardCommonSendInner(&server.engine, innerPacket(pool, 2, 1));
    drain(&server, &client);
    setTime(now_millis + 9000);
    wireguardCommonLoop(&server.engine);
    twfRequire(client.delivered == 1 && server.delivered == 2 && server.count == 0,
               "ordinary return data failed to satisfy the passive keepalive deadline");
    destroyEndpoints(&client, &server);
}

static void testRecoveryClock(buffer_pool_t *pool)
{
    endpoint_t client = {0}, server = {0};
    setTime(1000);
    setupEndpoints(&client, &server);
    establish(&client, &server);
    wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
    drain(&client, &server);

    // More than 15 seconds pass inside a callback. Only the fresh clock advances.
    now_millis = 17000;
    wireguardCommonLoop(&client.engine);
    wireguardCommonLoop(&server.engine);
    twfRequire(client.count == 0 && server.count == 0, "recovery timers advanced without a loop clock update");
    setTime(now_millis);
    wireguardCommonLoop(&client.engine);
    wireguardCommonLoop(&server.engine);
    twfRequire(onlyMessage(&client, MESSAGE_HANDSHAKE_INITIATION) && onlyMessage(&server, MESSAGE_TRANSPORT_DATA),
               "owner loop clock did not release the handshake and keepalive");

    discardOutput(&client);
    now_millis = 1000 + REJECT_AFTER_TIME * 1000U;
    wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
    twfRequire(client.count == 0 && ! client.engine.first_peer->curr_keypair.valid,
               "stale loop clock extended the transport key's hard lifetime");
    destroyEndpoints(&client, &server);
}

static void testReentrantKeepalive(buffer_pool_t *pool)
{
    endpoint_t client = {0}, server = {0};
    setTime(1000);
    setupEndpoints(&client, &server);
    establish(&client, &server);
    wireguardCommonSendInner(&server.engine, innerPacket(pool, 2, 1));
    drain(&server, &client);
    setTime(10000);
    // A real packet returns inside the client's send, nine seconds into its existing reply deadline.
    wireguardCommonSendInner(&server.engine, innerPacket(pool, 2, 1));
    twfRequire(onlyMessage(&server, MESSAGE_TRANSPORT_DATA), "missing synchronous reply");
    client.receive_during_output = sbufDuplicate(server.packets[server.head]);
    discardOutput(&server);
    wireguardCommonSendInner(&client.engine, innerPacket(pool, 1, 2));
    drain(&client, &server);
    setTime(19999);
    wireguardCommonLoop(&client.engine);
    twfRequire(client.delivered == 2 && server.delivered == 1 && client.count == 0,
               "reentrant data inherited the satisfied keepalive deadline");
    setTime(20000);
    client.refuse_next_output = true;
    wireguardCommonLoop(&client.engine);
    twfRequire(! client.refuse_next_output && client.count == 0, "reentrant data lost its own keepalive deadline");
    setTime(now_millis + WIREGUARDIF_TIMER_MSECS);
    wireguardCommonLoop(&client.engine);
    twfRequire(onlyMessage(&client, MESSAGE_TRANSPORT_DATA) &&
                   sbufGetLength(client.packets[client.head]) ==
                       sizeof(message_transport_data_t) + WIREGUARD_AUTHTAG_LEN,
               "carrier refusal consumed the passive reply obligation");
    drain(&client, &server);
    setTime(26000);
    wireguardCommonLoop(&client.engine);
    twfRequire(client.count == 0, "synchronous return traffic left the unanswered-data handshake armed");
    destroyEndpoints(&client, &server);
}

static void testUnansweredDataRecovery(buffer_pool_t *pool, bool from_server, uint16_t interval)
{
    endpoint_t     client = {0}, server = {0};
    endpoint_t    *sender   = from_server ? &server : &client;
    endpoint_t    *receiver = from_server ? &client : &server;
    const uint8_t  src      = from_server ? 2 : 1;
    const uint8_t  dst      = from_server ? 1 : 2;
    const uint32_t start    = UINT32_MAX - 10000U;
    setTime(start);
    setupEndpoints(&client, &server);
    establish(&client, &server);
    wireguard_peer_t *peer   = sender->engine.first_peer;
    peer->keepalive_interval = interval;
    peer->active             = ! from_server;
    // Model a restarted server in one direction and delayed return traffic in the other.
    if (! from_server)
        twfRequire(wireguardifDisconnect(&receiver->engine, 0) == ERR_OK, "failed to forget remote session");
    wireguardCommonSendInner(&sender->engine, innerPacket(pool, src, dst));
    drain(sender, receiver);
    setTime(start + 9000U);
    wireguardCommonSendInner(&sender->engine, innerPacket(pool, src, dst));
    drain(sender, receiver);
    setTime(start + 14999U);
    wireguardCommonLoop(&sender->engine);
    const unsigned delivered_before_recovery = from_server ? 2 : 0;
    twfRequire(peer->curr_keypair.valid && receiver->delivered == delivered_before_recovery && sender->count == 0,
               "fresh session initiated before fifteen seconds of unanswered traffic");
    setTime(start + 15333U);
    wireguardCommonLoop(&sender->engine);
    twfRequire(onlyMessage(sender, MESSAGE_HANDSHAKE_INITIATION),
               "continued unanswered data postponed the recovery handshake");
    const uint32_t first_index = peer->pending_handshake.sender;
    drain(sender, receiver);
    twfRequire(onlyMessage(receiver, MESSAGE_HANDSHAKE_RESPONSE), "receiver did not answer the recovery handshake");
    discardOutput(receiver);
    if (from_server)
    {
        // Old-key authenticated traffic answers the silence timer. The new handshake still needs a response.
        const unsigned authenticated_before = sender->authenticated;
        wireguardifSendKeepalive(&receiver->engine, receiver->engine.first_peer);
        drain(receiver, sender);
        twfRequire(sender->authenticated == authenticated_before + 1, "old-key keepalive was not authenticated");
    }
    setTime(now_millis + 4999U);
    wireguardCommonLoop(&sender->engine);
    twfRequire(sender->count == 0, "unanswered rekey retried before five seconds");
    setTime(now_millis + 334U);
    wireguardCommonLoop(&sender->engine);
    twfRequire(peer->curr_keypair.valid && onlyMessage(sender, MESSAGE_HANDSHAKE_INITIATION) &&
                   peer->pending_handshake.sender != first_index,
               "lost rekey response did not trigger a fresh initiation while the old key was valid");
    exchange(sender, receiver);
    wireguardCommonSendInner(&sender->engine, innerPacket(pool, src, dst));
    drain(sender, receiver);
    setTime(now_millis + 5333U);
    wireguardCommonLoop(&sender->engine);
    twfRequire(receiver->delivered == delivered_before_recovery + 1 && sender->count == 0,
               "successful retry failed to restore delivery or left another initiation scheduled");
    destroyEndpoints(&client, &server);
}

/* Eligibility can wait on a carrier or authorization lock while the loop clock stands still. */
static bool reachAttemptDeadline(void *context, wireguard_peer_t *peer)
{
    discard context;
    now_millis = peer->handshake_attempt_millis + REKEY_ATTEMPT_TIME * 1000U;
    return true;
}

static void testAgingKeyDuringAttempt(buffer_pool_t *pool)
{
    endpoint_t client = {0}, server = {0};
    setTime(1000);
    setupEndpoints(&client, &server);
    establish(&client, &server);
    wireguard_peer_t *peer = server.engine.first_peer;

    setTime(71000);
    wireguardCommonSendInner(&server.engine, innerPacket(pool, 2, 1));
    discardOutput(&server);
    setTime(86400);
    wireguardCommonLoop(&server.engine);
    twfRequire(onlyMessage(&server, MESSAGE_HANDSHAKE_INITIATION), "unanswered server data did not start recovery");
    discardOutput(&server);
    setTime(171000); /* The responder key reaches its 170-second age threshold during this attempt. */
    wireguardCommonLoop(&server.engine);
    twfRequire(onlyMessage(&server, MESSAGE_HANDSHAKE_INITIATION), "ongoing recovery missed an eligible retry");
    discardOutput(&server);
    setTime(178000);
    wireguardCommonLoop(&server.engine);
    wireguardCommonLoop(&server.engine);
    twfRequire(server.count == 0 && peer->curr_keypair.valid && ! peer->retry_handshake,
               "old responder key renewed the retry window without fresh demand");

    now_millis += 1000;
    const uint32_t demand_deadline = now_millis + REKEY_ATTEMPT_TIME * 1000U;
    wireguardCommonRequestHandshake(&server.engine, peer);
    twfRequire(onlyMessage(&server, MESSAGE_HANDSHAKE_INITIATION), "fresh demand could not restart recovery");
    discardOutput(&server);
    setTime(demand_deadline - 1U);
    server.engine.callbacks.can_initiate = reachAttemptDeadline;
    wireguardCommonLoop(&server.engine);
    twfRequire(server.count == 0 && now_millis == demand_deadline,
               "fresh demand used a stale start or its final retry crossed the attempt deadline");
    destroyEndpoints(&client, &server);
}

static void testCookieAtAttemptDeadline(void)
{
    endpoint_t client = {0}, server = {0};
    setTime(1000);
    setupEndpoints(&client, &server);
    under_load             = true;
    wireguard_peer_t *peer = client.engine.first_peer;
    twfRequire(wireguardifStartHandshake(&client.engine, peer, false) == ERR_OK, "cookie setup initiation failed");
    drain(&client, &server);
    twfRequire(onlyMessage(&server, MESSAGE_COOKIE_REPLY), "missing cookie challenge");
    sbuf_t *late = sbufDuplicate(server.packets[server.head]);

    setTime(90999);
    drain(&server, &client);
    twfRequire(onlyMessage(&client, MESSAGE_HANDSHAKE_INITIATION) && peer->last_initiation_tx == 90999,
               "timely cookie did not retransmit the pending initiation");
    discardOutput(&client);
    /* Eligibility crosses the deadline before the periodic loop can observe it. */
    client.engine.callbacks.can_initiate = reachAttemptDeadline;
    wireguardCommonReceive(&client.engine, sbufDuplicate(late), &server.ip, 51820);
    twfRequire(client.count == 0 && peer->last_initiation_tx == 90999 && now_millis == 91000,
               "cookie retransmitted after eligibility crossed the attempt deadline");
    client.engine.callbacks.can_initiate = NULL;
    wireguardCommonReceive(&client.engine, late, &server.ip, 51820);
    twfRequire(client.count == 0, "cookie arriving after the deadline rearmed the attempt");
    wireguardCommonLoop(&client.engine);
    setTime(97000);
    wireguardCommonLoop(&client.engine);
    twfRequire(client.count == 0 && ! peer->retry_handshake, "late cookie rearmed the expired attempt");
    under_load = false;
    destroyEndpoints(&client, &server);
}

static void testRetryAndPersistentKeepalive(void)
{
    endpoint_t client = {0}, server = {0};
    setTime(0);
    setupEndpoints(&client, &server);
    now_millis             = 1000; /* First send occurs partway through a long loop iteration. */
    wireguard_peer_t *peer = client.engine.first_peer;
    peer->active           = true;
    twfRequire(wireguardifStartHandshake(&client.engine, peer, false) == ERR_OK, "retry initiation failed");
    discardOutput(&client);
    setTime(5999);
    wireguardCommonLoop(&client.engine);
    twfRequire(client.count == 0, "normal handshake retried before five seconds");
    setTime(6333);
    wireguardCommonLoop(&client.engine);
    twfRequire(onlyMessage(&client, MESSAGE_HANDSHAKE_INITIATION) && peer->last_initiation_tx == now_millis,
               "normal handshake did not retry within five seconds plus jitter");
    discardOutput(&client);
    peer->active = false; // Isolate this attempt from an active client's ongoing connection policy.
    setTime(90999);
    wireguardCommonLoop(&client.engine);
    twfRequire(onlyMessage(&client, MESSAGE_HANDSHAKE_INITIATION), "handshake attempts stopped before 90 seconds");
    discardOutput(&client);
    now_millis += 5333U; /* The loop cache still places the attempt inside its retry window. */
    wireguardCommonLoop(&client.engine);
    twfRequire(client.count == 0 && ! peer->retry_handshake && peer->session_erase_armed &&
                   peer->session_erase_millis == 1000,
               "handshake retries exceeded their 90-second budget or postponed secret erasure");
    destroyEndpoints(&client, &server);
    const uint16_t intervals[] = {0, 25, 175, 180, 65535};
    for (size_t i = 0; i < sizeof(intervals) / sizeof(intervals[0]); ++i)
    {
        client     = (endpoint_t) {0};
        server     = (endpoint_t) {0};
        setTime(1000);
        setupEndpoints(&client, &server);
        establish(&client, &server);
        peer                     = client.engine.first_peer;
        peer->keepalive_interval = intervals[i];
        const uint32_t deadline  = 1000U + (intervals[i] ? intervals[i] : 65535U) * 1000U;
        setTime(deadline - 1);
        // Keep the transport key fresh without sending a packet: isolate optional keepalive scheduling.
        peer->handshake.local_index  = peer->curr_keypair.local_index;
        peer->handshake.remote_index = peer->curr_keypair.remote_index;
        memset(peer->handshake.chaining_key, 0x73, sizeof(peer->handshake.chaining_key));
        twfRequire(wireguardStartSession(peer, true), "keepalive fixture session derivation failed");
        wireguardCommonLoop(&client.engine);
        twfRequire(client.count == 0, "persistent keepalive fired before its configured interval");
        setTime(deadline);
        if (intervals[i] != 0)
        {
            client.refuse_next_output = true;
            wireguardCommonLoop(&client.engine);
            twfRequire(! client.refuse_next_output && client.count == 0,
                       "due persistent keepalive did not attempt carrier submission");
            setTime(deadline + WIREGUARDIF_TIMER_MSECS);
        }
        wireguardCommonLoop(&client.engine);
        twfRequire(client.count == (intervals[i] ? 1U : 0U), "persistent keepalive did not follow configuration");
        if (intervals[i])
            twfRequire(wireguardGetMessageType(sbufGetRawPtr(client.packets[client.head]),
                                               sbufGetLength(client.packets[client.head])) == MESSAGE_TRANSPORT_DATA,
                       "persistent keepalive generated a handshake instead of transport");
        twfRequire(wireguardifDisconnect(&client.engine, 0) == ERR_OK && ! peer->session_erase_armed &&
                       peer->session_erase_millis == 0,
                   "disconnect retained erasure bookkeeping");
        twfRequire(wireguardifRemovePeer(&client.engine, 0) == ERR_OK &&
                       peerLookupByPeerIndex(&client.engine, 0) == NULL,
                   "removed peer remained reachable by its local id");
        destroyEndpoints(&client, &server);
    }
}

static bool removeSendingPeer(void *context, sbuf_t *packet, wireguard_peer_t *peer, const ip_addr_t *address,
                              uint16_t port)
{
    discard        address;
    discard        port;
    endpoint_t    *endpoint = context;
    const uint32_t receiver = peer->curr_keypair.local_index;
    twfRequire(peerLookupByReceiver(&endpoint->engine, receiver) == peer, "live receiver id was not indexed");
    twfRequire(wireguardifRemovePeer(&endpoint->engine, peer->id) == ERR_OK &&
                   peerLookupByReceiver(&endpoint->engine, receiver) == NULL && endpoint->engine.peer_count == 0,
               "retirement during output left the peer registered");
    twfRequire(! peer->valid && allZero(&peer->curr_keypair, sizeof(peer->curr_keypair)) &&
                   allZero(peer->public_key_dh, sizeof(peer->public_key_dh)),
               "retired peer retained secrets during an outstanding output callback");
    reuseBuffer(packet);
    return true;
}

static void testReentrantRemoval(void)
{
    endpoint_t client = {0}, server = {0};
    setTime(1000);
    setupEndpoints(&client, &server);
    establish(&client, &server);
    client.engine.first_peer->keepalive_interval = 1;
    client.engine.callbacks.output               = removeSendingPeer;
    setTime(2000);
    wireguardCommonLoop(&client.engine);
    twfRequire(client.engine.first_peer == NULL && client.engine.retired_peers == NULL,
               "timer failed to settle a reentrantly removed peer");
    destroyEndpoints(&client, &server);
}

enum
{
    kTimerPeers = 9
};

typedef struct timer_output_s
{
    size_t   paused_id;
    unsigned remaining;
    bool     attempted[kTimerPeers], retire_sender;
} timer_output_t;

static bool boundedTimerOutput(void *context, sbuf_t *packet, wireguard_peer_t *peer, const ip_addr_t *ip,
                               uint16_t port)
{
    discard         ip;
    discard         port;
    timer_output_t *output = context;
    const size_t    id     = peer->id;
    twfRequire(wireguardGetMessageType(sbufGetRawPtr(packet), sbufGetLength(packet)) == MESSAGE_TRANSPORT_DATA &&
                   id < kTimerPeers && ! output->attempted[id],
               "timer revisited a peer or sent an unexpected packet");
    output->attempted[id] = true;
    reuseBuffer(packet);
    if (id == output->paused_id || output->remaining == 0)
        return false;
    --output->remaining;
    if (output->retire_sender)
    {
        output->retire_sender = false;
        twfRequire(wireguardifRemovePeer(peer->device, id) == ERR_OK, "failed to retire the timer sender");
    }
    return true;
}

static void testTimerFairness(void)
{
    timer_output_t     output = {.paused_id = kTimerPeers - 2};
    wireguard_device_t device;
    setTime(1000);
    twfRequire(wireguardCommonInit(&device,
                                   "EBJOHctLU2w8uteyTE+WU0hruB09Ub0vwVS+Gt9wAls=",
                                   &output,
                                   (wireguard_callbacks_t) {.output = boundedTimerOutput}),
               "timer device initialization failed");
    for (unsigned i = 0; i < kTimerPeers; ++i)
    {
        const uint8_t     key[WIREGUARD_PUBLIC_KEY_LEN] = {9, (uint8_t) (i + 1)};
        wireguard_peer_t *peer                          = wireguardPeerCreate(&device, key, NULL);
        twfRequire(peer != NULL, "timer peer creation failed");
        peer->curr_keypair.valid = peer->curr_keypair.sending_valid = true;
        peer->curr_keypair.keypair_millis                           = now_millis;
        peer->keepalive_interval                                    = 1;
    }
    wireguard_peer_t *tail = peerLookupByPeerIndex(&device, 0);
    /* Each productive tick admits two packets, with a fully blocked tick between them.
     * The second peer in scan order always refuses, even when capacity remains. */
    for (unsigned tick = 0; tick < 8; ++tick)
    {
        setTime(1000 + tick * WIREGUARDIF_TIMER_MSECS);
        output.remaining = tick % 2 == 0 ? 2 : 0;
        memoryZero(output.attempted, sizeof(output.attempted));
        if (tick == 1)
        {
            tail->prev_keypair.valid          = true;
            tail->prev_keypair.keypair_millis = now_millis - REJECT_AFTER_TIME * 1000U;
        }
        wireguardCommonLoop(&device);
        twfRequire(output.remaining == 0 && ! tail->prev_keypair.valid,
                   "output pressure interfered with timer service");
    }
    for (wireguard_peer_t *peer = device.first_peer; peer != NULL; peer = peer->next)
        twfRequire((peer->authenticated_sends != 0) == (peer->id != output.paused_id),
                   "a writable peer starved behind the bounded timer output");

    /* Remove the resume point from its own output callback. The wrapped scan
     * must still visit every other due peer once, then survive another removal between ticks. */
    for (unsigned pass = 0; pass < 3; ++pass)
    {
        setTime(10000 + pass * 2000U);
        output.paused_id     = SIZE_MAX;
        output.remaining     = 1;
        output.retire_sender = pass == 1;
        memoryZero(output.attempted, sizeof(output.attempted));
        wireguardCommonLoop(&device);
        for (wireguard_peer_t *peer = device.first_peer; peer != NULL; peer = peer->next)
            twfRequire(output.attempted[peer->id], "cursor retirement skipped a peer's timer");
        if (pass == 1)
            twfRequire(! output.retire_sender && device.next_timer_peer != NULL &&
                           wireguardifRemovePeer(&device, device.next_timer_peer->id) == ERR_OK,
                       "failed to retire the next deferred peer");
    }
    wireguardDeviceDestroy(&device);
}

static void testLocalIdWrap(void)
{
    endpoint_t client = {0}, server = {0};
    setupEndpoints(&client, &server);
    wireguard_peer_t *original                      = client.engine.first_peer;
    uint8_t           key[WIREGUARD_PUBLIC_KEY_LEN] = {9};
    client.engine.next_peer_id                      = SIZE_MAX - 1;
    wireguard_peer_t *last                          = wireguardPeerCreate(&client.engine, key, NULL);
    key[1]                                          = 1;
    wireguard_peer_t *wrapped                       = wireguardPeerCreate(&client.engine, key, NULL);
    twfRequire(last != NULL && last->id == SIZE_MAX - 1 && wrapped != NULL && wrapped->id == 1 &&
                   peerLookupByPeerIndex(&client.engine, 0) == original &&
                   peerLookupByPeerIndex(&client.engine, last->id) == last &&
                   peerLookupByPeerIndex(&client.engine, wrapped->id) == wrapped,
               "local id wrap refused a peer or reused an occupied id");
    destroyEndpoints(&client, &server);
}

int main(void)
{
    testCaseSet("wireguard_protocol_test");
    twfRequire(userTestRuntimeInitialize(), "crypto setup failed");
    twfRequire(createNetworkLogger(NULL, false) != NULL, "logger setup failed");
    twf_worker_env_t environment;
    twfWorkerEnvSetup(&environment, 8192, 32);
    testLocalIdWrap();
    testReentrantRemoval();
    testTimerFairness();
    testPeerPrefixes();
    testTransportPadding(environment.pool);
    endpoint_t client = {0}, server = {0};
    setTime(1000);
    setupEndpoints(&client, &server);
    twfRequire(wireguardifStartHandshake(&client.engine, client.engine.first_peer, true) == ERR_OK,
               "initiation failed");
    exchange(&client, &server);
    twfRequire(client.engine.first_peer->curr_keypair.valid && server.engine.first_peer->curr_keypair.valid,
               "bidirectional handshake did not establish session keys");
    wireguardCommonSendInner(&client.engine, innerPacket(environment.pool, 1, 2));
    exchange(&client, &server);
    twfRequire(server.delivered == 1 && client.replay != NULL, "authenticated inner packet was not published");
    ip_addr_t roaming;
    twfRequire(ipaddr_aton("198.51.100.1", &roaming), "roaming parse failed");
    wireguardCommonReceive(&server.engine, client.replay, &roaming, 51821);
    client.replay = NULL;
    twfRequire(server.delivered == 1 && ipAddrCmp(&server.engine.first_peer->ip, &client.ip),
               "replay roamed or published");
    wireguardCommonSendInner(&client.engine, innerPacket(environment.pool, 7, 2));
    exchange(&client, &server);
    twfRequire(server.delivered == 1, "peer injected another inner source");
    client.ip = roaming;
    wireguardCommonSendInner(&client.engine, innerPacket(environment.pool, 1, 2));
    exchange(&client, &server);
    twfRequire(server.delivered == 2 && ipAddrCmp(&server.engine.first_peer->ip, &roaming),
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
    testCookieAtAttemptDeadline();
    testAgingKeyDuringAttempt(environment.pool);
    testCarrierCookies(environment.pool);
    testReplayWindow();
    testAuthenticatedReplayAndMessageLimit(environment.pool);
    testPassiveKeepalive(environment.pool, 0);
    testPassiveKeepalive(environment.pool, 60);
    testRecoveryClock(environment.pool);
    testReentrantKeepalive(environment.pool);
    testUnansweredDataRecovery(environment.pool, false, 0);
    testUnansweredDataRecovery(environment.pool, true, 60);
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
