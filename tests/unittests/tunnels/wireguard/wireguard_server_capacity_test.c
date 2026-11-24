/*
 * 5,000 simultaneous connection-mode peers with distinct accounts and ingress
 * lines. Every peer completes the real handshake through the fixture adapter.
 * The first and last exchange inner UDP traffic; an idle account expires and
 * authenticates again after its worker retires the old binding. No sockets.
 * CTest: waterwall.wireguard_server_capacity_unit
 */
#include "wireguard_server_fixture.h"

enum
{
    kPeerCount     = 5000,
    kAccountIdBase = 1000,
    kPortBase      = 20000,
    kTimingSamples = 31
};

static unsigned          expected_user, echoed, received;
static const char *const server_peer_settings =
    "{\"publickey\":\"GnRcOavdc180YrXak138cZxWlMoEUZL0Mg/ZyWhLBgo=\",\"allowedips\":\"0.0.0.0/0\"}";

/* All clients stay at the same protocol time during setup, including while
 * their worker queues are pumped. Only measureTimer samples elapsed host time. */
static unsigned int fixture_millis = 10000;
unsigned int        __wrap_getTickMS(void);
unsigned long long  __wrap_getHRTimeUs(void);
unsigned long long  __real_getHRTimeUs(void);

unsigned int __wrap_getTickMS(void)
{
    return fixture_millis;
}

unsigned long long __wrap_getHRTimeUs(void)
{
    return (unsigned long long) fixture_millis * 1000U;
}

static void ingressFinish(tunnel_t *t, line_t *line)
{
    discard t;
    lineDestroy(line);
}

static line_t *openIngress(wg_server_fixture_t *f, wid_t wid, uint16_t port)
{
    const wid_t previous = tosSetCurrentWorker(wid);
    line_t     *line     = lineCreateForWorker(0, f->chain->line_pools, wid);
    addresscontextSetIpAddressPortProtocol(lineGetSourceAddressContext(line), "192.0.2.1", 51820, IP_PROTO_UDP);
    addresscontextSetTransportOffer(lineGetDestinationAddressContext(line), kAddressContextTransportUdp);
    lineGetRoutingContext(line)->peer_source_port = port;
    const bool accepted                           = lineCallWithRef(line, tunnelNextUpStreamInit, f->adapter);
    discard    tosSetCurrentWorker(previous);
    return accepted ? line : NULL;
}

static void closeIngress(wg_server_fixture_t *f, line_t *line)
{
    const wid_t previous = tosSetCurrentWorker(lineGetWID(line));
    tunnelNextUpStreamFinish(f->adapter, line);
    lineDestroy(line);
    discard tosSetCurrentWorker(previous);
}

static void echoPayload(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    const user_handle_t *user = lineGetCurrentUser(line);
    twfRequire(user != NULL && user->user_id == expected_user && sbufGetLength(packet) == 1,
               "UDP payload reached the wrong inner account");
    ++echoed;
    tunnelPrevDownStreamPayload(t, line, packet);
}

static void receiveEcho(void *context, sbuf_t *packet, wireguard_peer_t *peer)
{
    discard              peer;
    wg_server_fixture_t *f     = context;
    const user_t        *user  = usersLookupByIdentifier(&f->users, expected_user);
    const uint8_t       *bytes = sbufGetRawPtr(packet);
    twfRequire(sbufGetLength(packet) == 29 && memoryEqual(bytes + 16, ip_2_ip4(&user->wireguard_allowed_ip), 4) &&
                   bytes[28] == 0x5a,
               "client received the wrong inner UDP response");
    ++received;
    reuseBuffer(packet);
}

static void outputOnIngress(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    twfRequire(line == wg_fixture->ingress[lineGetWID(line)], "reply selected another peer's ingress");
    wgAdapterPayload(t, line, packet);
}

static user_t *addAccount(wg_server_fixture_t *f, unsigned index)
{
    char password[48], range[32];
    snprintf(password, sizeof(password), "wg-scale-fixture-%u", index);
    snprintf(range, sizeof(range), "10.77.%u.%u/32", (index + 1) / 256, (index + 1) % 256);
    user_t account;
    twfRequire(userCreate(&account, password), "scale account creation failed");
    userSetId(&account, kAccountIdBase + index);
    twfRequire(userSetWireGuardAllowedIps(&account, range) && usersAddUser(&f->users, &account),
               "distinct account/range insertion failed");
    userDestroy(&account);
    return usersLookupByIdentifier(&f->users, kAccountIdBase + index);
}

static void authenticate(wg_server_fixture_t *f, wireguard_device_t *client, const user_t *account,
                         const cJSON *server_peer, line_t *line)
{
    char key[45] = {0};
    twfRequire(wwBase64Encode(account->sha256_pass.bytes, 32, key) == 44 &&
                   wireguardCommonInit(
                       client, key, f, (wireguard_callbacks_t) {.output = wgClientOutput, .inner = receiveEcho}),
               "scale client initialization failed");
    wCryptoZero(key, sizeof(key));
    size_t id;
    twfRequire(wireguardCommonAddConfiguredPeer(client, server_peer, &id), "scale client peer insertion failed");
    wireguard_peer_t *peer       = peerLookupByPeerIndex(client, id);
    f->ingress[lineGetWID(line)] = line;
    twfRequire(wireguardifStartHandshake(client, peer, true) == ERR_OK, "scale client initiation failed");
    wgServerFixtureExchangeClientOnWorker(f, client, lineGetWID(line), 0);
    const wireguard_peer_t *server_side = peerLookupByPubkey(&f->state->engine, client->public_key);
    twfRequire(server_side != NULL && server_side->curr_keypair.valid && peer->curr_keypair.valid,
               "authenticated session keys missing");
}

static void roundTrip(wg_server_fixture_t *f, wireguard_device_t *client, line_t *line, unsigned index)
{
    expected_user                = kAccountIdBase + index;
    f->ingress[lineGetWID(line)] = line;
    sbuf_t       *packet         = wgServerFixtureUdpPacket(f, 40001);
    uint8_t      *bytes          = sbufGetMutablePtr(packet);
    const user_t *user           = usersLookupByIdentifier(&f->users, expected_user);
    memoryCopy(bytes + 12, ip_2_ip4(&user->wireguard_allowed_ip), 4);
    twfRequire(calcFullPacketChecksum(bytes, 29), "scale packet checksum failed");
    const unsigned before = received;
    wireguardCommonSendInner(client, packet);
    wgServerFixtureExchangeClientOnWorker(f, client, lineGetWID(line), 0);
    twfRequire(received == before + 1 && echoed == received, "authenticated UDP round trip failed");
}

static int compareTime(const void *a, const void *b)
{
    const uint64_t first = *(const uint64_t *) a, second = *(const uint64_t *) b;
    return first < second ? -1 : first > second;
}

static void measureTimer(wg_server_fixture_t *f)
{
    uint64_t reconciliation[kTimingSamples], timer[kTimingSamples];
    for (unsigned i = 0; i < 2; ++i)
        wireguardserverTick(f->state->timer);
    for (unsigned i = 0; i < kTimingSamples; ++i)
    {
        uint64_t start = __real_getHRTimeUs();
        wireguardserverReconcile(f->state, true);
        reconciliation[i] = __real_getHRTimeUs() - start;
        start             = __real_getHRTimeUs();
        wireguardserverTick(f->state->timer);
        timer[i] = __real_getHRTimeUs() - start;
    }
    qsort(reconciliation, kTimingSamples, sizeof(reconciliation[0]), compareTime);
    qsort(timer, kTimingSamples, sizeof(timer[0]), compareTime);
    printf("%u quiet authenticated peers, %u samples (us), reconciliation median=%" PRIu64 " max=%" PRIu64
           ", full timer median=%" PRIu64 " max=%" PRIu64 "\n",
           kPeerCount,
           kTimingSamples,
           reconciliation[kTimingSamples / 2],
           reconciliation[kTimingSamples - 1],
           timer[kTimingSamples / 2],
           timer[kTimingSamples - 1]);
}

static void orphanAdmissionPressure(void)
{
    testCaseSet("WireGuard ingress admission after account expiry and roaming");
    wg_server_fixture_t f;
    wgServerFixtureSetup(&f, 2, ",\"max-unauthenticated-ingress\":2");
    f.adapter->fnFinD     = ingressFinish;
    f.adapter->fnPayloadD = outputOnIngress;
    f.sink->fnPayloadU    = echoPayload;
    twfRequire(wwStartupSucceeded(wgServerFixtureStart(&f)), "pressure server startup failed");
    wgServerFixturePump(&f);
    wireguard_device_t clients[7] = {0};
    line_t            *lines[6];
    cJSON             *server_peer = cJSON_Parse(server_peer_settings);
    for (unsigned i = 0; i < 6; ++i)
    {
        const wid_t owner = i == 1 ? 0 : 1;
        lines[i]          = i == 5 ? lines[4] : openIngress(&f, owner, (uint16_t) (kPortBase + i));
        twfRequire(lines[i] != NULL, "pressure fixture ingress refused");
        authenticate(&f, &clients[i], addAccount(&f, i), server_peer, lines[i]);
        if (i < 4)
            lineRef(lines[i]); /* Observe owner Finish after eviction. */
    }

    /* The first two lines fill both waiting slots; the fifth still shares
     * its ingress with another healthy account and cannot be reclaimed. */
    for (unsigned i = 0; i < 5; ++i)
        if (i < 2 || i == 4)
            userSetClientViewExpiry(usersLookupByIdentifier(&f.users, kAccountIdBase + i), 1, true);
    wireguardserverTick(f.state->timer);
    wgServerFixturePump(&f);
    twfRequire(f.state->unauthenticated_ingress == 2 && lineIsAlive(lines[4]), "last-binding demotion lost a slot");
    roundTrip(&f, &clients[5], lines[5], 5);

    /* Worker 1 refuses closes while worker 0 can settle the other unused
     * endpoint. New arrivals must reach it without reopening worker 1. */
    workerMessagesCloseAdmission(&f.env.workers[1]);
    line_t *elsewhere = openIngress(&f, 0, 11000);
    if (elsewhere == NULL)
        elsewhere = openIngress(&f, 0, 11000);
    twfRequire(elsewhere != NULL, "unavailable worker prevented another worker from reclaiming its endpoint");
    wgServerFixturePump(&f);
    twfRequire(lineIsAlive(lines[0]) && ! lineIsAlive(lines[1]) && f.state->unauthenticated_ingress == 2 &&
                   openIngress(&f, 0, 11002) == NULL,
               "a refused close transferred the wrong endpoint or waiting slot");
    for (unsigned i = 2; i <= 3; ++i)
    {
        f.ingress[1]           = lines[5];
        wireguard_peer_t *peer = peerLookupByPubkey(&clients[i], f.state->engine.public_key);
        wireguardifSendKeepalive(&clients[i], peer);
        wgServerFixtureExchangeClient(&f, &clients[i], 0);
        const server_line_t *ls = lineGetState(lines[i], f.server);
        twfRequire(atomicLoad(&ls->ingress->closing), "uncharged ingress still admitted packets after roaming");
    }
    discard tosSetCurrentWorker(1);
    sbuf_t *arrived = bufferpoolGetSmallBuffer(f.env.pools[1]);
    tunnelNextUpStreamPayload(f.adapter, lines[2], arrived);
    twfRequire(! lineIsAlive(lines[2]) && lineIsAlive(lines[3]), "owner-side input failed to close its orphan");
    discard tosSetCurrentWorker(0);
    twfRequire(workerMessagesOpenAdmission(&f.env.workers[1]), "could not resume owner queue");

    line_t *newcomer = openIngress(&f, 1, 11001);
    twfRequire(newcomer != NULL && openIngress(&f, 0, 11002) == NULL && f.state->unauthenticated_ingress == 2,
               "fresh ingress failed to reclaim only charged orphans");
    wireguardserverTick(f.state->timer);
    wgServerFixturePump(&f);
    for (unsigned i = 0; i < 4; ++i)
    {
        twfRequire(! lineIsAlive(lines[i]), "displaced or retrying orphan survived owner cleanup");
        lineUnref(lines[i]);
    }
    authenticate(&f, &clients[6], addAccount(&f, 6), server_peer, newcomer);
    roundTrip(&f, &clients[6], newcomer, 6);
    roundTrip(&f, &clients[5], lines[5], 5);
    closeIngress(&f, elsewhere);
    closeIngress(&f, newcomer);
    closeIngress(&f, lines[5]);
    f.ingress[0] = f.ingress[1] = NULL;
    for (unsigned i = 0; i < ARRAY_SIZE(clients); ++i)
        wireguardDeviceDestroy(&clients[i]);
    cJSON_Delete(server_peer);
    wgServerFixtureClose(&f, wwLifecycleProcessShutdown());
}

int main(void)
{
    orphanAdmissionPressure();
    testCaseSet("wireguard_server_capacity_test");
    wg_server_fixture_t f;
    wgServerFixtureSetup(&f, 1, ",\"max-unauthenticated-ingress\":2");
    f.adapter->fnFinD     = ingressFinish;
    f.adapter->fnPayloadD = outputOnIngress;
    f.sink->fnPayloadU    = echoPayload;
    twfRequire(wwStartupSucceeded(wgServerFixtureStart(&f)), "scale server startup failed");
    wgServerFixturePump(&f);
    line_t *pending = openIngress(&f, 0, 10000), *second = openIngress(&f, 0, 10001);
    twfRequire(pending && second && openIngress(&f, 0, 10002) == NULL,
               "unauthenticated ingress budget was not enforced");
    closeIngress(&f, second);

    line_t             *lines[kPeerCount];
    wireguard_device_t *clients     = memoryAllocateZero(kPeerCount * sizeof(*clients));
    cJSON              *server_peer = cJSON_Parse(server_peer_settings);
    twfRequire(server_peer != NULL, "scale client peer settings failed");
    for (unsigned i = 0; i < kPeerCount; ++i)
    {
        user_t *account = addAccount(&f, i);
        lines[i]        = openIngress(&f, 0, (uint16_t) (kPortBase + i));
        twfRequire(lines[i] != NULL, "authenticated peer still occupied provisional ingress capacity");
        authenticate(&f, &clients[i], account, server_peer, lines[i]);
    }
    twfRequire(binding_map_t_size(&f.state->epochs) == kPeerCount, "server lost a live binding during growth");
    twfRequire(clients[0].first_peer->curr_keypair.keypair_millis == fixture_millis,
               "first transport key must use the fixture clock");
    measureTimer(&f);
    roundTrip(&f, &clients[0], lines[0], 0);
    roundTrip(&f, &clients[kPeerCount - 1], lines[kPeerCount - 1], kPeerCount - 1);

    user_t        *expired        = usersLookupByIdentifier(&f.users, kAccountIdBase);
    const uint64_t previous_epoch = wireguardserverSourceEpoch(f.state, &expired->wireguard_allowed_ip);
    twfRequire(previous_epoch != 0 && expired->runtime.active_cons_out == 1, "first account has no binding or flow");
    userSetClientViewExpiry(expired, fixture_millis + WIREGUARDIF_TIMER_MSECS, true);
    fixture_millis += WIREGUARDIF_TIMER_MSECS;
    wloopUpdateTime(f.env.loops[0]);
    wireguardserverTick(f.state->timer);
    wgServerFixturePump(&f);
    wireguardserverTick(f.state->timer);
    twfRequire(binding_map_t_size(&f.state->epochs) == kPeerCount - 1 &&
                   wireguardserverSourceEpoch(f.state, &expired->wireguard_allowed_ip) == 0 &&
                   expired->runtime.active_cons_out == 0,
               "expired account retained its binding or inner flow");
    roundTrip(&f, &clients[kPeerCount - 1], lines[kPeerCount - 1], kPeerCount - 1);
    userSetClientViewExpiry(expired, 0, false);
    wireguardDeviceDestroy(&clients[0]);
    authenticate(&f, &clients[0], expired, server_peer, lines[0]);
    twfRequire(binding_map_t_size(&f.state->epochs) == kPeerCount &&
                   wireguardserverSourceEpoch(f.state, &expired->wireguard_allowed_ip) > previous_epoch,
               "reactivated account did not obtain a new binding");
    roundTrip(&f, &clients[0], lines[0], 0);

    cJSON_Delete(server_peer);
    closeIngress(&f, pending);
    for (unsigned i = 0; i < kPeerCount; ++i)
    {
        wireguardDeviceDestroy(&clients[i]);
        closeIngress(&f, lines[i]);
    }
    memoryFree(clients);
    f.ingress[0] = NULL;
    wgServerFixtureClose(&f, wwLifecycleProcessShutdown());
    return 0;
}
