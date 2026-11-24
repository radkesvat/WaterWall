/* Client carrier ownership, endpoint validation, retry throttling, reentrant
 * replacement, and pending packets across key refusal and deadline expiry.
 * CTest: waterwall.wireguard_client_carrier_unit */
#include "WireGuardClient/structure.h"
#define __wrap_bufferpoolReuseBuffer carrierLedgerRecycle
#include "fixtures/failure/tunnel_orderly_shutdown_harness.h"
#undef __wrap_bufferpoolReuseBuffer
#include "fixtures/user_runtime.h"
#include "loggers/network_logger.h"

static unsigned carrier_inits, carrier_sends;
static bool     refuse_init, pause_init, replace_on_send;
static unsigned carrier_receives;
static uint64_t received_carrier_id;
static uint32_t now_millis;
static unsigned clock_reads_until_advance;
static uint32_t advance_clock_to;

static buffer_pool_t *expected_recycle_pool;
static uintptr_t      expected_refused_packet;

static wireguard_device_t remote_engine;
static ip_addr_t          carrier_source;
static sbuf_t            *remote_response;
static char               delivered_ids[16];
static size_t             delivered_count;
static char               nested_packet_id;

void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *packet);
void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *packet)
{
    if (expected_recycle_pool != NULL)
    {
        twfRequire(currentThreadOwnsWorker(0) && pool == expected_recycle_pool,
                   "client queue drop used a pool outside the receiving worker");
        if ((uintptr_t) packet == expected_refused_packet)
            expected_refused_packet = 0;
    }
    carrierLedgerRecycle(pool, packet);
}

static void setTime(uint32_t millis)
{
    getCurrentWorkerLoop()->cur_hrtime = (uint64_t) millis * 1000U;
    now_millis                         = millis;
}

unsigned int __wrap_getTickMS(void);
unsigned int __wrap_getTickMS(void)
{
    if (clock_reads_until_advance != 0 && --clock_reads_until_advance == 0)
        setTime(advance_clock_to);
    return now_millis;
}

bool __wrap_isSystemUnderLoad(double threshold);
bool __wrap_isSystemUnderLoad(double threshold)
{
    discard threshold;
    return false;
}

void __real_wireguardCommonReceiveOnCarrier(wireguard_device_t *device, sbuf_t *packet, uint64_t carrier_id);
void __wrap_wireguardCommonReceiveOnCarrier(wireguard_device_t *device, sbuf_t *packet, uint64_t carrier_id);
void __wrap_wireguardCommonReceiveOnCarrier(wireguard_device_t *device, sbuf_t *packet, uint64_t carrier_id)
{
    if (remote_engine.first_peer != NULL)
    {
        __real_wireguardCommonReceiveOnCarrier(device, packet, carrier_id);
        return;
    }
    ++carrier_receives;
    received_carrier_id = carrier_id;
    reuseBuffer(packet);
}

static sbuf_t *makeInnerPacket(buffer_pool_t *pool, char id)
{
    const uint8_t bytes[] = {0x45, 0, 0, 21, 0, 0, 0, 0, 64, 253, 0, 0, 10, 1, 0, 1, 10, 1, 0, 2, (uint8_t) id};
    sbuf_t       *packet  = bufferpoolGetSmallBuffer(pool);
    sbufWrite(packet, bytes, sizeof(bytes));
    sbufSetLength(packet, sizeof(bytes));
    return packet;
}

static size_t submitInnerPacket(tunnel_t *client, char id)
{
    sbuf_t      *packet = makeInnerPacket(getCurrentWorkerBufferPool(), id);
    const size_t charge = sbufGetAllocationCharge(packet);
    wireguardclientSendInner(client, packet, NULL);
    return charge;
}

static void carrierInit(tunnel_t *t, line_t *line)
{
    ++carrier_inits;
    const address_context_t *destination = lineGetDestinationAddressContext(line);
    twfRequire(! addresscontextDestinationIsPinned(destination) && destination->port == 51820 &&
                   addresscontextClassifyTransport(destination) == kAddressContextTransportUdp &&
                   addresscontextIsIpType(destination),
               "carrier Init did not receive overridable initial UDP destination metadata");
    if (refuse_init)
        tunnelPrevDownStreamFinish(t, line);
    else
    {
        /* A proxy can retain an unresolved logical hostname while selecting a
         * different physical transport. Client receive must not inspect it. */
        address_context_t *selected = lineGetDestinationAddressContext(line);
        addresscontextReset(selected);
        addresscontextDomainSet(selected, "relay.example.invalid", 21);
        addresscontextSetPort(selected, 443);
        addresscontextSetOnlyProtocol(selected, IP_PROTO_TCP);
        if (pause_init)
        {
            pause_init                      = false;
            wireguardclient_tstate_t *state = tunnelGetState(t->prev);
            sbuf_t                   *early = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
            twfRequire(! state->engine.callbacks.output(state, early, NULL, NULL, 0) && carrier_sends == 0,
                       "WireGuard output reentered an unfinished carrier Init");
            tunnelPrevDownStreamPause(t, line);
        }
    }
}
static void carrierPayload(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    if (remote_engine.first_peer != NULL)
    {
        wireguardCommonReceive(&remote_engine, packet, &carrier_source, 51820);
        if (nested_packet_id != 0)
        {
            const char id    = nested_packet_id;
            nested_packet_id = 0;
            /* Advance on the nested fresh packet's final key check. */
            clock_reads_until_advance = 2;
            advance_clock_to          = now_millis + 1U;
            discard submitInnerPacket(t->prev, id);
        }
        return;
    }
    ++carrier_sends;
    if (carrier_sends == 1)
    {
        twfRequire(wireguardGetMessageType(sbufGetRawPtr(packet), sbufGetLength(packet)) ==
                       MESSAGE_HANDSHAKE_INITIATION,
                   "the first carrier payload was not a WireGuard handshake");
        tunnelPrevDownStreamPayload(t, line, bufferpoolGetSmallBuffer(lineGetBufferPool(line)));
    }
    lineReuseBuffer(line, packet);
    if (replace_on_send)
    {
        replace_on_send = false;
        tunnelPrevDownStreamFinish(t, line);
        wireguardclient_tstate_t *state = tunnelGetState(t->prev);
        now_millis += 400;
        twfRequire(wireguardclientEnsureCarrier(state) != NULL, "reentrant replacement was refused");
    }
}
static void carrierFinish(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
}

static bool captureHandshakeResponse(void *context, sbuf_t *packet, wireguard_peer_t *peer, const ip_addr_t *ip,
                                     uint16_t port)
{
    discard context;
    discard peer;
    discard ip;
    discard port;
    twfRequire(remote_response == NULL &&
                   wireguardGetMessageType(sbufGetRawPtr(packet), sbufGetLength(packet)) == MESSAGE_HANDSHAKE_RESPONSE,
               "remote peer did not produce exactly one handshake response");
    remote_response = packet;
    return true;
}

static void receiveInnerPacket(void *context, sbuf_t *packet, wireguard_peer_t *peer)
{
    discard context;
    discard peer;
    twfRequire(sbufGetLength(packet) == 21 && delivered_count < ARRAY_SIZE(delivered_ids),
               "remote peer received an unexpected inner packet");
    delivered_ids[delivered_count++] = (char) sbufGetRawPtr(packet)[20];
    reuseBuffer(packet);
}

static void setUpRemotePeer(void)
{
    twfRequire(ipaddr_aton("192.0.2.1", &carrier_source), "test carrier source address is invalid");
    const wireguard_callbacks_t callbacks = {.output = captureHandshakeResponse, .inner = receiveInnerPacket};
    twfRequire(wireguardCommonInit(&remote_engine, "EBJOHctLU2w8uteyTE+WU0hruB09Ub0vwVS+Gt9wAls=", NULL, callbacks),
               "remote peer could not initialize");
    cJSON *settings =
        cJSON_Parse("{\"publickey\":\"dDUfRvZSDy8jZBsB4kQflTO+iwlLbR+jgb840fumqUM=\",\"allowedips\":\"10.1.0.1/32\"}");
    size_t index;
    twfRequire(wireguardCommonAddConfiguredPeer(&remote_engine, settings, &index), "remote peer configuration failed");
    cJSON_Delete(settings);
}

static void finishHandshake(wireguardclient_tstate_t *state)
{
    sbuf_t *response = remote_response;
    twfRequire(response != NULL, "remote peer did not return a handshake response");
    remote_response = NULL;
    tunnelDownStreamPayload(state->tunnel, state->carrier, response);
    twfRequire(wireguardCommonPeerCanSend(state->engine.first_peer), "handshake did not install a usable key");
}

static void renewKey(wireguardclient_tstate_t *state)
{
    twfRequire(wireguardifStartHandshake(&state->engine, state->engine.first_peer, true) == ERR_OK,
               "client could not send a new handshake");
    finishHandshake(state);
}

static void expectPending(const wireguardclient_tstate_t *state, unsigned count, size_t charge, const char *message)
{
    twfRequire(state->pending_count == count && state->pending_charge == charge, message);
}

static void expectDelivery(const wireguardclient_tstate_t *state, const char *ids)
{
    expectPending(state, 0, 0, "delivered or expired packets left pending queue charge");
    twfRequire(delivered_count == strlen(ids) && memoryEqual(delivered_ids, ids, delivered_count),
               "remote peer received missing, duplicate, stale or out-of-order packets");
    delivered_count = 0;
    twfRequireNoLeakedBuffers();
}

static void testCrossWorkerPendingDiscard(tos_worker_env_t *environment, wireguardclient_tstate_t *state)
{
    twfRequireNoLeakedBuffers();
    const uint32_t expiry = now_millis + REKEY_ATTEMPT_TIME * 1000U;
    const unsigned limit  = ARRAY_SIZE(state->pending);
    tunnel_t      *client = state->tunnel;
    line_t        *input  = tunnelchainGetWorkerPacketLine(client->chain, 1);
    size_t         charge = 0;

    testWorkerBindWID(1);
    for (unsigned i = 0; i < limit; ++i)
    {
        sbuf_t *packet = makeInnerPacket(lineGetBufferPool(input), 'q');
        charge += sbufGetAllocationCharge(packet);
        tunnelUpStreamPayload(client, input, packet);
    }
    testWorkerBindWID(0);
    expectPending(state, 0, 0, "worker 1 modified the pending queue before owner dispatch");
    twfRequire(atomicLoad(&state->dispatch.count) == limit, "worker 0 did not receive every cross-worker submission");
    tosPumpWorker(environment, 0);
    expectPending(state, limit, charge, "worker 0 did not retain the worker-1 packets with their allocation charges");

    setTime(expiry - 1U);
    testWorkerBindWID(1);
    sbuf_t *excess          = makeInnerPacket(lineGetBufferPool(input), 'r');
    expected_refused_packet = (uintptr_t) excess;
    tunnelUpStreamPayload(client, input, excess);
    testWorkerBindWID(0);
    expected_recycle_pool = environment->pools[0];
    tosPumpWorker(environment, 0);
    expectPending(state, limit, charge, "full queue admitted a fresh packet");
    twfRequire(expected_refused_packet == 0, "full queue did not recycle the refused packet");
    twfRequire(atomicLoad(&state->dispatch.count) == 0 && atomicLoad(&state->dispatch.bytes) == 0,
               "owner dispatch retained accounting after full-queue refusal");

    setTime(expiry);
    const uint32_t recycles_before_expiry = twfRecycleCount();
    wireguardclientFlushPending(state);
    expected_recycle_pool = NULL;
    expectPending(state, 0, 0, "expired worker-1 packets retained queue accounting");
    twfRequireEqualU32(twfRecycleCount() - recycles_before_expiry, limit, "expiry did not recycle every packet once");
    twfRequireNoLeakedBuffers();
}

static void testPendingExpiry(wireguardclient_tstate_t *state)
{
    const uint32_t    window = REKEY_ATTEMPT_TIME * 1000U;
    wireguard_peer_t *peer   = state->engine.first_peer;

    setTime(0);
    state->tunnel->onStart(state->tunnel);
    twfRequire(state->timer != NULL, "client timer setup failed");
    const size_t idle_charge = submitInnerPacket(state->tunnel, 'a');
    setTime(window - 1U);
    state->timer->cb((wevent_t *) state->timer);
    expectPending(state, 1, idle_charge, "timer expired the idle queue at 89,999 ms");
    setTime(window);
    state->timer->cb((wevent_t *) state->timer);
    expectPending(state, 0, 0, "timer did not expire the idle queue at 90,000 ms");
    finishHandshake(state);
    expectDelivery(state, "");

    setTime(now_millis + 1000U);
    peer->curr_keypair.sending_valid = false;
    discard submitInnerPacket(state->tunnel, 'b');
    setTime(now_millis + window);
    renewKey(state);
    expectDelivery(state, "");

    setTime(now_millis + 1000U);
    peer->curr_keypair.sending_valid = false;
    discard submitInnerPacket(state->tunnel, 'c');
    setTime(now_millis + window);
    const size_t fresh_charge = submitInnerPacket(state->tunnel, 'd');
    expectPending(state, 1, fresh_charge, "new demand retained packets from an expired queue");
    renewKey(state);
    expectDelivery(state, "d");

    setTime(UINT32_MAX - window / 2);
    peer->curr_keypair.sending_valid = false;
    const size_t first_charge        = submitInnerPacket(state->tunnel, 'e');
    setTime(now_millis + window - 1U);
    const size_t second_charge = submitInnerPacket(state->tunnel, 'f');
    expectPending(state, 2, first_charge + second_charge, "clock wrap expired the queue before 90,000 ms");
    setTime(now_millis + 1U);
    renewKey(state);
    expectDelivery(state, "ef");
}

static void testKeyRefusal(wireguardclient_tstate_t *state)
{
    const uint32_t       key_lifetime = REJECT_AFTER_TIME * 1000U;
    wireguard_keypair_t *key          = &state->engine.first_peer->curr_keypair;

    setTime(key->keypair_millis + key_lifetime);
    size_t charge = submitInnerPacket(state->tunnel, 'g');
    expectPending(state, 1, charge, "fresh packet was lost with an already-expired key");
    renewKey(state);
    expectDelivery(state, "g");

    setTime(key->keypair_millis + key_lifetime - 1U);
    clock_reads_until_advance = 2; /* Admission, then the engine's key check. */
    advance_clock_to          = now_millis + 1U;
    charge                    = submitInnerPacket(state->tunnel, 'h');
    expectPending(state, 1, charge, "fresh packet was lost when its key expired after admission");
    renewKey(state);
    expectDelivery(state, "h");

    setTime(key->keypair_millis + key_lifetime - 1U);
    key->sending_valid = false;
    charge             = submitInnerPacket(state->tunnel, 'i');
    charge += submitInnerPacket(state->tunnel, 'j');
    const uint32_t demand_time = now_millis;
    key->sending_valid         = true;
    clock_reads_until_advance  = 3; /* Queue age, admission, then the engine's key check. */
    advance_clock_to           = now_millis + 1U;
    wireguardclientFlushPending(state);
    expectPending(state, 2, charge, "final key refusal lost or double-charged the queue head");
    twfRequire(state->pending_demand_millis == demand_time, "restoring the queue head renewed its deadline");
    renewKey(state);
    expectDelivery(state, "ij");

    setTime(key->keypair_millis + key_lifetime - 1U);
    nested_packet_id = 'l';
    charge           = submitInnerPacket(state->tunnel, 'k');
    expectPending(state, 1, charge, "nested key refusal escaped its send or charged the wrong packet");
    renewKey(state);
    expectDelivery(state, "kl");
}

static void testClientEndpoint(node_t *node)
{
    static const struct
    {
        const char *text;
        uint16_t    port;
        uint8_t     family;
    } cases[] = {
        {"[2001:db8::1]:443", 443, IPADDR_TYPE_V6},
        {"192.0.2.1:443", 443, IPADDR_TYPE_V4},
        {"vpn.example.com:443", 443, IPADDR_TYPE_ANY},
        {"192.0.2.1:1", 1, IPADDR_TYPE_V4},
        {"[::1]:65535", 65535, IPADDR_TYPE_V6},
        {.text = "2001:db8::1:443"},
        {.text = "[2001:db8::1:443"},
        {.text = "2001:db8::1]:443"},
        {.text = "vpn[.example.com:443"},
        {.text = "[2001:db8::1]extra:443"},
        {.text = "[2001:db8::1x]:443"},
        {.text = "[vpn.example.com]:443"},
        {.text = "[192.0.2.1]:443"},
        {.text = ":443"},
        {.text = "vpn.example.com:"},
        {.text = "vpn.example.com:0"},
        {.text = "vpn.example.com:65536"},
        {.text = "vpn.example.com:+443"},
        {.text = "vpn.example.com: 443"},
        {.text = "vpn.example.com:443 "},
        {.text = "vpn.example.com:443x"},
    };
    cJSON *peers    = cJSON_GetObjectItemCaseSensitive(node->node_settings_json, "peers");
    cJSON *endpoint = cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(peers, 0), "endpoint");
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        twfRequire(cJSON_SetValuestring(endpoint, cases[i].text) != NULL, "could not set test endpoint");
        tunnel_t *client = node->createHandle(node);
        twfRequire((client != NULL) == (cases[i].port != 0), cases[i].text);
        if (client == NULL)
            continue;

        const wireguardclient_tstate_t *state = tunnelGetState(client);
        twfRequireEqualU32(state->endpoint.port, cases[i].port, "client endpoint port");
        if (cases[i].family == IPADDR_TYPE_ANY)
        {
            twfRequire(addresscontextIsDomain(&state->endpoint) && ! state->endpoint.domain_resolved,
                       "client endpoint should remain an unresolved hostname");
            twfRequireEqualText(state->endpoint.domain, "vpn.example.com", "client endpoint hostname");
        }
        else
        {
            twfRequire(addresscontextIsIpType(&state->endpoint), "client endpoint should be an IP address");
            twfRequireEqualU32(state->endpoint.ip_address.type, cases[i].family, "client endpoint IP family");
        }
        client->onDestroy(client, wwLifecycleStartupRollback());
    }
    twfRequire(cJSON_SetValuestring(endpoint, "127.0.0.1:51820") != NULL, "could not restore carrier test endpoint");
}

static void testClientMtu(node_t *node)
{
    static const struct
    {
        const char *json;
        uint16_t    expected;
    } cases[] = {{NULL, 1280}, {"68", 68}, {"65535", 65535}, {"67", 0}, {"65536", 0}, {"1420.5", 0}, {"\"1420\"", 0}};
    CORE_DEFAULT_MTU = 1280;
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        if (cases[i].json != NULL)
            cJSON_AddItemToObject(node->node_settings_json, "mtu", cJSON_Parse(cases[i].json));
        tunnel_t *client = node->createHandle(node);
        twfRequire((client != NULL) == (cases[i].expected != 0), "client MTU range or type validation failed");
        if (client != NULL)
        {
            const wireguardclient_tstate_t *state = tunnelGetState(client);
            twfRequireEqualU32(state->engine.padding_mtu, cases[i].expected, "client padding MTU");
            client->onDestroy(client, wwLifecycleStartupRollback());
        }
        cJSON_DeleteItemFromObjectCaseSensitive(node->node_settings_json, "mtu");
    }
}

int main(void)
{
    testCaseSet("wireguard_client_carrier_test");
    twfRequire(userTestRuntimeInitialize(), "runtime crypto setup failed");
    twfRequire(createNetworkLogger(NULL, false) != NULL, "logger setup failed");
    tos_worker_env_t environment;
    testSpliceInventoryInitialize(32);
    tosWorkerEnvSetup(&environment, 2, 8192, kTwfDefaultSmallBufferSize);
    node_t node             = nodeWireGuardClientGet();
    node.node_settings_json = cJSON_Parse("{\"privatekey\":\"0MHoX6RogAEFxKF7c5E84tA1Qy3l9u8IzJfgcVt4B2Y=\","
                                          "\"peers\":[{\"publickey\":\"GnRcOavdc180YrXak138cZxWlMoEUZL0Mg/ZyWhLBgo=\","
                                          "\"allowedips\":\"0.0.0.0/0\",\"endpoint\":\"127.0.0.1:51820\"}]}");
    testClientMtu(&node);
    testClientEndpoint(&node);
    CORE_DEFAULT_MTU = 1500;
    tunnel_t *client = node.createHandle(&node);
    twfRequire(client != NULL, "client construction failed");
    wireguardclient_tstate_t *state = tunnelGetState(client);
    twfRequireEqualU32(state->engine.padding_mtu, 1420, "client default padding MTU");
    tunnel_t *sink   = tunnelCreate(NULL, 0, 0);
    sink->fnInitU    = carrierInit;
    sink->fnPayloadU = carrierPayload;
    sink->fnFinU     = carrierFinish;
    tunnelBind(client, sink);
    tunnel_chain_t *chain       = tunnelchainCreate(environment.count);
    chain->sum_line_state_size  = client->lstate_size;
    chain->sum_padding_left     = 32;
    chain->contains_packet_node = true;
    tunnelchainFinalize(chain);
    client->chain = sink->chain = chain;
    refuse_init                 = true;
    /* The worker sampled its clock before a long callback in the same batch. */
    getCurrentWorkerLoop()->cur_hrtime = 1000000;
    now_millis                         = 1500;
    twfRequire(wireguardclientEnsureCarrier(state) == NULL && state->carrier == NULL && carrier_inits == 1,
               "synchronous rejection leaked its owned normal line");
    now_millis                         = 1899;
    getCurrentWorkerLoop()->cur_hrtime = (uint64_t) now_millis * 1000U;
    twfRequire(wireguardclientEnsureCarrier(state) == NULL && carrier_inits == 1,
               "loop clock refresh shortened the 400 ms retry gap");
    refuse_init   = false;
    pause_init    = true;
    now_millis    = 1900;
    line_t *first = wireguardclientEnsureCarrier(state);
    twfRequire(first != NULL, "carrier did not recover after rejection");
    const uint64_t first_carrier_id = state->carrier_id;
    twfRequire(first_carrier_id != 0, "carrier cookie identity is absent");
    wireguardclientSendInner(client, bufferpoolGetSmallBuffer(environment.pools[0]), NULL);
    twfRequire(state->pending_count == 1 && carrier_sends == 0, "inner packets escaped before the WireGuard handshake");

    twfRequire(! state->engine.callbacks.output(state, bufferpoolGetSmallBuffer(environment.pools[0]), NULL, NULL, 0) &&
                   carrier_sends == 0,
               "Pause during Init did not suppress carrier output");
    tunnelPrevDownStreamResume(sink, first);
    state->engine.first_peer->active = true;
    wireguardCommonLoop(&state->engine);
    twfRequire(carrier_sends == 1, "WireGuard handshake did not start before Est");
    twfRequire(carrier_receives == 1 && received_carrier_id == first_carrier_id,
               "handshake reply before Est failed on the exact carrier with a nonnumeric endpoint");
    twfRequire(state->pending_count == 1 && ! wireguardCommonPeerCanSend(state->engine.first_peer),
               "carrier output bypassed the WireGuard key gate");

    lineRef(first);
    tunnelPrevDownStreamPause(sink, first);
    tunnelPrevDownStreamEst(sink, first);
    tunnelPrevDownStreamEst(sink, first);
    twfRequire(! state->engine.callbacks.output(state, bufferpoolGetSmallBuffer(environment.pools[0]), NULL, NULL, 0) &&
                   carrier_sends == 1,
               "late or repeated Est admitted writes on a paused carrier");
    tunnelPrevDownStreamResume(sink, first);
    replace_on_send = true;
    twfRequire(state->engine.callbacks.output(state, bufferpoolGetSmallBuffer(environment.pools[0]), NULL, NULL, 0) &&
                   carrier_sends == 2 && state->carrier != NULL && state->carrier != first,
               "old carrier completion cleared its reentrant replacement");
    twfRequire(state->carrier_id != first_carrier_id && state->carrier_id != 0,
               "replacement carrier reused a cookie identity");
    tunnelDownStreamPayload(client, first, bufferpoolGetSmallBuffer(environment.pools[0]));
    twfRequire(carrier_receives == 1, "stale carrier delivered a datagram to the current protocol engine");
    lineUnref(first);
    line_t *replacement = state->carrier;
    tunnelDownStreamPayload(client, replacement, bufferpoolGetSmallBuffer(environment.pools[0]));
    twfRequire(carrier_receives == 2 && received_carrier_id == state->carrier_id,
               "replacement carrier did not use its own cookie identity");
    wireguardclientDiscardPending(state);
    testCrossWorkerPendingDiscard(&environment, state);
    setUpRemotePeer();
    testPendingExpiry(state);
    testKeyRefusal(state);
    wireguardDeviceDestroy(&remote_engine);
    client->onQuiesceRequest(client, wwLifecycleProcessShutdown());
    client->onWorkerQuiesce(client, 0, wwLifecycleProcessShutdown());
    twfRequire(! state->engine.callbacks.output(state, bufferpoolGetSmallBuffer(environment.pools[0]), NULL, NULL, 0) &&
                   carrier_sends == 2,
               "quiesced carrier admitted a new write");
    tunnelDownStreamPayload(client, replacement, bufferpoolGetSmallBuffer(environment.pools[0]));
    twfRequire(carrier_receives == 2, "quiesced carrier admitted new input");
    lineRef(replacement);
    tunnelDownStreamFin(client, replacement);
    twfRequire(! lineIsAlive(replacement) && state->carrier == NULL, "owner Finish retained a live normal line");
    lineUnref(replacement);
    client->onWorkerStop(client, 0, wwLifecycleProcessShutdown());
    client->onDestroy(client, wwLifecycleProcessShutdown());
    tunnelDestroy(sink);
    tunnelchainDestroy(chain);
    cJSON_Delete(node.node_settings_json);
    memoryFree(node.type);
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();
    tosWorkerEnvTeardown(&environment);
    for (wid_t wid = 0; wid < environment.count; ++wid)
    {
        threadsafegenericpoolDestroy(environment.wios_pools[wid]);
        master_pool_t *masters[] = {environment.large_masters[wid],
                                    environment.medium_masters[wid],
                                    environment.small_masters[wid],
                                    environment.splice_masters[wid]};
        for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
        {
            masterpoolMakeEmpty(masters[i]);
            masterpoolDestroy(masters[i]);
        }
    }
    masterpoolMakeEmpty(environment.message_master);
    masterpoolDestroy(environment.message_master);
    masterpoolMakeEmpty(environment.wios_master);
    masterpoolDestroy(environment.wios_master);
    GSTATE.masterpool_messages = NULL;
    networkloggerDestroy();
    userTestRuntimeCleanup();
    return 0;
}
