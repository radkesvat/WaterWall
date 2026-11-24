/* Real client carrier ownership, endpoint-before-Init, handshake before Est,
 * retry throttling and reentrant replacement. The carrier fixture is synchronous.
 * CTest: waterwall.wireguard_client_carrier_unit */
#include "../../../../../tunnels/WireGuardClient/client.c"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/user_runtime.h"

static unsigned carrier_inits, carrier_sends;
static bool     refuse_init, pause_init, replace_on_send;
static unsigned carrier_receives;
static uint64_t received_carrier_id;
static uint32_t now_millis;

unsigned int __wrap_getTickMS(void);
unsigned int __wrap_getTickMS(void)
{
    return now_millis;
}

void __wrap_wireguardCommonReceiveOnCarrier(wireguard_device_t *device, sbuf_t *packet, uint64_t carrier_id);
void __wrap_wireguardCommonReceiveOnCarrier(wireguard_device_t *device, sbuf_t *packet, uint64_t carrier_id)
{
    discard device;
    ++carrier_receives;
    received_carrier_id = carrier_id;
    reuseBuffer(packet);
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
            pause_init      = false;
            client_t *state = tunnelGetState(t->prev);
            sbuf_t   *early = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
            twfRequire(! output(state, early, NULL, NULL, 0) && carrier_sends == 0,
                       "WireGuard output reentered an unfinished carrier Init");
            tunnelPrevDownStreamPause(t, line);
        }
    }
}
static void carrierPayload(tunnel_t *t, line_t *line, sbuf_t *packet)
{
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
        client_t *state = tunnelGetState(t->prev);
        now_millis += 400;
        twfRequire(ensureCarrier(state) != NULL, "reentrant replacement was refused");
    }
}
static void carrierFinish(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
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
            const client_t *state = tunnelGetState(client);
            twfRequireEqualU32(state->engine.padding_mtu, cases[i].expected, "client padding MTU");
            destroy(client, wwLifecycleStartupRollback());
        }
        cJSON_DeleteItemFromObjectCaseSensitive(node->node_settings_json, "mtu");
    }
}

int main(void)
{
    testCaseSet("wireguard_client_carrier_test");
    twfRequire(userTestRuntimeInitialize(), "runtime crypto setup failed");
    twfRequire(createNetworkLogger(NULL, false) != NULL, "logger setup failed");
    twf_worker_env_t environment;
    twfWorkerEnvSetup(&environment, 8192, 32);
    node_t node             = nodeWireGuardClientGet();
    node.node_settings_json = cJSON_Parse("{\"privatekey\":\"0MHoX6RogAEFxKF7c5E84tA1Qy3l9u8IzJfgcVt4B2Y=\","
                                          "\"peers\":[{\"publickey\":\"GnRcOavdc180YrXak138cZxWlMoEUZL0Mg/ZyWhLBgo=\","
                                          "\"allowedips\":\"0.0.0.0/0\",\"endpoint\":\"127.0.0.1:51820\"}]}");
    testClientMtu(&node);
    CORE_DEFAULT_MTU = 1500;
    tunnel_t *client = node.createHandle(&node);
    twfRequire(client != NULL, "client construction failed");
    client_t *state = tunnelGetState(client);
    twfRequireEqualU32(state->engine.padding_mtu, 1420, "client default padding MTU");
    tunnel_t *sink   = tunnelCreate(NULL, 0, 0);
    sink->fnInitU    = carrierInit;
    sink->fnPayloadU = carrierPayload;
    sink->fnFinU     = carrierFinish;
    tunnelBind(client, sink);
    tunnel_chain_t *chain       = tunnelchainCreate(1);
    chain->sum_line_state_size  = client->lstate_size;
    chain->contains_packet_node = true;
    tunnelchainFinalize(chain);
    client->chain = sink->chain = chain;
    refuse_init                 = true;
    /* The worker sampled its clock before a long callback in the same batch. */
    getCurrentWorkerLoop()->cur_hrtime = 1000000;
    now_millis                         = 1500;
    twfRequire(ensureCarrier(state) == NULL && state->carrier == NULL && carrier_inits == 1,
               "synchronous rejection leaked its owned normal line");
    now_millis                         = 1899;
    getCurrentWorkerLoop()->cur_hrtime = (uint64_t) now_millis * 1000U;
    twfRequire(ensureCarrier(state) == NULL && carrier_inits == 1, "loop clock refresh shortened the 400 ms retry gap");
    refuse_init   = false;
    pause_init    = true;
    now_millis    = 1900;
    line_t *first = ensureCarrier(state);
    twfRequire(first != NULL, "carrier did not recover after rejection");
    const uint64_t first_carrier_id = state->carrier_id;
    twfRequire(first_carrier_id != 0, "carrier cookie identity is absent");
    sendInner(client, bufferpoolGetSmallBuffer(environment.pool), NULL);
    twfRequire(state->pending_count == 1 && carrier_sends == 0, "inner packets escaped before the WireGuard handshake");

    twfRequire(! output(state, bufferpoolGetSmallBuffer(environment.pool), NULL, NULL, 0) && carrier_sends == 0,
               "Pause during Init did not suppress carrier output");
    tunnelPrevDownStreamResume(sink, first);
    state->engine.first_peer->active = true;
    wireguardCommonLoop(&state->engine);
    twfRequire(carrier_sends == 1, "WireGuard handshake did not start before Est");
    twfRequire(carrier_receives == 1 && received_carrier_id == first_carrier_id,
               "handshake reply before Est failed on the exact carrier with a nonnumeric endpoint");
    twfRequire(state->pending_count == 1 && ! sessionReady(state), "carrier output bypassed the WireGuard key gate");

    lineRef(first);
    tunnelPrevDownStreamPause(sink, first);
    tunnelPrevDownStreamEst(sink, first);
    tunnelPrevDownStreamEst(sink, first);
    twfRequire(! output(state, bufferpoolGetSmallBuffer(environment.pool), NULL, NULL, 0) && carrier_sends == 1,
               "late or repeated Est admitted writes on a paused carrier");
    tunnelPrevDownStreamResume(sink, first);
    replace_on_send = true;
    twfRequire(output(state, bufferpoolGetSmallBuffer(environment.pool), NULL, NULL, 0) && carrier_sends == 2 &&
                   state->carrier != NULL && state->carrier != first,
               "old carrier completion cleared its reentrant replacement");
    twfRequire(state->carrier_id != first_carrier_id && state->carrier_id != 0,
               "replacement carrier reused a cookie identity");
    payloadDown(client, first, bufferpoolGetSmallBuffer(environment.pool));
    twfRequire(carrier_receives == 1, "stale carrier delivered a datagram to the current protocol engine");
    lineUnref(first);
    line_t *replacement = state->carrier;
    payloadDown(client, replacement, bufferpoolGetSmallBuffer(environment.pool));
    twfRequire(carrier_receives == 2 && received_carrier_id == state->carrier_id,
               "replacement carrier did not use its own cookie identity");
    quiesceRequest(client, wwLifecycleProcessShutdown());
    twfRequire(! output(state, bufferpoolGetSmallBuffer(environment.pool), NULL, NULL, 0) && carrier_sends == 2,
               "quiesced carrier admitted a new write");
    payloadDown(client, replacement, bufferpoolGetSmallBuffer(environment.pool));
    twfRequire(carrier_receives == 2, "quiesced carrier admitted new input");
    lineRef(replacement);
    finishDown(client, replacement);
    twfRequire(! lineIsAlive(replacement) && state->carrier == NULL, "owner Finish retained a live normal line");
    lineUnref(replacement);
    stopWorker(client, 0, wwLifecycleProcessShutdown());
    destroy(client, wwLifecycleProcessShutdown());
    tunnelDestroy(sink);
    tunnelchainDestroy(chain);
    cJSON_Delete(node.node_settings_json);
    memoryFree(node.type);
    twfWorkerEnvTeardown(&environment);
    networkloggerDestroy();
    userTestRuntimeCleanup();
    return 0;
}
