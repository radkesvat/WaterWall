/* Real client carrier ownership, endpoint-before-Init, retry throttling and
 * reentrant replacement. The generic carrier is an explicit synchronous fixture.
 * CTest: waterwall.wireguard_client_carrier_unit */
#include "../../../../../tunnels/WireGuardClient/client.c"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/user_runtime.h"

static unsigned carrier_inits, carrier_sends;
static bool     refuse_init, replace_on_send;
static unsigned carrier_receives;
static uint64_t received_carrier_id;

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
        tunnelPrevDownStreamEst(t, line);
    }
}
static void carrierPayload(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    ++carrier_sends;
    lineReuseBuffer(line, packet);
    if (replace_on_send)
    {
        replace_on_send = false;
        tunnelPrevDownStreamFinish(t, line);
        client_t *state = tunnelGetState(t->prev);
        state->last_attempt -= 400;
        twfRequire(ensureCarrier(state) != NULL, "reentrant replacement was refused");
    }
}
static void carrierFinish(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
}

int main(void)
{
    testCaseSet("wireguard_client_carrier_test");
    twfRequire(userTestRuntimeInitialize(), "runtime crypto setup failed");
    twf_worker_env_t environment;
    twfWorkerEnvSetup(&environment, 8192, 32);
    node_t node             = nodeWireGuardClientGet();
    node.node_settings_json = cJSON_Parse("{\"privatekey\":\"0MHoX6RogAEFxKF7c5E84tA1Qy3l9u8IzJfgcVt4B2Y=\","
                                          "\"peers\":[{\"publickey\":\"GnRcOavdc180YrXak138cZxWlMoEUZL0Mg/ZyWhLBgo=\","
                                          "\"allowedips\":\"0.0.0.0/0\",\"endpoint\":\"127.0.0.1:51820\"}]}");
    tunnel_t *client        = node.createHandle(&node);
    twfRequire(client != NULL, "client construction failed");
    client_t *state  = tunnelGetState(client);
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
    twfRequire(ensureCarrier(state) == NULL && state->carrier == NULL && carrier_inits == 1,
               "synchronous rejection leaked its owned normal line");
    twfRequire(ensureCarrier(state) == NULL && carrier_inits == 1, "rejection caused a tight carrier retry");
    refuse_init = false;
    state->last_attempt -= 400;
    line_t *first = ensureCarrier(state);
    twfRequire(first != NULL && state->established, "carrier did not recover after rejection");
    const uint64_t first_carrier_id = state->carrier_id;
    twfRequire(first_carrier_id != 0, "carrier cookie identity is absent");
    payloadDown(client, first, bufferpoolGetSmallBuffer(environment.pool));
    twfRequire(carrier_receives == 1 && received_carrier_id == first_carrier_id,
               "generic carrier receive required a numeric connector endpoint");
    lineRef(first);
    pauseDown(client, first);
    twfRequire(! output(state, bufferpoolGetSmallBuffer(environment.pool), NULL, NULL, 0) && carrier_sends == 0,
               "paused carrier emitted a datagram");
    resumeDown(client, first);
    replace_on_send = true;
    twfRequire(output(state, bufferpoolGetSmallBuffer(environment.pool), NULL, NULL, 0) && carrier_sends == 1 &&
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
    lineRef(replacement);
    finishDown(client, replacement);
    twfRequire(! lineIsAlive(replacement) && state->carrier == NULL, "owner Finish retained a live normal line");
    lineUnref(replacement);
    quiesceRequest(client, wwLifecycleProcessShutdown());
    destroy(client, wwLifecycleProcessShutdown());
    tunnelDestroy(sink);
    tunnelchainDestroy(chain);
    cJSON_Delete(node.node_settings_json);
    memoryFree(node.type);
    twfWorkerEnvTeardown(&environment);
    userTestRuntimeCleanup();
    return 0;
}
