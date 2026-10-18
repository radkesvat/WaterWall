/*
 * Covers: one API response above 65 KiB through actual TcpOverUdpClient/Server.
 * Setup: one real event worker, both production reliable-stream nodes and
 * APIServer. A bounded test-only datagram wire drops each direction's first
 * packet and reverses pairs; a private registered operation returns binary data.
 * Checks: exact complete frame/body, a single dispatch after retransmission,
 * actual loss/reordering, borrowed-line and final job/budget settlement.
 * Limits: no sockets or randomized impairment; namespace cases cover transports
 * and real AuthenticationClient.status separately. Target lookup is a seam to a
 * private fixture operation, not a production API endpoint.
 * CTest: waterwall.apiserver_reliable_stream_unit
 */
#include "APIServer/structure.h"
#include "TcpOverUdpClient/interface.h"
#include "TcpOverUdpServer/interface.h"
#include "test_assert.h"
#include "wwapi.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kResponseBodySize = 70001,
    kWireCapacity     = 512,
    kReceiveCapacity  = 128 * 1024
};

typedef struct wire_queue_s
{
    sbuf_t  *packets[kWireCapacity];
    size_t   count;
    unsigned emitted;
    bool     dropped;
    bool     reordered;
} wire_queue_t;

static tunnel_t    *source, *client, *wire, *server, *api;
static tunnel_t     target;
static line_t      *connection;
static wire_queue_t queues[2];
static uint8_t      received[kReceiveCapacity];
static size_t       received_size;
static unsigned     dispatches;

node_api_target_status_t __wrap_nodemanagerResolveApiTarget(const char *config, const char *name, tunnel_t **out,
                                                            const char **resolved_config);

node_api_target_status_t __wrap_nodemanagerResolveApiTarget(const char *config, const char *name, tunnel_t **out,
                                                            const char **resolved_config)
{
    if ((config && strcmp(config, "fixture") != 0) || strcmp(name, "private-target") != 0)
        return kNodeApiTargetNotFound;
    *out = &target;
    if (resolved_config)
        *resolved_config = "fixture";
    return kNodeApiTargetFound;
}

static api_result_t largeBinary(tunnel_t *instance, sbuf_t *request, const node_api_call_context_t *context)
{
    static const uint8_t expected[] = {0, 0x7f, 0x80, 0xff};
    require(instance == &target && currentThreadIsEventWorkerWID(0), "Private handler ran on the wrong worker");
    require(context->max_response_body_size >= kResponseBodySize,
            "Handler received insufficient reserved response space");
    require(sbufGetLength(request) == sizeof(expected) &&
                memcmp(sbufGetRawPtr(request), expected, sizeof(expected)) == 0,
            "Reliable request reconstruction changed binary bytes");
    bufferpoolReuseBuffer(getCurrentEventWorkerBufferPool(), request);
    ++dispatches;
    sbuf_t *result = bufferpoolGetBestFit(getCurrentEventWorkerBufferPool(), kResponseBodySize, 0);
    for (size_t i = 0; i < kResponseBodySize; ++i)
        sbufGetMutablePtr(result)[i] = (uint8_t) i;
    sbufSetLength(result, kResponseBodySize);
    return (api_result_t) {.result_code = kApiResultOk, .buffer = result};
}

static const node_api_operation_t operation = {.name                  = "private-large",
                                               .handler               = largeBinary,
                                               .read_only             = true,
                                               .request_content_type  = "application/octet-stream",
                                               .response_content_type = "application/octet-stream",
                                               .response_encoding     = kNodeApiEncodingBase64,
                                               .execution             = kNodeApiSpecifiedWorker,
                                               .wid                   = 0};

static void previousEst(tunnel_t *tunnel, line_t *line)
{
    require(tunnel == source && line == connection, "Unexpected reliable stream establishment");
}

static void previousFinish(tunnel_t *tunnel, line_t *line)
{
    discard tunnel;
    discard line;
    require(false, "Reliable API stream closed before fixture owner cleanup");
}

static void previousPayload(tunnel_t *tunnel, line_t *line, sbuf_t *buffer)
{
    require(tunnel == source && line == connection, "Reply reached an unexpected source line");
    size_t length = sbufGetLength(buffer);
    require(length <= sizeof(received) - received_size, "API emitted more than the bounded expected reply");
    memcpy(received + received_size, sbufGetRawPtr(buffer), length);
    received_size += length;
    lineReuseBuffer(line, buffer);
}

static void queuePacket(size_t direction, line_t *line, sbuf_t *packet)
{
    wire_queue_t *queue = &queues[direction];
    require(line == connection, "Wire received a foreign line");
    require(++queue->emitted < 10000, "Reliable stream made no bounded progress");
    if (! queue->dropped)
    {
        queue->dropped = true;
        lineReuseBuffer(line, packet);
        return;
    }
    require(queue->count < kWireCapacity, "Test datagram queue overflowed");
    queue->packets[queue->count++] = packet;
}

static void wireUp(tunnel_t *tunnel, line_t *line, sbuf_t *packet)
{
    require(tunnel == wire, "Unexpected upstream wire");
    queuePacket(0, line, packet);
}

static void wireDown(tunnel_t *tunnel, line_t *line, sbuf_t *packet)
{
    require(tunnel == wire, "Unexpected downstream wire");
    queuePacket(1, line, packet);
}

static void flushWire(void)
{
    for (size_t direction = 0; direction < 2; ++direction)
    {
        wire_queue_t *queue = &queues[direction];
        sbuf_t       *batch[kWireCapacity];
        size_t        count = queue->count;
        memcpy(batch, queue->packets, count * sizeof(*batch));
        queue->count = 0; /* New/reentrant packets belong to the next bounded turn. */
        for (size_t i = 0; i < count; i += 2)
        {
            size_t pair = i + 1 < count ? 2 : 1;
            if (pair == 2)
                queue->reordered = true;
            for (size_t j = pair; j > 0; --j)
            {
                sbuf_t *packet = batch[i + j - 1];
                if (direction == 0)
                    tunnelNextUpStreamPayload(wire, connection, packet);
                else
                    tunnelPrevDownStreamPayload(wire, connection, packet);
            }
        }
    }
}

static bool responseComplete(void)
{
    if (received_size < 4)
        return false;
    uint32_t length =
        ((uint32_t) received[0] << 24) | ((uint32_t) received[1] << 16) | ((uint32_t) received[2] << 8) | received[3];
    require(length > 65535 && length <= kReceiveCapacity - 4,
            "API response length was truncated or exceeded its bound");
    require(received_size <= length + 4U, "Reliable stream duplicated bytes or interleaved another API frame");
    return received_size == length + 4U;
}

static void verifyResponse(void)
{
    require(responseComplete(), "Reliable stream did not reconstruct one complete API response");
    char *json_text = memoryAllocate(received_size - 4 + 1);
    memcpy(json_text, received + 4, received_size - 4);
    json_text[received_size - 4] = '\0';
    cJSON *json                  = cJSON_Parse(json_text);
    require(json && cJSON_IsNull(cJSON_GetObjectItemCaseSensitive(json, "error")),
            "Response contains a gateway failure");
    require(strcmp(cJSON_GetObjectItemCaseSensitive(json, "id")->valuestring, "large-reliable") == 0,
            "Response correlation changed during reconstruction");
    cJSON *result = cJSON_GetObjectItemCaseSensitive(json, "result");
    require(cJSON_GetObjectItemCaseSensitive(result, "code")->valueint == 0, "Private handler failed");
    const char *encoded = cJSON_GetObjectItemCaseSensitive(result, "body")->valuestring;
    uint8_t    *decoded = memoryAllocate(strlen(encoded));
    int         length  = wwBase64DecodeCanonical(encoded, (unsigned int) strlen(encoded), decoded, strlen(encoded));
    require(length == kResponseBodySize, "Large binary body was truncated or corrupted");
    for (size_t i = 0; i < kResponseBodySize; ++i)
        require(decoded[i] == (uint8_t) i, "Large binary body changed through reliable stream reconstruction");
    require(dispatches == 1, "Retransmission dispatched the same API request more than once");
    require(queues[0].dropped && queues[1].dropped && queues[1].reordered,
            "Fixture did not actually exercise deterministic loss and response reordering");
    memoryFree(decoded);
    cJSON_Delete(json);
    memoryFree(json_text);
}

int main(void)
{
    testCaseSet("apiserver_reliable_stream_test");
    static char            log_off[]    = "OFF";
    ww_construction_data_t init         = {.workers_count = 1, .ram_profile = 4, .mtu_size = 1500};
    init.internal_logger_data.log_level = log_off;
    init.core_logger_data.log_level     = log_off;
    init.network_logger_data.log_level  = log_off;
    init.dns_logger_data.log_level      = log_off;
    require(wwStartupSucceeded(createGlobalState(init)), "Real worker runtime construction failed");
    require(nodeApiRegister(&target, &operation, 1), "Private operation registration failed");
    node_t nodes[5]             = {{.type = stringDuplicate("PrivateSource"), .flags = kNodeFlagChainHead},
                                   nodeTcpOverUdpClientGet(),
                                   {.type = stringDuplicate("PrivateWire")},
                                   nodeTcpOverUdpServerGet(),
                                   nodeAPIServerGet()};
    nodes[1].node_settings_json = cJSON_Parse("{\"mtu\":1500}");
    nodes[3].node_settings_json = cJSON_Parse("{\"mtu\":1500}");
    nodes[4].node_settings_json = cJSON_Parse(
        "{\"clients\":[{\"name\":\"fixture-client\","
        "\"token\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
        "\"allow\":[{\"config\":\"fixture\",\"node\":\"private-target\",\"operations\":[\"private-large\"]}]}]}");
    source = tunnelCreate(&nodes[0], 0, 0);
    client = nodes[1].createHandle(&nodes[1]);
    wire   = tunnelCreate(&nodes[2], 0, 0);
    server = nodes[3].createHandle(&nodes[3]);
    api    = nodes[4].createHandle(&nodes[4]);
    require(source && client && wire && server && api, "Reliable stream tunnel construction failed");
    source->fnEstD            = previousEst;
    source->fnFinD            = previousFinish;
    source->fnPayloadD        = previousPayload;
    wire->fnPayloadU          = wireUp;
    wire->fnPayloadD          = wireDown;
    tunnel_t       *tunnels[] = {source, client, wire, server, api};
    tunnel_chain_t *chain     = tunnelchainCreate(1);
    uint32_t        offset    = 0;
    for (size_t i = 0; i < ARRAY_SIZE(tunnels); ++i)
    {
        if (i > 0)
            tunnelBind(tunnels[i - 1], tunnels[i]);
        tunnelchainInsert(chain, tunnels[i]);
        tunnels[i]->onIndex(tunnels[i], (uint16_t) i, &offset);
    }
    tunnelchainFinalize(chain);
    apiserverOnPrepair(api);
    nodeApiFreeze();
    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);
    connection = lineCreateForWorker(0, chain->line_pools, 0); /* Fixture source owns this normal line. */
    tunnelNextUpStreamInit(source, connection);
    static const char request[] =
        "{\"id\":\"large-reliable\",\"auth\":{\"client\":\"fixture-client\","
        "\"token\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"},"
        "\"selector\":{\"config\":\"fixture\",\"node\":\"private-target\"},\"operation\":\"private-large\","
        "\"content_type\":\"application/octet-stream\",\"body_encoding\":\"base64\",\"body\":\"AH+A/w==\"}";
    sbuf_t  *input = bufferpoolGetBestFit(lineGetBufferPool(connection), sizeof(request) + 3, 0);
    uint8_t *bytes = sbufGetMutablePtr(input);
    uint32_t size  = sizeof(request) - 1;
    bytes[0]       = (uint8_t) (size >> 24);
    bytes[1]       = (uint8_t) (size >> 16);
    bytes[2]       = (uint8_t) (size >> 8);
    bytes[3]       = (uint8_t) size;
    memcpy(bytes + 4, request, size);
    sbufSetLength(input, size + 4);
    tunnelNextUpStreamPayload(source, connection, input);
    uint64_t deadline = nodeApiNowMs() + 8000;
    while (! responseComplete() && nodeApiNowMs() < deadline)
    {
        discard wloopProcessEvents(getWorkerLoop(0), 0);
        flushWire();
        wwSleepMS(1);
    }
    verifyResponse();
    deadline = nodeApiNowMs() + 300;
    while (nodeApiNowMs() < deadline)
    {
        discard wloopProcessEvents(getWorkerLoop(0), 0);
        flushWire();
        wwSleepMS(1);
    }
    verifyResponse();
    nodeApiCloseAdmission();
    const ww_lifecycle_context_t *context = wwLifecycleStartupRollback();
    apiserverOnQuiesceRequest(api, context);
    apiserverOnWorkerQuiesce(api, 0, context);
    client->onQuiesceRequest(client, context);
    server->onQuiesceRequest(server, context);
    tunnelNextUpStreamFinish(source, connection);
    lineDestroy(connection);
    connection = NULL;
    for (size_t direction = 0; direction < 2; ++direction)
        for (size_t i = 0; i < queues[direction].count; ++i)
            bufferpoolReuseBuffer(getCurrentEventWorkerBufferPool(), queues[direction].packets[i]);
    apiserver_tstate_t *state = tunnelGetState(api);
    size_t              bytes_used, jobs;
    nodeApiDomainGetUsage(state->domain, &bytes_used, &jobs);
    require(bytes_used == 0 && jobs == 0 && atomic_load(&state->session_count) == 0,
            "Reliable API stream leaked sessions/jobs/reservations");
    for (size_t i = 0; i < ARRAY_SIZE(tunnels); ++i)
        tunnels[i]->onDestroy(tunnels[i], context);
    tunnelchainDestroy(chain);
    for (size_t i = 0; i < ARRAY_SIZE(nodes); ++i)
    {
        cJSON_Delete(nodes[i].node_settings_json);
        memoryFree(nodes[i].type);
    }
    nodeApiUnregister(&target);
    require(workerInstallApplicationQuiesceRequest(getWorker(0), context) != kWorkerQuiesceRequestUnavailable,
            "Worker zero quiescence request failed");
    workerPerformQuiesce(getWorker(0), context);
    require(workerRequestDrain(getWorker(0)), "Worker zero drain request failed");
    workerPerformDrain(getWorker(0), context);
    require(workerRequestTeardown(getWorker(0)), "Worker zero teardown request failed");
    workerPerformTeardown(getWorker(0));
    destroyGlobalState();
    puts("apiserver_reliable_stream_test: all cases passed");
    return 0;
}
