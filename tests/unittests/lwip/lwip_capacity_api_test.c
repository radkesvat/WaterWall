/*
 * Covers: the registered process-wide stack-stats operation on a real event
 * worker, with live pool, ordinary/recovery retained-storage and port reservations. Checks exact
 * counters/schema, bounded empty-object input, deadline/working/result refusal,
 * exactly-once request recycling, unregister and production shutdown.
 * Setup: one real runtime worker; bufferpoolReuseBuffer is wrapped only to count
 * request settlement and validate its owning pool. No lines, sockets or traffic.
 * CTest: waterwall.lwip_capacity_api_unit (Debug and Release).
 */
#include "wwapi.h"

#include "lwip/capacity.h"
#include "lwip/capacity_api.h"
#include "lwip/memp.h"
#include "lwip/port_registry.h"
#include "worker_messages.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static tunnel_t                        target;
static const node_api_operation_t     *operation;
static sbuf_t                         *watched_request;
static unsigned                        request_recycles;
static bool                            completed;
static const ww_lwip_capacity_config_t configuration = {
    .memory_budget = 2U * 1024U * 1024U,
    .tcp_flows     = 3,
    .udp_flows     = 5,
    .tcp_listeners = 7,
    .tcp_segments  = 11,
    .rx_wrappers   = 13,
};

void __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer);
void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer);
void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer)
{
    if (buffer == watched_request)
    {
        require(pool == getCurrentWorkerBufferPool(), "request recycled through a foreign pool");
        ++request_recycles;
        watched_request = NULL;
    }
    __real_bufferpoolReuseBuffer(pool, buffer);
}

static node_api_call_context_t context(void)
{
    return (node_api_call_context_t) {.operation                = "stack-stats",
                                      .principal                = "monitor",
                                      .deadline_ms              = nodeApiNowMs() + 5000,
                                      .max_response_body_size   = 32768,
                                      .working_memory_allowance = 256U * 1024U};
}

static api_result_t invoke(const void *body, size_t length, const node_api_call_context_t *ctx)
{
    buffer_pool_t *pool    = getCurrentWorkerBufferPool();
    sbuf_t        *request = bufferpoolGetBestFit(pool, length, 0);
    sbufSetLength(request, length);
    if (length != 0)
        memoryCopy(sbufGetMutablePtr(request), body, length);
    watched_request     = request;
    request_recycles    = 0;
    api_result_t result = operation->handler(&target, request, ctx);
    require(watched_request == NULL && request_recycles == 1, "handler did not consume its request exactly once");
    return result;
}

static cJSON *parseResult(api_result_t result, enum api_result_e expected)
{
    require(result.result_code == expected && result.buffer != NULL, "unexpected API result");
    const char *bytes  = (const char *) sbufGetRawPtr(result.buffer);
    size_t      length = sbufGetLength(result.buffer);
    require(memchr(bytes, 0, length) == NULL, "UTF-8 response contains a NUL byte");
    const char *end  = NULL;
    cJSON      *json = cJSON_ParseWithLengthOpts(bytes, length, &end, false);
    require(cJSON_IsObject(json) && end == bytes + length, "response is not one complete JSON object");
    bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), result.buffer);
    return json;
}

static void checkString(const cJSON *object, const char *key, const char *expected)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, key);
    require(cJSON_IsString(value) && strcmp(value->valuestring, expected) == 0, key);
}

static void checkWide(const cJSON *object, const char *key, uint64_t expected)
{
    char text[32];
    int  length = snprintf(text, sizeof(text), "%llu", (unsigned long long) expected);
    require(length > 0 && (size_t) length < sizeof(text), "wide counter formatting overflow");
    checkString(object, key, text);
}

static void checkCount(const cJSON *object, const char *key, uint32_t expected)
{
    int64_t value = -1;
    require(jsonGetObjectIntegerInRange(object, key, 0, UINT32_MAX, &value) == kJsonValuePresent &&
                (uint64_t) value == expected,
            key);
}

static void testSnapshot(void)
{
    enum
    {
        kSegments              = 11,
        kExternalBytes         = 12345,
        kRecoveryExternalBytes = 2345,
        kRecoveryHeadroom      = 131072
    };
    void *segments[kSegments];
    for (size_t i = 0; i < ARRAY_SIZE(segments); ++i)
    {
        segments[i] = memp_malloc(MEMP_TCP_SEG);
        require(segments[i] != NULL, "segment allocation refused below configured limit");
    }
    require(memp_malloc(MEMP_TCP_SEG) == NULL, "configured segment limit did not refuse allocation");
    require(wwLwipCapacityTryReserveExternal(kExternalBytes), "external reservation refused");
    void *external = memoryAllocate(kExternalBytes);
    require(! wwLwipCapacityTryReserveExternal((size_t) configuration.memory_budget),
            "external reservation exceeded the byte ceiling");
    require(wwLwipCapacityRecoveryHeadroom() == kRecoveryHeadroom, "incorrect recovery headroom within configured cap");
    require(wwLwipCapacityTryReserveExternalRecovery(kRecoveryExternalBytes), "recovery external reservation refused");
    void *recovery_external = memoryAllocate(kRecoveryExternalBytes);
    require(! wwLwipCapacityTryReserveExternalRecovery(kRecoveryHeadroom),
            "recovery reservation exceeded its reserved headroom");

    ip_addr_t local, remote;
    IP_ADDR4(&local, 10, 0, 0, 1);
    IP_ADDR4(&remote, 10, 0, 0, 2);
    ww_lwip_port_scope_t scope = {0};
    require(wwLwipPortScopeAllocate(kWwLwipTcp, &scope, &local, &remote, 443, 45000, 45000) == 45000,
            "scoped port reservation refused");

    ww_lwip_capacity_snapshot_t snapshot;
    ww_lwip_pool_snapshot_t     pools[64];
    size_t                      count = wwLwipCapacitySnapshot(&snapshot, pools, ARRAY_SIZE(pools));
    require(count > 0 && count <= ARRAY_SIZE(pools) && snapshot.dynamic, "dynamic pools are unavailable");
    require(snapshot.external_bytes == kExternalBytes + kRecoveryExternalBytes && snapshot.external_refusals == 2,
            "external capacity accounting did not settle the refusal");
    require(snapshot.recovery_headroom == kRecoveryHeadroom && snapshot.recovery_bytes == kRecoveryExternalBytes &&
                snapshot.external_recovery_bytes == kRecoveryExternalBytes && snapshot.recovery_refusals == 1 &&
                snapshot.byte_refusals == 2,
            "recovery partition accounting did not preserve totals and refusal categories");
    node_api_call_context_t ctx  = context();
    cJSON                  *json = parseResult(invoke("{}", 2, &ctx), kApiResultOk);
    checkString(json, "scope", "process");
    require(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "dynamic")), "dynamic mode missing");
    require(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "held_includes_worker_caches")),
            "cache reservation semantics missing");
    checkWide(json, "memory_budget", configuration.memory_budget);
    checkWide(json, "reserved_bytes", snapshot.reserved_bytes);
    checkWide(json, "peak_reserved_bytes", snapshot.peak_reserved_bytes);
    checkWide(json, "external_bytes", snapshot.external_bytes);
    checkWide(json, "recovery_headroom", snapshot.recovery_headroom);
    checkWide(json, "recovery_bytes", snapshot.recovery_bytes);
    checkWide(json, "external_recovery_bytes", snapshot.external_recovery_bytes);
    checkWide(json, "recovery_refusals", snapshot.recovery_refusals);
    checkWide(json, "byte_refusals", snapshot.byte_refusals);
    checkWide(json, "external_refusals", snapshot.external_refusals);
    checkWide(json, "reclaimed_bytes", snapshot.reclaimed_bytes);
    const cJSON *limits = cJSON_GetObjectItemCaseSensitive(json, "limits");
    require(cJSON_IsObject(limits), "limits object missing");
    checkCount(limits, "tcp_flows", configuration.tcp_flows);
    checkCount(limits, "udp_flows", configuration.udp_flows);
    checkCount(limits, "tcp_listeners", configuration.tcp_listeners);
    checkCount(limits, "tcp_segments", configuration.tcp_segments);
    checkCount(limits, "rx_wrappers", configuration.rx_wrappers);
    const cJSON *json_pools = cJSON_GetObjectItemCaseSensitive(json, "pools");
    require(cJSON_IsArray(json_pools) && (size_t) cJSON_GetArraySize(json_pools) == count, "pool inventory missing");
    bool found_segments = false;
    for (size_t i = 0; i < count; ++i)
    {
        const cJSON *pool = cJSON_GetArrayItem(json_pools, (int) i);
        checkString(pool, "name", pools[i].name);
        checkCount(pool, "object_size", pools[i].object_size);
        checkCount(pool, "limit", pools[i].limit);
        checkCount(pool, "allocated", pools[i].allocated);
        checkCount(pool, "held", pools[i].held);
        checkCount(pool, "peak_held", pools[i].peak_held);
        checkWide(pool, "reserved_bytes", pools[i].reserved_bytes);
        checkWide(pool, "entry_refusals", pools[i].entry_refusals);
        checkWide(pool, "byte_refusals", pools[i].byte_refusals);
        if (pools[i].limit == kSegments && pools[i].held == kSegments && pools[i].entry_refusals != 0)
            found_segments = true;
    }
    require(found_segments, "exhausted segment pool omitted from diagnostics");
    const cJSON *ports = cJSON_GetObjectItemCaseSensitive(json, "ports");
    require(cJSON_IsObject(ports), "port counters missing");
    const cJSON *tcp = cJSON_GetObjectItemCaseSensitive(ports, "tcp");
    const cJSON *udp = cJSON_GetObjectItemCaseSensitive(ports, "udp");
    checkWide(tcp, "active", 1);
    checkWide(tcp, "peak", 1);
    checkWide(tcp, "scoped", 1);
    checkWide(tcp, "unscoped", 0);
    checkWide(tcp, "refused", 0);
    checkWide(udp, "active", 0);
    checkWide(udp, "peak", 0);
    checkWide(udp, "scoped", 0);
    checkWide(udp, "unscoped", 0);
    checkWide(udp, "refused", 0);
    cJSON_Delete(json);

    wwLwipPortScopeRelease(kWwLwipTcp, &scope);
    memoryFree(external);
    wwLwipCapacityReleaseExternal(kExternalBytes);
    memoryFree(recovery_external);
    wwLwipCapacityReleaseExternalRecovery(kRecoveryExternalBytes);
    for (size_t i = 0; i < ARRAY_SIZE(segments); ++i)
        memp_free(MEMP_TCP_SEG, segments[i]);
    ctx                     = context();
    const char whitespace[] = " \t{ \r\n} \n";
    json                    = parseResult(invoke(whitespace, sizeof(whitespace) - 1, &ctx), kApiResultOk);
    checkWide(json, "external_bytes", 0);
    checkWide(json, "recovery_bytes", 0);
    checkWide(json, "external_recovery_bytes", 0);
    checkWide(json, "recovery_refusals", 1);
    ports = cJSON_GetObjectItemCaseSensitive(json, "ports");
    tcp   = cJSON_GetObjectItemCaseSensitive(ports, "tcp");
    checkWide(tcp, "active", 0);
    checkWide(tcp, "peak", 1);
    cJSON_Delete(json);
}

static void testInputAndBounds(void)
{
    const char             *invalid[] = {"", "[]", "{", "}", "null", "{}x", "{}{}", "{{}}", "{\"extra\":1}", "{\v}"};
    node_api_call_context_t ctx       = context();
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        cJSON *json = parseResult(invoke(invalid[i], strlen(invalid[i]), &ctx), kApiResultError);
        checkString(json, "error", "expected_empty_object");
        cJSON_Delete(json);
    }
    const char embedded_nul[] = {'{', '}', 0};
    cJSON     *json           = parseResult(invoke(embedded_nul, sizeof(embedded_nul), &ctx), kApiResultError);
    checkString(json, "error", "expected_empty_object");
    cJSON_Delete(json);
    char padded[65];
    memset(padded, ' ', sizeof(padded));
    padded[0] = '{';
    padded[1] = '}';
    json      = parseResult(invoke(padded, 64, &ctx), kApiResultOk);
    cJSON_Delete(json);
    json = parseResult(invoke(padded, sizeof(padded), &ctx), kApiResultError);
    checkString(json, "error", "expected_empty_object");
    cJSON_Delete(json);

    for (unsigned i = 0; i < 3; ++i)
    {
        ctx = context();
        if (i == 0)
            ctx.deadline_ms = 0;
        else if (i == 1)
            ctx.working_memory_allowance = 0;
        else
            ctx.max_response_body_size = 1;
        api_result_t result = invoke("{}", 2, &ctx);
        require(result.result_code == kApiResultError && result.buffer == NULL,
                "bounded request produced an unadmitted result");
        result = invoke("[]", 2, &ctx);
        require(result.result_code == kApiResultError && result.buffer == NULL,
                "malformed request bypassed response bounds");
    }
}

static void runTests(void *worker_argument, void *arg1, void *arg2, void *arg3)
{
    worker_t *worker = worker_argument;
    (void) arg1;
    (void) arg2;
    (void) arg3;
    require(worker->wid == 0 && currentThreadOwnsWorker(worker->wid), "fixture did not execute on worker zero");
    TEST_RUN_CASE(testSnapshot);
    TEST_RUN_CASE(testInputAndBounds);
    completed = true;
    require(requestProgramShutdown(0), "shutdown request refused");
}

int main(void)
{
    testCaseSet("lwip_capacity_api_setup");
    wwLwipCapacityConfigure(&configuration);
    static char            off[]        = "OFF";
    ww_construction_data_t data         = {.workers_count = 1, .ram_profile = 4, .mtu_size = 1500};
    data.internal_logger_data.log_level = off;
    data.core_logger_data.log_level     = off;
    data.network_logger_data.log_level  = off;
    data.dns_logger_data.log_level      = off;
    require(wwStartupSucceeded(createGlobalState(data)), "runtime construction failed");
    require(wwLwipCapacityRegisterApi(&target), "capacity operation registration failed");
    require(! wwLwipCapacityRegisterApi(&target), "duplicate registration accepted");
    operation = nodeApiFind(&target, "stack-stats");
    require(operation != NULL && operation->read_only && operation->execution == kNodeApiCallingWorker &&
                operation->response_encoding == kNodeApiEncodingUtf8,
            "capacity operation descriptor is incorrect");
    require(strcmp(operation->request_content_type, "application/json") == 0 &&
                strcmp(operation->response_content_type, "application/json") == 0,
            "capacity content types are incorrect");
    require(nodeApiFind(&target, "Stack-Stats") == NULL, "operation matching ignored case");
    nodeApiFreeze();
    require(sendWorkerMessageForceQueueWithCleanup(0, runTests, NULL, NULL, NULL, NULL) == kWorkerMessageSubmitAccepted,
            "test callback admission failed");
    require(applicationShutdownCommitRuntime(), "runtime commit failed");
    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);
    require(wloopRun(getWorkerLoop(0)) == kWLoopRunQuiesced && completed, "test callback did not complete");
    nodeApiUnregister(&target);
    require(! nodeApiHasRegistration(&target) && nodeApiFind(&target, "stack-stats") == NULL,
            "unregister retained capacity operation");
    globalstateRunShutdownSequence();
    destroyGlobalState();
    return 0;
}
