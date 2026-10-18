/* APIServer borrowed-line composition with real queues, pools, framing and timer
 * roots. A private echo/large operation replaces only global target discovery;
 * the core resolver has a separate real NodeManager fixture. Deterministic time
 * and refusal seams cover FIFO, request/output windows, late jobs and reentry.
 * CTest: waterwall.apiserver_session_unit. No sockets or public network. */
#include "APIServer/structure.h"
#include "instance/worker_messages.h"
#include "wloop_internal.h"

#include "test_assert.h"

#define require(c, m) TEST_REQUIRE(TEST_FAILURE_EXIT, c, m)

static uint64_t now_us = UINT64_C(6000000000000);
static bool     refuse_timer, refuse_message, refuse_reply;
static bool     hold_reply, hold_message;
static struct
{
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *args[3];
} held;
static tunnel_t       *api, *source;
static tunnel_t        target;
static node_t          node;
static tunnel_chain_t *chain;
static line_t         *line;
static unsigned        calls, finishes, establishments, pauses, resumes, writes;
static bool            close_est, close_output, pause_output;
static uint8_t         captured[4 * 1024 * 1024];
static size_t          captured_size;
static size_t          timer_baseline;
static unsigned        nested_fragments;

static void sendBytes(const void *bytes, size_t size);

uint64_t __wrap_getHRTimeUs(void);
uint64_t __wrap_getHRTimeUs(void)
{
    return now_us;
}
wtimer_t *__real_wtimerAdd(wloop_t *, wtimer_cb, uint32_t, uint32_t);
wtimer_t *__wrap_wtimerAdd(wloop_t *, wtimer_cb, uint32_t, uint32_t);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb callback, uint32_t timeout, uint32_t repeat)
{
    return refuse_timer ? NULL : __real_wtimerAdd(loop, callback, timeout, repeat);
}
worker_message_submit_result_e __real_sendWorkerMessageForceQueueWithCleanup(wid_t, WorkerMessageCallback,
                                                                             WorkerMessageCleanupCallback, void *,
                                                                             void *, void *);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t, WorkerMessageCallback,
                                                                             WorkerMessageCleanupCallback, void *,
                                                                             void *, void *);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *a, void *b, void *c)
{
    if (refuse_message)
    {
        refuse_message = false;
        cleanup(a, b, c, kWorkerMessageCancelEnqueueFailure);
        return kWorkerMessageSubmitRejectedCleanupRan;
    }
    if (hold_message)
    {
        require(held.callback == NULL, "completion seam already occupied");
        hold_message  = false;
        held.callback = callback;
        held.cleanup  = cleanup;
        held.args[0]  = a;
        held.args[1]  = b;
        held.args[2]  = c;
        return kWorkerMessageSubmitAccepted;
    }
    return __real_sendWorkerMessageForceQueueWithCleanup(wid, callback, cleanup, a, b, c);
}

node_api_target_status_t __wrap_nodemanagerResolveApiTarget(const char *, const char *, tunnel_t **, const char **);
node_api_target_status_t __wrap_nodemanagerResolveApiTarget(const char *config, const char *name, tunnel_t **result,
                                                            const char **resolved)
{
    if (strcmp(name, "duplicate") == 0 && ! config)
        return kNodeApiTargetAmbiguous;
    if ((config && strcmp(config, "one") != 0) || (strcmp(name, "echo") != 0 && strcmp(name, "duplicate") != 0))
        return kNodeApiTargetNotFound;
    *result = &target;
    if (resolved)
        *resolved = "one";
    return kNodeApiTargetFound;
}

static api_result_t handler(tunnel_t *t, sbuf_t *request, const node_api_call_context_t *ctx)
{
    require(t == &target && currentThreadIsEventWorkerWID(0), "handler target affinity");
    ++calls;
    if (refuse_reply)
    {
        refuse_reply   = false;
        refuse_message = true;
    }
    if (hold_reply)
    {
        hold_reply   = false;
        hold_message = true;
    }
    if (strcmp(ctx->operation, "large") == 0 || strcmp(ctx->operation, "oversize") == 0)
    {
        bufferpoolReuseBuffer(getCurrentEventWorkerBufferPool(), request);
        size_t size = strcmp(ctx->operation, "large") == 0 ? 70001 : ctx->max_response_body_size + 1;
        request     = bufferpoolGetBestFit(getCurrentEventWorkerBufferPool(), (uint32_t) size, 0);
        memset(sbufGetMutablePtr(request), 'x', size);
        sbufSetLength(request, (uint32_t) size);
    }
    return (api_result_t) {.result_code = kApiResultOk, .buffer = request};
}

static const node_api_operation_t operations[] = {{.name                  = "echo",
                                                   .handler               = handler,
                                                   .read_only             = true,
                                                   .request_content_type  = "application/json",
                                                   .response_content_type = "application/json",
                                                   .response_encoding     = kNodeApiEncodingUtf8,
                                                   .execution             = kNodeApiSpecifiedWorker,
                                                   .wid                   = 0},
                                                  {.name                  = "large",
                                                   .handler               = handler,
                                                   .read_only             = true,
                                                   .request_content_type  = "application/json",
                                                   .response_content_type = "text/plain",
                                                   .response_encoding     = kNodeApiEncodingUtf8,
                                                   .execution             = kNodeApiSpecifiedWorker,
                                                   .wid                   = 0},
                                                  {.name                  = "oversize",
                                                   .handler               = handler,
                                                   .read_only             = true,
                                                   .request_content_type  = "application/json",
                                                   .response_content_type = "text/plain",
                                                   .response_encoding     = kNodeApiEncodingUtf8,
                                                   .execution             = kNodeApiSpecifiedWorker,
                                                   .wid                   = 0}};

static const char settings[] =
    "{\"clients\":[{\"name\":\"operator\",\"token\":\""
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "\",\"allow\":[{\"config\":\"one\",\"node\":\"echo\",\"operations\":[\"echo\",\"large\",\"oversize\"]}]}]}";
static const char request[] =
    "{\"id\":\"a\",\"auth\":{\"client\":\"operator\",\"token\":\""
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "\"},\"selector\":{\"config\":\"one\",\"node\":\"echo\"},\"operation\":\"echo\","
    "\"content_type\":\"application/json\",\"body_encoding\":\"utf8\",\"body\":\" exact \\\"body\\\" \\n\"}";

static apiserver_lstate_t *state(void)
{
    return lineGetState(line, api);
}
static void sourceCloseLine(line_t *l)
{
    tunnelUpStreamFin(api, l);
    require(lineIsAlive(l), "borrower destroyed its line");
    lineDestroy(l);
}
static void sourceClose(void)
{
    sourceCloseLine(line);
}
static void onFinish(tunnel_t *t, line_t *l)
{
    discard t;
    ++finishes;
    require(((apiserver_lstate_t *) lineGetState(l, api))->tunnel == NULL, "local Finish preceded state destruction");
    lineDestroy(l);
}
static void onEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++establishments;
    if (close_est)
        sourceCloseLine(l);
}
static void onPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++pauses;
}
static void onResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++resumes;
}
static void onOutput(tunnel_t *t, line_t *l, sbuf_t *buffer)
{
    discard t;
    size_t  n = sbufGetLength(buffer);
    require(n <= sizeof(captured) - captured_size, "output capture limit");
    memcpy(captured + captured_size, sbufGetRawPtr(buffer), n);
    captured_size += n;
    ++writes;
    lineReuseBuffer(l, buffer);
    if (pause_output)
        tunnelUpStreamPause(api, l);
    if (close_output)
        sourceCloseLine(l);
    if (nested_fragments)
    {
        unsigned fragments = nested_fragments;
        nested_fragments   = 0;
        const uint8_t byte = 0;
        for (unsigned i = 0; i < fragments && lineIsAlive(l); ++i)
            sendBytes(&byte, 1);
    }
}

static void pump(void)
{
    now_us += 2000;
    require(wloopProcessEvents(getWorkerLoop(0), 0) >= 0, "event progress");
}

static void secondLine(void)
{
    line = lineCreate(chain->line_pools, 0);
    lineRef(line);
    tunnelUpStreamInit(api, line);
}

static void releaseLine(line_t *l)
{
    if (lineIsAlive(l))
        sourceCloseLine(l);
    for (size_t i = 0; i < api->lstate_size; ++i)
        require(((uint8_t *) lineGetState(l, api))[i] == 0, "borrowed state retained bytes");
    lineUnref(l);
}

static void openSettings(const char *text)
{
    nodeApiRegistryInitialize();
    require(nodeApiRegister(&target, operations, ARRAY_SIZE(operations)), "private test operation registration");
    calls = finishes = establishments = pauses = resumes = writes = 0;
    captured_size                                                 = 0;
    node                                                          = nodeAPIServerGet();
    node.node_settings_json                                       = cJSON_Parse(text);
    require(node.node_settings_json != NULL, "fixture settings");
    api = apiserverTunnelCreate(&node);
    require(api != NULL, "valid API settings rejected");
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    api->onPrepare(api);
    require(wwStartupSucceeded(wwStartupContextEnd(&startup)), "valid allowlist rejected");
    nodeApiFreeze();
    source             = tunnelCreate(NULL, 0, 0);
    source->fnFinD     = onFinish;
    source->fnEstD     = onEst;
    source->fnPauseD   = onPause;
    source->fnResumeD  = onResume;
    source->fnPayloadD = onOutput;
    tunnelBind(source, api);
    chain = tunnelchainCreate(1);
    tunnelchainInsert(chain, api);
    uint32_t offset = 0;
    source->onIndex(source, 0, &offset);
    api->onIndex(api, 1, &offset);
    tunnelchainFinalize(chain);
    secondLine();
}

static void openLine(void)
{
    openSettings(settings);
}

static void openWithLimit(const char *key, unsigned value)
{
    cJSON *json = cJSON_Parse(settings);
    require(json != NULL && cJSON_AddNumberToObject(json, key, value) != NULL, "fixture limit setting");
    char *text = cJSON_PrintUnformatted(json);
    require(text != NULL, "fixture limit serialization");
    openSettings(text);
    memoryFree(text);
    cJSON_Delete(json);
}

static void closeLine(void)
{
    releaseLine(line);
    for (unsigned i = 0; i < 8; ++i)
        pump();
    apiserver_tstate_t *ts = tunnelGetState(api);
    size_t              bytes, jobs;
    nodeApiDomainGetUsage(ts->domain, &bytes, &jobs);
    require(bytes == 0 && jobs == 0 && atomicLoad(&ts->session_count) == 0, "API reservation/session leak");
    require(getWorkerLoop(0)->ntimers == timer_baseline, "API timer leak");
    api->onDestroy(api, wwLifecycleStartupRollback());
    nodeApiUnregister(&target);
    nodeApiRegistryDestroy();
    tunnelDestroy(source);
    tunnelchainDestroy(chain);
    cJSON_Delete(node.node_settings_json);
    memoryFree(node.type);
    require(held.callback == NULL && ! hold_message && ! hold_reply, "held detached completion leaked");
    close_est = close_output = pause_output = refuse_timer = refuse_message = refuse_reply = false;
    nested_fragments                                                                       = 0;
}

static void sendBytes(const void *bytes, size_t size)
{
    require(lineIsAlive(line), "sending on dead line");
    sbuf_t *buffer = bufferpoolGetBestFit(lineGetBufferPool(line), (uint32_t) size, 0);
    if (size)
        memcpy(sbufGetMutablePtr(buffer), bytes, size);
    sbufSetLength(buffer, (uint32_t) size);
    tunnelUpStreamPayload(api, line, buffer);
}

static uint8_t *frame(const char *json, size_t *size)
{
    size_t   n     = strlen(json);
    uint8_t *bytes = memoryAllocate(n + 4);
    bytes[0]       = (uint8_t) (n >> 24);
    bytes[1]       = (uint8_t) (n >> 16);
    bytes[2]       = (uint8_t) (n >> 8);
    bytes[3]       = (uint8_t) n;
    memcpy(bytes + 4, json, n);
    *size = n + 4;
    return bytes;
}

static void sendRequest(const char *json)
{
    size_t   n;
    uint8_t *bytes = frame(json, &n);
    sendBytes(bytes, n);
    memoryFree(bytes);
}

static void settle(unsigned expected)
{
    for (unsigned i = 0; i < 100 && lineIsAlive(line) && (state()->requests || state()->input_head); ++i)
        pump();
    require(calls == expected, "dispatch count");
}

static cJSON *reply(size_t *offset)
{
    require(*offset + 4 <= captured_size, "missing response prefix");
    uint8_t *p = captured + *offset;
    size_t   n = ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
    require(n && n <= captured_size - *offset - 4, "interleaved/truncated response");
    cJSON *json = cJSON_ParseWithLength((char *) p + 4, n);
    require(json != NULL, "invalid response JSON");
    *offset += n + 4;
    return json;
}

static void expectError(const char *code)
{
    size_t       offset = 0;
    cJSON       *json   = reply(&offset);
    const cJSON *error  = cJSON_GetObjectItemCaseSensitive(json, "error");
    const cJSON *actual = cJSON_GetObjectItemCaseSensitive(error, "code");
    require(cJSON_IsString(actual) && strcmp(actual->valuestring, code) == 0, "gateway code");
    require(offset == captured_size, "unexpected extra error frame");
    cJSON_Delete(json);
}

static char *changedRequest(const char *key, const char *value)
{
    cJSON *json = cJSON_Parse(request);
    require(json != NULL, "request fixture syntax");
    if (strcmp(key, "node") == 0)
        cJSON_ReplaceItemInObjectCaseSensitive(
            cJSON_GetObjectItemCaseSensitive(json, "selector"), key, cJSON_CreateString(value));
    else if (strcmp(key, "token") == 0 || strcmp(key, "client") == 0)
        cJSON_ReplaceItemInObjectCaseSensitive(
            cJSON_GetObjectItemCaseSensitive(json, "auth"), key, cJSON_CreateString(value));
    else
        cJSON_ReplaceItemInObjectCaseSensitive(json, key, cJSON_CreateString(value));
    char *text = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    return text;
}

static void framing(void)
{
    size_t   n;
    uint8_t *bytes = frame(request, &n);
    for (size_t split = 0; split <= 4; ++split)
    {
        openLine();
        sendBytes(bytes, split);
        require(calls == 0 && captured_size == 0, "partial header dispatched");
        for (size_t i = split; i < n; ++i)
            sendBytes(bytes + i, 1);
        require(calls == 0, "same-worker handler executed inline");
        settle(1);
        size_t offset = 0;
        cJSON *json   = reply(&offset);
        cJSON *result = cJSON_GetObjectItemCaseSensitive(json, "result");
        require(strcmp(cJSON_GetObjectItemCaseSensitive(result, "body")->valuestring, " exact \"body\" \n") == 0,
                "opaque request body changed");
        cJSON_Delete(json);
        require(offset == captured_size && finishes == 0, "valid frame closed or overconsumed");
        closeLine();
    }
    openLine();
    uint8_t *coalesced = memoryAllocate(n * 3);
    for (size_t i = 0; i < 3; ++i)
        memcpy(coalesced + i * n, bytes, n);
    sendBytes(coalesced, n * 3);
    settle(3);
    size_t offset = 0;
    for (unsigned i = 0; i < 3; ++i)
        cJSON_Delete(reply(&offset));
    require(offset == captured_size, "coalesced frame boundaries");
    memoryFree(coalesced);
    closeLine();
    const uint8_t bad[][4] = {{0, 0, 0, 0}, {255, 255, 255, 255}};
    for (size_t i = 0; i < ARRAY_SIZE(bad); ++i)
    {
        openLine();
        sendBytes(bad[i], 4);
        require(! lineIsAlive(line) && calls == 0, "bad length remained admitted");
        expectError("invalid_request");
        closeLine();
    }
    openLine();
    sendBytes(bytes, n / 2);
    sourceClose();
    require(captured_size == 0 && finishes == 0, "truncated source Finish was reflected");
    closeLine();
    memoryFree(bytes);
}

static void policyAndResults(void)
{
    static const char *const fields[] = {"token", "client", "operation", "node", "content_type"};
    static const char *const values[] = {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                                         "unknown",
                                         "unlisted",
                                         "missing",
                                         "text/plain"};
    static const char *const errors[] = {
        "unauthorized", "unauthorized", "forbidden", "target_not_found", "unsupported_content_type"};
    for (size_t i = 0; i < ARRAY_SIZE(fields); ++i)
    {
        openLine();
        char *text = changedRequest(fields[i], values[i]);
        sendRequest(text);
        memoryFree(text);
        settle(0);
        expectError(errors[i]);
        require(lineIsAlive(line) == (i >= 2), "authentication close policy");
        closeLine();
    }
    openLine();
    char *large = changedRequest("operation", "large");
    sendRequest(large);
    settle(1);
    size_t offset = 0;
    cJSON *json   = reply(&offset);
    cJSON *result = cJSON_GetObjectItemCaseSensitive(json, "result");
    require(strlen(cJSON_GetObjectItemCaseSensitive(result, "body")->valuestring) == 70001 && writes > 1,
            "large response was truncated or not chunked");
    cJSON_Delete(json);
    closeLine();
    memoryFree(large);
    openLine();
    char *oversize = changedRequest("operation", "oversize");
    sendRequest(oversize);
    settle(1);
    expectError("response_too_large");
    require(writes == 1, "oversized result published a prefix");
    memoryFree(oversize);
    closeLine();
}

static void pressureAndReentry(void)
{
    openLine();
    tunnelUpStreamPause(api, line);
    tunnelUpStreamPause(api, line);
    for (unsigned i = 0; i < 9; ++i)
        sendRequest(request);
    for (unsigned i = 0; i < 6; ++i)
        pump();
    require(calls == 1 && captured_size == 0 && pauses > 0, "paused FIFO admission");
    tunnelUpStreamResume(api, line);
    tunnelUpStreamResume(api, line);
    settle(9);
    require(resumes > 0 && state()->requests == NULL, "FIFO drain did not autonomously resume input");
    closeLine();
    close_est = true;
    openLine();
    require(! lineIsAlive(line) && establishments == 1 && finishes == 0, "reentrant Est closure");
    closeLine();
    openLine();
    close_output = true;
    sendRequest(request);
    settle(1);
    require(! lineIsAlive(line) && finishes == 0, "reentrant response closure");
    closeLine();
    openLine();
    sendRequest(request);
    sourceClose();
    for (unsigned i = 0; i < 6; ++i)
        pump();
    require(calls == 0 && captured_size == 0, "closed session queued handler executed");
    closeLine();
}

static void sendNumberedOperation(unsigned index, const char *operation)
{
    char id[32];
    snprintf(id, sizeof(id), "request-%u", index);
    cJSON *json = cJSON_Parse(request);
    require(json != NULL && cJSON_ReplaceItemInObjectCaseSensitive(json, "id", cJSON_CreateString(id)) &&
                cJSON_ReplaceItemInObjectCaseSensitive(json, "operation", cJSON_CreateString(operation)),
            "numbered request fixture");
    char *text = cJSON_PrintUnformatted(json);
    require(text != NULL, "numbered request serialization");
    sendRequest(text);
    memoryFree(text);
    cJSON_Delete(json);
}

static void expectQueuedResponsesDrained(unsigned count, bool large_first)
{
    settle(large_first ? 1 : 0);
    require(lineIsAlive(line) && finishes == 0, "queued responses unexpectedly closed the connection");
    require(state()->requests == NULL && state()->requests_tail == NULL && state()->request_count == 0 &&
                state()->job == NULL && state()->output == NULL && state()->input_head == NULL &&
                state()->input_fragments == 0 && state()->input_bytes == 0,
            "complete queued requests stalled without another input event");
    require(! state()->input_paused && resumes > 0, "queued-response continuation did not release input pressure");
    size_t offset = 0;
    for (unsigned i = 0; i < count; ++i)
    {
        char id[32];
        snprintf(id, sizeof(id), "request-%u", i);
        cJSON       *json   = reply(&offset);
        const cJSON *actual = cJSON_GetObjectItemCaseSensitive(json, "id");
        const cJSON *error  = cJSON_GetObjectItemCaseSensitive(json, "error");
        const cJSON *result = cJSON_GetObjectItemCaseSensitive(json, "result");
        require(cJSON_IsString(actual) && strcmp(actual->valuestring, id) == 0,
                "queued responses lost FIFO request identity");
        if (large_first && i == 0)
        {
            const cJSON *body = cJSON_GetObjectItemCaseSensitive(result, "body");
            require(cJSON_IsNull(error) && cJSON_IsString(body) && strlen(body->valuestring) == 70001,
                    "queued asynchronous response was truncated or replaced");
        }
        else
        {
            const cJSON *code = cJSON_GetObjectItemCaseSensitive(error, "code");
            require(cJSON_IsString(code) && strcmp(code->valuestring, "forbidden") == 0 && cJSON_IsNull(result),
                    "queued forbidden operation did not preserve its gateway error");
        }
        cJSON_Delete(json);
    }
    require(offset == captured_size, "queued requests produced extra responses");
    size_t bytes, jobs;
    nodeApiDomainGetUsage(((apiserver_tstate_t *) tunnelGetState(api))->domain, &bytes, &jobs);
    require(jobs == 0 && bytes == sizeof(apiserver_lstate_t) &&
                bufferbudgetGetUsage(&state()->budget).charge == sizeof(apiserver_lstate_t),
            "queued-response continuation retained request or job reservations");
}

static void queuedErrorsContinueAfterResume(void)
{
    openLine();
    tunnelUpStreamPause(api, line);
    for (unsigned i = 0; i < 9; ++i)
        sendNumberedOperation(i, "unlisted");
    require(calls == 0 && captured_size == 0 && state()->request_count == 9 && state()->input_head == NULL &&
                state()->input_paused && pauses > 0,
            "paused immediate-error queue fixture did not reach input pressure");
    /* One Resume must drain every admitted request across bounded turns, with
     * no further input or advisory notification to supply accidental progress. */
    tunnelUpStreamResume(api, line);
    expectQueuedResponsesDrained(9, false);
    closeLine();
}

static void queuedErrorsContinueAfterAsyncReply(void)
{
    openLine();
    hold_reply = true;
    sendNumberedOperation(0, "large");
    for (unsigned i = 1; i < 9; ++i)
        sendNumberedOperation(i, "unlisted");
    for (unsigned i = 0; i < 8 && held.callback == NULL; ++i)
        pump();
    require(held.callback != NULL && calls == 1 && captured_size == 0 && state()->request_count == 9 &&
                state()->input_head == NULL && state()->input_paused && pauses > 0,
            "asynchronous reply fixture did not retain its complete request queue");
    require(__real_sendWorkerMessageForceQueueWithCleanup(
                0, held.callback, held.cleanup, held.args[0], held.args[1], held.args[2]) ==
                kWorkerMessageSubmitAccepted,
            "queued-response completion requeue");
    memoryZero(&held, sizeof(held));
    expectQueuedResponsesDrained(9, true);
    closeLine();
}

static void deadlinesAndRefusal(void)
{
    openLine();
    refuse_message = true;
    sendRequest(request);
    expectError("busy");
    require(lineIsAlive(line) && calls == 0, "synchronous submission refusal");
    closeLine();
    openLine();
    refuse_reply = true;
    sendRequest(request);
    for (unsigned i = 0; i < 4; ++i)
        pump();
    require(calls == 1 && captured_size == 0, "reply refusal unexpectedly delivered");
    now_us += UINT64_C(11000000);
    pump();
    expectError("timeout");
    require(! lineIsAlive(line), "request timeout failed to close");
    closeLine();
    openLine();
    tunnelUpStreamPause(api, line);
    sendRequest(request);
    for (unsigned i = 0; i < 4; ++i)
        pump();
    require(state()->output && state()->requests->deadline_ms == 0, "request window not handed to output");
    now_us += UINT64_C(11000000);
    pump();
    require(lineIsAlive(line) && captured_size == 0, "request deadline shortened output window");
    now_us += UINT64_C(5000000);
    pump();
    require(! lineIsAlive(line) && captured_size == 0, "paused output deadline failed");
    closeLine();
    openLine();
    tunnelUpStreamPause(api, line);
    sendRequest(request);
    sendRequest(request);
    for (unsigned i = 0; i < 4; ++i)
        pump();
    now_us += UINT64_C(11000000);
    pump();
    require(! lineIsAlive(line) && captured_size == 0, "queued timeout emitted out of FIFO order");
    closeLine();
    openLine();
    size_t   n;
    uint8_t *bytes = frame(request, &n);
    sendBytes(bytes, 1);
    now_us += UINT64_C(14000000);
    sendBytes(bytes + 1, 1);
    now_us += UINT64_C(2000000);
    pump();
    require(! lineIsAlive(line), "trickle reset absolute frame timeout");
    expectError("timeout");
    memoryFree(bytes);
    closeLine();
    openLine();
    refuse_timer = true;
    sendRequest(request);
    require(! lineIsAlive(line), "refused continuation left immortal request");
    closeLine();
    openLine();
    now_us += UINT64_C(61000000);
    pump();
    require(! lineIsAlive(line), "idle deadline");
    closeLine();
}

static void hardLimits(void)
{
    openWithLimit("max_sessions", 1);
    line_t *first = line;
    secondLine();
    apiserver_tstate_t *ts = tunnelGetState(api);
    require(! lineIsAlive(line) && lineIsAlive(first) && atomicLoad(&ts->session_count) == 1 && establishments == 1 &&
                finishes == 1,
            "session cap did not reject only the new line");
    releaseLine(line);
    line = first;
    closeLine();

    openWithLimit("max_input_fragments", 2);
    nested_fragments = 3;
    sendRequest(request);
    settle(1);
    require(! lineIsAlive(line) && finishes == 1 && writes == 1,
            "nested tiny fragments bypassed the input entry limit");
    closeLine();

    openLine();
    ts                       = tunnelGetState(api);
    sbuf_t *oversized_charge = bufferpoolGetBestFit(lineGetBufferPool(line), (uint32_t) ts->limits.max_line_memory, 0);
    require(sbufGetAllocationCharge(oversized_charge) >
                ts->limits.max_line_memory - bufferbudgetGetUsage(&state()->budget).charge,
            "line-budget fixture did not exceed retained allocation allowance");
    sbufSetLength(oversized_charge, 1);
    tunnelUpStreamPayload(api, line, oversized_charge);
    require(! lineIsAlive(line) && calls == 0 && captured_size == 0,
            "small logical payload bypassed retained allocation limit");
    closeLine();

    openLine();
    ts = tunnelGetState(api);
    size_t bytes, jobs;
    nodeApiDomainGetUsage(ts->domain, &bytes, &jobs);
    size_t reserved = ts->limits.max_memory - bytes;
    require(nodeApiDomainTryReserve(ts->domain, reserved) && ! nodeApiDomainTryReserve(ts->domain, 1),
            "aggregate exact budget boundary");
    const uint8_t byte = 0;
    sendBytes(&byte, 1);
    require(! lineIsAlive(line) && calls == 0 && captured_size == 0,
            "full aggregate budget did not settle the affected session");
    nodeApiDomainGetUsage(ts->domain, &bytes, &jobs);
    require(bytes == reserved && jobs == 0, "aggregate refusal leaked session reservation");
    nodeApiDomainRelease(ts->domain, reserved);
    closeLine();

    openWithLimit("max_jobs", 1);
    sendRequest(request);
    first = line;
    ts    = tunnelGetState(api);
    nodeApiDomainGetUsage(ts->domain, &bytes, &jobs);
    require(jobs == 1 && calls == 0, "first job was not retained while queued");
    secondLine();
    sendRequest(request);
    expectError("busy");
    nodeApiDomainGetUsage(ts->domain, &bytes, &jobs);
    require(lineIsAlive(line) && jobs == 1 && calls == 0, "job cap admitted or released an unfinished job");
    releaseLine(line);
    line          = first;
    captured_size = 0;
    settle(1);
    size_t offset = 0;
    cJSON_Delete(reply(&offset));
    require(offset == captured_size, "admitted job reply count");
    closeLine();
}

static void lateCompletionAndReuse(void)
{
    openLine();
    hold_reply = true;
    sendRequest(request);
    for (unsigned i = 0; i < 8 && held.callback == NULL; ++i)
        pump();
    require(held.callback != NULL && calls == 1 && captured_size == 0, "completion was not held after execution");
    uint64_t old_session = state()->session_token;
    line_t  *old_storage = line;
    releaseLine(line);
    apiserver_tstate_t *ts = tunnelGetState(api);
    size_t              bytes, jobs;
    nodeApiDomainGetUsage(ts->domain, &bytes, &jobs);
    require(bytes > 0 && jobs == 1 && atomicLoad(&ts->session_count) == 0,
            "disconnect released an unsettled detached job");
    secondLine();
    require(line == old_storage && state()->session_token != old_session,
            "fixture did not reuse line storage with a fresh session token");
    char *replacement = changedRequest("id", "replacement");
    sendRequest(replacement);
    memoryFree(replacement);
    require(__real_sendWorkerMessageForceQueueWithCleanup(
                0, held.callback, held.cleanup, held.args[0], held.args[1], held.args[2]) ==
                kWorkerMessageSubmitAccepted,
            "held completion requeue");
    memoryZero(&held, sizeof(held));
    settle(2);
    size_t offset = 0;
    cJSON *json   = reply(&offset);
    require(strcmp(cJSON_GetObjectItemCaseSensitive(json, "id")->valuestring, "replacement") == 0 &&
                offset == captured_size && lineIsAlive(line),
            "late reply reached reused connection state");
    cJSON_Delete(json);
    nodeApiDomainGetUsage(ts->domain, &bytes, &jobs);
    require(jobs == 0 && bytes == sizeof(apiserver_lstate_t), "late job reservation was not settled exactly once");
    closeLine();
}

static void partialOutputExpiry(void)
{
    char *large = changedRequest("operation", "large");
    for (unsigned queued = 0; queued < 2; ++queued)
    {
        openLine();
        pause_output = true;
        sendRequest(large);
        if (queued)
            sendRequest(request);
        for (unsigned i = 0; i < 8 && captured_size == 0; ++i)
            pump();
        require(writes == 1 && state()->output_offset > 4 && state()->output_offset < state()->output_size &&
                    state()->output_paused && state()->requests->deadline_ms == 0,
                "fixture did not pause a partially emitted response");
        size_t before = captured_size;
        now_us += queued ? UINT64_C(11000000) : UINT64_C(16000000);
        pump();
        require(! lineIsAlive(line) && captured_size == before && calls == 1 && finishes == 1,
                "expiry inserted a frame into partial output or dispatched an expired successor");
        closeLine();
    }
    memoryFree(large);
}

static void shutdownCase(void)
{
    openLine();
    sendRequest(request);
    const ww_lifecycle_context_t *context = wwLifecycleStartupRollback();
    nodeApiCloseAdmission();
    api->onQuiesceRequest(api, context);
    api->onWorkerQuiesce(api, 0, context);
    require(state()->timer == NULL && state()->job == NULL && lineIsAlive(line), "borrowed quiescence contract");
    for (unsigned i = 0; i < 6; ++i)
        pump();
    require(calls == 0 && captured_size == 0, "quiesced API work delivered");
    closeLine();
}

int main(void)
{
    static char            off[]        = "OFF";
    ww_construction_data_t init         = {.workers_count = 1, .ram_profile = 1, .mtu_size = 1500};
    init.internal_logger_data.log_level = off;
    init.core_logger_data.log_level     = off;
    init.network_logger_data.log_level  = off;
    init.dns_logger_data.log_level      = off;
    require(wwStartupSucceeded(createGlobalState(init)), "runtime init");
    timer_baseline = getWorkerLoop(0)->ntimers;
    TEST_RUN_CASE(framing);
    TEST_RUN_CASE(policyAndResults);
    TEST_RUN_CASE(pressureAndReentry);
    TEST_RUN_CASE(queuedErrorsContinueAfterResume);
    TEST_RUN_CASE(queuedErrorsContinueAfterAsyncReply);
    TEST_RUN_CASE(deadlinesAndRefusal);
    TEST_RUN_CASE(hardLimits);
    TEST_RUN_CASE(lateCompletionAndReuse);
    TEST_RUN_CASE(partialOutputExpiry);
    TEST_RUN_CASE(shutdownCase);
    const ww_lifecycle_context_t *context = wwLifecycleStartupRollback();
    require(workerInstallApplicationQuiesceRequest(getWorker(0), context) != kWorkerQuiesceRequestUnavailable,
            "quiesce");
    workerPerformQuiesce(getWorker(0), context);
    require(workerRequestDrain(getWorker(0)), "drain request");
    workerPerformDrain(getWorker(0), context);
    require(workerRequestTeardown(getWorker(0)), "teardown request");
    workerPerformTeardown(getWorker(0));
    destroyGlobalState();
    return 0;
}
