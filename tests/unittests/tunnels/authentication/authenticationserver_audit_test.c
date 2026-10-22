/* CTest: waterwall.authenticationserver_audit_unit
 * Real registered mutations plus a gated file append: redaction, exact outcome,
 * bounded queue overflow, failed writer isolation, copied actors and shutdown drain.
 * Append/save wrappers inject explicit I/O outcomes; queue, mutations and rollback are real. */
#include "AuthenticationServer/api.h"
#include "AuthenticationServer/audit.h"
#include "AuthenticationServer/edit_token.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "loggers/network_logger.h"
#include "wthread.h"

static twf_worker_env_t                      env;
static tunnel_t                             *server;
static node_api_call_context_t               context;
static wsem_t                                entered, release_writer;
static atomic_bool                           hold_append, fail_append;
static bool                                  fail_save;
static atomic_bool                           fail_summary, capture_close;
static authenticationserver_audit_snapshot_t close_snapshot;
static atomic_ullong                         test_monotonic_us, test_wall_ms;

unsigned long long __real_getHRTimeUs(void);
unsigned long long __wrap_getHRTimeUs(void);
unsigned long long __wrap_getHRTimeUs(void)
{
    return atomic_load(&test_monotonic_us);
}

int __wrap_gettimeofday(struct timeval *value, void *zone);
int __wrap_gettimeofday(struct timeval *value, void *zone)
{
    discard        zone;
    const uint64_t ms = atomic_load(&test_wall_ms);
    value->tv_sec     = (time_t) (ms / 1000U);
    value->tv_usec    = (suseconds_t) ((ms % 1000U) * 1000U);
    return 0;
}

static bool recordContainsSummary(const char *record, size_t length)
{
    const char   marker[]      = "\"operation\":\"rejection-summary\"";
    const size_t marker_length = sizeof(marker) - 1;
    if (length < marker_length)
        return false;
    for (size_t offset = 0; offset <= length - marker_length; ++offset)
        if (memcmp(record + offset, marker, marker_length) == 0)
            return true;
    return false;
}

bool __real_authenticationserverAuditWriterAppend(authenticationserver_audit_writer_t *, const char *, size_t,
                                                  authenticationserver_audit_error_t *);
bool __wrap_authenticationserverAuditWriterAppend(authenticationserver_audit_writer_t *, const char *, size_t,
                                                  authenticationserver_audit_error_t *);
bool __wrap_authenticationserverAuditWriterAppend(authenticationserver_audit_writer_t *writer, const char *record,
                                                  size_t length, authenticationserver_audit_error_t *error)
{
    if (atomic_exchange(&hold_append, false))
    {
        semaphorePost(&entered);
        twfRequire(semaphoreWait(&release_writer), "writer release failed");
    }
    if (atomic_exchange(&fail_append, false) ||
        (recordContainsSummary(record, length) && atomic_exchange(&fail_summary, false)))
    {
        *error =
            (authenticationserver_audit_error_t) {.code = kAuthenticationServerAuditErrorWrite, .native_error = EIO};
        return false;
    }
    return __real_authenticationserverAuditWriterAppend(writer, record, length, error);
}

bool __real_authenticationserverSaveDatabaseLockedForReason(authenticationserver_tstate_t *,
                                                            authenticationserver_save_reason_t);
bool __wrap_authenticationserverSaveDatabaseLockedForReason(authenticationserver_tstate_t *,
                                                            authenticationserver_save_reason_t);
bool __wrap_authenticationserverSaveDatabaseLockedForReason(authenticationserver_tstate_t     *ts,
                                                            authenticationserver_save_reason_t reason)
{
    if (fail_save)
    {
        fail_save = false;
        return false;
    }
    return __real_authenticationserverSaveDatabaseLockedForReason(ts, reason);
}

static authenticationserver_tstate_t *state(void)
{
    return tunnelGetState(server);
}

bool __real_authenticationserverAuditWriterClose(authenticationserver_audit_writer_t *,
                                                 authenticationserver_audit_error_t *);
bool __wrap_authenticationserverAuditWriterClose(authenticationserver_audit_writer_t *,
                                                 authenticationserver_audit_error_t *);
bool __wrap_authenticationserverAuditWriterClose(authenticationserver_audit_writer_t *writer,
                                                 authenticationserver_audit_error_t  *error)
{
    if (atomic_exchange(&capture_close, false))
        authenticationserverAuditSnapshot(state()->audit, &close_snapshot);
    return __real_authenticationserverAuditWriterClose(writer, error);
}

static void readToken(char token[49])
{
    authenticationserverEditTokenFormat(state()->api_instance_id, state()->store.config_revision, token);
}

static cJSON *call(const char *operation, const char *body, const char *expected_error)
{
    sbuf_t *input = bufferpoolGetBestFit(env.pool, (uint32_t) strlen(body), 0);
    memoryCopy(sbufGetMutablePtr(input), body, strlen(body));
    sbufSetLength(input, (uint32_t) strlen(body));
    context.operation   = operation;
    api_result_t result = nodeApiFind(server, operation)->handler(server, input, &context);
    twfRequire(result.buffer != NULL, "missing bounded result");
    cJSON *json = cJSON_ParseWithLength((const char *) sbufGetRawPtr(result.buffer), sbufGetLength(result.buffer));
    bufferpoolReuseBuffer(env.pool, result.buffer);
    twfRequire(cJSON_IsObject(json), "invalid result JSON");
    if (expected_error == NULL)
        twfRequire(result.result_code == kApiResultOk, "valid mutation failed");
    else
    {
        const cJSON *error = cJSON_GetObjectItemCaseSensitive(json, "error");
        const cJSON *code  = cJSON_GetObjectItemCaseSensitive(error, "code");
        twfRequire(result.result_code == kApiResultError && cJSON_IsString(code) &&
                       strcmp(code->valuestring, expected_error) == 0,
                   "incorrect mutation refusal");
    }
    twfRequireNoLeakedBuffers();
    return json;
}

static void waitFor(uint64_t written, uint64_t failures)
{
    const uint64_t deadline = __real_getHRTimeUs() + UINT64_C(5000000);
    for (;;)
    {
        authenticationserver_audit_snapshot_t snapshot;
        authenticationserverAuditSnapshot(state()->audit, &snapshot);
        if (snapshot.written_records == written && snapshot.write_failures == failures && snapshot.queued_records == 0)
            return;
        twfRequire(__real_getHRTimeUs() < deadline, "audit writer did not settle");
        usleep(1000);
    }
}

static void expectText(const cJSON *json, const char *key, const char *expected)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(json, key);
    twfRequire(cJSON_IsString(value) && strcmp(value->valuestring, expected) == 0, "audit field value mismatch");
}

static unsigned inspectFile(const char *path, bool outcomes)
{
    FILE *file = fopen(path, "rb");
    twfRequire(file != NULL, "audit file missing");
    char     line[kAuthenticationServerAuditRecordCap + 1];
    unsigned count = 0;
    while (fgets(line, sizeof(line), file) != NULL)
    {
        ++count;
        size_t length = strlen(line);
        twfRequire(length > 0 && line[length - 1] == '\n' && strstr(line, "PRIVATE_PASSWORD") == NULL &&
                       strstr(line, "PRIVATE_NOTE") == NULL,
                   "partial audit record or secret leaked");
        cJSON *json = cJSON_Parse(line);
        twfRequire(cJSON_IsObject(json) &&
                       cJSON_GetArraySize(json) ==
                           (cJSON_IsNull(cJSON_GetObjectItemCaseSensitive(json, "error")) ? 16 : 17),
                   "audit schema changed");
        char sequence[24];
        snprintf(sequence, sizeof(sequence), "%u", count);
        expectText(json, "sequence", sequence);
        expectText(json, "config", "audit-unit");
        expectText(json, "node", "accounts");
        expectText(json, "server_instance", "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
        if (outcomes)
        {
            expectText(json, "source", "api");
            expectText(json, "actor", "administrator");
            expectText(json, "gateway_config", "gateway-config");
            expectText(json, "gateway_node", "gateway-node");
            expectText(json, "outcome", count == 2 || count == 5 ? "rejected" : "committed");
            if (count == 2)
                expectText(json, "error", "id_exists");
            if (count == 5)
                expectText(json, "error", "invalid_request");
        }
        cJSON_Delete(json);
    }
    twfRequire(! ferror(file) && fclose(file) == 0, "audit read failed");
    return count;
}

static void startAudit(const char *path)
{
    atomic_store(&test_monotonic_us, UINT64_C(1000000));
    atomic_store(&test_wall_ms, UINT64_C(1792454400000));
    state()->audit =
        authenticationserverAuditCreate(path, 1024 * 1024, 2, "audit-unit", "accounts", state()->api_instance_id);
    twfRequire(state()->audit != NULL, "audit startup failed");
}

static void stopAudit(void)
{
    authenticationserverAuditDestroy(state()->audit);
    state()->audit = NULL;
}

static void mutations(const char *path)
{
    startAudit(path);
    cJSON_Delete(call("create-user", "{\"id\":\"42\",\"password\":\"PRIVATE_PASSWORD_INITIAL\"}", NULL));
    waitFor(1, 0);
    cJSON_Delete(call("create-user", "{\"id\":\"42\",\"password\":\"PRIVATE_PASSWORD_DUPLICATE\"}", "id_exists"));
    waitFor(2, 0);
    char token[49], body[512];
    readToken(token);
    snprintf(body,
             sizeof(body),
             "{\"id\":\"42\",\"if_match\":\"%s\",\"patch\":{\"enabled\":false,\"notes\":\"PRIVATE_NOTE\"}}",
             token);
    cJSON_Delete(call("update-user", body, NULL));
    waitFor(3, 0);
    readToken(token);
    snprintf(
        body, sizeof(body), "{\"id\":\"42\",\"if_match\":\"%s\",\"password\":\"PRIVATE_PASSWORD_ROTATED\"}", token);
    cJSON_Delete(call("change-user-password", body, NULL));
    waitFor(4, 0);
    atomic_fetch_add(&test_monotonic_us, UINT64_C(5000000));
    cJSON_Delete(call("change-user-password", "{\"password\":\"PRIVATE_PASSWORD_MALFORMED\",", "invalid_request"));
    waitFor(5, 0);
    stopAudit();
    twfRequire(inspectFile(path, true) == 5, "mutation outcomes missing from audit");
}

static void queueAndDrain(const char *path)
{
    startAudit(path);
    atomic_store(&hold_append, true);
    authenticationserverAuditRecordProducer(state()->audit, "producer", "UpdateUser", 42, 100, 0, NULL);
    twfRequire(semaphoreWait(&entered), "writer gate failed");
    for (unsigned i = 0; i < kAuthenticationServerAuditQueueCap; ++i)
        authenticationserverAuditRecordProducer(state()->audit, "producer", "UpdateUser", 42, 101 + i, 0, NULL);
    authenticationserverAuditRecordProducer(state()->audit, "producer", "UpdateUser", 42, 999, 0, NULL);
    authenticationserver_audit_snapshot_t snapshot;
    authenticationserverAuditSnapshot(state()->audit, &snapshot);
    twfRequire(snapshot.enabled && ! snapshot.healthy &&
                   snapshot.queued_records == kAuthenticationServerAuditQueueCap && snapshot.written_records == 0 &&
                   snapshot.dropped_records == 1 && snapshot.write_failures == 0 &&
                   strcmp(snapshot.last_error, "queue_full") == 0,
               "queue overflow accounting incorrect");
    semaphorePost(&release_writer);
    /* No wait for output: Destroy must drain all 257 accepted records itself. */
    stopAudit();
    twfRequire(inspectFile(path, false) == kAuthenticationServerAuditQueueCap + 1, "shutdown lost accepted records");
}

static void unauthenticatedRefusals(const char *path)
{
    startAudit(path);
    atomic_store(&hold_append, true);
    authenticationserverAuditRecordProducer(state()->audit, "producer", "UpdateUser", 42, 100, 0, NULL);
    twfRequire(semaphoreWait(&entered), "writer gate failed");
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, 0, 2);
    line_t        *line                                                = twfLinePoolCreateLine(&lines);
    const uint8_t  correlation[kAuthenticationServerCorrelationIdSize] = {0, 0, 0, 1};
    const char     refusal[]                                           = "authentication-required";
    const uint64_t revision                                            = state()->store.config_revision;
    const size_t   count                                               = usersCount(&state()->store.users);
    for (unsigned i = 0; i < kAuthenticationServerAuditQueueCap * 2; ++i)
    {
        rwlockWriteLock(&state()->state_lock);
        sbuf_t *response = authenticationserverDispatchRequest(i % 2 ? kAuthenticationServerRequestTypeAddNewUser
                                                                     : kAuthenticationServerRequestTypeUpdateUser,
                                                               correlation,
                                                               server,
                                                               line,
                                                               NULL,
                                                               NULL,
                                                               0);
        rwlockWriteUnlock(&state()->state_lock);
        twfRequire(response != NULL &&
                       sbufGetLength(response) == kAuthenticationServerResponseHeaderSize + sizeof(refusal) - 1 &&
                       ((const uint8_t *) sbufGetRawPtr(response))[0] == kAuthenticationServerResponseTypeError &&
                       memcmp((const uint8_t *) sbufGetRawPtr(response) + kAuthenticationServerResponseHeaderSize,
                              refusal,
                              sizeof(refusal) - 1) == 0,
                   "unauthenticated administration did not retain its protocol refusal");
        lineReuseBuffer(line, response);
    }
    lineDestroy(line);
    twfLinePoolTeardown(&lines);
    authenticationserver_audit_snapshot_t snapshot;
    authenticationserverAuditSnapshot(state()->audit, &snapshot);
    twfRequire(snapshot.enabled && snapshot.healthy && snapshot.queued_records == 0 && snapshot.dropped_records == 0 &&
                   snapshot.write_failures == 0 && snapshot.last_error == NULL &&
                   state()->store.config_revision == revision && usersCount(&state()->store.users) == count,
               "unauthenticated refusals consumed audit capacity, degraded health, or mutated users");
    cJSON_Delete(call("create-user", "{\"id\":\"46\",\"password\":\"PRIVATE_PASSWORD_REAL_ADMIN\"}", NULL));
    authenticationserverAuditSnapshot(state()->audit, &snapshot);
    twfRequire(snapshot.healthy && snapshot.queued_records == 1 && snapshot.dropped_records == 0,
               "anonymous refusals prevented authenticated administrative auditing");
    semaphorePost(&release_writer);
    waitFor(2, 0);
    stopAudit();
    twfRequire(inspectFile(path, false) == 2, "unauthenticated refusals entered the administrative audit file");
    FILE *file = fopen(path, "rb");
    char  record[kAuthenticationServerAuditRecordCap + 1];
    twfRequire(file && fgets(record, sizeof(record), file) && fgets(record, sizeof(record), file) && fclose(file) == 0,
               "cannot read authenticated audit event");
    cJSON *json = cJSON_Parse(record);
    twfRequire(cJSON_IsObject(json), "authenticated audit event is not JSON");
    expectText(json, "source", "api");
    expectText(json, "actor", "administrator");
    expectText(json, "operation", "create-user");
    expectText(json, "outcome", "committed");
    cJSON_Delete(json);
    twfRequireNoLeakedBuffers();
}

static void rejectionSampling(const char *path)
{
    startAudit(path);
    atomic_store(&hold_append, true);
    authenticationserverAuditRecordProducer(state()->audit, "producer", "UpdateUser", 42, 100, 0, NULL);
    twfRequire(semaphoreWait(&entered), "sampling writer gate failed");
    for (unsigned i = 0; i < 100; ++i)
    {
        if (i % 2)
            authenticationserverAuditRecordApi(state()->audit, &context, "create-user", 42, 0, 0, "id_exists");
        else
            authenticationserverAuditRecordProducer(
                state()->audit, i % 3 ? "other" : "producer", "UpdateUser", 42, 0, 0, "invalid-user");
    }
    atomic_store(&test_monotonic_us, UINT64_C(5999000));
    atomic_store(&test_wall_ms, UINT64_C(1000)); /* Backward wall time cannot admit a sample. */
    authenticationserverAuditRecordProducer(state()->audit, "third", "AddNewUser", 42, 0, 0, "invalid-user");
    authenticationserver_audit_snapshot_t snapshot;
    authenticationserverAuditSnapshot(state()->audit, &snapshot);
    twfRequire(snapshot.healthy && snapshot.queued_records == 1 && snapshot.suppressed_rejections == 100 &&
                   snapshot.dropped_records == 0,
               "rejection rate or wall-clock immunity failed");
    atomic_store(&test_monotonic_us, UINT64_C(6000000));
    authenticationserverAuditRecordApi(state()->audit, &context, "update-user", 42, 0, 0, "conflict");
    atomic_store(&test_monotonic_us, UINT64_C(600000000)); /* Idle time earns only one sample. */
    authenticationserverAuditRecordProducer(state()->audit, "fourth", "AddNewUser", 42, 0, 0, "invalid-user");
    authenticationserverAuditRecordProducer(state()->audit, "fifth", "UpdateUser", 42, 0, 0, "invalid-user");
    for (unsigned i = 0; i < 13; ++i)
        authenticationserverAuditRecordProducer(state()->audit, "producer", "UpdateUser", 42, 101 + i, 0, NULL);
    atomic_fetch_add(&test_monotonic_us, UINT64_C(5000000));
    authenticationserverAuditRecordApi(state()->audit, &context, "create-user", 42, 0, 0, "id_exists");
    for (unsigned i = 16; i < kAuthenticationServerAuditQueueCap; ++i)
        authenticationserverAuditRecordProducer(state()->audit, "producer", "UpdateUser", 42, 101 + i, 0, NULL);
    authenticationserverAuditRecordApi(state()->audit, &context, "create-user", 42, 0, 0, "id_exists");
    authenticationserverAuditSnapshot(state()->audit, &snapshot);
    twfRequire(snapshot.healthy && snapshot.queued_records == kAuthenticationServerAuditQueueCap &&
                   snapshot.suppressed_rejections == 103 && snapshot.dropped_records == 0 &&
                   snapshot.last_error == NULL,
               "reserved commit capacity or intentional suppression accounting failed");
    cJSON *status_json = call("status", "{}", NULL);
    expectText(cJSON_GetObjectItemCaseSensitive(status_json, "audit"), "suppressed_rejections", "103");
    cJSON_Delete(status_json);
    semaphorePost(&release_writer);
    stopAudit();
    twfRequire(inspectFile(path, false) == kAuthenticationServerAuditQueueCap + 2,
               "sampling drain omitted accepted records or final aggregate");
    FILE    *file = fopen(path, "rb");
    char     line[kAuthenticationServerAuditRecordCap + 1];
    unsigned index = 0, rejected = 0;
    while (fgets(line, sizeof(line), file) != NULL)
    {
        ++index;
        cJSON *json = cJSON_Parse(line);
        if (! cJSON_IsNull(cJSON_GetObjectItemCaseSensitive(json, "error")))
        {
            ++rejected;
            expectText(json, "node_suppressed_rejections", index == 3 ? "100" : index == 258 ? "3" : "0");
            if (index == 258)
            {
                expectText(json, "source", "server");
                expectText(json, "operation", "rejection-summary");
                expectText(json, "error", "suppressed-rejections");
                expectText(json, "outcome", "rejected");
                const char *nulls[] = {"actor", "gateway_config", "gateway_node", "user_id", "config_revision"};
                for (unsigned i = 0; i < sizeof(nulls) / sizeof(nulls[0]); ++i)
                    twfRequire(cJSON_IsNull(cJSON_GetObjectItemCaseSensitive(json, nulls[i])),
                               "node-wide summary attributed to an individual operation");
                twfRequire(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(json, "fields")) == 0,
                           "node-wide summary claimed account changes");
            }
        }
        cJSON_Delete(json);
    }
    twfRequire(rejected == 4 && fclose(file) == 0, "rejection burst accumulated extra samples");
}

static void summaryFailure(const char *path)
{
    startAudit(path);
    authenticationserverAuditRecordProducer(state()->audit, "producer", "UpdateUser", 42, 100, 0, NULL);
    authenticationserverAuditRecordProducer(state()->audit, "producer", "UpdateUser", 42, 0, 0, "invalid-user");
    for (unsigned i = 0; i < 23; ++i)
        authenticationserverAuditRecordProducer(state()->audit, "other", "AddNewUser", 0, 0, 0, "invalid-user");
    waitFor(2, 0);
    atomic_store(&capture_close, true);
    atomic_store(&fail_summary, true);
    stopAudit();
    twfRequire(! atomic_load(&capture_close) && ! atomic_load(&fail_summary) && ! close_snapshot.healthy &&
                   close_snapshot.written_records == 2 && close_snapshot.queued_records == 0 &&
                   close_snapshot.suppressed_rejections == 23 && close_snapshot.dropped_records == 1 &&
                   close_snapshot.write_failures == 1 && strcmp(close_snapshot.last_error, "write") == 0,
               "failed final aggregate counted suppressed events as lost records or hid writer failure");
    twfRequire(inspectFile(path, false) == 2, "failed summary affected earlier accepted records");
}

static void appendSpanBoundaries(const char *path)
{
    authenticationserver_audit_error_t   error;
    authenticationserver_audit_writer_t *writer = authenticationserverAuditWriterOpen(path, 1024, 2, &error);
    twfRequire(writer != NULL, "span-check audit writer failed to open");
    /* These complete JSONL records intentionally have no NUL terminator. */
    const char ordinary[sizeof("{\"operation\":\"UpdateUser\",\"outcome\":\"committed\"}\n") - 1] =
        "{\"operation\":\"UpdateUser\",\"outcome\":\"committed\"}\n";
    const char summary[sizeof("{\"operation\":\"rejection-summary\"}\n") - 1] =
        "{\"operation\":\"rejection-summary\"}\n";
    const char   trailing[]    = "{\"operation\":\"UpdateUser\"}\n\"operation\":\"rejection-summary\"";
    const size_t prefix_length = sizeof("{\"operation\":\"UpdateUser\"}\n") - 1;
    atomic_store(&fail_summary, true);
    twfRequire(__wrap_authenticationserverAuditWriterAppend(writer, trailing, prefix_length, &error) &&
                   atomic_load(&fail_summary),
               "summary marker outside the supplied record consumed the injected failure");
    twfRequire(__wrap_authenticationserverAuditWriterAppend(writer, ordinary, sizeof(ordinary), &error) &&
                   atomic_load(&fail_summary),
               "nonterminated ordinary record consumed the summary failure");
    twfRequire(! __wrap_authenticationserverAuditWriterAppend(writer, summary, sizeof(summary), &error) &&
                   ! atomic_load(&fail_summary) && error.code == kAuthenticationServerAuditErrorWrite &&
                   error.native_error == EIO,
               "nonterminated summary record did not consume its injected failure");
    twfRequire(authenticationserverAuditWriterClose(writer, &error), "span-check audit writer failed to close");

    FILE *file = fopen(path, "rb");
    char  written[sizeof(trailing) + sizeof(ordinary)];
    twfRequire(file != NULL && fread(written, 1, sizeof(written), file) == prefix_length + sizeof(ordinary) &&
                   feof(file) && ! ferror(file) && fclose(file) == 0 && memcmp(written, trailing, prefix_length) == 0 &&
                   memcmp(written + prefix_length, ordinary, sizeof(ordinary)) == 0,
               "span-check append wrote bytes outside the accepted records");
}

static void writerFailure(const char *path)
{
    startAudit(path);
    atomic_store(&hold_append, true);
    atomic_store(&fail_append, true);
    cJSON_Delete(call("create-user", "{\"id\":\"43\",\"password\":\"PRIVATE_PASSWORD_BEFORE_FAILURE\"}", NULL));
    twfRequire(semaphoreWait(&entered), "writer gate failed");
    authenticationserverAuditRecordProducer(state()->audit, "producer", "UpdateUser", 42, 100, 0, NULL);
    semaphorePost(&release_writer);
    waitFor(0, 1);
    uint64_t revision = state()->store.config_revision;
    cJSON_Delete(call("create-user", "{\"id\":\"44\",\"password\":\"PRIVATE_PASSWORD_AFTER_FAILURE\"}", NULL));
    twfRequire(state()->store.config_revision == revision + 1 &&
                   usersLookupByIdentifier(&state()->store.users, 44) != NULL,
               "failed audit writer changed account commitment");
    authenticationserverAuditRecordProducer(state()->audit, "producer", "UpdateUser", 42, 0, 0, "invalid-user");
    authenticationserver_audit_snapshot_t snapshot;
    authenticationserverAuditSnapshot(state()->audit, &snapshot);
    twfRequire(snapshot.enabled && ! snapshot.healthy && snapshot.queued_records == 0 &&
                   snapshot.written_records == 0 && snapshot.dropped_records == 4 && snapshot.write_failures == 1 &&
                   snapshot.suppressed_rejections == 0 && strcmp(snapshot.last_error, "write") == 0,
               "failed writer did not account for queued and subsequent records");
    stopAudit();
    twfRequire(inspectFile(path, false) == 0, "injected failure unexpectedly wrote a record");
}

static void producerRollback(const char *path)
{
    startAudit(path);
    /* The fixture owns this normal line; the dispatcher only borrows it to
     * allocate a reply. It emits no inter-tunnel callbacks. */
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, 0, 2);
    line_t                        *line            = twfLinePoolCreateLine(&lines);
    char                           producer_name[] = "rollback-producer";
    authenticationserver_session_t session         = {.client_name = producer_name, .allow_user_write = true};
    const uint8_t                  correlation[kAuthenticationServerCorrelationIdSize] = {0, 0, 0, 1};
    const char                     body[]   = "{\"id\":\"45\",\"password\":\"PRIVATE_PASSWORD_ROLLED_BACK\"}";
    const uint64_t                 revision = state()->store.config_revision;
    const size_t                   count    = usersCount(&state()->store.users);
    fail_save                               = true;
    rwlockWriteLock(&state()->state_lock);
    sbuf_t *reply = authenticationserverDispatchRequest(kAuthenticationServerRequestTypeAddNewUser,
                                                        correlation,
                                                        server,
                                                        line,
                                                        &session,
                                                        (const uint8_t *) body,
                                                        sizeof(body) - 1);
    rwlockWriteUnlock(&state()->state_lock);
    const char error[] = "database-save-failed";
    twfRequire(! fail_save && reply != NULL &&
                   sbufGetLength(reply) == kAuthenticationServerResponseHeaderSize + sizeof(error) - 1 &&
                   ((const uint8_t *) sbufGetRawPtr(reply))[0] == kAuthenticationServerResponseTypeError &&
                   memcmp((const uint8_t *) sbufGetRawPtr(reply) + kAuthenticationServerResponseHeaderSize,
                          error,
                          sizeof(error) - 1) == 0,
               "producer save failure did not return its rollback refusal");
    lineReuseBuffer(line, reply);
    twfRequire(state()->store.config_revision == revision && usersCount(&state()->store.users) == count &&
                   usersLookupByIdentifier(&state()->store.users, 45) == NULL &&
                   usersLookupByPassword(&state()->store.users, "PRIVATE_PASSWORD_ROLLED_BACK") == NULL &&
                   usersValidate(&state()->store.users),
               "producer rollback retained account/index state or changed revision");
    lineDestroy(line);
    twfLinePoolTeardown(&lines);
    stopAudit();
    twfRequire(inspectFile(path, false) == 1, "producer rollback did not record exactly one outcome");
    FILE *file = fopen(path, "rb");
    char  record[kAuthenticationServerAuditRecordCap + 1];
    twfRequire(file != NULL && fgets(record, sizeof(record), file) != NULL && fclose(file) == 0,
               "cannot read producer rollback event");
    cJSON *json = cJSON_Parse(record);
    twfRequire(cJSON_IsObject(json), "producer rollback event is not JSON");
    expectText(json, "source", "producer");
    expectText(json, "actor", "rollback-producer");
    expectText(json, "operation", "AddNewUser");
    expectText(json, "user_id", "45");
    expectText(json, "outcome", "rejected");
    expectText(json, "error", "database-save-failed");
    twfRequire(cJSON_IsNull(cJSON_GetObjectItemCaseSensitive(json, "config_revision")),
               "producer rollback event claimed a committed revision");
    cJSON_Delete(json);
    twfRequireNoLeakedBuffers();
}

int main(void)
{
    twfSetCase("AuthenticationServer administrative audit");
    twfRequire(createNetworkLogger(NULL, false) && wCryptoGlobalInit() == kWCryptoOk, "runtime init failed");
    twfWorkerEnvSetup(&env, 8192, 32);
    nodeApiRegistryInitialize();
    server = tunnelCreate(NULL, sizeof(authenticationserver_tstate_t), 0);
    twfRequire(server != NULL, "server allocation failed");
    rwlockinit(&state()->state_lock);
    twfRequire(usersCreate(&state()->store.users), "users init failed");
    state()->database_loaded       = true;
    state()->store.config_revision = 84;
    state()->store.stats_revision  = 19;
    memset(state()->api_instance_id, 0x5a, 16);
    authenticationserverInitializeAccountingClock(state());
    authenticationserverInitializeExportLimit(state());
    twfRequire(authenticationserverRegisterApi(server), "registration failed");
    context = (node_api_call_context_t) {.principal                = "administrator",
                                         .gateway_config           = "gateway-config",
                                         .gateway_node             = "gateway-node",
                                         .deadline_ms              = UINT64_MAX,
                                         .max_response_body_size   = kAuthenticationServerApiBodyCap,
                                         .working_memory_allowance = 4 * 1024 * 1024};
    authenticationserver_audit_snapshot_t disabled;
    authenticationserverAuditSnapshot(NULL, &disabled);
    twfRequire(! disabled.enabled && disabled.healthy && disabled.queued_records == 0 &&
                   disabled.written_records == 0 && disabled.dropped_records == 0 &&
                   disabled.suppressed_rejections == 0 && disabled.write_failures == 0 && disabled.last_error == NULL,
               "disabled audit has nonempty telemetry");
    semaphoreInit(&entered, 0);
    semaphoreInit(&release_writer, 0);
    atomic_init(&hold_append, false);
    atomic_init(&fail_append, false);
    char directory[] = "/tmp/ww-audit-events-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "temporary directory failed");
    atomic_init(&test_monotonic_us, UINT64_C(1000000));
    atomic_init(&test_wall_ms, UINT64_C(1792454400000));
    atomic_init(&fail_summary, false);
    atomic_init(&capture_close, false);
    char paths[8][256], bad[256];
    snprintf(bad, sizeof(bad), "%s/missing/audit.jsonl", directory);
    twfRequire(authenticationserverAuditCreate(bad, 16384, 2, "audit-unit", "accounts", state()->api_instance_id) ==
                   NULL,
               "invalid audit path did not refuse startup");
    for (unsigned i = 0; i < 8; ++i)
        snprintf(paths[i], sizeof(paths[i]), "%s/audit-%u.jsonl", directory, i);
    appendSpanBoundaries(paths[7]);
    mutations(paths[0]);
    queueAndDrain(paths[1]);
    writerFailure(paths[2]);
    producerRollback(paths[3]);
    unauthenticatedRefusals(paths[4]);
    rejectionSampling(paths[5]);
    summaryFailure(paths[6]);
    for (unsigned i = 0; i < 8; ++i)
    {
        char lock[300];
        snprintf(lock, sizeof(lock), "%.*s.lock", (int) sizeof(paths[i]) - 1, paths[i]);
        twfRequire(unlink(paths[i]) == 0 && unlink(lock) == 0, "audit file cleanup failed");
    }
    twfRequire(rmdir(directory) == 0, "temporary directory cleanup failed");
    semaphoreDestroy(&entered);
    semaphoreDestroy(&release_writer);
    nodeApiUnregister(server);
    usersDestroy(&state()->store.users);
    rwlockDestroy(&state()->state_lock);
    tunnelDestroy(server);
    nodeApiRegistryDestroy();
    twfWorkerEnvTeardown(&env);
    wCryptoGlobalCleanup();
    networkloggerDestroy();
    return 0;
}
