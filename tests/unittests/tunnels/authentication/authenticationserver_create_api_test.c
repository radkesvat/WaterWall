/* CTest: waterwall.authenticationserver_create_api_unit
 * Registered create-only handler: strict schema, fresh-account defaults and
 * credentials, refusal atomicity, contention, concurrency, persistence and real
 * dispatcher late/abandoned/shutdown replies. Calls own buffers and no line. */
#include "AuthenticationServer/config_create.h"
#include "AuthenticationServer/config_update.h"
#include "api/dispatcher.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "loggers/network_logger.h"
#include "wthread.h"

static twf_worker_env_t        env;
static tunnel_t               *server;
static node_api_call_context_t context;
static uint64_t                fake_time_us;
static unsigned                clock_reads, expire_after, crypto_failure, init_calls, init_failure;
static bool                    check_crypto_unlocked;
static unsigned                collision_kind;
static const user_t           *collision_source;

static authenticationserver_tstate_t *state(void)
{
    return tunnelGetState(server);
}

uint64_t __real_getHRTimeUs(void);
uint64_t __wrap_getHRTimeUs(void);
uint64_t __wrap_getHRTimeUs(void)
{
    if (fake_time_us == 0)
        return __real_getHRTimeUs();
    if (expire_after != 0 && ++clock_reads >= expire_after)
        return fake_time_us + UINT64_C(1000000);
    return fake_time_us;
}

int __real_pthread_rwlock_init(pthread_rwlock_t *, const pthread_rwlockattr_t *);
int __wrap_pthread_rwlock_init(pthread_rwlock_t *, const pthread_rwlockattr_t *);
int __wrap_pthread_rwlock_init(pthread_rwlock_t *lock, const pthread_rwlockattr_t *attr)
{
    if (init_failure && ++init_calls == init_failure)
        return EAGAIN;
    return __real_pthread_rwlock_init(lock, attr);
}

static void cryptoLockCheck(void)
{
    if (! check_crypto_unlocked)
        return;
    twfRequire(rwlockTryWriteLock(&state()->state_lock), "credential derivation held server state");
    twfRequire(rwlockTryWriteLock(&state()->store.users.lock), "credential derivation held collection");
    rwlockWriteUnlock(&state()->store.users.lock);
    rwlockWriteUnlock(&state()->state_lock);
}
wcrypto_status_t __real_wCryptoSHA224(sha224_hash_t *, const unsigned char *, size_t);
wcrypto_status_t __real_wCryptoSHA256(sha256_hash_t *, const unsigned char *, size_t);
wcrypto_status_t __real_wCryptoX25519(unsigned char *, const unsigned char *, const unsigned char *);
wcrypto_status_t __wrap_wCryptoSHA224(sha224_hash_t *, const unsigned char *, size_t);
wcrypto_status_t __wrap_wCryptoSHA256(sha256_hash_t *, const unsigned char *, size_t);
wcrypto_status_t __wrap_wCryptoX25519(unsigned char *, const unsigned char *, const unsigned char *);
wcrypto_status_t __wrap_wCryptoSHA224(sha224_hash_t *out, const unsigned char *in, size_t length)
{
    cryptoLockCheck();
    if (collision_kind == 1)
    {
        *out = collision_source->sha224_pass;
        return kWCryptoOk;
    }
    return crypto_failure == 1 ? kWCryptoBackendFailed : __real_wCryptoSHA224(out, in, length);
}
wcrypto_status_t __wrap_wCryptoSHA256(sha256_hash_t *out, const unsigned char *in, size_t length)
{
    cryptoLockCheck();
    if (collision_kind == 2)
    {
        *out = collision_source->sha256_pass;
        return kWCryptoOk;
    }
    return crypto_failure == 2 ? kWCryptoBackendFailed : __real_wCryptoSHA256(out, in, length);
}
wcrypto_status_t __wrap_wCryptoX25519(unsigned char *out, const unsigned char *scalar, const unsigned char *point)
{
    cryptoLockCheck();
    if (collision_kind == 3)
    {
        memoryCopy(out, collision_source->wireguard_publickey, 32);
        return kWCryptoOk;
    }
    return crypto_failure == 3 ? kWCryptoBackendFailed : __real_wCryptoX25519(out, scalar, point);
}

typedef struct queued_message_s
{
    WorkerMessageCallback callback;
    void                 *arg1, *arg2, *arg3;
} queued_message_t;
static queued_message_t        queued[4];
static size_t                  queue_count;
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t, WorkerMessageCallback,
                                                                             WorkerMessageCleanupCallback, void *,
                                                                             void *, void *);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    discard cleanup;
    twfRequire(wid == 0 && queue_count < 4, "unexpected detached message");
    queued[queue_count++] = (queued_message_t) {callback, arg1, arg2, arg3};
    return kWorkerMessageSubmitAccepted;
}
static void nextMessage(void)
{
    twfRequire(queue_count > 0, "missing detached message");
    queued_message_t message = queued[0];
    for (size_t i = 1; i < queue_count; ++i)
        queued[i - 1] = queued[i];
    --queue_count;
    message.callback(&env.worker, message.arg1, message.arg2, message.arg3);
}

static const cJSON *field(const cJSON *object, const char *name)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, name);
    twfRequire(value != NULL, "missing response field");
    return value;
}
static void requestText(char *out, size_t capacity, uint64_t id, const char *password, const char *config)
{
    int n = snprintf(out,
                     capacity,
                     "{\"id\":\"%" PRIu64 "\",\"password\":\"%s\"%s%s}",
                     id,
                     password,
                     config == NULL ? "" : ",\"config\":",
                     config == NULL ? "" : config);
    twfRequire(n > 0 && (size_t) n < capacity, "fixture body overflow");
}
static cJSON *callOperation(const char *operation, const void *body, size_t size, const char *error)
{
    sbuf_t *input = bufferpoolGetBestFit(env.pool, (uint32_t) size, 0);
    memoryCopy(sbufGetMutablePtr(input), body, size);
    sbufSetLength(input, (uint32_t) size);
    const uint64_t revision = state()->store.config_revision;
    const size_t   count = usersCount(&state()->store.users), slots = state()->store.users.slot_count;
    context.operation   = operation;
    api_result_t result = nodeApiFind(server, operation)->handler(server, input, &context);
    twfRequire(result.result_code == (error == NULL ? kApiResultOk : kApiResultError) && result.buffer != NULL,
               "incorrect operation result");
    const size_t length = sbufGetLength(result.buffer);
    char        *raw    = memoryAllocate(length + 1);
    memoryCopy(raw, sbufGetRawPtr(result.buffer), length);
    raw[length]                  = 0;
    static const char *secrets[] = {
        "password", "sha224", "sha256", "uuid_pass", "wireguard_publickey", "SECRET_SENTINEL"};
    for (size_t i = 0; i < sizeof(secrets) / sizeof(*secrets); ++i)
        twfRequire(strstr(raw, secrets[i]) == NULL, "credential leaked in public output");
    cJSON *json = cJSON_Parse(raw);
    memoryFree(raw);
    twfRequire(cJSON_IsObject(json), "response is not JSON");
    if (error != NULL)
    {
        twfRequire(strcmp(field(field(json, "error"), "code")->valuestring, error) == 0, "wrong create error code");
        twfRequire(state()->store.config_revision == revision && usersCount(&state()->store.users) == count &&
                       state()->store.users.slot_count == slots,
                   "refusal changed active state or consumed slot");
        twfRequire(cJSON_GetArraySize(json) == 1, "error disclosed extra state");
    }
    else if (strcmp(operation, "create-user") == 0)
    {
        char expected[24], token[49];
        snprintf(expected, sizeof(expected), "%" PRIu64, revision + 1);
        authenticationserverEditTokenFormat(state()->api_instance_id, revision + 1, token);
        twfRequire(cJSON_GetArraySize(json) == 3 && length <= 256 &&
                       strcmp(field(json, "config_revision")->valuestring, expected) == 0 &&
                       strcmp(field(json, "edit_token")->valuestring, token) == 0 &&
                       state()->store.config_revision == revision + 1 &&
                       usersCount(&state()->store.users) == count + 1 && state()->store.users.slot_count == slots + 1,
                   "ACK did not identify exactly one insertion");
    }
    bufferpoolReuseBuffer(env.pool, result.buffer);
    twfRequireNoLeakedBuffers();
    return json;
}
static void call(const char *body, const char *error)
{
    cJSON_Delete(callOperation("create-user", body, strlen(body), error));
}
static void create(uint64_t id, const char *password, const char *config, const char *error)
{
    char body[4096];
    requestText(body, sizeof(body), id, password, config);
    call(body, error);
}
static cJSON *readUser(uint64_t id)
{
    char body[80];
    snprintf(body, sizeof(body), "{\"id\":\"%" PRIu64 "\"}", id);
    return callOperation("get-user", body, strlen(body), NULL);
}

static void registration(void)
{
    const char *names[] = {"status", "get-user", "list-users", "update-user", "create-user"};
    for (size_t i = 0; i < 5; ++i)
    {
        const node_api_operation_t *op = nodeApiFind(server, names[i]);
        twfRequire(op != NULL && op->read_only == (i < 3) && op->execution == kNodeApiCallingWorker &&
                       strcmp(op->request_content_type, "application/json") == 0 &&
                       strcmp(op->response_content_type, "application/json") == 0,
                   "descriptor changed capability or execution contract");
    }
}

static void parsing(void)
{
    static const char *invalid[] = {"",
                                    "null",
                                    "[]",
                                    "{}",
                                    "{\"id\":\"50\"}",
                                    "{\"password\":\"x\"}",
                                    "{\"id\":50,\"password\":\"x\"}",
                                    "{\"id\":true,\"password\":\"x\"}",
                                    "{\"id\":\"50\",\"password\":null}",
                                    "{\"id\":\"50\",\"password\":false}",
                                    "{\"id\":\"50\",\"password\":\"\"}",
                                    "{\"id\":\"50\",\"password\":\"a\\u0000b\"}",
                                    "{\"id\":\"50\",\"password\":\"\300\200\"}",
                                    "{\"id\":\"50\",\"password\":\"\\ud800\"}",
                                    "{\"id\":\"50\",\"password\":\"x\",\"config\":null}",
                                    "{\"id\":\"50\",\"password\":\"x\",\"config\":[]}",
                                    "{\"id\":\"50\",\"password\":\"x\",\"id\":\"50\"}",
                                    "{\"id\":\"50\",\"password\":\"x\",\"passw\\u006frd\":\"y\"}",
                                    "{\"id\":\"50\",\"password\":\"x\",\"config\":{},\"config\":{}}",
                                    "{\"id\":\"50\",\"password\":\"x\",\"if_match\":\"x\"}",
                                    "{\"id\":\"50\",\"password\":\"x\",\"edit_token\":\"x\"}",
                                    "{\"id\":\"50\",\"password\":\"x\",\"request_id\":\"x\"}",
                                    "{\"id\":\"50\",\"password\":\"x\",\"extra\":false}",
                                    "{\"id\":\"50\",\"password\":\"x\"} trailing"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i)
        call(invalid[i], "invalid_request");
    static const char *configs[] = {"{\"enabled\":null}",
                                    "{\"enabled\":1}",
                                    "{\"enabled\":\"false\"}",
                                    "{\"enabled\":false,\"enabl\\u0065d\":true}",
                                    "{\"name\":false}",
                                    "{\"email\":null}",
                                    "{\"notes\":\"x\\u0000y\"}",
                                    "{\"notes\":\"\355\240\200\"}",
                                    "{\"id\":\"50\"}",
                                    "{\"password\":\"x\"}",
                                    "{\"sha256_pass\":\"x\"}",
                                    "{\"uuid_pass\":\"x\"}",
                                    "{\"wireguard_publickey\":\"x\"}",
                                    "{\"stats\":{}}",
                                    "{\"runtime\":{}}",
                                    "{\"client_time\":{}}",
                                    "{\"usage\":{\"u\":\"0\"}}",
                                    "{\"time\":{\"created_at_ms\":\"0\"}}",
                                    "{\"time\":{\"first_usage_at_ms\":\"0\"}}",
                                    "{\"wireguard-allowed-ips\":\"\"}",
                                    "{\"record-stat-interval-ms\":\"0\"}",
                                    "{\"limit\":{}}",
                                    "{\"time\":{}}",
                                    "{\"limit\":null}",
                                    "{\"limit\":{\"traffic\":{}}}",
                                    "{\"limit\":{\"bandwidth\":{}}}",
                                    "{\"limit\":{\"traffic\":{\"up\":\"0\"}}}",
                                    "{\"limit\":{\"bandwidth\":{\"total\":\"0\"}}}",
                                    "{\"limit\":{\"cons-in\":\"0\"}}",
                                    "{\"limit\":{\"traffic\":{\"u\":{\"x\":\"0\"}}}}",
                                    "{\"gid\":0}",
                                    "{\"gid\":null}",
                                    "{\"gid\":\"\"}",
                                    "{\"gid\":\"00\"}",
                                    "{\"gid\":\"01\"}",
                                    "{\"gid\":\"+1\"}",
                                    "{\"gid\":\"-1\"}",
                                    "{\"gid\":\" 1\"}",
                                    "{\"gid\":\"1 \"}",
                                    "{\"gid\":\"1.0\"}",
                                    "{\"gid\":\"1e0\"}",
                                    "{\"gid\":\"18446744073709551616\"}",
                                    "{\"record_stat_interval_ms\":\"2147483648\"}",
                                    "{\"record_stat_interval_ms\":-1}"};
    for (size_t i = 0; i < sizeof(configs) / sizeof(*configs); ++i)
        create(50, "parser-secret", configs[i], "invalid_request");
    const char *ids[] = {"0", "00", "01", "+50", "-1", " 1", "1 ", "1.0", "1e0", "18446744073709551616"};
    char        body[2048];
    for (size_t i = 0; i < sizeof(ids) / sizeof(*ids); ++i)
    {
        snprintf(body, sizeof(body), "{\"id\":\"%s\",\"password\":\"x\"}", ids[i]);
        call(body, "invalid_request");
    }
    static const char nul[] = "{\"id\":\"50\",\"password\":\"x\"}\0{}";
    cJSON_Delete(callOperation("create-user", nul, sizeof(nul) - 1, "invalid_request"));
    strcpy(body, "{");
    for (unsigned i = 0; i < 40; ++i)
    {
        char entry[32];
        snprintf(entry, sizeof(entry), "%s\"k%u\":false", i == 0 ? "" : ",", i);
        strcat(body, entry);
    }
    strcat(body, "}");
    call(body, "invalid_request");
    char *large = memoryAllocate(32769);
    memset(large, ' ', 32769);
    cJSON_Delete(callOperation("create-user", large, 32769, "invalid_request"));
    /* Exactly 32 KiB is valid. A long password remains exact, beyond producer
     * protocol's separate password limit, and configuration is omitted. */
    const char  *prefix = "{\"id\":\"50\",\"password\":\"";
    const size_t head = strlen(prefix), password_length = 32768 - head - 2;
    memoryCopy(large, prefix, head);
    memset(large + head, 'x', password_length);
    memoryCopy(large + 32766, "\"}", 3);
    cJSON_Delete(callOperation("create-user", large, 32768, NULL));
    user_t *u = usersLookupByIdentifier(&state()->store.users, 50);
    twfRequire(u != NULL && strlen(u->password) == password_length, "bounded password was truncated");
    memorySecureZero(large, 32769);
    memoryFree(large);
}

static void defaultsAndConfiguration(void)
{
    check_crypto_unlocked = true;
    const uint64_t before = getTimeOfDayMS();
    create(UINT64_C(9007199254740993), "  SECRET_SENTINEL\u20ac  ", NULL, NULL);
    check_crypto_unlocked = false;
    user_t *u             = usersLookupByIdentifier(&state()->store.users, UINT64_C(9007199254740993));
    twfRequire(u != NULL && u->enabled && u->gid == 0 && u->name[0] == 0 && u->email[0] == 0 && u->notes[0] == 0 &&
                   u->wireguard_allowed_ips[0] == 0 && u->record_stat_interval_ms == 120000 &&
                   u->timeinfo.created_at_ms >= before && u->timeinfo.created_at_ms <= getTimeOfDayMS() &&
                   u->timeinfo.first_usage_at_ms == 0 && u->timeinfo.expire_at_ms == 0 &&
                   u->timeinfo.expire_after_first_usage_ms == 0,
               "fresh default fields wrong");
    const user_stat_t         zero_stats   = {0};
    const user_runtime_stat_t zero_runtime = {0};
    const user_client_time_t  zero_time    = {0};
    const user_limit_t        zero_limit   = {0};
    twfRequire(memcmp(&u->stats, &zero_stats, sizeof(zero_stats)) == 0 &&
                   memcmp(&u->runtime, &zero_runtime, sizeof(zero_runtime)) == 0 &&
                   memcmp(&u->client_time, &zero_time, sizeof(zero_time)) == 0 &&
                   memcmp(&u->limit, &zero_limit, sizeof(zero_limit)) == 0 &&
                   strcmp(u->password, "  SECRET_SENTINEL\u20ac  ") == 0,
               "fresh account inherited usage, limits, runtime or altered password bytes");
    twfRequire(usersLookupByPassword(&state()->store.users, u->password) == u &&
                   usersLookupBySHA224(&state()->store.users, u->sha224_pass.bytes) == u &&
                   usersLookupBySHA256(&state()->store.users, u->sha256_pass.bytes) == u &&
                   usersLookupByWireGuardPublicKey(&state()->store.users, u->wireguard_publickey) == u &&
                   ! u->uuid_pass_valid,
               "new credential indexes unusable");
    cJSON_Delete(readUser(u->id));
    create(51, "empty-config-secret", "{}", NULL);
    create(
        UINT64_MAX,
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "{\"name\":\"alice\",\"email\":\"alice@example.invalid\",\"notes\":\"note \\u20ac\","
        "\"wireguard_allowed_ips\":\"10.8.0.123/24\",\"gid\":\"18446744073709551615\",\"enabled\":false,"
        "\"record_stat_interval_ms\":\"2147483647\",\"limit\":{\"traffic\":{\"u\":\"18446744073709551615\",\"d\":\"2\","
        "\"total\":\"3\"},"
        "\"bandwidth\":{\"u\":\"4\",\"d\":\"5\"},\"ips\":\"6\",\"devices\":\"7\",\"cons_in\":\"8\",\"cons_out\":\"9\"},"
        "\"time\":{\"expire_at_ms\":\"1\",\"expire_after_first_usage_ms\":\"18446744073709551615\"}}",
        NULL);
    user_t *v = usersLookupByIdentifier(&state()->store.users, UINT64_MAX);
    twfRequire(v && ! v->enabled && v->gid == UINT64_MAX && v->record_stat_interval_ms == INT_MAX &&
                   strcmp(v->name, "alice") == 0 && strcmp(v->email, "alice@example.invalid") == 0 &&
                   strcmp(v->notes, "note \342\202\254") == 0 && strcmp(v->wireguard_allowed_ips, "10.8.0.0/24") == 0 &&
                   v->limit.traffic.u == UINT64_MAX && v->limit.traffic.d == 2 && v->limit.traffic.total == 3 &&
                   v->limit.bandwidth.u == 4 && v->limit.bandwidth.d == 5 && v->limit.ips == 6 &&
                   v->limit.devices == 7 && v->limit.cons_in == 8 && v->limit.cons_out == 9 &&
                   v->timeinfo.expire_at_ms == 1 && v->timeinfo.expire_after_first_usage_ms == UINT64_MAX &&
                   v->timeinfo.first_usage_at_ms == 0 && v->uuid_pass_valid &&
                   usersLookupByUUID(&state()->store.users, v->uuid_pass) == v,
               "configuration/UUID semantics wrong");
    ip_addr_t address;
    twfRequire(ipaddr_aton("10.8.0.254", &address) &&
                   usersLookupByWireGuardAllowedIp(&state()->store.users, &address) == v,
               "new Allowed-IP index absent");
    cJSON_Delete(readUser(UINT64_MAX));
    create(52,
           "zero-sentinels",
           "{\"name\":\"\",\"email\":\"\",\"notes\":\"\",\"wireguard_allowed_ips\":\"\","
           "\"record_stat_interval_ms\":\"0\",\"gid\":\"0\",\"limit\":{\"traffic\":{\"total\":\"0\"}},"
           "\"time\":{\"expire_at_ms\":\"0\"}}",
           NULL);
    twfRequire(usersLookupByIdentifier(&state()->store.users, 52)->record_stat_interval_ms == 0 &&
                   usersLookupByIdentifier(&state()->store.users, u->id) == u && usersValidate(&state()->store.users),
               "zero sentinel or stable pointers lost");
}

static void duplicatesAndFailures(void)
{
    create(51, "different-password", "{\"name\":\"alice\"}", "id_exists");
    create(60, "empty-config-secret", NULL, "credentials_exist");
    collision_source = usersLookupByIdentifier(&state()->store.users, 51);
    for (collision_kind = 1; collision_kind <= 3; ++collision_kind)
        create(60, "forced-derived-collision", NULL, "credentials_exist");
    collision_kind   = 0;
    collision_source = NULL;
    create(60, "fresh-duplicate-name", "{\"name\":\"alice\"}", "name_exists");
    create(60, "F47AC10B-58CC-4372-A567-0E02B2C3D479", NULL, "credentials_exist");
    create(60, "fresh-range", "{\"wireguard_allowed_ips\":\"10.8.0.5/32\"}", "allowed_ips_overlap");
    create(60, "fresh-range", "{\"wireguard_allowed_ips\":\"garbage\"}", "invalid_allowed_ips");
    static const char *malformed_cidrs[] = {
        "10/8", "192.168.1/24", "010.0.0.1/32", "12345::/16", "1:2:3:4:5:6:7:8zz/128", "10. 0.0.1/32"};
    for (size_t i = 0; i < sizeof(malformed_cidrs) / sizeof(malformed_cidrs[0]); ++i)
    {
        char config[160];
        snprintf(config, sizeof(config), "{\"wireguard_allowed_ips\":\"%s\"}", malformed_cidrs[i]);
        create(60, "fresh-strict-range", config, "invalid_allowed_ips");
    }
    for (crypto_failure = 1; crypto_failure <= 3; ++crypto_failure)
        create(60, "backend-failure", NULL, "creation_failed");
    crypto_failure = 0;
    for (init_failure = 1; init_failure <= 4; ++init_failure)
    {
        init_calls = 0;
        create(60, "native-init-failure", NULL, "creation_failed");
    }
    init_failure = 0;
    create(60, "recovered-native-init", NULL, NULL);
    context.max_response_body_size = 255;
    create(61, "response-failure", NULL, "response_too_large");
    context.max_response_body_size   = kAuthenticationServerApiBodyCap;
    context.working_memory_allowance = 4096;
    create(61, "working-failure", NULL, "resource_limit");
    context.working_memory_allowance = 4 * 1024 * 1024;
    context.deadline_ms              = nodeApiNowMs();
    create(61, "expired-preparation", NULL, "timeout");
    context.deadline_ms = UINT64_MAX;
    fake_time_us        = 1000000;
    context.deadline_ms = 1500;
    for (unsigned i = 1; i <= 24; ++i)
    {
        clock_reads  = 0;
        expire_after = i;
        create(61, "deadline-failure", NULL, "timeout");
    }
    expire_after        = 0;
    fake_time_us        = 0;
    context.deadline_ms = UINT64_MAX;
    twfRequire(usersValidate(&state()->store.users), "refusal corrupted indexes");
}

static void acknowledgementPoolCharge(void)
{
    master_pool_t *masters[3];
    for (size_t i = 0; i < 3; ++i)
    {
        masters[i] = masterpoolCreateWithCapacity(8);
        twfRequire(masters[i] != NULL, "ACK charge master creation failed");
    }
    buffer_pool_t *pool = bufferpoolCreate(masters[0], masters[1], masters[2], 4, 65536, 65536, 128, 8192, 8192);
    twfRequire(pool != NULL, "ACK charge pool creation failed");
    buffer_pool_t *previous_pool = env.pool;
    env.pool = env.pool_shortcut[0] = env.worker.buffer_pool = pool;
    size_t previous_allowance                                = context.working_memory_allowance;
    context.working_memory_allowance                         = 16384;
    const char *body                                         = "{\"id\":\"62\",\"password\":\"ack-budget-secret\"}";
    sbuf_t     *input                                        = bufferpoolGetBestFit(pool, (uint32_t) strlen(body), 0);
    memoryCopy(sbufGetMutablePtr(input), body, strlen(body));
    sbufSetLength(input, (uint32_t) strlen(body));
    authenticationserver_create_request_t parsed;
    twfRequire(authenticationserverParseCreate(input, &context, &parsed) == NULL,
               "ACK-only allowance did not fit bounded preparation");
    buffer_pool_fit_t fit;
    twfRequire(bufferpoolQueryBestFit(pool, 256, 0, &fit) && fit.allocation_charge > context.working_memory_allowance &&
                   usersPreparedNewUserOwnedBytes(parsed.candidate) < context.working_memory_allowance,
               "ACK-only refusal did not exercise actual pool tier charge");
    usersFreePreparedNewUser(parsed.candidate);
    call(body, "resource_limit");
    twfRequire(usersLookupByIdentifier(&state()->store.users, 62) == NULL && usersValidate(&state()->store.users),
               "ACK charge refusal published an account");
    context.working_memory_allowance = previous_allowance;
    env.pool = env.pool_shortcut[0] = env.worker.buffer_pool = previous_pool;
    twfRequireNoLeakedBuffers();
    bufferpoolDestroy(pool);
    for (size_t i = 0; i < 3; ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
}

typedef struct lock_holder_s
{
    wrwlock_t  *lock;
    wsem_t      acquired, release;
    atomic_bool held;
} lock_holder_t;
static WTHREAD_ROUTINE(holdLock)
{
    lock_holder_t *holder = userdata;
    rwlockWriteLock(holder->lock);
    atomic_store(&holder->held, true);
    semaphorePost(&holder->acquired);
    twfRequire(semaphoreWait(&holder->release), "lock barrier failed");
    atomic_store(&holder->held, false);
    rwlockWriteUnlock(holder->lock);
    return 0;
}
static void lockRefusal(void)
{
    user_t    *u       = usersLookupByIdentifier(&state()->store.users, 42);
    wrwlock_t *locks[] = {&state()->state_lock, &state()->store.users.lock, &u->lock, &u->stats_lock};
    for (size_t i = 0; i < 4; ++i)
    {
        lock_holder_t holder = {.lock = locks[i]};
        atomic_init(&holder.held, false);
        semaphoreInit(&holder.acquired, 0);
        semaphoreInit(&holder.release, 0);
        wthread_t thread;
        twfRequire(threadCreate(&thread, holdLock, &holder) == kWThreadErrorNone, "lock holder start");
        twfRequire(semaphoreWait(&holder.acquired), "lock acquisition barrier");
        /* callOperation samples collection size, so invoke directly while the
         * collection is held to prove handler acquisition itself never waits. */
        char body[512];
        requestText(body, sizeof(body), 70 + i, i == 3 ? "stats-lock-create" : "config-lock-create", NULL);
        sbuf_t *input = bufferpoolGetBestFit(env.pool, (uint32_t) strlen(body), 0);
        memoryCopy(sbufGetMutablePtr(input), body, strlen(body));
        sbufSetLength(input, (uint32_t) strlen(body));
        api_result_t result = nodeApiFind(server, "create-user")->handler(server, input, &context);
        cJSON *json = cJSON_ParseWithLength((const char *) sbufGetRawPtr(result.buffer), sbufGetLength(result.buffer));
        twfRequire(result.result_code == (i < 2 ? kApiResultError : kApiResultOk) &&
                       (i >= 2 || strcmp(field(field(json, "error"), "code")->valuestring, "busy") == 0) &&
                       atomic_load(&holder.held),
                   "creation waited for held lock or acquired an existing user lock");
        cJSON_Delete(json);
        bufferpoolReuseBuffer(env.pool, result.buffer);
        semaphorePost(&holder.release);
        twfRequire(threadJoin(thread) == 0, "lock holder join");
        semaphoreDestroy(&holder.release);
        semaphoreDestroy(&holder.acquired);
    }
}

typedef struct writer_s
{
    authenticationserver_create_request_t request;
    sbuf_t                               *ack;
    wsem_t                               *ready, *start;
    const char                           *error;
} writer_t;
static WTHREAD_ROUTINE(createWriter)
{
    writer_t *writer = userdata;
    semaphorePost(writer->ready);
    twfRequire(semaphoreWait(writer->start), "writer start barrier");
    writer->error = authenticationserverApplyCreate(server, &writer->request, &context, writer->ack, 4 * 1024 * 1024);
    return 0;
}
static void concurrentCreation(void)
{
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        wsem_t ready, start;
        semaphoreInit(&ready, 0);
        semaphoreInit(&start, 0);
        writer_t       writers[2] = {0};
        wthread_t      threads[2];
        char           bodies[2][512];
        const uint64_t revision = state()->store.config_revision;
        for (size_t i = 0; i < 2; ++i)
        {
            const uint64_t id    = 100 + mode * 10 + (mode == 0 ? 0 : i);
            const char *password = mode == 1 ? "shared-race-password" : i == 0 ? "race-password-a" : "race-password-b";
            char        distinct[80];
            snprintf(distinct, sizeof(distinct), "%s-%u", password, mode);
            requestText(bodies[i], sizeof(bodies[i]), id, distinct, NULL);
            sbuf_t *input = bufferpoolGetBestFit(env.pool, (uint32_t) strlen(bodies[i]), 0);
            memoryCopy(sbufGetMutablePtr(input), bodies[i], strlen(bodies[i]));
            sbufSetLength(input, (uint32_t) strlen(bodies[i]));
            twfRequire(authenticationserverParseCreate(input, &context, &writers[i].request) == NULL,
                       "writer parse failed");
            writers[i].ack   = bufferpoolGetBestFit(env.pool, 256, 0);
            writers[i].ready = &ready;
            writers[i].start = &start;
            twfRequire(threadCreate(&threads[i], createWriter, &writers[i]) == kWThreadErrorNone,
                       "writer thread failed");
        }
        twfRequire(semaphoreWait(&ready) && semaphoreWait(&ready), "writer readiness failed");
        semaphorePost(&start);
        semaphorePost(&start);
        unsigned committed = 0;
        for (size_t i = 0; i < 2; ++i)
        {
            twfRequire(threadJoin(threads[i]) == 0, "writer join failed");
            if (writers[i].error == NULL)
                ++committed;
            else
                twfRequire(strcmp(writers[i].error, "busy") == 0 ||
                               strcmp(writers[i].error, mode == 0 ? "id_exists" : "credentials_exist") == 0,
                           "unexpected race loser");
            usersFreePreparedNewUser(writers[i].request.candidate);
            bufferpoolReuseBuffer(env.pool, writers[i].ack);
        }
        if (mode < 2)
            twfRequire(committed == 1, "same identity race published multiple accounts");
        else
        {
            twfRequire(committed >= 1, "independent creations both refused");
            for (size_t i = 0; i < 2; ++i)
                if (writers[i].error != NULL)
                {
                    call(bodies[i], NULL);
                    ++committed;
                }
            twfRequire(committed == 2, "independent valid creation could not commit");
        }
        twfRequire(state()->store.config_revision == revision + committed, "race revision increment mismatch");
        for (size_t i = 0; i < 2; ++i)
            call(bodies[i],
                 mode == 1 && usersLookupByIdentifier(&state()->store.users, 110 + i) == NULL ? "credentials_exist"
                                                                                              : "id_exists");
        semaphoreDestroy(&start);
        semaphoreDestroy(&ready);
    }
}

static void readCoherence(void)
{
    cJSON *page = callOperation("list-users", "{\"limit\":1}", 11, NULL);
    char   cursor[65], token[49], body[256];
    memoryCopy(cursor, field(page, "next_cursor")->valuestring, 65);
    memoryCopy(token, field(page, "edit_token")->valuestring, 49);
    cJSON_Delete(page);
    /* Real stats-only transaction does not prevent creation. */
    rwlockWriteLock(&state()->state_lock);
    userAddTraffic(usersLookupByIdentifier(&state()->store.users, 42), 3, 4);
    authenticationserverBumpStatsRevision(server);
    rwlockWriteUnlock(&state()->state_lock);
    create(140, "coherence-password", NULL, NULL);
    snprintf(body, sizeof(body), "{\"cursor\":\"%s\",\"limit\":1}", cursor);
    cJSON_Delete(callOperation("list-users", body, strlen(body), "stale_cursor"));
    snprintf(body, sizeof(body), "{\"id\":\"42\",\"if_match\":\"%s\",\"patch\":{\"enabled\":true}}", token);
    cJSON_Delete(callOperation("update-user", body, strlen(body), "conflict"));
    const char *operations[] = {"status", "get-user", "list-users"};
    const char *requests[]   = {"{}", "{\"id\":\"140\"}", "{}"};
    authenticationserverEditTokenFormat(state()->api_instance_id, state()->store.config_revision, token);
    for (size_t i = 0; i < 3; ++i)
    {
        cJSON *json = callOperation(operations[i], requests[i], strlen(requests[i]), NULL);
        twfRequire(strcmp(field(json, "edit_token")->valuestring, token) == 0, "read tokens disagree after creation");
        cJSON_Delete(json);
    }
}

static void persistence(void)
{
    char directory[] = "/tmp/ww-auth-create-save-XXXXXX", primary[512], backup[520];
    twfRequire(mkdtemp(directory) != NULL, "persistence directory failed");
    snprintf(primary, sizeof(primary), "%s/users.json", directory);
    snprintf(backup, sizeof(backup), "%s.backup", primary);
    static const char initial[] = "{\"users\":[]}\n";
    int               fd        = open(primary, O_WRONLY | O_CREAT | O_EXCL, 0600);
    twfRequire(fd >= 0 && write(fd, initial, sizeof(initial) - 1) == sizeof(initial) - 1 && close(fd) == 0,
               "persistence seed failed");
    char *old_primary = state()->db_path, *old_backup = state()->backup_path;
    state()->db_path     = primary;
    state()->backup_path = backup;
    create(150, "persisted-new-secret", "{\"enabled\":false,\"name\":\"persisted\"}", NULL);
    char *disk = readFile(primary);
    twfRequire(disk && strcmp(disk, initial) == 0 && ! isFile(backup) && ! state()->primary_save_last_attempt_valid &&
                   ! state()->primary_save_last_success_valid && state()->primary_save_last_attempt_ms == 0 &&
                   state()->primary_save_last_success_ms == 0 &&
                   state()->primary_save_last_result == kAuthenticationServerSaveNotAttempted,
               "creation initiated persistence or changed telemetry");
    memoryFree(disk);
    twfRequire(authenticationserverSaveDatabase(state()), "ordinary later save failed");
    disk        = readFile(primary);
    cJSON *json = cJSON_Parse(disk);
    memoryFree(disk);
    users_t loaded;
    twfRequire(usersCreate(&loaded) && usersFeedJson(&loaded, json), "saved collection reload failed");
    cJSON_Delete(json);
    user_t *u = usersLookupByPassword(&loaded, "persisted-new-secret");
    twfRequire(u && u->id == 150 && ! u->enabled && strcmp(u->name, "persisted") == 0 &&
                   u->timeinfo.first_usage_at_ms == 0 && u->stats.traffic.u == 0 && usersValidate(&loaded),
               "later save lost fresh account");
    usersDestroy(&loaded);
    state()->db_path     = old_primary;
    state()->backup_path = old_backup;
    twfRequire(unlink(primary) == 0 && unlink(backup) == 0 && rmdir(directory) == 0, "persistence cleanup failed");
}

static unsigned                   completions;
static node_api_dispatch_status_t completion_status;
static void                       complete(void *arg, uint64_t session, uint64_t request, const node_api_reply_t *reply)
{
    discard arg;
    twfRequire(session == 1 && request == 1, "dispatcher identities changed");
    ++completions;
    completion_status = reply->status;
}
static void detachedDelivery(void)
{
    nodeApiFreeze();
    node_api_domain_t *domain = nodeApiDomainCreate(16 * 1024 * 1024, 4, complete, NULL);
    twfRequire(domain != NULL, "dispatcher domain failed");
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        char body[512], password[80];
        snprintf(password, sizeof(password), "detached-create-%u", mode);
        requestText(body, sizeof(body), 200 + mode, password, NULL);
        fake_time_us             = 1000000;
        const uint64_t  revision = state()->store.config_revision;
        node_api_job_t *job      = nodeApiJobCreate(domain,
                                               server,
                                               nodeApiFind(server, "create-user"),
                                               0,
                                               1,
                                               1,
                                               1500,
                                               "creator",
                                               NULL,
                                               NULL,
                                               body,
                                               strlen(body),
                                               4096,
                                               4 * 1024 * 1024);
        twfRequire(job && nodeApiJobSubmit(job) == kNodeApiDispatchOk && queue_count == 1,
                   "detached submission failed");
        nextMessage();
        twfRequire(state()->store.config_revision == revision + 1 && queue_count == 1, "handler failed commit");
        node_api_job_t *pending = NULL;
        if (mode == 0)
            fake_time_us = 2000000;
        else if (mode == 1)
            nodeApiJobAbandon(job);
        else
        {
            const char *waiting = "{\"id\":\"250\",\"password\":\"never-published\"}";
            pending             = nodeApiJobCreate(domain,
                                       server,
                                       nodeApiFind(server, "create-user"),
                                       0,
                                       1,
                                       1,
                                       1500,
                                       "creator",
                                       NULL,
                                       NULL,
                                       waiting,
                                       strlen(waiting),
                                       4096,
                                       4 * 1024 * 1024);
            twfRequire(pending && nodeApiJobSubmit(pending) == kNodeApiDispatchOk, "queued shutdown creation failed");
            nodeApiCloseAdmission();
        }
        const unsigned previous = completions;
        nextMessage();
        twfRequire(completions == previous + (mode == 0 ? 1 : 0) &&
                       (mode != 0 || completion_status == kNodeApiDispatchTimeout),
                   "late/abandoned completion mismatch");
        nodeApiJobRelease(job);
        if (pending)
        {
            nextMessage();
            nextMessage();
            nodeApiJobRelease(pending);
        }
        fake_time_us = 0;
        call(body, "id_exists");
        twfRequire(usersLookupByPassword(&state()->store.users, password) != NULL &&
                       usersLookupByIdentifier(&state()->store.users, 250) == NULL &&
                       state()->store.config_revision == revision + 1,
                   "delivery failure removed, replaced or duplicated account");
        size_t bytes, jobs;
        nodeApiDomainGetUsage(domain, &bytes, &jobs);
        twfRequire(bytes == 0 && jobs == 0, "detached creation leaked reservation");
    }
    nodeApiDomainDestroy(domain);
}

int main(void)
{
    twfSetCase("AuthenticationServer create-user API");
    twfRequire(createNetworkLogger(NULL, false) != NULL && wCryptoGlobalInit() == kWCryptoOk,
               "runtime initialization failed");
    twfWorkerEnvSetup(&env, 8192, 32);
    nodeApiRegistryInitialize();
    server = tunnelCreate(NULL, sizeof(authenticationserver_tstate_t), 0);
    twfRequire(server != NULL, "server allocation failed");
    rwlockinit(&state()->state_lock);
    twfRequire(usersCreate(&state()->store.users), "collection init failed");
    state()->database_loaded       = true;
    state()->store.config_revision = 84;
    state()->store.stats_revision  = 19;
    memset(state()->api_instance_id, 0x5a, 16);
    authenticationserverInitializeAccountingClock(state());
    user_t source;
    twfRequire(userCreate(&source, "existing-secret"), "existing user create failed");
    source.id                         = 42;
    source.stats.traffic              = (user_ud_t) {100, 200};
    source.timeinfo.first_usage_at_ms = 456;
    twfRequire(usersAddUser(&state()->store.users, &source), "existing user insert failed");
    userDestroy(&source);
    user_t *existing                           = usersLookupByIdentifier(&state()->store.users, 42);
    existing->runtime.active_cons_out          = 3;
    existing->client_time.clock_valid          = true;
    existing->client_time.accounting_anchor_ms = 777;
    const user_runtime_stat_t runtime          = existing->runtime;
    const user_client_time_t  client_time      = existing->client_time;
    twfRequire(authenticationserverRegisterApi(server), "registration failed");
    context = (node_api_call_context_t) {.operation                = "create-user",
                                         .principal                = "creator",
                                         .deadline_ms              = UINT64_MAX,
                                         .max_response_body_size   = kAuthenticationServerApiBodyCap,
                                         .working_memory_allowance = 4 * 1024 * 1024};
    registration();
    parsing();
    defaultsAndConfiguration();
    duplicatesAndFailures();
    acknowledgementPoolCharge();
    lockRefusal();
    concurrentCreation();
    const uint64_t stats_revision = state()->store.stats_revision;
    readCoherence();
    persistence();
    twfRequire(usersLookupByIdentifier(&state()->store.users, 42) == existing && existing->stats.traffic.u == 103 &&
                   existing->stats.traffic.d == 204 && existing->timeinfo.first_usage_at_ms == 456 &&
                   memcmp(&existing->runtime, &runtime, sizeof(runtime)) == 0 &&
                   memcmp(&existing->client_time, &client_time, sizeof(client_time)) == 0 &&
                   state()->store.stats_revision == stats_revision + 1,
               "creation changed existing accounting/runtime state");
    detachedDelivery();
    state()->store.config_revision = UINT64_MAX - 1;
    create(300, "maximum-revision", NULL, NULL);
    create(301, "exhausted-revision", NULL, "revision_exhausted");
    twfRequire(usersValidate(&state()->store.users), "final indexes invalid");
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
