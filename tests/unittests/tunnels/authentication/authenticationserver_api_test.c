/* CTest: waterwall.authenticationserver_api_unit
 * Direct registered provider: strict bodies, credential-free schemas, exact IDs,
 * bounded pagination/cursors, budgets, corrupt records and side-effect freedom.
 * Contention/lifecycle and real transport transactions have separate fixtures. */
#include "AuthenticationServer/api.h"
#include "AuthenticationServer/edit_token.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "loggers/network_logger.h"

static twf_worker_env_t        env;
static tunnel_t               *server;
static size_t                  last_body_size;
static node_api_call_context_t context;

static cJSON *callBytes(const char *operation, const char *body, size_t length, const char *expected_error)
{
    const node_api_operation_t *descriptor = nodeApiFind(server, operation);
    twfRequire(descriptor != NULL, "missing descriptor");
    sbuf_t *input = bufferpoolGetBestFit(env.pool, (uint32_t) length, 0);
    memoryCopy(sbufGetMutablePtr(input), body, length);
    sbufSetLength(input, (uint32_t) length);
    context.operation   = operation;
    api_result_t result = descriptor->handler(server, input, &context);
    twfRequire(result.buffer != NULL, "missing bounded response body");
    last_body_size   = sbufGetLength(result.buffer);
    const char *raw  = (const char *) sbufGetRawPtr(result.buffer);
    char       *text = memoryAllocate(last_body_size + 1);
    memoryCopy(text, raw, last_body_size);
    text[last_body_size]         = '\0';
    static const char *secrets[] = {"CREDENTIAL_SENTINEL",
                                    "PRODUCER_SENTINEL",
                                    "SESSION_SENTINEL",
                                    "PRIVATE_PATH_SENTINEL",
                                    "sha224_pass",
                                    "sha256_pass",
                                    "uuid_pass",
                                    "wireguard_publickey",
                                    "password",
                                    "client_time",
                                    "runtime"};
    for (size_t i = 0; i < sizeof(secrets) / sizeof(*secrets); ++i)
        twfRequire(strstr(text, secrets[i]) == NULL, "private state leaked in response");
    cJSON *json = cJSON_Parse(text);
    memoryFree(text);
    bufferpoolReuseBuffer(env.pool, result.buffer);
    twfRequire(cJSON_IsObject(json), "response was not a JSON object");
    if (expected_error != NULL)
    {
        const cJSON *code = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(json, "error"), "code");
        twfRequire(result.result_code == kApiResultError && cJSON_IsString(code) &&
                       strcmp(code->valuestring, expected_error) == 0,
                   "wrong operation failure");
    }
    else
        twfRequire(result.result_code == kApiResultOk && cJSON_GetObjectItemCaseSensitive(json, "error") == NULL,
                   "expected successful operation");
    return json;
}

static cJSON *call(const char *operation, const char *body, const char *error)
{
    return callBytes(operation, body, strlen(body), error);
}

static void expectError(const char *operation, const char *body, const char *error)
{
    cJSON_Delete(call(operation, body, error));
}

static const cJSON *field(const cJSON *object, const char *name)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, name);
    twfRequire(value != NULL, "missing public field");
    return value;
}

static void expectString(const cJSON *object, const char *name, const char *expected)
{
    const cJSON *value = field(object, name);
    twfRequire(cJSON_IsString(value) && strcmp(value->valuestring, expected) == 0, "incorrect public string");
}

static void add(uint64_t id)
{
    user_t source;
    char   password[80];
    snprintf(password, sizeof(password), "CREDENTIAL_SENTINEL-%" PRIu64, id);
    twfRequire(userCreate(&source, password), "user setup failed");
    source.id = id;
    if (id == UINT64_MAX)
    {
        source.gid     = 7;
        source.enabled = false;
        memoryFree(source.name);
        source.name = stringDuplicate("Alice\"\n\t\\\001\342\202\254");
        memoryFree(source.email);
        source.email = stringDuplicate("alice@example.invalid");
        memoryFree(source.notes);
        source.notes = stringDuplicate("public notes");
        twfRequire(userSetWireGuardAllowedIps(&source, "10.0.0.0/24"), "routing setup failed");
        source.limit    = (user_limit_t) {.traffic   = {11, 12, UINT64_MAX},
                                          .bandwidth = {13, 14},
                                          .ips       = 15,
                                          .devices   = 16,
                                          .cons_in   = 17,
                                          .cons_out  = 18};
        source.timeinfo = (user_time_info_t) {
            .created_at_ms = 19, .expire_at_ms = 20, .expire_after_first_usage_ms = 21, .first_usage_at_ms = 22};
        source.stats.traffic           = (user_ud_t) {23, 24};
        source.record_stat_interval_ms = 25;
    }
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    twfRequire(usersAddUser(&ts->store.users, &source), "could not add fixture user");
    userDestroy(&source);
}

static void parsing(void)
{
    static const char *invalid[] = {"",
                                    "[]",
                                    "null",
                                    "{} trailing",
                                    "{\"x\":1}",
                                    "{\"id\":\"1\",\"id\":\"2\"}",
                                    "{\"id\":\"0\"}",
                                    "{\"id\":\"01\"}",
                                    "{\"id\":\"+1\"}",
                                    "{\"id\":\" 1\"}",
                                    "{\"id\":\"1.0\"}",
                                    "{\"id\":\"18446744073709551616\"}",
                                    "{\"id\":1}",
                                    "{\"id\":true}",
                                    "{\"id\":null}",
                                    "{\"id\":\"1\\u0000suffix\"}",
                                    "{\"id\":\"1\",\"\\u0069d\":\"1\"}",
                                    "{\"id\":[[[\"1\"]]]}",
                                    "{\"id\":\"\300\200\"}"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i)
        expectError("get-user", invalid[i], "invalid_request");
    expectError("status", "{\"include_accounting\":true}", "invalid_request");
    expectError("list-users", "{\"limit\":0}", "invalid_request");
    expectError("list-users", "{\"limit\":101}", "invalid_request");
    expectError("list-users", "{\"limit\":1.5}", "invalid_request");
    expectError("list-users", "{\"limit\":1e0}", "invalid_request");
    expectError("list-users", "{\"limit\":true}", "invalid_request");
    expectError("list-users", "{\"cursor\":null}", "invalid_cursor");
    expectError("list-users", "{\"cursor\":\"\"}", "invalid_cursor");
    char oversized[4098];
    memset(oversized, ' ', sizeof(oversized));
    oversized[0] = '{';
    oversized[1] = '}';
    cJSON_Delete(callBytes("status", oversized, sizeof(oversized), "invalid_request"));
    static const char nul[] = "{}\0{}";
    cJSON_Delete(callBytes("status", nul, sizeof(nul) - 1, "invalid_request"));
    context.deadline_ms = nodeApiNowMs();
    expectError("status", "{}", "timeout");
    context.deadline_ms = UINT64_MAX;
}

static void detail(void)
{
    expectError("get-user", "{\"id\":\"999\"}", "not_found");
    cJSON       *body = call("get-user", "{\"id\":\"18446744073709551615\"}", NULL);
    const cJSON *u    = field(body, "user");
    expectString(u, "id", "18446744073709551615");
    expectString(u, "gid", "7");
    twfRequire(cJSON_IsFalse(field(u, "enabled")), "enabled was not Boolean");
    expectString(u, "name", "Alice\"\n\t\\\001\342\202\254");
    expectString(u, "email", "alice@example.invalid");
    expectString(u, "notes", "public notes");
    expectString(u, "wireguard_allowed_ips", "10.0.0.0/24");
    expectString(u, "record_stat_interval_ms", "25");
    const cJSON *limit = field(u, "limit"), *traffic = field(limit, "traffic"), *bandwidth = field(limit, "bandwidth");
    expectString(traffic, "u", "11");
    expectString(traffic, "d", "12");
    expectString(traffic, "total", "18446744073709551615");
    expectString(bandwidth, "u", "13");
    expectString(bandwidth, "d", "14");
    expectString(limit, "ips", "15");
    expectString(limit, "devices", "16");
    expectString(limit, "cons_in", "17");
    expectString(limit, "cons_out", "18");
    const cJSON *time = field(u, "time"), *usage = field(u, "usage");
    expectString(time, "created_at_ms", "19");
    expectString(time, "expire_at_ms", "20");
    expectString(time, "expire_after_first_usage_ms", "21");
    expectString(time, "first_usage_at_ms", "22");
    expectString(usage, "u", "23");
    expectString(usage, "d", "24");
    expectString(body, "config_revision", "84");
    expectString(body, "stats_revision", "1902");
    cJSON_Delete(body);
    body = call("get-user", "{\"id\":\"9007199254740993\"}", NULL);
    u    = field(body, "user");
    expectString(u, "id", "9007199254740993");
    expectString(u, "notes", "");
    expectString(field(field(u, "limit"), "traffic"), "total", "0");
    expectString(field(u, "time"), "first_usage_at_ms", "0");
    expectString(u, "record_stat_interval_ms", "120000");
    cJSON_Delete(body);
}

static void editTokenCodec(void)
{
    uint8_t identity[16];
    for (size_t i = 0; i < sizeof(identity); ++i)
        identity[i] = (uint8_t) i;
    char token[kAuthenticationServerEditTokenChars + 1];
    authenticationserverEditTokenFormat(identity, 84, token);
    twfRequire(strcmp(token, "000102030405060708090a0b0c0d0e0f0000000000000054") == 0, "noncanonical edit token");
    uint8_t  decoded[16];
    uint64_t revision = 0;
    twfRequire(authenticationserverEditTokenParse(token, decoded, &revision) && revision == 84 &&
                   memcmp(identity, decoded, sizeof(identity)) == 0,
               "edit token failed exact round trip");
    authenticationserverEditTokenFormat(identity, UINT64_MAX, token);
    twfRequire(strcmp(token + 32, "ffffffffffffffff") == 0 &&
                   authenticationserverEditTokenParse(token, decoded, &revision) && revision == UINT64_MAX,
               "edit token lost maximum revision");
    authenticationserverEditTokenFormat(identity, 0, token);
    twfRequire(authenticationserverEditTokenParse(token, decoded, &revision) && revision == 0,
               "edit token lost zero revision");
    static const char *invalid[] = {"",
                                    "000102030405060708090a0b0c0d0e0f000000000000005",
                                    "000102030405060708090a0b0c0d0e0f00000000000000540",
                                    "000102030405060708090a0b0c0d0e0F0000000000000054",
                                    "000102030405060708090a0b0c0d0e0f000000000000005G",
                                    " 00102030405060708090a0b0c0d0e0f0000000000000054"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i)
    {
        memset(decoded, 0xa5, sizeof(decoded));
        revision = 123;
        twfRequire(! authenticationserverEditTokenParse(invalid[i], decoded, &revision) && revision == 123,
                   "accepted malformed edit token or changed failed revision");
        for (size_t j = 0; j < sizeof(decoded); ++j)
            twfRequire(decoded[j] == 0xa5, "failed edit token changed instance identity");
    }
}

static void expectReadTokens(const char *expected)
{
    static const char *operations[] = {"status", "get-user", "list-users"};
    static const char *requests[]   = {"{}", "{\"id\":\"9007199254740993\"}", "{}"};
    for (size_t i = 0; i < sizeof(operations) / sizeof(*operations); ++i)
    {
        cJSON *body = call(operations[i], requests[i], NULL);
        expectString(body, "edit_token", expected);
        cJSON_Delete(body);
    }
}

static void editTokens(void)
{
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    char                           expected[kAuthenticationServerEditTokenChars + 1];
    authenticationserverEditTokenFormat(ts->api_instance_id, ts->store.config_revision, expected);
    expectReadTokens(expected);

    authenticationserver_status_t      status;
    authenticationserver_user_view_t   user;
    authenticationserver_page_view_t   page;
    authenticationserver_api_request_t request = {.limit = 1};
    twfRequire(authenticationserverStatusSnapshot(server, 0, &status) == kAuthenticationServerStatusOk &&
                   authenticationserverCopyUserView(server, UINT64_C(9007199254740993), 1024 * 1024, 0, &user) ==
                       NULL &&
                   authenticationserverCopyPageView(server, &request, 1024 * 1024, 0, &page) == NULL,
               "owned edit token snapshots failed");
    rwlockWriteLock(&ts->state_lock);
    userAddTraffic(usersLookupByIdentifier(&ts->store.users, UINT64_C(9007199254740993)), 1, 2);
    authenticationserverBumpStatsRevision(server);
    rwlockWriteUnlock(&ts->state_lock);
    expectReadTokens(expected);

    rwlockWriteLock(&ts->state_lock);
    user_config_patch_t patch = {.mask = kUserConfigEnabled, .enabled = true};
    twfRequire(authenticationserverPatchConfigAndBumpRevision(server, UINT64_C(9007199254740993), &patch) ==
                   kUsersUpdateResultOk,
               "same-value configuration transaction failed");
    rwlockWriteUnlock(&ts->state_lock);
    char changed[kAuthenticationServerEditTokenChars + 1];
    authenticationserverEditTokenFormat(ts->api_instance_id, ts->store.config_revision, changed);
    twfRequire(strcmp(expected, changed) != 0, "same-value edit preserved edit token");
    expectReadTokens(changed);

    /* Stand in for a recreated server with a repeated revision. Existing owned
     * snapshots must retain the identity and revision copied before unlocking. */
    rwlockWriteLock(&ts->state_lock);
    ts->api_instance_id[0] ^= 1;
    rwlockWriteUnlock(&ts->state_lock);
    char recreated[kAuthenticationServerEditTokenChars + 1];
    authenticationserverEditTokenFormat(ts->api_instance_id, ts->store.config_revision, recreated);
    twfRequire(strcmp(changed, recreated) != 0, "recreated instance reused edit token");
    expectReadTokens(recreated);
    char owned[kAuthenticationServerEditTokenChars + 1];
    authenticationserverEditTokenFormat(status.instance_id, status.config_revision, owned);
    twfRequire(strcmp(expected, owned) == 0, "status retained live edit-token state");
    authenticationserverEditTokenFormat(user.instance_id, user.config_revision, owned);
    twfRequire(strcmp(expected, owned) == 0, "detail retained live edit-token state");
    authenticationserverEditTokenFormat(page.instance_id, page.config_revision, owned);
    twfRequire(strcmp(expected, owned) == 0, "page retained live edit-token state");
    userPublicDetailDestroy(&user.user);
    memoryFree(page.users);
}

static void continuation(char out[160], const char *cursor, size_t limit)
{
    int length = snprintf(out, 160, "{\"cursor\":\"%s\",\"limit\":%zu}", cursor, limit);
    twfRequire(length > 0 && length < 160, "request overflow");
}

static void pagination(void)
{
    uint64_t ids[127];
    size_t   seen             = 0;
    char     request[160]     = "{\"limit\":1}";
    char     first_cursor[65] = {0};
    for (;;)
    {
        cJSON *body = call("list-users", request, NULL);
        expectString(body, "total_users", "127");
        const cJSON *users = field(body, "users");
        twfRequire(cJSON_IsArray(users) && cJSON_GetArraySize(users) > 0, "zero-progress page");
        const cJSON *entry;
        cJSON_ArrayForEach(entry, users)
        {
            const cJSON *id    = field(entry, "id");
            uint64_t     value = strtoull(id->valuestring, NULL, 10);
            for (size_t i = 0; i < seen; ++i)
                twfRequire(ids[i] != value, "duplicate account in traversal");
            twfRequire(seen < 127, "too many listed accounts");
            ids[seen++] = value;
            twfRequire(cJSON_GetObjectItemCaseSensitive(entry, "email") == NULL &&
                           cJSON_GetObjectItemCaseSensitive(entry, "notes") == NULL &&
                           cJSON_GetObjectItemCaseSensitive(entry, "limit") == NULL,
                       "detail leaked into summary");
        }
        const cJSON *cursor = field(body, "next_cursor");
        if (cJSON_IsNull(cursor))
        {
            cJSON_Delete(body);
            break;
        }
        twfRequire(cJSON_IsString(cursor) && strlen(cursor->valuestring) == 64, "noncanonical cursor");
        if (first_cursor[0] == '\0')
            memoryCopy(first_cursor, cursor->valuestring, 65);
        continuation(request, cursor->valuestring, seen == 1 ? 50 : 100);
        cJSON_Delete(body);
    }
    twfRequire(seen == 127, "omitted accounts");
    cJSON *body = call("list-users", "{}", NULL);
    twfRequire(cJSON_GetArraySize(field(body, "users")) == 50, "default page size changed");
    cJSON_Delete(body);
    body = call("list-users", "{\"limit\":100}", NULL);
    twfRequire(cJSON_GetArraySize(field(body, "users")) == 100, "maximum page size changed");
    cJSON_Delete(body);
    continuation(request, first_cursor, 1);
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    rwlockWriteLock(&ts->state_lock);
    user_config_patch_t patch = {.mask = kUserConfigEnabled, .enabled = true};
    twfRequire(authenticationserverPatchConfigAndBumpRevision(server, 9007199254740993ULL, &patch) ==
                   kUsersUpdateResultOk,
               "configuration transaction failed");
    rwlockWriteUnlock(&ts->state_lock);
    expectError("list-users", request, "stale_cursor");
    body = call("list-users", "{\"limit\":1}", NULL);
    char cursor[65];
    memoryCopy(cursor, field(body, "next_cursor")->valuestring, 65);
    cJSON_Delete(body);
    /* A canonical position equal to the collection count is terminal. */
    char end[65];
    memoryCopy(end, cursor, 65);
    snprintf(end + 48, 17, "%016x", 127);
    continuation(request, end, 100);
    body = call("list-users", request, NULL);
    twfRequire(cJSON_GetArraySize(field(body, "users")) == 0 && cJSON_IsNull(field(body, "next_cursor")),
               "bad terminal page");
    cJSON_Delete(body);
    memset(end + 48, 'f', 16);
    continuation(request, end, 1);
    expectError("list-users", request, "invalid_cursor");
    cursor[0] = cursor[0] == 'a' ? 'b' : 'a';
    continuation(request, cursor, 1);
    expectError("list-users", request, "stale_cursor");
    cursor[0] = 'A';
    continuation(request, cursor, 1);
    expectError("list-users", request, "invalid_cursor");
}

static void budgetsAndRecords(void)
{
    authenticationserver_tstate_t *ts       = tunnelGetState(server);
    cJSON                         *body     = call("list-users", "{\"limit\":1}", NULL);
    size_t                         one_size = last_body_size;
    cJSON_Delete(body);
    buffer_pool_fit_t fit;
    twfRequire(bufferpoolQueryBestFit(env.pool, one_size, 0, &fit), "fit query failed");
    size_t allowance                 = context.working_memory_allowance;
    context.working_memory_allowance = kAuthenticationServerApiScratchCharge +
                                       sizeof(authenticationserver_page_view_t) + sizeof(user_public_summary_t) +
                                       fit.allocation_charge;
    body = call("list-users", "{\"limit\":100}", NULL);
    twfRequire(cJSON_GetArraySize(field(body, "users")) >= 1 && cJSON_IsString(field(body, "next_cursor")),
               "budget lost progress");
    cJSON_Delete(body);
    context.working_memory_allowance = allowance;
    context.max_response_body_size   = 100;
    expectError("list-users", "{}", "response_too_large");
    expectError("get-user", "{\"id\":\"18446744073709551615\"}", "record_too_large");
    context.max_response_body_size = kAuthenticationServerApiBodyCap;
    char *huge                     = memoryAllocate(kAuthenticationServerApiBodyCap + 2);
    memset(huge, 'x', kAuthenticationServerApiBodyCap + 1);
    huge[kAuthenticationServerApiBodyCap + 1] = '\0';
    user_config_patch_t patch = {.mask = kUserConfigNotes | kUserConfigName, .notes = huge, .name = huge};
    rwlockWriteLock(&ts->state_lock);
    twfRequire(authenticationserverPatchConfigAndBumpRevision(server, UINT64_MAX, &patch) == kUsersUpdateResultOk,
               "large config failed");
    rwlockWriteUnlock(&ts->state_lock);
    memoryFree(huge);
    expectError("get-user", "{\"id\":\"18446744073709551615\"}", "record_too_large");
    body               = call("list-users", "{\"limit\":1}", NULL);
    const cJSON *entry = cJSON_GetArrayItem(field(body, "users"), 0);
    expectString(entry, "name_preview_state", "truncated");
    twfRequire(strlen(field(entry, "name_preview")->valuestring) == 256, "preview bound wrong");
    cJSON_Delete(body);
    char *escaped = memoryAllocate(65537);
    memset(escaped, 1, 65536);
    escaped[65536] = '\0';
    patch = (user_config_patch_t) {.mask = kUserConfigName | kUserConfigNotes, .name = "short", .notes = escaped};
    rwlockWriteLock(&ts->state_lock);
    twfRequire(authenticationserverPatchConfigAndBumpRevision(server, UINT64_MAX, &patch) == kUsersUpdateResultOk,
               "escaped configuration setup failed");
    rwlockWriteUnlock(&ts->state_lock);
    memoryFree(escaped);
    expectError("get-user", "{\"id\":\"18446744073709551615\"}", "record_too_large");
    cJSON_Delete(call("list-users", "{\"limit\":1}", NULL));
    patch = (user_config_patch_t) {.mask = kUserConfigName | kUserConfigNotes, .name = "\355\240\200", .notes = ""};
    rwlockWriteLock(&ts->state_lock);
    twfRequire(authenticationserverPatchConfigAndBumpRevision(server, UINT64_MAX, &patch) == kUsersUpdateResultOk,
               "malformed config setup failed");
    rwlockWriteUnlock(&ts->state_lock);
    expectError("get-user", "{\"id\":\"18446744073709551615\"}", "invalid_record_encoding");
    body  = call("list-users", "{\"limit\":1}", NULL);
    entry = cJSON_GetArrayItem(field(body, "users"), 0);
    expectString(entry, "name_preview_state", "invalid_encoding");
    twfRequire(cJSON_IsNull(field(entry, "name_preview")), "malformed prefix was emitted");
    cJSON_Delete(body);
}

static void readOnly(void)
{
    authenticationserver_tstate_t *ts     = tunnelGetState(server);
    uint64_t                       config = ts->store.config_revision, stats = ts->store.stats_revision;
    user_t                        *user = usersLookupByIdentifier(&ts->store.users, UINT64_MAX);
    user_stat_t                    before;
    userGetStats(user, &before);
    user_time_info_t time_before;
    userGetTimeInfo(user, &time_before);
    for (unsigned i = 0; i < 5; ++i)
    {
        cJSON *body = call("status", "{}", NULL);
        expectString(body, "user_count", "127");
        expectString(field(body, "primary_save"), "last_result", "not_attempted");
        twfRequire(cJSON_IsNull(field(field(body, "primary_save"), "last_attempt_age_ms")), "fabricated save history");
        cJSON_Delete(body);
        cJSON_Delete(call("list-users", "{}", NULL));
        cJSON_Delete(call("get-user", "{\"id\":\"9007199254740993\"}", NULL));
    }
    user_stat_t after;
    userGetStats(user, &after);
    user_time_info_t time_after;
    userGetTimeInfo(user, &time_after);
    twfRequire(config == ts->store.config_revision && stats == ts->store.stats_revision &&
                   memcmp(&before, &after, sizeof(before)) == 0 &&
                   memcmp(&time_before, &time_after, sizeof(time_before)) == 0,
               "query changed accounting/configuration");
}

int main(void)
{
    twfSetCase("AuthenticationServer registered read-only views");
    twfRequire(createNetworkLogger(NULL, false) != NULL && wCryptoGlobalInit() == kWCryptoOk, "runtime init failed");
    twfWorkerEnvSetup(&env, 8192, 32);
    nodeApiRegistryInitialize();
    server = tunnelCreate(NULL, sizeof(authenticationserver_tstate_t), 0);
    twfRequire(server != NULL, "server allocation failed");
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    rwlockinit(&ts->state_lock);
    twfRequire(usersCreate(&ts->store.users), "users init failed");
    ts->database_loaded       = true;
    ts->store.config_revision = 84;
    ts->store.stats_revision  = 1902;
    authenticationserverInitializeAccountingClock(ts);
    memset(ts->api_instance_id, 0x5a, sizeof(ts->api_instance_id));
    twfRequire(authenticationserverRegisterApi(server), "registration failed");
    context      = (node_api_call_context_t) {.principal                = "tester",
                                              .deadline_ms              = UINT64_MAX,
                                              .max_response_body_size   = kAuthenticationServerApiBodyCap,
                                              .working_memory_allowance = 1024 * 1024};
    cJSON *empty = call("list-users", "{}", NULL);
    twfRequire(cJSON_GetArraySize(field(empty, "users")) == 0 && cJSON_IsNull(field(empty, "next_cursor")),
               "empty table failed");
    cJSON_Delete(empty);
    add(UINT64_MAX);
    add(UINT64_C(9007199254740993));
    parsing();
    detail();
    editTokenCodec();
    editTokens();
    for (uint64_t id = 1000; id < 1125; ++id)
        add(id);
    pagination();
    budgetsAndRecords();
    readOnly();
    nodeApiUnregister(server);
    usersDestroy(&ts->store.users);
    rwlockDestroy(&ts->state_lock);
    tunnelDestroy(server);
    nodeApiRegistryDestroy();
    twfWorkerEnvTeardown(&env);
    wCryptoGlobalCleanup();
    networkloggerDestroy();
    return 0;
}
