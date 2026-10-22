#include "fixtures/user_runtime.h"
/* CTest: waterwall.authenticationserver_update_api_unit
 * Strict conditional edits through the registered handler, refusal atomicity,
 * barrier-controlled contention/CAS, and real dispatcher late/lost completion.
 * API calls own buffers only; no connection line is created by this fixture. */
#include "AuthenticationServer/config_update.h"
#include "api/dispatcher.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "loggers/network_logger.h"
#include "wthread.h"

static twf_worker_env_t        env;
static tunnel_t               *server;
static node_api_call_context_t context;
static uint64_t                fake_time_us;
static unsigned                clock_reads, expire_after;

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

static authenticationserver_tstate_t *state(void)
{
    return tunnelGetState(server);
}

static const cJSON *field(const cJSON *json, const char *key)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(json, key);
    twfRequire(value != NULL, "missing response field");
    return value;
}

static void token(char out[49])
{
    authenticationserverEditTokenFormat(state()->api_instance_id, state()->store.config_revision, out);
}

static void requestText(char *out, size_t cap, uint64_t id, const char *match, const char *patch)
{
    int n = snprintf(out, cap, "{\"id\":\"%" PRIu64 "\",\"if_match\":\"%s\",\"patch\":%s}", id, match, patch);
    twfRequire(n > 0 && (size_t) n < cap, "fixture request exceeded capacity");
}

static cJSON *callBytes(const void *body, size_t size, const char *error)
{
    sbuf_t *input = bufferpoolGetBestFit(env.pool, (uint32_t) size, 0);
    memoryCopy(sbufGetMutablePtr(input), body, size);
    sbufSetLength(input, (uint32_t) size);
    const bool     was_dirty = state()->database_dirty;
    const uint64_t revision  = state()->store.config_revision;
    api_result_t   result    = nodeApiFind(server, "update-user")->handler(server, input, &context);
    twfRequire(result.result_code == (error == NULL ? kApiResultOk : kApiResultError), "incorrect update result");
    twfRequire(result.buffer != NULL, "missing update result body");
    twfRequire(state()->database_dirty == (was_dirty || error == NULL),
               "update result changed dirty state incorrectly");
    cJSON *json = cJSON_ParseWithLength((const char *) sbufGetRawPtr(result.buffer), sbufGetLength(result.buffer));
    twfRequire(cJSON_IsObject(json), "update response is not JSON");
    if (error != NULL)
    {
        twfRequire(strcmp(field(field(json, "error"), "code")->valuestring, error) == 0, "wrong update error code");
        twfRequire(state()->store.config_revision == revision, "failed operation changed revision");
        twfRequire(cJSON_GetArraySize(json) == 1, "error disclosed extra state");
    }
    else
    {
        char expected[24], expected_token[49];
        snprintf(expected, sizeof(expected), "%" PRIu64, revision + 1);
        token(expected_token);
        twfRequire(state()->store.config_revision == revision + 1 && cJSON_GetArraySize(json) == 3 &&
                       strcmp(field(json, "config_revision")->valuestring, expected) == 0 &&
                       strcmp(field(json, "edit_token")->valuestring, expected_token) == 0 &&
                       sbufGetLength(result.buffer) <= kAuthenticationServerUpdateAckCap,
                   "ACK did not identify committed transaction");
    }
    bufferpoolReuseBuffer(env.pool, result.buffer);
    twfRequireNoLeakedBuffers();
    return json;
}

static void call(const char *body, const char *error)
{
    cJSON_Delete(callBytes(body, strlen(body), error));
}

static void edit(uint64_t id, const char *patch, const char *error)
{
    state()->database_dirty = false;
    char match[49], body[4096];
    token(match);
    requestText(body, sizeof(body), id, match, patch);
    call(body, error);
}

static void parsing(void)
{
    static const char *roots[] = {
        "", "null", "[]", "{}", "{\"id\":\"42\"}", "{\"id\":\"42\",\"if_match\":null,\"patch\":{\"enabled\":false}}"};
    for (size_t i = 0; i < sizeof(roots) / sizeof(*roots); ++i)
        call(roots[i], "invalid_request");
    static const char *patches[] = {"{}",
                                    "[]",
                                    "null",
                                    "{\"enabled\":null}",
                                    "{\"enabled\":1}",
                                    "{\"enabled\":\"false\"}",
                                    "{\"enabled\":false,\"enabled\":true}",
                                    "{\"enabled\":false,\"enabl\\u0065d\":true}",
                                    "{\"name\":false}",
                                    "{\"name\":\"a\\u0000b\"}",
                                    "{\"notes\":\"\300\200\"}",
                                    "{\"email\":\"\\ud800\"}",
                                    "{\"id\":\"42\"}",
                                    "{\"password\":\"x\"}",
                                    "{\"sha256_pass\":\"x\"}",
                                    "{\"wireguard_publickey\":\"x\"}",
                                    "{\"usage\":{\"u\":\"0\"}}",
                                    "{\"runtime\":{\"active_cons_out\":\"0\"}}",
                                    "{\"client_time\":{}}",
                                    "{\"stats\":{}}",
                                    "{\"time\":{\"created_at_ms\":\"0\"}}",
                                    "{\"time\":{\"first_usage_at_ms\":\"0\"}}",
                                    "{\"wireguard-allowed-ips\":\"\"}",
                                    "{\"record-stat-interval-ms\":\"0\"}",
                                    "{\"limit\":{}}",
                                    "{\"limit\":null}",
                                    "{\"limit\":{\"traffic\":{}}}",
                                    "{\"limit\":{\"bandwidth\":{}}}",
                                    "{\"time\":{}}",
                                    "{\"time\":{\"extra\":\"0\"}}",
                                    "{\"limit\":{\"traffic\":{\"up\":\"0\"}}}",
                                    "{\"limit\":{\"bandwidth\":{\"total\":\"0\"}}}",
                                    "{\"limit\":{\"cons-in\":\"0\"}}",
                                    "{\"limit\":{\"devices\":false}}",
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
                                    "{\"record_stat_interval_ms\":-1}",
                                    "{\"enabled\":false,\"notes\":null}",
                                    "{\"limit\":{\"traffic\":{\"u\":{\"extra\":\"1\"}}}}"};
    user_t            *u         = usersLookupByIdentifier(&state()->store.users, 42);
    for (size_t i = 0; i < sizeof(patches) / sizeof(*patches); ++i)
    {
        edit(42, patches[i], "invalid_request");
        twfRequire(u->enabled && u->gid == 7 && strcmp(u->name, "original") == 0, "invalid patch partially applied");
    }
    char match[49], body[4096];
    token(match);
    static const char *ids[] = {"0", "00", "01", "+42", "-42", "42 ", "18446744073709551616"};
    for (size_t i = 0; i < sizeof(ids) / sizeof(*ids); ++i)
    {
        snprintf(
            body, sizeof(body), "{\"id\":\"%s\",\"if_match\":\"%s\",\"patch\":{\"enabled\":false}}", ids[i], match);
        call(body, "invalid_request");
    }
    requestText(body, sizeof(body), 42, match, "{\"enabled\":false}");
    size_t n = strlen(body);
    strcpy(body + n, " trailing");
    call(body, "invalid_request");
    body[n]     = '\0';
    body[n + 1] = 'x';
    cJSON_Delete(callBytes(body, n + 2, "invalid_request"));
    snprintf(
        body, sizeof(body), "{\"id\":\"42\",\"if_match\":\"%s\",\"patch\":{\"enabled\":false},\"extra\":0}", match);
    call(body, "invalid_request");
    snprintf(
        body, sizeof(body), "{\"id\":\"42\",\"id\":\"42\",\"if_match\":\"%s\",\"patch\":{\"enabled\":false}}", match);
    call(body, "invalid_request");
    match[0] = 'A';
    requestText(body, sizeof(body), 42, match, "{\"enabled\":false}");
    call(body, "invalid_request");
    char *large = memoryAllocate(kAuthenticationServerUpdateRequestCap + 1);
    memset(large, ' ', kAuthenticationServerUpdateRequestCap + 1);
    cJSON_Delete(callBytes(large, kAuthenticationServerUpdateRequestCap + 1, "invalid_request"));
    memoryFree(large);
    /* 64 lexical values are checked before JSON tree construction. */
    strcpy(body, "{");
    for (unsigned i = 0; i < 40; ++i)
    {
        char entry[32];
        snprintf(entry, sizeof(entry), "%s\"key%u\":false", i == 0 ? "" : ",", i);
        strcat(body, entry);
    }
    strcat(body, "}");
    call(body, "invalid_request");
    /* The update limit remains independent of the smaller read-body limit. */
    char *exact = memoryAllocate(kAuthenticationServerUpdateRequestCap + 1);
    token(match);
    int prefix = snprintf(exact,
                          kAuthenticationServerUpdateRequestCap,
                          "{\"id\":\"42\",\"if_match\":\"%s\",\"patch\":{\"notes\":\"",
                          match);
    twfRequire(prefix > 0 && prefix < kAuthenticationServerUpdateRequestCap - 3, "exact-boundary prefix overflow");
    memset(exact + prefix, 'x', kAuthenticationServerUpdateRequestCap - (size_t) prefix - 3);
    memoryCopy(exact + kAuthenticationServerUpdateRequestCap - 3, "\"}}", 4);
    cJSON_Delete(callBytes(exact, kAuthenticationServerUpdateRequestCap, NULL));
    memoryFree(exact);
}

static void fieldSemantics(void)
{
    user_t                  *u              = usersLookupByIdentifier(&state()->store.users, 42);
    const user_stat_t        stats          = u->stats;
    user_runtime_stat_t      runtime        = u->runtime;
    const user_client_time_t client_time    = u->client_time;
    const uint64_t           stats_revision = state()->store.stats_revision;
    uint8_t                  digest[sizeof(u->sha256_pass)];
    memoryCopy(digest, &u->sha256_pass, sizeof(digest));
    const uint64_t created = u->timeinfo.created_at_ms, first = u->timeinfo.first_usage_at_ms;
    const uint64_t bandwidth_before = getHRTimeUs() / 1000U;
    edit(42,
         "{\"name\":\"renamed\",\"email\":\"new@example.invalid\",\"notes\":\"note \\u20ac\","
         "\"wireguard_allowed_ips\":\"10.8.0.123/24\",\"gid\":\"18446744073709551615\","
         "\"enabled\":false,\"record_stat_interval_ms\":\"2147483647\","
         "\"limit\":{\"traffic\":{\"u\":\"18446744073709551615\",\"d\":\"2\",\"total\":\"3\"},"
         "\"bandwidth\":{\"u\":\"4\",\"d\":\"5\"},\"ips\":\"6\",\"devices\":\"7\","
         "\"cons_in\":\"8\",\"cons_out\":\"9\"},"
         "\"time\":{\"expire_at_ms\":\"1\",\"expire_after_first_usage_ms\":\"18446744073709551615\"}}",
         NULL);
    twfRequire(strcmp(u->name, "renamed") == 0 && strcmp(u->email, "new@example.invalid") == 0 &&
                   strcmp(u->notes, "note \342\202\254") == 0 && strcmp(u->wireguard_allowed_ips, "10.8.0.0/24") == 0 &&
                   u->gid == UINT64_MAX && ! u->enabled && u->record_stat_interval_ms == INT_MAX &&
                   u->limit.traffic.u == UINT64_MAX && u->limit.traffic.d == 2 && u->limit.traffic.total == 3 &&
                   u->limit.bandwidth.u == 4 && u->limit.bandwidth.d == 5 && u->limit.ips == 6 &&
                   u->limit.devices == 7 && u->limit.cons_in == 8 && u->limit.cons_out == 9 &&
                   u->timeinfo.expire_at_ms == 1 && u->timeinfo.expire_after_first_usage_ms == UINT64_MAX,
               "editable field semantics mismatch");
    /* Explicit finite-rate edits initialize only their private bucket policy.
     * Validate that permitted delta before retaining the full protected-state
     * oracle, including unchanged waiter identities and later sparse edits. */
    const uint64_t bandwidth_after = getHRTimeUs() / 1000U;
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        const user_bandwidth_state_t *bandwidth = &u->runtime.bandwidth[direction];
        twfRequire(bandwidth->policy_valid && bandwidth->rate == 4 + direction && bandwidth->bucket.credit == 1 &&
                       bandwidth->bucket.remainder == 0 && bandwidth->bucket.has_clock &&
                       bandwidth->bucket.last_refill_ms >= bandwidth_before &&
                       bandwidth->bucket.last_refill_ms <= bandwidth_after && bandwidth->oversized_ticket == 0 &&
                       bandwidth->oversized_capacity == 0 && bandwidth->head == runtime.bandwidth[direction].head &&
                       bandwidth->tail == runtime.bandwidth[direction].tail,
                   "finite bandwidth edit did not install the defined initial credit or changed waiters");
    }
    memoryCopy(runtime.bandwidth, u->runtime.bandwidth, sizeof(runtime.bandwidth));
    /* Disabled and expired users remain editable; omitted siblings survive. */
    edit(42, "{\"limit\":{\"traffic\":{\"total\":\"0\"}},\"time\":{\"expire_at_ms\":\"0\"}}", NULL);
    twfRequire(u->limit.traffic.u == UINT64_MAX && u->limit.traffic.d == 2 && u->limit.traffic.total == 0 &&
                   u->limit.bandwidth.d == 5 && u->timeinfo.expire_at_ms == 0 &&
                   u->timeinfo.expire_after_first_usage_ms == UINT64_MAX,
               "sparse edit replaced omitted siblings");
    edit(42,
         "{\"name\":\"\",\"email\":\"\",\"notes\":\"\",\"wireguard_allowed_ips\":\"\","
         "\"gid\":\"0\",\"record_stat_interval_ms\":\"0\"}",
         NULL);
    twfRequire(u->name[0] == '\0' && u->email[0] == '\0' && u->notes[0] == '\0' &&
                   u->wireguard_allowed_ips[0] == '\0' && ! u->wireguard_allowed_ips_valid && u->gid == 0 &&
                   u->record_stat_interval_ms == 0 && usersValidate(&state()->store.users),
               "clear/zero sentinel semantics mismatch");
    twfRequire(memcmp(&stats, &u->stats, sizeof(stats)) == 0 && memcmp(&runtime, &u->runtime, sizeof(runtime)) == 0 &&
                   memcmp(&client_time, &u->client_time, sizeof(client_time)) == 0 &&
                   memcmp(digest, &u->sha256_pass, sizeof(digest)) == 0 &&
                   strcmp(u->password, "CREDENTIAL_SENTINEL") == 0 && u->timeinfo.created_at_ms == created &&
                   u->timeinfo.first_usage_at_ms == first && state()->store.stats_revision == stats_revision &&
                   ! state()->primary_save_last_attempt_valid && ! state()->primary_save_last_success_valid,
               "configuration edit changed protected state or initiated saving");
}

static void conflictsAndRefusal(void)
{
    char match[49], old[49], body[4096];
    token(match);
    memoryCopy(old, match, sizeof(old));
    edit(43, "{\"enabled\":false}", NULL);
    requestText(body, sizeof(body), 42, old, "{\"enabled\":true}");
    call(body, "conflict");
    token(match);
    match[0] = match[0] == 'a' ? 'b' : 'a';
    requestText(body, sizeof(body), 999, match, "{\"enabled\":true}");
    call(body, "conflict"); /* Token check precedes durable ID lookup. */
    edit(999, "{\"enabled\":true}", "not_found");
    edit(42, "{\"enabled\":false}", NULL); /* Same value still revises once. */
    edit(42, "{\"name\":\"occupied\",\"enabled\":true}", "name_exists");
    edit(42, "{\"wireguard_allowed_ips\":\"10.9.0.5/32\",\"enabled\":true}", "allowed_ips_overlap");
    edit(42, "{\"wireguard_allowed_ips\":\"not-a-range\",\"enabled\":true}", "invalid_allowed_ips");
    static const char *malformed_cidrs[] = {
        "10/8", "192.168.1/24", "010.0.0.1/32", "12345::/16", "1:2:3:4:5:6:7:8zz/128", "10. 0.0.1/32"};
    for (size_t i = 0; i < sizeof(malformed_cidrs) / sizeof(malformed_cidrs[0]); ++i)
    {
        char patch[160];
        snprintf(patch, sizeof(patch), "{\"wireguard_allowed_ips\":\"%s\",\"enabled\":true}", malformed_cidrs[i]);
        edit(42, patch, "invalid_allowed_ips");
    }
    user_t *u = usersLookupByIdentifier(&state()->store.users, 42);
    twfRequire(! u->enabled && u->name[0] == '\0' && u->wireguard_allowed_ips[0] == '\0', "refusal changed fields");
    context.max_response_body_size = 255;
    edit(42, "{\"enabled\":true}", "response_too_large");
    context.max_response_body_size   = kAuthenticationServerApiBodyCap;
    context.working_memory_allowance = 4096;
    edit(42, "{\"enabled\":true}", "resource_limit");
    context.working_memory_allowance = 1024 * 1024;
    context.deadline_ms              = nodeApiNowMs();
    edit(42, "{\"enabled\":true}", "timeout");
    context.deadline_ms = UINT64_MAX;
    /* The chunked ACK renderer and bounded preparation make twelve clock
     * checks before commit. Expire at each check, rather than assuming the
     * former byte-at-a-time renderer still performs twenty or more reads. */
    fake_time_us        = UINT64_C(1000000);
    context.deadline_ms = 1500;
    for (unsigned i = 1; i <= 12; ++i)
    {
        clock_reads  = 0;
        expire_after = i;
        edit(42, "{\"enabled\":true}", "timeout");
    }
    fake_time_us        = 0;
    expire_after        = 0;
    context.deadline_ms = UINT64_MAX;
    twfRequire(! u->enabled && usersValidate(&state()->store.users), "precommit refusal corrupted account/indexes");
}

static void exportAllowance(void)
{
    user_t candidate;
    twfRequire(userCreate(&candidate, "export-update"), "export patch candidate");
    candidate.id = 99002;
    twfRequire(usersAddUser(&state()->store.users, &candidate), "export patch insertion");
    userDestroy(&candidate);
    user_t *stored = usersLookupByIdentifier(&state()->store.users, 99002);
    size_t  required;
    twfRequire(userMeasureExportUpperBound(stored, &required) == kUserPublicOk, "export patch measure");
    const size_t saved             = state()->max_user_export_bytes;
    state()->max_user_export_bytes = required;
    edit(99002, "{\"notes\":\"x\"}", "user_too_large");
    twfRequire(stored->notes == NULL || stored->notes[0] == 0, "refused patch changed text");
    edit(99002, "{\"enabled\":false}", NULL);
    state()->max_user_export_bytes = required + 1;
    edit(99002, "{\"notes\":\"x\"}", NULL);
    edit(99002, "{\"notes\":\"xx\"}", "user_too_large");
    twfRequire(strcmp(stored->notes, "x") == 0, "one-byte oversized patch changed text");
    state()->max_user_export_bytes = saved;
}

static void acknowledgementPoolCharge(void)
{
    /* A small error fits the 128-byte tier, while the fixed 256-byte success
     * reservation must pay for a real 64-KiB pooled allocation. */
    master_pool_t *masters[3];
    for (size_t i = 0; i < 3; ++i)
    {
        masters[i] = masterpoolCreateWithCapacity(8);
        twfRequire(masters[i] != NULL, "ACK charge master allocation failed");
    }
    buffer_pool_t *pool = bufferpoolCreate(masters[0], masters[1], masters[2], 4, 65536, 65536, 128, 8192, 8192);
    twfRequire(pool != NULL, "ACK charge pool creation failed");
    buffer_pool_t *previous_pool = env.pool;
    env.pool = env.pool_shortcut[0] = env.worker.buffer_pool = pool;
    const size_t previous_allowance                          = context.working_memory_allowance;
    context.working_memory_allowance                         = 16384;
    char match[49], body[1024];
    token(match);
    requestText(body, sizeof(body), 42, match, "{\"enabled\":true}");
    sbuf_t *input = bufferpoolGetBestFit(pool, (uint32_t) strlen(body), 0);
    memoryCopy(sbufGetMutablePtr(input), body, strlen(body));
    sbufSetLength(input, (uint32_t) strlen(body));
    authenticationserver_update_request_t parsed;
    twfRequire(authenticationserverParseUpdate(input, &context, &parsed) == NULL,
               "ACK-only refusal allowance did not fit bounded parsing");
    buffer_pool_fit_t fit;
    twfRequire(bufferpoolQueryBestFit(pool, kAuthenticationServerUpdateAckCap, 0, &fit) &&
                   fit.allocation_charge > context.working_memory_allowance &&
                   usersPreparedConfigPatchOwnedBytes(parsed.patch) < context.working_memory_allowance,
               "ACK-only refusal did not exercise actual pool charge");
    usersFreePreparedConfigPatch(parsed.patch);
    user_t    *u       = usersLookupByIdentifier(&state()->store.users, 42);
    const bool enabled = u->enabled;
    edit(42, "{\"enabled\":true}", "resource_limit");
    twfRequire(u->enabled == enabled && usersValidate(&state()->store.users),
               "ACK allocation refusal changed account or indexes");
    twfRequireNoLeakedBuffers();
    context.working_memory_allowance = previous_allowance;
    env.pool = env.pool_shortcut[0] = env.worker.buffer_pool = previous_pool;
    bufferpoolDestroy(pool);
    for (size_t i = 0; i < 3; ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
}

static void laterPersistence(void)
{
    char directory[] = "/tmp/ww-auth-update-save-XXXXXX";
    char primary[512], backup[520];
    twfRequire(mkdtemp(directory) != NULL, "update persistence directory failed");
    int n = snprintf(primary, sizeof(primary), "%s/users.json", directory);
    twfRequire(n > 0 && (size_t) n < sizeof(primary), "update primary path overflow");
    n = snprintf(backup, sizeof(backup), "%s.backup", primary);
    twfRequire(n > 0 && (size_t) n < sizeof(backup), "update backup path overflow");
    static const char initial[] = "{\"users\":[]}\n";
    int               fd        = open(primary, O_WRONLY | O_CREAT | O_EXCL, 0600);
    twfRequire(fd >= 0, "update persistence seed open failed");
    twfRequire(write(fd, initial, sizeof(initial) - 1U) == (ssize_t) (sizeof(initial) - 1U),
               "update persistence seed write failed");
    twfRequire(close(fd) == 0, "update persistence seed close failed");
    authenticationserver_tstate_t *ts               = state();
    char                          *previous_primary = ts->db_path, *previous_backup = ts->backup_path;
    ts->db_path              = primary;
    ts->backup_path          = backup;
    const bool     attempted = ts->primary_save_last_attempt_valid, succeeded = ts->primary_save_last_success_valid;
    const uint64_t attempt_ms = ts->primary_save_last_attempt_ms, success_ms = ts->primary_save_last_success_ms;
    const authenticationserver_save_result_t last_result = ts->primary_save_last_result;
    edit(42, "{\"notes\":\"later-save-marker\"}", NULL);
    char *disk = readFile(primary);
    twfRequire(disk != NULL && strcmp(disk, initial) == 0 && ! isFile(backup) &&
                   ts->primary_save_last_attempt_valid == attempted &&
                   ts->primary_save_last_success_valid == succeeded && ts->primary_save_last_attempt_ms == attempt_ms &&
                   ts->primary_save_last_success_ms == success_ms && ts->primary_save_last_result == last_result,
               "API edit initiated persistence or changed primary-save history");
    memoryFree(disk);
    const uint64_t revision = ts->store.config_revision, stats_revision = ts->store.stats_revision;
    twfRequire(authenticationserverSaveDatabase(ts), "later explicit database save failed");
    twfRequire(ts->primary_save_last_attempt_valid && ts->primary_save_last_success_valid &&
                   ts->primary_save_last_result == kAuthenticationServerSaveSuccess &&
                   ts->store.config_revision == revision && ts->store.stats_revision == stats_revision,
               "explicit save changed revision or failed to record its outcome");
    disk = readFile(primary);
    twfRequire(disk != NULL, "saved primary could not be read");
    cJSON *saved = cJSON_Parse(disk);
    memoryFree(disk);
    users_t reloaded;
    twfRequire(usersCreate(&reloaded), "saved users collection creation failed");
    twfRequire(saved != NULL && usersFeedJson(&reloaded, saved), "explicit save could not reload account data");
    cJSON_Delete(saved);
    user_t *u = usersLookupByIdentifier(&reloaded, 42);
    twfRequire(u != NULL && strcmp(u->notes, "later-save-marker") == 0 &&
                   strcmp(u->password, "CREDENTIAL_SENTINEL") == 0 && u->stats.traffic.u == 100 &&
                   u->stats.traffic.d == 200 && u->timeinfo.created_at_ms == 123 &&
                   u->timeinfo.first_usage_at_ms == 456,
               "later save omitted edit or changed protected account data");
    usersDestroy(&reloaded);
    disk = readFile(backup);
    twfRequire(disk != NULL && strcmp(disk, initial) == 0, "explicit save lost previous primary recovery candidate");
    memoryFree(disk);
    ts->db_path     = previous_primary;
    ts->backup_path = previous_backup;
    twfRequire(unlink(primary) == 0 && unlink(backup) == 0 && rmdir(directory) == 0,
               "update persistence fixture cleanup failed");
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
    twfRequire(semaphoreWait(&holder->release), "lock release barrier failed");
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
        twfRequire(threadCreate(&thread, holdLock, &holder) == kWThreadErrorNone, "lock holder start failed");
        twfRequire(semaphoreWait(&holder.acquired), "lock acquisition barrier failed");
        edit(42, "{\"enabled\":false}", i == 3 ? NULL : "busy");
        twfRequire(atomic_load(&holder.held), "update waited for held lock");
        semaphorePost(&holder.release);
        twfRequire(threadJoin(thread) == 0, "lock holder join failed");
        semaphoreDestroy(&holder.release);
        semaphoreDestroy(&holder.acquired);
    }
}

typedef struct writer_s
{
    authenticationserver_update_request_t request;
    sbuf_t                               *ack;
    wsem_t                               *ready, *start;
    const char                           *error;
} writer_t;

static WTHREAD_ROUTINE(conditionalWriter)
{
    writer_t *writer = userdata;
    semaphorePost(writer->ready);
    twfRequire(semaphoreWait(writer->start), "writer start barrier failed");
    writer->error = authenticationserverApplyConditionalUpdate(server, &writer->request, &context, writer->ack, 0);
    return 0;
}

static void twoWriters(void)
{
    wsem_t ready, start;
    semaphoreInit(&ready, 0);
    semaphoreInit(&start, 0);
    writer_t  writers[2] = {0};
    wthread_t threads[2];
    char      match[49], body[1024];
    token(match);
    const uint64_t revision = state()->store.config_revision;
    requestText(body, sizeof(body), 42, match, "{\"enabled\":false}");
    for (size_t i = 0; i < 2; ++i)
    {
        sbuf_t *input = bufferpoolGetBestFit(env.pool, (uint32_t) strlen(body), 0);
        memoryCopy(sbufGetMutablePtr(input), body, strlen(body));
        sbufSetLength(input, (uint32_t) strlen(body));
        twfRequire(authenticationserverParseUpdate(input, &context, &writers[i].request) == NULL,
                   "writer parse failed");
        writers[i].ack   = bufferpoolGetBestFit(env.pool, 256, 0);
        writers[i].ready = &ready;
        writers[i].start = &start;
        twfRequire(threadCreate(&threads[i], conditionalWriter, &writers[i]) == kWThreadErrorNone,
                   "writer start failed");
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
            twfRequire(strcmp(writers[i].error, "busy") == 0 || strcmp(writers[i].error, "conflict") == 0,
                       "unexpected CAS loser result");
        usersFreePreparedConfigPatch(writers[i].request.patch);
        bufferpoolReuseBuffer(env.pool, writers[i].ack);
    }
    twfRequire(committed == 1 && state()->store.config_revision == revision + 1, "CAS committed more/less than once");
    call(body, "conflict");
    semaphoreDestroy(&start);
    semaphoreDestroy(&ready);
}

static unsigned                   completions;
static node_api_dispatch_status_t completion_status;
static void                       complete(void *arg, uint64_t session, uint64_t request, const node_api_reply_t *reply)
{
    discard arg;
    twfRequire(session == 1 && request == 1, "dispatcher identifiers changed");
    ++completions;
    completion_status = reply->status;
}

static void detachedDelivery(void)
{
    nodeApiFreeze();
    node_api_domain_t *domain = nodeApiDomainCreate(8 * 1024 * 1024, 4, complete, NULL);
    twfRequire(domain != NULL, "dispatcher domain failed");
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        char match[49], body[1024];
        token(match);
        requestText(body, sizeof(body), 42, match, "{\"gid\":\"99\"}");
        fake_time_us           = UINT64_C(1000000);
        const uint64_t  before = state()->store.config_revision;
        node_api_job_t *job    = nodeApiJobCreate(domain,
                                               server,
                                               nodeApiFind(server, "update-user"),
                                               0,
                                               1,
                                               1,
                                               1500,
                                               "editor",
                                               NULL,
                                               NULL,
                                               body,
                                               strlen(body),
                                               4096,
                                               1024 * 1024);
        twfRequire(job != NULL && nodeApiJobSubmit(job) == kNodeApiDispatchOk && queue_count == 1,
                   "detached edit submission failed");
        nextMessage(); /* Real handler committed, completion remains queued. */
        twfRequire(state()->store.config_revision == before + 1 && queue_count == 1, "handler did not commit");
        node_api_job_t *queued_at_shutdown = NULL;
        if (mode == 0)
            fake_time_us = UINT64_C(2000000);
        else if (mode == 1)
            nodeApiJobAbandon(job);
        else
        {
            char fresh[49], pending[1024];
            token(fresh);
            requestText(pending, sizeof(pending), 42, fresh, "{\"gid\":\"100\"}");
            queued_at_shutdown = nodeApiJobCreate(domain,
                                                  server,
                                                  nodeApiFind(server, "update-user"),
                                                  0,
                                                  1,
                                                  1,
                                                  1500,
                                                  "editor",
                                                  NULL,
                                                  NULL,
                                                  pending,
                                                  strlen(pending),
                                                  4096,
                                                  1024 * 1024);
            twfRequire(queued_at_shutdown != NULL && nodeApiJobSubmit(queued_at_shutdown) == kNodeApiDispatchOk,
                       "queued shutdown edit submission failed");
            nodeApiCloseAdmission();
        }
        unsigned previous = completions;
        nextMessage();
        twfRequire(completions == previous + (mode == 0 ? 1 : 0) &&
                       (mode != 0 || completion_status == kNodeApiDispatchTimeout),
                   "late/lost delivery mismatch");
        nodeApiJobRelease(job);
        if (queued_at_shutdown != NULL)
        {
            nextMessage(); /* Admission closed before this queued handler ran. */
            nextMessage(); /* Its shutdown completion is also suppressed. */
            nodeApiJobRelease(queued_at_shutdown);
            twfRequire(completions == previous, "shutdown delivered a closed-admission reply");
        }
        fake_time_us = 0;
        call(body, "conflict");
        user_t *u = usersLookupByIdentifier(&state()->store.users, 42);
        twfRequire(u->gid == 99 && state()->store.config_revision == before + 1,
                   "delivery failure rolled back/replayed edit");
        size_t bytes, jobs;
        nodeApiDomainGetUsage(domain, &bytes, &jobs);
        twfRequire(bytes == 0 && jobs == 0, "detached edit leaked reservation");
    }
    nodeApiDomainDestroy(domain);
}

int main(void)
{
    twfSetCase("AuthenticationServer conditional update API");
    twfRequire(createNetworkLogger(NULL, false) != NULL && userTestRuntimeInitialize(), "runtime init failed");
    twfWorkerEnvSetup(&env, 8192, 32);
    nodeApiRegistryInitialize();
    server = tunnelCreate(NULL, sizeof(authenticationserver_tstate_t), 0);
    twfRequire(server != NULL, "server allocation failed");
    authenticationserver_tstate_t *ts = state();
    rwlockinit(&ts->state_lock);
    twfRequire(usersCreate(&ts->store.users), "users init failed");
    ts->database_loaded       = true;
    ts->store.config_revision = 84;
    ts->store.stats_revision  = 19;
    memset(ts->api_instance_id, 0x5a, sizeof(ts->api_instance_id));
    authenticationserverInitializeAccountingClock(ts);
    authenticationserverInitializeExportLimit(ts);
    user_t source;
    twfRequire(userCreate(&source, "CREDENTIAL_SENTINEL"), "user creation failed");
    source.id                         = 42;
    source.gid                        = 7;
    source.timeinfo.created_at_ms     = 123;
    source.timeinfo.first_usage_at_ms = 456;
    source.stats.traffic              = (user_ud_t) {100, 200};
    memoryFree(source.name);
    source.name                = stringDuplicate("original");
    source.export_strings.name = userMeasureExportString(source.name);
    twfRequire(usersAddUser(&ts->store.users, &source), "fixture add failed");
    userDestroy(&source);
    twfRequire(userCreate(&source, "other-password"), "second user creation failed");
    source.id = 43;
    memoryFree(source.name);
    source.name                = stringDuplicate("occupied");
    source.export_strings.name = userMeasureExportString(source.name);
    twfRequire(userSetWireGuardAllowedIps(&source, "10.9.0.0/24") && usersAddUser(&ts->store.users, &source),
               "second add failed");
    userDestroy(&source);
    user_t *u                           = usersLookupByIdentifier(&ts->store.users, 42);
    u->runtime.active_cons_out          = 3;
    u->client_time.clock_valid          = true;
    u->client_time.accounting_anchor_ms = 777;
    twfRequire(authenticationserverRegisterApi(server), "registration failed");
    context = (node_api_call_context_t) {.operation                = "update-user",
                                         .principal                = "editor",
                                         .deadline_ms              = UINT64_MAX,
                                         .max_response_body_size   = kAuthenticationServerApiBodyCap,
                                         .working_memory_allowance = 1024 * 1024};
    parsing();
    fieldSemantics();
    conflictsAndRefusal();
    acknowledgementPoolCharge();
    lockRefusal();
    twoWriters();
    laterPersistence();
    exportAllowance();
    detachedDelivery();
    twfRequire(usersValidate(&ts->store.users), "final user/index validation failed");
    nodeApiUnregister(server);
    usersDestroy(&ts->store.users);
    rwlockDestroy(&ts->state_lock);
    tunnelDestroy(server);
    nodeApiRegistryDestroy();
    twfWorkerEnvTeardown(&env);
    userTestRuntimeCleanup();
    networkloggerDestroy();
    return 0;
}
