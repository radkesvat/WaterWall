/* CTest: waterwall.authenticationserver_password_api_unit
 * Strict registered credentials-only conditional mutation, preservation, bounded
 * admission and detached reply loss. Handlers consume owned buffers, no line. */
#include "AuthenticationServer/config_create.h"
#include "AuthenticationServer/config_update.h"
#include "AuthenticationServer/password_change.h"
#include "api/dispatcher.h"
#define __wrap_bufferpoolReuseBuffer passwordLedgerReuseBuffer
#include "fixtures/failure/tunnel_line_failure_harness.h"
#undef __wrap_bufferpoolReuseBuffer
#include "loggers/network_logger.h"
#include "wthread.h"

static twf_worker_env_t        env;
static tunnel_t               *server;
static node_api_call_context_t context;
static uint64_t                fake_time_us;
static unsigned                clock_reads, expire_after, crypto_failure, collision_kind;
static unsigned                crypto_calls[3];
static bool                    inspect_crypto;
static const user_t           *collision_source;
static sbuf_t                 *wipe_input;
static size_t                  wipe_input_length;
static unsigned                wiped_inputs;

void __wrap_bufferpoolReuseBuffer(buffer_pool_t *, sbuf_t *);
void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer)
{
    if (buffer == wipe_input)
    {
        const uint8_t *bytes = sbufGetRawPtr(buffer);
        for (size_t i = 0; i < wipe_input_length; ++i)
            twfRequire(bytes[i] == 0, "secret request recycled without wiping every byte");
        wipe_input        = NULL;
        wipe_input_length = 0;
        ++wiped_inputs;
    }
    passwordLedgerReuseBuffer(pool, buffer);
}

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
    ++clock_reads;
    return expire_after != 0 && clock_reads >= expire_after ? fake_time_us + UINT64_C(1000000) : fake_time_us;
}

static void checkCrypto(unsigned primitive)
{
    if (! inspect_crypto)
        return;
    ++crypto_calls[primitive];
    twfRequire(rwlockTryWriteLock(&state()->state_lock), "crypto held server state");
    twfRequire(rwlockTryWriteLock(&state()->store.users.lock), "crypto held collection");
    user_t *target = state()->store.users.items[0];
    twfRequire(rwlockTryWriteLock(&target->lock), "crypto held target configuration");
    rwlockWriteUnlock(&target->lock);
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
    checkCrypto(0);
    if (collision_kind == 1)
    {
        *out = collision_source->sha224_pass;
        return kWCryptoOk;
    }
    return crypto_failure == 1 ? kWCryptoBackendFailed : __real_wCryptoSHA224(out, in, length);
}
wcrypto_status_t __wrap_wCryptoSHA256(sha256_hash_t *out, const unsigned char *in, size_t length)
{
    checkCrypto(1);
    if (collision_kind == 2)
    {
        *out = collision_source->sha256_pass;
        return kWCryptoOk;
    }
    return crypto_failure == 2 ? kWCryptoBackendFailed : __real_wCryptoSHA256(out, in, length);
}
wcrypto_status_t __wrap_wCryptoX25519(unsigned char *out, const unsigned char *scalar, const unsigned char *point)
{
    checkCrypto(2);
    if (collision_kind == 3)
    {
        memoryCopy(out, collision_source->wireguard_publickey, 32);
        return kWCryptoOk;
    }
    return crypto_failure == 3 ? kWCryptoBackendFailed : __real_wCryptoX25519(out, scalar, point);
}

typedef struct password_queued_message_s
{
    WorkerMessageCallback callback;
    void                 *arg1, *arg2, *arg3;
} password_queued_message_t;
static password_queued_message_t queued[4];
static size_t                    queue_count;
worker_message_submit_result_e   __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t, WorkerMessageCallback,
                                                                               WorkerMessageCleanupCallback, void *,
                                                                               void *, void *);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    discard cleanup;
    twfRequire(wid == 0 && queue_count < 4, "unexpected detached message");
    queued[queue_count++] = (password_queued_message_t) {callback, arg1, arg2, arg3};
    return kWorkerMessageSubmitAccepted;
}
static void nextMessage(void)
{
    twfRequire(queue_count != 0, "missing queued message");
    password_queued_message_t next = queued[0];
    for (size_t i = 1; i < queue_count; ++i)
        queued[i - 1] = queued[i];
    --queue_count;
    next.callback(&env.worker, next.arg1, next.arg2, next.arg3);
}

static const cJSON *field(const cJSON *object, const char *name)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, name);
    twfRequire(value != NULL, "missing result field");
    return value;
}
static void token(char out[49])
{
    authenticationserverEditTokenFormat(state()->api_instance_id, state()->store.config_revision, out);
}
static void requestText(char *out, size_t capacity, uint64_t id, const char *match, const char *password)
{
    int n = snprintf(
        out, capacity, "{\"id\":\"%" PRIu64 "\",\"if_match\":\"%s\",\"password\":\"%s\"}", id, match, password);
    twfRequire(n > 0 && (size_t) n < capacity, "request fixture overflow");
}
static sbuf_t *inputBytes(const void *body, size_t size)
{
    sbuf_t *input = bufferpoolGetBestFit(env.pool, (uint32_t) size, 0);
    memoryCopy(sbufGetMutablePtr(input), body, size);
    sbufSetLength(input, (uint32_t) size);
    return input;
}
static sbuf_t *passwordInputBytes(const void *body, size_t size)
{
    twfRequire(wipe_input == NULL, "prior secret input was not consumed");
    wipe_input        = inputBytes(body, size);
    wipe_input_length = size;
    return wipe_input;
}
static cJSON *callBytes(const void *body, size_t size, const char *error)
{
    const bool     was_dirty = state()->database_dirty;
    const uint64_t revision = state()->store.config_revision, stats_revision = state()->store.stats_revision;
    users_t       *users = &state()->store.users;
    const size_t   count = usersCount(users), slots = users->slot_count;
    user_t       **order = memoryAllocate(count * sizeof(*order));
    memoryCopy(order, users->items, count * sizeof(*order));
    api_result_t result =
        nodeApiFind(server, "change-user-password")->handler(server, passwordInputBytes(body, size), &context);
    twfRequire(result.result_code == (error == NULL ? kApiResultOk : kApiResultError) && result.buffer != NULL,
               "wrong password operation status");
    twfRequire(state()->database_dirty == (was_dirty || error == NULL),
               "password result changed dirty state incorrectly");
    cJSON *json = cJSON_ParseWithLength((const char *) sbufGetRawPtr(result.buffer), sbufGetLength(result.buffer));
    twfRequire(cJSON_IsObject(json), "password result is not JSON");
    if (error != NULL)
    {
        const char *actual = field(field(json, "error"), "code")->valuestring;
        if (strcmp(actual, error) != 0)
        {
            fprintf(stderr, "Expected %s, received %s\n", error, actual);
            twfRequire(false, "wrong password error code");
        }
        twfRequire(state()->store.config_revision == revision && cJSON_GetArraySize(json) == 1,
                   "refusal changed revision or disclosed state");
    }
    else
    {
        char expected[24], match[49];
        snprintf(expected, sizeof(expected), "%" PRIu64, revision + 1);
        token(match);
        twfRequire(state()->store.config_revision == revision + 1 && cJSON_GetArraySize(json) == 3 &&
                       strcmp(field(json, "config_revision")->valuestring, expected) == 0 &&
                       strcmp(field(json, "edit_token")->valuestring, match) == 0 &&
                       sbufGetLength(result.buffer) <= kAuthenticationServerPasswordAckCap,
                   "ACK does not identify exact password commit");
    }
    twfRequire(state()->store.stats_revision == stats_revision && usersCount(users) == count &&
                   users->slot_count == slots && memcmp(order, users->items, count * sizeof(*order)) == 0,
               "password change altered statistics, count, slots or order");
    memoryFree(order);
    bufferpoolReuseBuffer(env.pool, result.buffer);
    twfRequireNoLeakedBuffers();
    return json;
}
static void call(const char *body, const char *error)
{
    cJSON_Delete(callBytes(body, strlen(body), error));
}
static void rotate(uint64_t id, const char *password, const char *error)
{
    state()->database_dirty = false;
    char match[49], body[4096];
    token(match);
    requestText(body, sizeof(body), id, match, password);
    call(body, error);
}
static void addUser(uint64_t id, const char *password)
{
    user_t source;
    twfRequire(userCreate(&source, password), "fixture user preparation failed");
    source.id = id;
    twfRequire(usersAddUser(&state()->store.users, &source), "fixture user insertion failed");
    userDestroy(&source);
}

static void registration(void)
{
    static const char *names[] = {
        "status", "get-user", "list-users", "update-user", "create-user", "change-user-password"};
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i)
    {
        const node_api_operation_t *op = nodeApiFind(server, names[i]);
        twfRequire(op && op->read_only == (i < 3) && op->execution == kNodeApiCallingWorker &&
                       strcmp(op->request_content_type, "application/json") == 0 &&
                       strcmp(op->response_content_type, "application/json") == 0 &&
                       op->response_encoding == kNodeApiEncodingUtf8,
                   "registered operation metadata incorrect");
    }
}
static void parsing(void)
{
    static const char *roots[] = {"",
                                  "null",
                                  "[]",
                                  "{}",
                                  "{\"id\":\"42\"}",
                                  "{\"id\":\"42\",\"password\":\"x\"}",
                                  "{\"if_match\":null,\"password\":\"x\"}",
                                  "{\"id\":\"42\",\"if_match\":\"x\",\"password\":\"x\"}",
                                  "\357\273\277{}"};
    for (size_t i = 0; i < sizeof(roots) / sizeof(*roots); ++i)
        call(roots[i], "invalid_request");
    static const char *ids[] = {"0", "00", "01", "+42", "-42", " 42", "42 ", "1.0", "1e0", "18446744073709551616"};
    char               match[49], body[4096];
    token(match);
    for (size_t i = 0; i < sizeof(ids) / sizeof(*ids); ++i)
    {
        snprintf(body, sizeof(body), "{\"id\":\"%s\",\"if_match\":\"%s\",\"password\":\"x\"}", ids[i], match);
        call(body, "invalid_request");
    }
    static const char *passwords[] = {"null",
                                      "false",
                                      "1",
                                      "[]",
                                      "{}",
                                      "\"\"",
                                      "\"a\\u0000b\"",
                                      "\"\300\200\"",
                                      "\"\\ud800\"",
                                      "\"\\udc00\"",
                                      "\"\\ud800x\"",
                                      "\"\\uZZZZ\""};
    for (size_t i = 0; i < sizeof(passwords) / sizeof(*passwords); ++i)
    {
        snprintf(body, sizeof(body), "{\"id\":\"42\",\"if_match\":\"%s\",\"password\":%s}", match, passwords[i]);
        call(body, "invalid_request");
    }
    static const char *extras[] = {"\"id\":\"42\"",          "\"i\\u0064\":\"42\"",
                                   "\"password\":\"y\"",     "\"passw\\u006frd\":\"y\"",
                                   "\"if_match\":\"x\"",     "\"if_matc\\u0068\":\"x\"",
                                   "\"old_password\":\"x\"", "\"new_password\":\"x\"",
                                   "\"patch\":{}",           "\"config\":{}",
                                   "\"sha224_pass\":\"x\"",  "\"sha256_pass\":\"x\"",
                                   "\"uuid_pass\":\"x\"",    "\"wireguard_publickey\":\"x\"",
                                   "\"enabled\":false",      "\"usage\":{}",
                                   "\"stats\":{}",           "\"time\":{}",
                                   "\"runtime\":{}",         "\"request_id\":\"x\"",
                                   "\"edit_token\":\"x\"",   "\"name\":\"x\"",
                                   "\"extra\":false"};
    for (size_t i = 0; i < sizeof(extras) / sizeof(*extras); ++i)
    {
        snprintf(body, sizeof(body), "{\"id\":\"42\",\"if_match\":\"%s\",\"password\":\"x\",%s}", match, extras[i]);
        call(body, "invalid_request");
    }
    const char *typed_ids[] = {"null", "42", "true", "[]", "{}"};
    for (size_t i = 0; i < sizeof(typed_ids) / sizeof(*typed_ids); ++i)
    {
        snprintf(body, sizeof(body), "{\"id\":%s,\"if_match\":\"%s\",\"password\":\"x\"}", typed_ids[i], match);
        call(body, "invalid_request");
    }
    static const char *matches[] = {"null", "false", "1", "[]", "{}", "\"\"", "\"a\\u0000b\""};
    for (size_t i = 0; i < sizeof(matches) / sizeof(*matches); ++i)
    {
        snprintf(body, sizeof(body), "{\"id\":\"42\",\"if_match\":%s,\"password\":\"x\"}", matches[i]);
        call(body, "invalid_request");
    }
    for (size_t i = 0; i < 4; ++i)
    {
        char bad[51];
        strcpy(bad, match);
        if (i == 0)
            bad[0] = 'A';
        if (i == 1)
            bad[47] = 0;
        if (i == 2)
            strcpy(bad + 48, "0");
        if (i == 3)
            bad[10] = 'g';
        requestText(body, sizeof(body), 42, bad, "x");
        call(body, "invalid_request");
    }
    requestText(body, sizeof(body), 42, match, "x");
    const size_t n = strlen(body);
    strcpy(body + n, " trailing");
    call(body, "invalid_request");
    body[n]     = 0;
    body[n + 1] = 'x';
    cJSON_Delete(callBytes(body, n + 2, "invalid_request"));
    strcpy(body, "{");
    for (unsigned i = 0; i < 10; ++i)
    {
        char entry[32];
        snprintf(entry, sizeof(entry), "%s\"k%u\":false", i ? "," : "", i);
        strcat(body, entry);
    }
    strcat(body, "}");
    call(body, "invalid_request");
    char *large = memoryAllocate(32769);
    memset(large, ' ', 32769);
    cJSON_Delete(callBytes(large, 32769, "invalid_request"));
    /* The exact body cap remains accepted, with no truncation of its password. */
    int head = snprintf(large, 32769, "{\"id\":\"42\",\"if_match\":\"%s\",\"password\":\"", match);
    twfRequire(head > 0, "large body prefix failed");
    size_t password_length = 32768 - (size_t) head - 2;
    memset(large + head, 'x', password_length);
    memoryCopy(large + 32766, "\"}", 3);
    cJSON_Delete(callBytes(large, 32768, NULL));
    twfRequire(strlen(usersLookupByIdentifier(&state()->store.users, 42)->password) == password_length,
               "exact request cap password truncated");
    memorySecureZero(large, 32769);
    memoryFree(large);
    rotate(UINT64_C(9007199254740993), "large-id-password", NULL);
    rotate(UINT64_MAX, "maximum-id-password", NULL);
}

static void credentialsAndPreservation(void)
{
    user_t                   *u    = usersLookupByIdentifier(&state()->store.users, 42);
    char                     *name = u->name, *email = u->email, *notes = u->notes, *allowed = u->wireguard_allowed_ips;
    const user_stat_t         stats          = u->stats;
    const user_limit_t        limits         = u->limit;
    const user_time_info_t    times          = u->timeinfo;
    const user_runtime_stat_t runtime        = u->runtime;
    const user_client_time_t  client_time    = u->client_time;
    const uint64_t            stats_revision = state()->store.stats_revision;
    const uint64_t            gid            = u->gid;
    const int                 interval       = u->record_stat_interval_ms;
    const bool                enabled        = u->enabled;
    sha224_hash_t             old224         = u->sha224_pass;
    sha256_hash_t             old256         = u->sha256_pass;
    uint8_t                   oldwg[32];
    memoryCopy(oldwg, u->wireguard_publickey, 32);
    memset(crypto_calls, 0, sizeof(crypto_calls));
    inspect_crypto = true;
    rotate(42, "  SECRET_SENTINEL\\u20ac  ", NULL);
    inspect_crypto = false;
    twfRequire(crypto_calls[0] == 1 && crypto_calls[1] == 1 && crypto_calls[2] == 1,
               "password primitives were repeated or skipped");
    twfRequire(strcmp(u->password, "  SECRET_SENTINEL\342\202\254  ") == 0 &&
                   userPasswordMatches(u, "  SECRET_SENTINEL\342\202\254  ") &&
                   ! userPasswordMatches(u, "initial-secret") &&
                   usersLookupByPassword(&state()->store.users, u->password) == u &&
                   usersLookupBySHA224(&state()->store.users, old224.bytes) == NULL &&
                   usersLookupBySHA256(&state()->store.users, old256.bytes) == NULL &&
                   usersLookupByWireGuardPublicKey(&state()->store.users, oldwg) == NULL &&
                   usersLookupBySHA224(&state()->store.users, u->sha224_pass.bytes) == u &&
                   usersLookupBySHA256(&state()->store.users, u->sha256_pass.bytes) == u &&
                   usersLookupByWireGuardPublicKey(&state()->store.users, u->wireguard_publickey) == u,
               "old/new credential membership incorrect");
    const char *uuid1 = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    rotate(42, uuid1, NULL);
    uint8_t uuid[16];
    memoryCopy(uuid, u->uuid_pass, 16);
    twfRequire(u->uuid_pass_valid && usersLookupByUUID(&state()->store.users, uuid) == u,
               "plain to UUID missed new identity");
    rotate(42, "F47AC10B-58CC-4372-A567-0E02B2C3D479", NULL);
    twfRequire(u->uuid_pass_valid && usersLookupByUUID(&state()->store.users, uuid) == u &&
                   ! userPasswordMatches(u, uuid1),
               "same-account UUID spelling rejected or plaintext normalized");
    rotate(42, "12345678-1234-4234-8234-123456789abc", NULL);
    twfRequire(usersLookupByUUID(&state()->store.users, uuid) == NULL && u->uuid_pass_valid,
               "UUID replacement kept stale identity");
    memoryCopy(uuid, u->uuid_pass, 16);
    rotate(42, "new-plain-secret", NULL);
    twfRequire(! u->uuid_pass_valid && usersLookupByUUID(&state()->store.users, uuid) == NULL,
               "UUID to plain retained identity");
    char old_token[49], body[512];
    token(old_token);
    rotate(42, "new-plain-secret", NULL);
    requestText(body, sizeof(body), 42, old_token, "new-plain-secret");
    call(body, "conflict");
    twfRequire(usersLookupByIdentifier(&state()->store.users, 42) == u && u->name == name && u->email == email &&
                   u->notes == notes && u->wireguard_allowed_ips == allowed && u->gid == gid && u->enabled == enabled &&
                   u->record_stat_interval_ms == interval && memcmp(&u->stats, &stats, sizeof(stats)) == 0 &&
                   memcmp(&u->limit, &limits, sizeof(limits)) == 0 &&
                   memcmp(&u->timeinfo, &times, sizeof(times)) == 0 &&
                   memcmp(&u->runtime, &runtime, sizeof(runtime)) == 0 &&
                   memcmp(&u->client_time, &client_time, sizeof(client_time)) == 0 &&
                   state()->store.stats_revision == stats_revision,
               "credentials-only transaction lost account/accounting/runtime fields");
    ip_addr_t address;
    ipaddr_aton("10.9.0.11", &address);
    twfRequire(usersLookupByWireGuardAllowedIp(&state()->store.users, &address) == u,
               "password change altered Allowed-IP membership");
    twfRequire(usersValidate(&state()->store.users), "password transitions corrupted indexes");
}

static void duplicatesAndFailures(void)
{
    user_t *u        = usersLookupByIdentifier(&state()->store.users, 42);
    collision_source = usersLookupByIdentifier(&state()->store.users, 43);
    for (unsigned kind = 1; kind <= 3; ++kind)
    {
        collision_kind = kind;
        rotate(42, "injected-collision-password", "credentials_exist");
        collision_kind = 0;
        twfRequire(strcmp(u->password, "new-plain-secret") == 0 && usersValidate(&state()->store.users),
                   "credential conflict changed an account/index");
    }
    rotate(42, collision_source->password, "credentials_exist");
    rotate(42, "98765432-1234-4234-8234-123456789ABC", "credentials_exist");
    for (unsigned kind = 1; kind <= 3; ++kind)
    {
        crypto_failure = kind;
        rotate(42, "backend-failure-password", "password_change_failed");
        crypto_failure = 0;
        twfRequire(strcmp(u->password, "new-plain-secret") == 0 && usersValidate(&state()->store.users),
                   "backend failure published credentials");
    }
    rotate(999, "not-found-password", "not_found");
    char match[49], body[512];
    token(match);
    match[0] = match[0] == '0' ? '1' : '0';
    requestText(body, sizeof(body), 999, match, "wrong-instance");
    call(body, "conflict");
    context.max_response_body_size = 255;
    rotate(42, "no-ack", "response_too_large");
    context.max_response_body_size = kAuthenticationServerApiBodyCap;
    char *old                      = memoryAllocate(32770);
    memset(old, 'p', 32769);
    old[32769] = 0;
    addUser(70, old);
    rotate(70, "overlong-old-password", "resource_limit");
    user_t *overlong = usersLookupByIdentifier(&state()->store.users, 70);
    twfRequire(strlen(overlong->password) == 32769, "old-password bound mutated stored value");
    old[32768] = 0;
    addUser(71, old);
    rotate(71, "exact-old-password-bound", NULL);
    memorySecureZero(old, 32770);
    memoryFree(old);
    /* Imported unrelated strings have no bearing on this indexed operation. */
    char *huge = memoryAllocate(65537);
    memset(huge, 'n', 65536);
    huge[65536]          = 0;
    user_update_t update = {.mask = kUserUpdateName | kUserUpdateNotes, .name = huge, .notes = huge};
    twfRequire(usersUpdateUser(&state()->store.users, (user_t *) collision_source, &update),
               "large metadata setup failed");
    rotate(42, "unrelated-large-metadata", NULL);
    memoryFree(huge);
}

static void workingBudget(void)
{
    char match[49], body[512];
    token(match);
    requestText(body, sizeof(body), 42, match, "budget-password");
    authenticationserver_password_request_t parsed;
    twfRequire(authenticationserverParsePasswordChange(passwordInputBytes(body, strlen(body)), &context, &parsed) ==
                   NULL,
               "budget preparation failed");
    const size_t retained = usersPreparedPasswordChangeOwnedBytes(parsed.password);
    const size_t peak     = usersPreparedPasswordChangePeakBytes(parsed.password);
    const size_t commit   = usersPreparedPasswordChangeCommitBytes(parsed.password);
    usersFreePreparedPasswordChange(parsed.password);
    twfRequire(retained != 0 && peak > retained && commit != 0, "prepared accounting omitted allocation/scratch");
    const size_t original            = context.working_memory_allowance;
    const size_t parser_charge       = 2 * strlen(body) + 16 * (sizeof(cJSON) + sizeof(char *) + 2);
    context.working_memory_allowance = kAuthenticationServerApiScratchCharge + parser_charge + peak - 1;
    twfRequire(
        strcmp(authenticationserverParsePasswordChange(passwordInputBytes(body, strlen(body)), &context, &parsed),
               "resource_limit") == 0 &&
            parsed.password == NULL,
        "preparation accepted one byte below peak allowance");
    context.working_memory_allowance++;
    twfRequire(authenticationserverParsePasswordChange(passwordInputBytes(body, strlen(body)), &context, &parsed) ==
                   NULL,
               "preparation rejected exact peak allowance");
    sbuf_t        *ack      = bufferpoolGetBestFit(env.pool, 256, 0);
    const uint64_t revision = state()->store.config_revision;
    twfRequire(strcmp(authenticationserverApplyConditionalPasswordChange(server, &parsed, &context, ack, commit - 1),
                      "resource_limit") == 0 &&
                   state()->store.config_revision == revision,
               "commit scratch admitted below exact allowance");
    twfRequire(authenticationserverApplyConditionalPasswordChange(server, &parsed, &context, ack, commit) == NULL &&
                   state()->store.config_revision == revision + 1,
               "exact commit scratch allowance rejected");
    usersFreePreparedPasswordChange(parsed.password);
    bufferpoolReuseBuffer(env.pool, ack);
    context.working_memory_allowance = original;

    /* Keep parser/preparation within 16 KiB while the real ACK tier costs 64 KiB.
     * Failure may be body-less because the same pool cannot admit diagnostics. */
    master_pool_t *masters[3];
    for (size_t i = 0; i < 3; ++i)
        masters[i] = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool = bufferpoolCreate(masters[0], masters[1], masters[2], 4, 65536, 65536, 128, 8192, 8192);
    twfRequire(pool != NULL, "ACK tier pool creation failed");
    buffer_pool_t *previous_pool = env.pool;
    env.pool = env.pool_shortcut[0] = env.worker.buffer_pool = pool;
    context.working_memory_allowance                         = 16384;
    token(match);
    requestText(body, sizeof(body), 42, match, "ack-tier-password");
    twfRequire(authenticationserverParsePasswordChange(passwordInputBytes(body, strlen(body)), &context, &parsed) ==
                   NULL,
               "ACK-only fixture did not fit preparation");
    usersFreePreparedPasswordChange(parsed.password);
    buffer_pool_fit_t fit;
    twfRequire(bufferpoolQueryBestFit(pool, 256, 0, &fit) && fit.allocation_charge > 16384,
               "ACK tier did not exceed working allowance");
    const uint64_t before = state()->store.config_revision;
    api_result_t   result =
        authenticationserverApiChangeUserPassword(server, passwordInputBytes(body, strlen(body)), &context);
    twfRequire(result.result_code == kApiResultError && state()->store.config_revision == before &&
                   strcmp(usersLookupByIdentifier(&state()->store.users, 42)->password, "budget-password") == 0,
               "ACK charge refusal mutated credentials");
    if (result.buffer != NULL)
        bufferpoolReuseBuffer(pool, result.buffer);
    twfRequireNoLeakedBuffers();
    context.working_memory_allowance = original;
    env.pool = env.pool_shortcut[0] = env.worker.buffer_pool = previous_pool;
    bufferpoolDestroy(pool);
    for (size_t i = 0; i < 3; ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
}

typedef struct password_lock_holder_s
{
    wrwlock_t  *lock;
    wsem_t      acquired, release;
    atomic_bool held;
} password_lock_holder_t;
static WTHREAD_ROUTINE(holdLock)
{
    password_lock_holder_t *holder = userdata;
    rwlockWriteLock(holder->lock);
    atomic_store(&holder->held, true);
    semaphorePost(&holder->acquired);
    twfRequire(semaphoreWait(&holder->release), "held lock barrier failed");
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
        char match[49], body[512];
        token(match);
        requestText(body, sizeof(body), 42, match, "held-lock-password");
        password_lock_holder_t holder = {.lock = locks[i]};
        atomic_init(&holder.held, false);
        semaphoreInit(&holder.acquired, 0);
        semaphoreInit(&holder.release, 0);
        wthread_t thread;
        twfRequire(threadCreate(&thread, holdLock, &holder) == kWThreadErrorNone, "holder thread start failed");
        twfRequire(semaphoreWait(&holder.acquired), "holder acquisition failed");
        api_result_t result =
            authenticationserverApiChangeUserPassword(server, passwordInputBytes(body, strlen(body)), &context);
        cJSON *json = cJSON_ParseWithLength((const char *) sbufGetRawPtr(result.buffer), sbufGetLength(result.buffer));
        twfRequire(atomic_load(&holder.held) && result.result_code == (i < 3 ? kApiResultError : kApiResultOk) &&
                       (i == 3 || strcmp(field(field(json, "error"), "code")->valuestring, "busy") == 0),
                   "credentials transaction waited or acquired statistics lock");
        cJSON_Delete(json);
        bufferpoolReuseBuffer(env.pool, result.buffer);
        semaphorePost(&holder.release);
        twfRequire(threadJoin(thread) == 0, "holder join failed");
        semaphoreDestroy(&holder.release);
        semaphoreDestroy(&holder.acquired);
    }
}
static void deadlineRefusal(void)
{
    fake_time_us        = 1000000;
    context.deadline_ms = 1500;
    clock_reads         = 0;
    expire_after        = 0;
    rotate(42, "deadline-password", NULL);
    const unsigned total = clock_reads;
    twfRequire(total > 10, "deadline fixture did not cover transaction/rendering");
    const unsigned points[] = {1, 2, 3, 4, 5, 6, total - 2, total - 1, total};
    for (size_t i = 0; i < sizeof(points) / sizeof(*points); ++i)
    {
        clock_reads  = 0;
        expire_after = points[i];
        rotate(42, "deadline-password", "timeout");
    }
    expire_after        = 0;
    fake_time_us        = 0;
    context.deadline_ms = UINT64_MAX;
    twfRequire(usersValidate(&state()->store.users), "deadline refusal corrupted indexes");
}
static void revisionCoherence(void)
{
    const node_api_operation_t *list   = nodeApiFind(server, "list-users");
    static const char           body[] = "{\"limit\":1}";
    api_result_t                page   = list->handler(server, inputBytes(body, sizeof(body) - 1), &context);
    cJSON *json = cJSON_ParseWithLength((const char *) sbufGetRawPtr(page.buffer), sbufGetLength(page.buffer));
    char   cursor[65], match[49];
    strcpy(cursor, field(json, "next_cursor")->valuestring);
    token(match);
    cJSON_Delete(json);
    bufferpoolReuseBuffer(env.pool, page.buffer);
    /* A real statistics-only mutation does not invalidate the current token. */
    rwlockWriteLock(&state()->state_lock);
    userAddTraffic(usersLookupByIdentifier(&state()->store.users, 42), 3, 4);
    authenticationserverBumpStatsRevision(server);
    rwlockWriteUnlock(&state()->state_lock);
    char request[512];
    requestText(request, sizeof(request), 42, match, "stats-token-password");
    call(request, NULL);
    snprintf(request, sizeof(request), "{\"cursor\":\"%s\",\"limit\":1}", cursor);
    page = list->handler(server, inputBytes(request, strlen(request)), &context);
    json = cJSON_ParseWithLength((const char *) sbufGetRawPtr(page.buffer), sbufGetLength(page.buffer));
    twfRequire(page.result_code == kApiResultError &&
                   strcmp(field(field(json, "error"), "code")->valuestring, "stale_cursor") == 0,
               "password mutation did not stale list cursor");
    cJSON_Delete(json);
    bufferpoolReuseBuffer(env.pool, page.buffer);
    requestText(request, sizeof(request), 42, match, "stats-token-password");
    call(request, "conflict");
}
static void persistence(void)
{
    char directory[] = "/tmp/ww-auth-password-save-XXXXXX", primary[512], backup[520];
    twfRequire(mkdtemp(directory) != NULL, "persistence directory failed");
    snprintf(primary, sizeof(primary), "%s/users.json", directory);
    snprintf(backup, sizeof(backup), "%s.backup", primary);
    static const char seed[] = "{\"users\":[]}\n";
    int               fd     = open(primary, O_WRONLY | O_CREAT | O_EXCL, 0600);
    twfRequire(fd >= 0 && write(fd, seed, sizeof(seed) - 1) == sizeof(seed) - 1 && close(fd) == 0,
               "persistence seed failed");
    char *previous_primary = state()->db_path, *previous_backup = state()->backup_path;
    state()->db_path     = primary;
    state()->backup_path = backup;
    rotate(42, "persisted-password", NULL);
    char *disk = readFile(primary);
    twfRequire(disk && strcmp(disk, seed) == 0 && ! isFile(backup) && ! state()->primary_save_last_attempt_valid &&
                   ! state()->primary_save_last_success_valid && state()->primary_save_last_attempt_ms == 0 &&
                   state()->primary_save_last_success_ms == 0 &&
                   state()->primary_save_last_result == kAuthenticationServerSaveNotAttempted,
               "password mutation saved immediately or altered telemetry");
    memoryFree(disk);
    twfRequire(authenticationserverSaveDatabase(state()), "later ordinary save failed");
    disk        = readFile(primary);
    cJSON *json = cJSON_Parse(disk);
    memoryFree(disk);
    users_t loaded;
    twfRequire(usersCreate(&loaded) && usersFeedJson(&loaded, json), "ordinary reload failed");
    cJSON_Delete(json);
    user_t *saved = usersLookupByPassword(&loaded, "persisted-password");
    user_t *u     = usersLookupByIdentifier(&state()->store.users, 42);
    twfRequire(saved && saved->id == 42 && saved->stats.traffic.u == u->stats.traffic.u &&
                   saved->stats.traffic.d == u->stats.traffic.d &&
                   memcmp(&saved->timeinfo, &u->timeinfo, sizeof(u->timeinfo)) == 0 && ! saved->enabled &&
                   strcmp(saved->name, u->name) == 0 && usersValidate(&loaded),
               "reload lost credentials or preserved account values");
    usersDestroy(&loaded);
    state()->db_path     = previous_primary;
    state()->backup_path = previous_backup;
    twfRequire(unlink(primary) == 0 && unlink(backup) == 0 && rmdir(directory) == 0, "save cleanup failed");
}

static unsigned                   completions;
static node_api_dispatch_status_t completion_status;
static void                       complete(void *arg, uint64_t session, uint64_t request, const node_api_reply_t *reply)
{
    discard arg;
    twfRequire(session == 1 && request == 1, "dispatch identities changed");
    ++completions;
    completion_status = reply->status;
}
static void detachedDelivery(void)
{
    nodeApiFreeze();
    node_api_domain_t *domain = nodeApiDomainCreate(16 * 1024 * 1024, 4, complete, NULL);
    twfRequire(domain != NULL, "detached domain failed");
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        char body[512], match[49], password[80];
        snprintf(password, sizeof(password), "detached-password-%u", mode);
        token(match);
        requestText(body, sizeof(body), 42, match, password);
        fake_time_us             = 1000000;
        const uint64_t  revision = state()->store.config_revision;
        node_api_job_t *job      = nodeApiJobCreate(domain,
                                               server,
                                               nodeApiFind(server, "change-user-password"),
                                               0,
                                               1,
                                               1,
                                               1500,
                                               "password-admin",
                                               NULL,
                                               NULL,
                                               body,
                                               strlen(body),
                                               4096,
                                               4 * 1024 * 1024);
        twfRequire(job && nodeApiJobSubmit(job) == kNodeApiDispatchOk && queue_count == 1,
                   "password job submission failed");
        nextMessage();
        twfRequire(state()->store.config_revision == revision + 1 && queue_count == 1,
                   "detached handler did not commit");
        node_api_job_t *pending = NULL;
        if (mode == 0)
            fake_time_us = 2000000;
        else if (mode == 1)
            nodeApiJobAbandon(job);
        else
        {
            char waiting[512], current[49];
            token(current);
            requestText(waiting, sizeof(waiting), 42, current, "closed-admission-password");
            pending = nodeApiJobCreate(domain,
                                       server,
                                       nodeApiFind(server, "change-user-password"),
                                       0,
                                       1,
                                       1,
                                       1500,
                                       "password-admin",
                                       NULL,
                                       NULL,
                                       waiting,
                                       strlen(waiting),
                                       4096,
                                       4 * 1024 * 1024);
            twfRequire(pending && nodeApiJobSubmit(pending) == kNodeApiDispatchOk, "queued shutdown request failed");
            nodeApiCloseAdmission();
        }
        const unsigned before = completions;
        nextMessage();
        twfRequire(completions == before + (mode == 0 ? 1 : 0) &&
                       (mode != 0 || completion_status == kNodeApiDispatchTimeout),
                   "late/abandoned password reply behaved incorrectly");
        nodeApiJobRelease(job);
        if (pending != NULL)
        {
            nextMessage();
            nextMessage();
            nodeApiJobRelease(pending);
        }
        fake_time_us = 0;
        call(body, "conflict");
        twfRequire(usersLookupByPassword(&state()->store.users, password) ==
                           usersLookupByIdentifier(&state()->store.users, 42) &&
                       usersLookupByPassword(&state()->store.users, "closed-admission-password") == NULL &&
                       state()->store.config_revision == revision + 1,
                   "reply loss rolled back/duplicated password or queued closed-admission job ran");
        size_t bytes, jobs;
        nodeApiDomainGetUsage(domain, &bytes, &jobs);
        twfRequire(bytes == 0 && jobs == 0, "detached password reservation leaked");
    }
    nodeApiDomainDestroy(domain);
}

int main(void)
{
    twfSetCase("AuthenticationServer change-user-password API");
    twfRequire(createNetworkLogger(NULL, false) && wCryptoGlobalInit() == kWCryptoOk, "runtime init failed");
    twfWorkerEnvSetup(&env, 8192, 32);
    nodeApiRegistryInitialize();
    server = tunnelCreate(NULL, sizeof(authenticationserver_tstate_t), 0);
    twfRequire(server != NULL, "server allocation failed");
    rwlockinit(&state()->state_lock);
    twfRequire(usersCreate(&state()->store.users), "collection initialization failed");
    state()->database_loaded       = true;
    state()->store.config_revision = 84;
    state()->store.stats_revision  = 19;
    memset(state()->api_instance_id, 0x5a, 16);
    authenticationserverInitializeAccountingClock(state());
    addUser(42, "initial-secret");
    addUser(43, "98765432-1234-4234-8234-123456789abc");
    addUser(UINT64_C(9007199254740993), "initial-large-id");
    addUser(UINT64_MAX, "initial-maximum-id");
    user_t       *u      = usersLookupByIdentifier(&state()->store.users, 42);
    user_update_t update = {.mask = kUserUpdateName | kUserUpdateEmail | kUserUpdateNotes | kUserUpdateGid |
                                    kUserUpdateEnabled | kUserUpdateRecordStatInterval |
                                    kUserUpdateWireGuardAllowedIps | kUserUpdateLimit | kUserUpdateTimeInfo |
                                    kUserUpdateStats,
                            .name                    = "preserved-name",
                            .email                   = "preserved@example.invalid",
                            .notes                   = "preserved-note",
                            .gid                     = 7,
                            .enabled                 = false,
                            .record_stat_interval_ms = 10000,
                            .wireguard_allowed_ips   = "10.9.0.0/24",
                            .limit                   = {.traffic = {4, 5, 6}},
                            .timeinfo                = {123, 456, 789, 900},
                            .stats                   = {.traffic = {100, 200}, .speed = {13, 17}}};
    twfRequire(usersUpdateUser(&state()->store.users, u, &update), "preservation setup failed");
    u->runtime.active_cons_out                  = 3;
    u->runtime.first_usage_push_requested       = true;
    u->client_time                              = (user_client_time_t) {.clock_valid          = true,
                                                                        .observed             = true,
                                                                        .observation_acked    = true,
                                                                        .accounting_anchor_ms = 777,
                                                                        .local_anchor_ms      = 88,
                                                                        .first_local_ms       = 55,
                                                                        .first_report_ms      = 666,
                                                                        .age_ms               = 1234,
                                                                        .age_valid            = true};
    u->client_view_expires_at_ms                = 2345;
    u->client_view_expiry_valid                 = true;
    u->client_view_expired                      = true;
    authenticationserver_auth_client_t producer = {.last_sequence = 9};
    memset(producer.accounting_epoch, 0x6a, sizeof(producer.accounting_epoch));
    memset(producer.last_digest, 0x7b, sizeof(producer.last_digest));
    state()->auth_clients       = &producer;
    state()->auth_clients_count = 1;
    twfRequire(authenticationserverRegisterApi(server), "registration failed");
    context = (node_api_call_context_t) {.operation                = "change-user-password",
                                         .principal                = "password-admin",
                                         .deadline_ms              = UINT64_MAX,
                                         .max_response_body_size   = kAuthenticationServerApiBodyCap,
                                         .working_memory_allowance = 4 * 1024 * 1024};
    registration();
    parsing();
    credentialsAndPreservation();
    duplicatesAndFailures();
    twfRequire(wiped_inputs > 70 && wipe_input == NULL, "secret input cleanup paths were not exercised");
    workingBudget();
    lockRefusal();
    deadlineRefusal();
    revisionCoherence();
    persistence();
    twfRequire(producer.last_sequence == 9 && producer.accounting_epoch[0] == 0x6a && producer.last_digest[0] == 0x7b &&
                   u->client_view_expires_at_ms == 2345 && u->client_view_expiry_valid && u->client_view_expired,
               "password change altered producer checkpoint or expiry projection");
    detachedDelivery();
    state()->store.config_revision = UINT64_MAX - 1;
    rotate(42, "maximum-revision-password", NULL);
    rotate(42, "revision-exhausted-password", "revision_exhausted");
    twfRequire(usersValidate(&state()->store.users), "final collection indexes invalid");
    state()->auth_clients       = NULL;
    state()->auth_clients_count = 0;
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
