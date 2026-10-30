/* CTest: waterwall.authenticationserver_responses_unit
 * Real request parsing and response FIFO; bounded charge, reentry and terminal ownership. */
#include "../../../../tunnels/Internals/AuthenticationCommon/stream.h"
#include "AuthenticationServer/api.h"
#include "AuthenticationServer/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/user_runtime.h"
#include "loggers/network_logger.h"

static const char *parse_watch;
static unsigned    parse_calls;
static wrwlock_t  *write_lock_watch;
static unsigned    watched_writes;
static char       *secret_watch, *decoded_watch, *serialized_watch;
static size_t      secret_watch_length, decoded_watch_length, serialized_watch_length;
static unsigned    secret_wiped, decoded_wiped, serialized_wiped;
static bool        inspect_auth_secret, inspect_user_json, refuse_serialization;

cJSON *__real_cJSON_ParseWithLengthOpts(const char *, size_t, const char **, cJSON_bool);
cJSON *__wrap_cJSON_ParseWithLengthOpts(const char *, size_t, const char **, cJSON_bool);
cJSON *__wrap_cJSON_ParseWithLengthOpts(const char *text, size_t length, const char **end, cJSON_bool terminated)
{
    if (text == parse_watch)
        ++parse_calls;
    cJSON *json = __real_cJSON_ParseWithLengthOpts(text, length, end, terminated);
    if (inspect_auth_secret)
    {
        cJSON *secret = cJSON_GetObjectItemCaseSensitive(json, "secret");
        if (cJSON_IsString(secret))
        {
            decoded_watch        = secret->valuestring;
            decoded_watch_length = strlen(decoded_watch);
        }
    }
    return json;
}

int __real_pthread_rwlock_wrlock(pthread_rwlock_t *lock);
int __wrap_pthread_rwlock_wrlock(pthread_rwlock_t *lock);
int __wrap_pthread_rwlock_wrlock(pthread_rwlock_t *lock)
{
    if (lock == write_lock_watch)
        ++watched_writes;
    return __real_pthread_rwlock_wrlock(lock);
}

static const char *lookup_text_watch;
static unsigned    lookup_text_copies;
cJSON             *__real_cJSON_AddStringToObject(cJSON *object, const char *name, const char *string);
cJSON             *__wrap_cJSON_AddStringToObject(cJSON *object, const char *name, const char *string);
cJSON             *__wrap_cJSON_AddStringToObject(cJSON *object, const char *name, const char *string)
{
    if (lookup_text_watch != NULL && string == lookup_text_watch)
        ++lookup_text_copies;
    return __real_cJSON_AddStringToObject(object, name, string);
}
char *__real_cJSON_SetValuestring(cJSON *object, const char *string);
char *__wrap_cJSON_SetValuestring(cJSON *object, const char *string);
char *__wrap_cJSON_SetValuestring(cJSON *object, const char *string)
{
    if (lookup_text_watch != NULL && string == lookup_text_watch)
        ++lookup_text_copies;
    return __real_cJSON_SetValuestring(object, string);
}

void __real_memoryFree(void *pointer);
void __wrap_memoryFree(void *pointer);
void __wrap_memoryFree(void *pointer)
{
    if (pointer != NULL && (pointer == secret_watch || pointer == decoded_watch || pointer == serialized_watch))
    {
        const size_t length = pointer == secret_watch    ? secret_watch_length
                              : pointer == decoded_watch ? decoded_watch_length
                                                         : serialized_watch_length;
        for (size_t i = 0; i < length; ++i)
            twfRequire(((const uint8_t *) pointer)[i] == 0, "owned secret reached free unwiped");
        if (pointer == secret_watch)
        {
            secret_watch = NULL;
            ++secret_wiped;
        }
        else if (pointer == decoded_watch)
        {
            decoded_watch = NULL;
            ++decoded_wiped;
        }
        else
        {
            serialized_watch = NULL;
            ++serialized_wiped;
        }
    }
    __real_memoryFree(pointer);
}
cJSON_bool __real_cJSON_PrintPreallocated(cJSON *json, char *buffer, const int length, const cJSON_bool format);
cJSON_bool __wrap_cJSON_PrintPreallocated(cJSON *json, char *buffer, const int length, const cJSON_bool format);
cJSON_bool __wrap_cJSON_PrintPreallocated(cJSON *json, char *buffer, const int length, const cJSON_bool format)
{
    const cJSON_bool result = __real_cJSON_PrintPreallocated(json, buffer, length, format);
    if (! inspect_user_json)
        return result;
    cJSON *password = cJSON_GetObjectItemCaseSensitive(json, "password");
    twfRequire(cJSON_IsString(password), "credential JSON fixture lost password");
    decoded_watch           = password->valuestring;
    decoded_watch_length    = strlen(decoded_watch);
    serialized_watch        = buffer;
    serialized_watch_length = result && ! refuse_serialization ? strlen(buffer) : (size_t) length;
    return result && ! refuse_serialization;
}

static twf_worker_env_t env;
static twf_line_pool_t  lines;
static tunnel_t        *server, *owner;
static line_t          *line;
static unsigned         closes, callbacks, depth, maximum_depth;
static bool             pause_once, close_once, nested_request;
static bool             nested_after_auth;
static uint8_t         *received;
static size_t           received_length;
static bool             count_growth;
static size_t           growth_bytes;
static unsigned         growth_allocations;

sbuf_t *__real_sbufCreateWithPadding(uint32_t size, uint16_t padding);
sbuf_t *__wrap_sbufCreateWithPadding(uint32_t size, uint16_t padding);
sbuf_t *__wrap_sbufCreateWithPadding(uint32_t size, uint16_t padding)
{
    /* Individual frames and output chunks use pool tiers no larger than
     * 64 KiB here. Count larger dedicated allocations to isolate message
     * construction from pool replenishment. */
    if (count_growth && size > MEDIUM_BUFFER_SIZE_RAM_HIGH)
    {
        ++growth_allocations;
        growth_bytes += size;
    }
    return __real_sbufCreateWithPadding(size, padding);
}

static void request(uint32_t id)
{
    sbuf_t *b = bufferpoolGetBestFit(env.pool, 77, 64);
    sbufSetLength(b, 77);
    memoryZero(sbufGetMutablePtr(b), 77);
    uint32_t body = htonl(73), correlation = htonl(id);
    memoryCopy(sbufGetMutablePtr(b), &body, 4);
    sbufGetMutablePtr(b)[68] = kAuthenticationServerRequestTypePing;
    memoryCopy(sbufGetMutablePtr(b) + 69, &correlation, 4);
    tunnelUpStreamPayload(server, line, b);
}

static void finished(tunnel_t *t, line_t *l)
{
    discard t;
    ++closes;
    lineDestroy(l);
}

static void output(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    ++depth;
    maximum_depth = max(maximum_depth, depth);
    ++callbacks;
    twfRequire(sbufGetLength(b) <= kAuthenticationServerOutputChunkSize, "oversized transport handoff");
    twfRequire(sbufGetAllocationCharge(b) < 128U * 1024U, "oversized transport allocation charge");
    twfRequire(sbufGetLeftCapacity(b) >= 64, "chunk lost chain padding");
    received = memoryReAllocate(received, received_length + sbufGetLength(b));
    memoryCopy(received + received_length, sbufGetRawPtr(b), sbufGetLength(b));
    received_length += sbufGetLength(b);
    lineReuseBuffer(l, b);
    if (nested_after_auth)
    {
        nested_after_auth = false;
        request(1000);
    }
    if (pause_once)
    {
        pause_once = false;
        tunnelUpStreamPause(server, l);
        if (nested_request)
        {
            request(999);
            tunnelUpStreamResume(server, l);
        }
    }
    if (close_once)
    {
        close_once = false;
        tunnelUpStreamFin(server, l);
        ++closes;
        lineDestroy(l);
    }
    --depth;
}

static authenticationserver_lstate_t *setup(void)
{
    closes = callbacks = depth = maximum_depth = 0;
    pause_once = close_once = nested_request = false;
    nested_after_auth                        = false;
    received_length                          = 0;
    received                                 = NULL;
    twfWorkerEnvSetup(&env, 8192, 64);
    server = tunnelCreate(NULL, sizeof(authenticationserver_tstate_t), sizeof(authenticationserver_lstate_t));
    owner  = tunnelCreate(NULL, 0, 0);
    twfRequire(server != NULL && owner != NULL, "tunnel construction failed");
    owner->fnPayloadD  = output;
    owner->fnFinD      = finished;
    server->fnPayloadU = authenticationserverTunnelUpStreamPayload;
    server->fnPauseU   = authenticationserverTunnelUpStreamPause;
    server->fnResumeU  = authenticationserverTunnelUpStreamResume;
    server->fnFinU     = authenticationserverTunnelUpStreamFinish;
    tunnelBind(owner, server);
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    rwlockinit(&ts->state_lock);
    authenticationserverInitializeAccountingClock(ts);
    authenticationserverInitializeExportLimit(ts);
    twfRequire(usersCreate(&ts->store.users), "users construction failed");
    twfLinePoolSetup(&lines, server->lstate_size, 4);
    line = twfLinePoolCreateLine(&lines);
    lineRef(line);
    authenticationserver_lstate_t *ls = lineGetState(line, server);
    authenticationserverLinestateInitialize(ls, env.pool);
    return ls;
}

static void teardown(void)
{
    if (lineIsAlive(line))
    {
        tunnelUpStreamFin(server, line);
        lineDestroy(line);
    }
    twfRequireLineStateZeroed(line, server, "response state survived Finish");
    lineUnref(line);
    twfLinePoolTeardown(&lines);
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    authenticationserverSessionsDestroy(ts);
    twfRequire(ts->snapshot_bytes == 0, "session destruction leaked snapshot storage");
    authenticationserverAuthClientsDestroy(ts);
    usersDestroy(&ts->store.users);
    rwlockDestroy(&ts->state_lock);
    tunnelDestroy(owner);
    tunnelDestroy(server);
    memoryFree(received);
    twfWorkerEnvTeardown(&env);
}

static sbuf_t *envelope(uint8_t type, const void *data, uint32_t size, unsigned frames)
{
    const uint32_t length = 68U + frames * (9U + size);
    sbuf_t        *b      = bufferpoolGetBestFit(env.pool, length, 64);
    sbufSetLength(b, length);
    memoryZero(sbufGetMutablePtr(b), length);
    uint32_t body = htonl(length - 4U);
    memoryCopy(sbufGetMutablePtr(b), &body, 4);
    for (unsigned i = 0; i < frames; ++i)
    {
        uint8_t *p  = sbufGetMutablePtr(b) + 68U + i * (9U + size);
        p[0]        = type;
        uint32_t id = htonl(i + 1U), n = htonl(size);
        memoryCopy(p + 1, &id, 4);
        memoryCopy(p + 5, &n, 4);
        if (size != 0)
            memoryCopy(p + 9, data, size);
    }
    return b;
}

static void configureCredentials(void)
{
    authenticationserver_tstate_t *ts           = tunnelGetState(server);
    ts->auth_clients                            = memoryAllocateZero(sizeof(*ts->auth_clients));
    ts->auth_clients_count                      = 1;
    ts->auth_clients[0].name                    = stringDuplicate("edge");
    ts->auth_clients[0].secret                  = stringDuplicate("secret");
    ts->auth_clients[0].session_idle_timeout_ms = 10000;
    ts->auth_clients[0].allow_user_pull         = true;
}

static void testPreauthBounds(void)
{
    for (unsigned split = 0; split <= 68; ++split)
    {
        authenticationserver_lstate_t *ls         = setup();
        uint8_t                        header[68] = {0};
        uint32_t                       size       = htonl(64U + 16385U);
        memoryCopy(header, &size, 4);
        for (unsigned part = 0; part < 2; ++part)
        {
            unsigned n = part == 0 ? split : 68U - split;
            if (n == 0)
                continue;
            sbuf_t *b = sbufCreateWithPadding(2U * 1024U * 1024U, 64);
            sbufSetLength(b, n);
            memoryCopy(sbufGetMutablePtr(b), header + (part == 0 ? 0 : split), n);
            tunnelUpStreamPayload(server, line, b);
            if (part == 0 && split < 68)
                twfRequire(lineIsAlive(line) && bufferstreamGetCharge(&ls->read_stream) <= 128U * 1024U,
                           "unvalidated prefix retained oversized carrier allocation");
        }
        twfRequire(! lineIsAlive(line) && closes == 1 && callbacks == 0,
                   "oversized preauth declaration was not rejected at the token boundary");
        teardown();
    }
    authenticationserver_lstate_t *ls         = setup();
    uint8_t                        header[68] = {0};
    uint32_t                       size       = htonl(64U + 16384U);
    memoryCopy(header, &size, 4);
    for (unsigned i = 0; i < sizeof(header); ++i)
    {
        sbuf_t *b = bufferpoolGetBestFit(env.pool, 1, 64);
        sbufSetLength(b, 1);
        *sbufGetMutablePtr(b) = header[i];
        tunnelUpStreamPayload(server, line, b);
        twfRequire(lineIsAlive(line) && bufferstreamGetCharge(&ls->read_stream) <= 128U * 1024U &&
                       bufferstreamGetEntryCount(&ls->read_stream) <= 64,
                   "tiny unauthenticated fragments exceeded retained bounds");
    }
    teardown();
}

static void testFrameCount(void)
{
    for (unsigned frames = 64; frames <= 65; ++frames)
    {
        setup();
        configureCredentials();
        /* A valid first Authenticate must not execute when frame 65 is present. */
        const char auth[] = "{\"name\":\"edge\",\"secret\":\"secret\"}";
        sbuf_t    *b      = envelope(kAuthenticationServerRequestTypeAuthenticate, auth, sizeof(auth) - 1U, frames);
        tunnelUpStreamPayload(server, line, b);
        authenticationserver_tstate_t *ts = tunnelGetState(server);
        if (frames == 65)
            twfRequire(! lineIsAlive(line) && callbacks == 0 && ts->sessions_count == 0,
                       "frame 65 allowed earlier authentication mutation");
        else
        {
            twfRequire(lineIsAlive(line) && ts->sessions_count == 1 && received_length > 20,
                       "64 request frames were refused");
            size_t   offset = 20;
            unsigned count  = 0;
            while (offset < received_length)
            {
                uint32_t size;
                memoryCopy(&size, received + offset + 5, 4);
                offset += 9U + ntohl(size);
                ++count;
            }
            twfRequire(offset == received_length && count == frames, "64 correlated replies were not preserved");
        }
        teardown();
    }
}

static void testAuthenticateValidation(void)
{
    const char *invalid[] = {"{\"name\":\"edge\",\"secret\":\"secret\",\"name\":\"edge\"}",
                             "{\"name\":\"edge\",\"secret\":\"secret\",\"unknown\":true}",
                             "{\"name\":\"edge\",\"secret\":\"secret\"}true",
                             "{\"name\":\"edge\\u0000suffix\",\"secret\":\"secret\"}",
                             "{\"name\":\"edge\",\"secret\":{\"nested\":{}}}",
                             "{\"name\":\"edge\",\"secret\":\"secret\",\"epoch\":\"invalid\"}",
                             "{\"name\":\"edge\",\"secret\":\"\xff\"}",
                             "{\"name\":\"edge\",\"secret\":\"wrong\"}"};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        authenticationserver_lstate_t *ls = setup();
        configureCredentials();
        tunnelUpStreamPause(server, line);
        tunnelUpStreamPayload(
            server, line, envelope(kAuthenticationServerRequestTypeAuthenticate, invalid[i], strlen(invalid[i]), 1));
        authenticationserver_tstate_t *ts = tunnelGetState(server);
        twfRequire(lineIsAlive(line) && ls->reject_further_input && callbacks == 0 && ts->sessions_count == 0 &&
                       bufferbudgetGetUsage(&ls->response_budget).entries == 1,
                   "failed authentication did not latch admission before paused response");
        if (i == 0)
            nested_after_auth = true;
        tunnelUpStreamResume(server, line);
        twfRequire(received_length > 29 && received[20] == kAuthenticationServerResponseTypeError,
                   "paused authentication error lost its correlated reply");
        if (i != 0)
            request(2);
        twfRequire(! lineIsAlive(line) && closes == 1 && callbacks == 1,
                   "subsequent or nested input after rejected authentication was processed");
        teardown();
    }
}

static void testGeometricConstruction(void)
{
    setup();
    configureCredentials();
    authenticationserver_tstate_t  *ts = tunnelGetState(server);
    const char                     *error;
    authenticationserver_session_t *session = authenticationserverSessionCreate(server, "edge", "secret", NULL, &error);
    twfRequire(session != NULL, "valid session creation failed");
    user_t user;
    twfRequire(userCreate(&user, "pw"), "user creation failed");
    userSetId(&user, 42);
    twfRequire(usersAddUser(&ts->store.users, &user), "user insertion failed");
    userDestroy(&user);
    char notes[12001];
    memset(notes, 'a', sizeof(notes) - 1);
    notes[sizeof(notes) - 1] = '\0';
    twfRequire(usersSetUserNotes(&ts->store.users, usersLookupByIdentifier(&ts->store.users, 42), notes),
               "notes setup failed");
    sbuf_t *b = envelope(kAuthenticationServerRequestTypeGetUserByPassword, "pw", 2, 64);
    memoryCopy(sbufGetMutablePtr(b) + 4, session->token, 64);
    growth_allocations = 0;
    growth_bytes       = 0;
    count_growth       = true;
    tunnelUpStreamPayload(server, line, b);
    count_growth = false;
    twfRequire(lineIsAlive(line) && received_length > 64U * 12000U, "large bounded multi-frame response was lost");
    twfRequire(growth_allocations > 0 && growth_allocations <= 7 && growth_bytes < received_length * 4U,
               "response construction performed per-frame allocation/copy growth");
    teardown();
}

static void testSessionAtEnvelopeEntry(void)
{
    setup();
    configureCredentials();
    const char     auth[]   = "{\"name\":\"edge\",\"secret\":\"secret\"}";
    sbuf_t        *b        = envelope(kAuthenticationServerRequestTypeAuthenticate, auth, sizeof(auth) - 1U, 1);
    const uint32_t previous = sbufGetLength(b);
    b                       = sbufReserveSpace(b, previous + 13U);
    sbufSetLength(b, previous + 13U);
    uint8_t *p    = sbufGetMutablePtr(b);
    uint32_t body = htonl(sbufGetLength(b) - 4U), id = htonl(2), size = htonl(4);
    memoryCopy(p, &body, 4);
    p[previous] = kAuthenticationServerRequestTypePing;
    memoryCopy(p + previous + 1U, &id, 4);
    memoryCopy(p + previous + 5U, &size, 4);
    memoryCopy(p + previous + 9U, "ping", 4);
    tunnelUpStreamPayload(server, line, b);
    const size_t sibling = 20U + 9U + 128U;
    const char   error[] = "authentication-required";
    twfRequire(lineIsAlive(line) && received[20] == kAuthenticationServerResponseTypeSession &&
                   received_length == sibling + 9U + sizeof(error) - 1U &&
                   received[sibling] == kAuthenticationServerResponseTypeError &&
                   memcmp(received + sibling + 9U, error, sizeof(error) - 1U) == 0,
               "successful Authenticate authorized its unauthenticated sibling");
    teardown();

    setup();
    configureCredentials();
    const char                     *reason;
    authenticationserver_session_t *session =
        authenticationserverSessionCreate(server, "edge", "secret", NULL, &reason);
    twfRequire(session != NULL, "valid session creation failed");
    uint8_t header[68];
    body = htonl(64U + 16385U);
    memoryCopy(header, &body, 4);
    memoryCopy(header + 4, session->token, 64);
    b = bufferpoolGetBestFit(env.pool, sizeof(header), 64);
    sbufSetLength(b, sizeof(header));
    memoryCopy(sbufGetMutablePtr(b), header, sizeof(header));
    tunnelUpStreamPayload(server, line, b);
    twfRequire(lineIsAlive(line) && callbacks == 0, "valid token could not authorize a fragmented ordinary message");
    authenticationserverSessionsDestroy(tunnelGetState(server));
    b = bufferpoolGetBestFit(env.pool, 16385, 64);
    sbufSetLength(b, 16385);
    memoryZero(sbufGetMutablePtr(b), 16385);
    tunnelUpStreamPayload(server, line, b);
    twfRequire(! lineIsAlive(line) && callbacks == 0,
               "large message executed after its token was replaced during reception");
    teardown();
}

static void testTinyRequestsAndBounds(void)
{
    for (unsigned bound = 0; bound < 3; ++bound)
    {
        authenticationserver_lstate_t *ls = setup();
        tunnelUpStreamPause(server, line);
        request(1);
        buffer_budget_cost_t cost = bufferbudgetGetUsage(&ls->response_budget);
        twfRequire(cost.entries == 1 && cost.charge < 8192, "tiny response retained a large allocation");
        if (bound == 0)
            ls->response_budget.limits.bytes = 2 * cost.bytes;
        if (bound == 1)
            ls->response_budget.limits.charge = 2 * cost.charge;
        if (bound == 2)
            ls->response_budget.limits.entries = 2;
        request(2);
        twfRequire(lineIsAlive(line), "equality at the response budget was refused");
        request(3);
        twfRequire(! lineIsAlive(line) && closes == 1 && callbacks == 0, "response refusal failed to close locally");
        teardown();
    }
    authenticationserver_lstate_t *ls = setup();
    tunnelUpStreamPause(server, line);
    for (unsigned i = 0; i < 1024; ++i)
        request(i + 1);
    twfRequire(bufferbudgetGetUsage(&ls->response_budget).entries == 1024, "documented entry bound was not reached");
    request(1025);
    twfRequire(! lineIsAlive(line) && closes == 1, "tiny unauthenticated requests bypassed entry bound");
    teardown();
}

static void testMaximumAndReentry(bool paused, bool finish)
{
    authenticationserver_lstate_t *ls = setup();
    const uint32_t length  = kAuthenticationServerMaxResponsePayload + kAuthenticationServerResponseEnvelopeHeaderSize;
    sbuf_t        *message = bufferpoolGetBestFit(env.pool, length, 64);
    sbufSetLength(message, length);
    uint8_t  header[29] = {0};
    uint32_t number     = htonl(length - 4);
    memoryCopy(header, &number, 4);
    header[20] = kAuthenticationServerResponseTypeError;
    number     = htonl(kAuthenticationServerMaxResponsePayload - kAuthenticationServerResponseHeaderSize);
    memoryCopy(header + 25, &number, 4);
    for (uint32_t i = 0; i < length; ++i)
        sbufGetMutablePtr(message)[i] = i < sizeof(header) ? header[i] : (uint8_t) ('a' + i % 26U);
    twfRequire(bufferqueueTryPushBack(&ls->response_queue, &message), "one maximum legal response was refused");
    if (paused)
        tunnelUpStreamPause(server, line);
    pause_once     = true;
    nested_request = ! finish;
    close_once     = finish;
    twfRequire(authenticationserverFlushResponses(server, line, ls) == ! finish || paused,
               "drain returned the wrong lifetime result");
    if (paused)
        tunnelUpStreamResume(server, line);
    if (! finish)
    {
        twfRequire(received_length > length, "nested response disappeared");
        for (uint32_t i = 0; i < length; ++i)
            twfRequire(received[i] == (i < sizeof(header) ? header[i] : (uint8_t) ('a' + i % 26U)),
                       "maximum response or FIFO order was corrupted");
        uint32_t id;
        memoryCopy(&id, received + length + 21, 4);
        twfRequire(ntohl(id) == 999 && maximum_depth == 1, "nested Resume competed with the active drain");
        bufferbudgetAssertEmpty(&ls->response_budget);
    }
    else
        twfRequire(! lineIsAlive(line) && closes == 1, "Finish during output left an orphan");
    teardown();
}

static cJSON *producerResponse(uint8_t operation, const void *data, uint32_t size, const char *error)
{
    memoryFree(received);
    received                          = NULL;
    received_length                   = 0;
    sbuf_t                        *b  = envelope(operation, data, size, 1);
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    if (ts->sessions_count != 0)
        memoryCopy(sbufGetMutablePtr(b) + 4, ts->sessions[0]->token, 64);
    tunnelUpStreamPayload(server, line, b);
    twfRequire(lineIsAlive(line) && received_length >= 29, "producer page did not respond");
    const uint32_t length = received_length - 29;
    if (error != NULL)
    {
        twfRequire(received[20] == kAuthenticationServerResponseTypeError && length == strlen(error) &&
                       memcmp(received + 29, error, length) == 0,
                   "wrong producer refusal");
        return NULL;
    }
    twfRequire(received[20] == kAuthenticationServerResponseTypeUsers ||
                   received[20] == kAuthenticationServerResponseTypeUser,
               "wrong producer response kind");
    cJSON *json = cJSON_ParseWithLength((const char *) received + 29, length);
    twfRequire(cJSON_IsObject(json), "page body was not JSON");
    return json;
}

static uint64_t pageValue(const cJSON *page, const char *name)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(page, name);
    uint64_t     number;
    twfRequire(cJSON_IsString(value) && getUint64FromJson(&number, value), "page metadata is not exact decimal string");
    return number;
}

static void pageRequest(char text[512], const char *cursor, size_t total, bool validate)
{
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    char                           epoch[65];
    memoryCopy(epoch, ts->auth_clients[0].accounting_epoch, 64);
    epoch[64] = 0;
    snprintf(
        text, 512, "{\"epoch\":\"%s\",\"sequence\":\"0\",\"digest\":\"%064u\"%s", epoch, 0, cursor == NULL ? "}" : ",");
    if (cursor != NULL)
        snprintf(text + strlen(text),
                 512 - strlen(text),
                 "\"cursor\":\"%s\",\"total\":\"%zu\"%s}",
                 cursor,
                 total,
                 validate ? ",\"validate\":true" : "");
}

static void producerSession(void)
{
    configureCredentials();
    static const char auth[] = "{\"name\":\"edge\",\"secret\":\"secret\"}";
    tunnelUpStreamPayload(
        server, line, envelope(kAuthenticationServerRequestTypeAuthenticate, auth, sizeof(auth) - 1, 1));
    twfRequire(((authenticationserver_tstate_t *) tunnelGetState(server))->sessions_count == 1, "producer auth failed");
}

static void testProducerParserBudgets(void)
{
    setup();
    producerSession();
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    ts->sessions[0]->allow_user_write = ts->sessions[0]->allow_stats_push = true;
    const uint8_t correlation[4]                                          = {0};
    const uint8_t operations[] = {kAuthenticationServerRequestTypePushUserStats,
                                  kAuthenticationServerRequestTypeUpdateUser,
                                  kAuthenticationServerRequestTypeAddNewUser};
    char         *wide         = memoryAllocate(80010);
    memoryCopy(wide, "{\"x\":[", 6);
    for (size_t i = 0; i < 40000; ++i)
    {
        wide[6 + 2 * i] = '0';
        wide[7 + 2 * i] = i == 39999 ? ']' : ',';
    }
    wide[80006] = '}';
    wide[80007] = 0;
    for (size_t i = 0; i < ARRAY_SIZE(operations); ++i)
    {
        parse_watch   = wide;
        parse_calls   = 0;
        sbuf_t *reply = authenticationserverDispatchRequest(
            operations[i], correlation, server, line, ts->sessions[0], (const uint8_t *) wide, 80007);
        parse_watch = NULL;
        twfRequire(reply != NULL && sbufReadUI8(reply) == kAuthenticationServerResponseTypeError && parse_calls == 0 &&
                       usersCount(&ts->store.users) == 0 && ts->auth_clients[0].last_sequence == 0,
                   "wide producer body allocated a tree or changed the store/checkpoint");
        lineReuseBuffer(line, reply);
        static const char shallow[] = "{\"x\":[]}";
        parse_watch                 = shallow;
        parse_calls                 = 0;
        reply                       = authenticationserverDispatchRequest(
            operations[i], correlation, server, line, ts->sessions[0], (const uint8_t *) shallow, sizeof(shallow) - 1U);
        parse_watch = NULL;
        twfRequire(reply != NULL && parse_calls == 1, "producer parser budget fixture bypassed parsing");
        lineReuseBuffer(line, reply);
    }
    memoryFree(wide);
    teardown();

    setup();
    ts               = tunnelGetState(server);
    write_lock_watch = &ts->state_lock;
    watched_writes   = 0;
    producerResponse(kAuthenticationServerRequestTypeUpdateUser, "{}", 2, "authentication-required");
    twfRequire(watched_writes == 0, "anonymous mutation request acquired exclusive state lock");
    producerSession();
    twfRequire(watched_writes == 1, "Authenticate did not acquire exclusive state lock");
    write_lock_watch = NULL;
    teardown();
}

static void testSnapshotBudgetAndLease(void)
{
    setup();
    producerSession();
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    char                           request[512], cursor[65];
    pageRequest(request, NULL, 0, false);
    ts->snapshot_max_bytes = 1;
    producerResponse(kAuthenticationServerRequestTypeGetUsersPage, request, strlen(request), "snapshot-resource-limit");
    twfRequire(ts->snapshot_bytes == 0 && ts->sessions[0]->snapshot == NULL, "snapshot refusal leaked storage");
    ts->snapshot_max_bytes = kAuthenticationServerDefaultSnapshotMaxBytes;
    cJSON *page = producerResponse(kAuthenticationServerRequestTypeGetUsersPage, request, strlen(request), NULL);
    strcpy(cursor, cJSON_GetObjectItemCaseSensitive(page, "cursor")->valuestring);
    cJSON_Delete(page);
    twfRequire(ts->snapshot_bytes != 0, "snapshot did not charge metadata");
    const size_t                   charged = ts->snapshot_bytes;
    authenticationserver_session_t sibling = {.accounting_client = ts->sessions[0]->accounting_client,
                                              .allow_user_pull   = true};
    memoryCopy(sibling.accounting_epoch, ts->sessions[0]->accounting_epoch, sizeof(sibling.accounting_epoch));
    const uint8_t correlation[4] = {0};
    sbuf_t       *shared         = authenticationserverDispatchRequest(kAuthenticationServerRequestTypeGetUsersPage,
                                                         correlation,
                                                         server,
                                                         line,
                                                         &sibling,
                                                         (const uint8_t *) request,
                                                         (uint32_t) strlen(request));
    twfRequire(shared != NULL && sbufReadUI8(shared) == kAuthenticationServerResponseTypeUsers &&
                   sibling.snapshot == ts->sessions[0]->snapshot && ts->snapshot_bytes == charged,
               "identical table capture did not share bounded storage");
    lineReuseBuffer(line, shared);
    authenticationserverSnapshotRelease(ts, &sibling);
    twfRequire(ts->snapshot_bytes == charged, "one snapshot reference freed another session's rows");
    authenticationserverSnapshotsExpire(
        ts, ts->sessions[0]->snapshot_last_page_ms + kAuthenticationServerDefaultSnapshotIdleTimeoutMs);
    twfRequire(ts->snapshot_bytes == 0 && ts->sessions[0]->snapshot == NULL, "expired snapshot retained storage");
    pageRequest(request, cursor, 0, true);
    producerResponse(kAuthenticationServerRequestTypeGetUsersPage, request, strlen(request), "stale_cursor");
    teardown();
}

static void testProducerPages(void)
{
    setup();
    producerSession();
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    for (uint64_t i = 0; i < 130; ++i)
    {
        char password[32];
        snprintf(password, sizeof(password), "page-%" PRIu64, i);
        user_t source;
        twfRequire(userCreate(&source, password), "page user failed");
        userSetId(&source, i + 1);
        twfRequire(usersAddUser(&ts->store.users, &source), "page insertion failed");
        userDestroy(&source);
    }
    char text[512], cursor[65], terminal[65];
    pageRequest(text, NULL, 0, false);
    cJSON *page = producerResponse(kAuthenticationServerRequestTypeGetUsersPage, text, strlen(text), NULL);
    twfRequire(pageValue(page, "position") == 0 && pageValue(page, "count") == 128 && pageValue(page, "total") == 130 &&
                   cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(page, "users")) == 128 &&
                   cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(page, "complete")),
               "first producer page boundary failed");
    strcpy(cursor, cJSON_GetObjectItemCaseSensitive(page, "cursor")->valuestring);
    cJSON_Delete(page);
    const uint64_t captured_stats = ts->store.stats_revision;
    authenticationserverBumpStatsRevision(server);
    const user_config_patch_t changed = {.mask = kUserConfigNotes, .notes = "changed during traversal"};
    twfRequire(usersPatchConfigByIdentifier(&ts->store.users, 129, &changed) == kUsersUpdateResultOk,
               "snapshot edit failed");
    authenticationserverBumpConfigRevision(server);
    pageRequest(text, cursor, 130, false);
    page = producerResponse(kAuthenticationServerRequestTypeGetUsersPage, text, strlen(text), NULL);
    twfRequire(pageValue(page, "position") == 128 && pageValue(page, "count") == 2 &&
                   cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(page, "complete")) &&
                   cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(page, "validated")),
               "terminal data page failed");
    twfRequire(pageValue(page, "stats-revision") == captured_stats &&
                   cJSON_GetObjectItemCaseSensitive(
                       cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(page, "users"), 0), "notes") == NULL,
               "concurrent edit changed captured page or accounting revision");
    strcpy(terminal, cJSON_GetObjectItemCaseSensitive(page, "cursor")->valuestring);
    cJSON_Delete(page);
    pageRequest(text, terminal, 130, true);
    page = producerResponse(kAuthenticationServerRequestTypeGetUsersPage, text, strlen(text), NULL);
    twfRequire(pageValue(page, "count") == 0 && pageValue(page, "position") == 130 &&
                   cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(page, "validated")),
               "final page validation failed");
    cJSON_Delete(page);
    twfRequire(ts->snapshot_bytes == 0, "terminal validation retained its snapshot");
    pageRequest(text, cursor, 131, false);
    producerResponse(kAuthenticationServerRequestTypeGetUsersPage, text, strlen(text), "stale_cursor");
    authenticationserverBumpConfigRevision(server);
    pageRequest(text, terminal, 130, true);
    producerResponse(kAuthenticationServerRequestTypeGetUsersPage, text, strlen(text), "stale_cursor");
    pageRequest(text, NULL, 0, false);
    char *digest = strstr(text, "digest\":\"");
    twfRequire(digest != NULL, "checkpoint fixture failed");
    digest[9] = '1';
    producerResponse(kAuthenticationServerRequestTypeGetUsersPage, text, strlen(text), "accounting-continuity-lost");
    teardown();

    setup();
    producerSession();
    ts = tunnelGetState(server);
    pageRequest(text, NULL, 0, false);
    page = producerResponse(kAuthenticationServerRequestTypeGetUsersPage, text, strlen(text), NULL);
    twfRequire(pageValue(page, "total") == 0 && pageValue(page, "count") == 0 &&
                   cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(page, "complete")),
               "empty table did not complete");
    cJSON_Delete(page);
    user_t source;
    twfRequire(userCreate(&source, "exceptional"), "exceptional row creation failed");
    userSetId(&source, 1);
    source.notes = memoryAllocate(300001);
    memset(source.notes, 'x', 300000);
    source.notes[300000]        = 0;
    source.export_strings.notes = userMeasureExportString(source.notes);
    twfRequire(usersAddUser(&ts->store.users, &source), "exceptional row insert failed");
    userDestroy(&source);
    page = producerResponse(kAuthenticationServerRequestTypeGetUsersPage, text, strlen(text), NULL);
    twfRequire(pageValue(page, "count") == 1 && received_length > 256 * 1024,
               "large first row was not exceptional page");
    cJSON_Delete(page);
    user_t *huge = usersLookupByIdentifier(&ts->store.users, 1);
    memoryFree(huge->notes);
    huge->notes = memoryAllocate(17 * 1024 * 1024 + 1);
    memset(huge->notes, 'x', 17 * 1024 * 1024);
    huge->notes[17 * 1024 * 1024] = 0;
    huge->export_strings.notes    = userMeasureExportString(huge->notes);
    producerResponse(kAuthenticationServerRequestTypeGetUsersPage, text, strlen(text), "user-too-large");
    teardown();
}

static void testCanonicalProducerLookups(void)
{
    setup();
    producerSession();
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    user_t                         source;
    twfRequire(userCreate(&source, "lookup"), "lookup user failed");
    userSetId(&source, 1);
    twfRequire(usersAddUser(&ts->store.users, &source), "lookup insertion failed");
    userDestroy(&source);
    sha224_hash_t a;
    sha256_hash_t b;
    twfRequire(wCryptoSHA224(&a, (const uint8_t *) "lookup", 6) == kWCryptoOk &&
                   wCryptoSHA256(&b, (const uint8_t *) "lookup", 6) == kWCryptoOk,
               "lookup digest failed");
    const uint8_t     kinds[]        = {kAuthenticationServerRequestTypeGetUserBySHA224,
                                        kAuthenticationServerRequestTypeGetUserBySHA256};
    const uint8_t     hex_kinds[]    = {kAuthenticationServerRequestTypeGetUserBySHA224Hex,
                                        kAuthenticationServerRequestTypeGetUserBySHA256Hex};
    const uint8_t     base64_kinds[] = {kAuthenticationServerRequestTypeGetUserBySHA224Base64,
                                        kAuthenticationServerRequestTypeGetUserBySHA256Base64};
    static const char hex[]          = "0123456789abcdef",
                      alphabet[]     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (unsigned i = 0; i < 2; ++i)
    {
        const uint8_t *digest = i == 0 ? a.bytes : b.bytes;
        const size_t   size   = i == 0 ? sizeof(a.bytes) : sizeof(b.bytes);
        cJSON_Delete(producerResponse(kinds[i], digest, size, NULL));
        char text[65];
        for (size_t j = 0; j < size; ++j)
        {
            text[2 * j]     = hex[digest[j] >> 4];
            text[2 * j + 1] = hex[digest[j] & 15];
        }
        cJSON_Delete(producerResponse(hex_kinds[i], text, 2 * size, NULL));
        const int length = wwBase64Encode(digest, size, text);
        cJSON_Delete(producerResponse(base64_kinds[i], text, length, NULL));
        const char  *error = i == 0 ? "invalid-sha224-base64" : "invalid-sha256-base64";
        const size_t last  = i == 0 ? 37 : 42;
        const char  *entry = strchr(alphabet, text[last]);
        twfRequire(entry != NULL, "base64 fixture failed");
        text[last] = alphabet[(entry - alphabet) + 1];
        producerResponse(base64_kinds[i], text, length, error);
        wwBase64Encode(digest, size, text);
        producerResponse(base64_kinds[i], text, length - 1, error);
        text[0] = '-';
        producerResponse(base64_kinds[i], text, length, error);
    }
    cJSON_Delete(producerResponse(kAuthenticationServerRequestTypeGetUserByPassword, "lookup", 6, NULL));
    producerResponse(kAuthenticationServerRequestTypeGetUserByPassword, "missing", 7, "user-not-found");
    a.bytes[0] ^= 0x80U;
    b.bytes[0] ^= 0x80U;
    producerResponse(kAuthenticationServerRequestTypeGetUserBySHA224, a.bytes, sizeof(a.bytes), "user-not-found");
    producerResponse(kAuthenticationServerRequestTypeGetUserBySHA256, b.bytes, sizeof(b.bytes), "user-not-found");
    const char nul[] = "look\0up";
    producerResponse(kAuthenticationServerRequestTypeGetUserByPassword, nul, sizeof(nul) - 1, "invalid-password");
    ts->sessions[0]->allow_user_pull = false;
    for (unsigned i = 0; i < 2; ++i)
    {
        producerResponse(kinds[i], "", 0, "user-pull-not-allowed");
        producerResponse(hex_kinds[i], "", 0, "user-pull-not-allowed");
        producerResponse(base64_kinds[i], "", 0, "user-pull-not-allowed");
    }
    producerResponse(kAuthenticationServerRequestTypeGetUserByPassword, "", 0, "user-pull-not-allowed");
    teardown();
}

static void testLongPasswordsAndAdmission(void)
{
    setup();
    producerSession();
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    for (size_t n = 1024; n <= 8192; n = n == 1024 ? 1025 : n == 1025 ? 8192 : 8193)
    {
        char *password = memoryAllocate(n + 1);
        memset(password, 'p', n);
        memcpy(password, " \342\202\254", 4);
        password[n - 1] = ' ';
        password[n]     = 0;
        user_t source;
        twfRequire(userCreate(&source, password), "long credential creation");
        userSetId(&source, n);
        twfRequire(usersAddUser(&ts->store.users, &source), "long credential insertion");
        userDestroy(&source);
        cJSON *row = producerResponse(kAuthenticationServerRequestTypeGetUserByPassword, password, n, NULL);
        twfRequire(strcmp(cJSON_GetObjectItemCaseSensitive(row, "password")->valuestring, password) == 0,
                   "long password bytes changed");
        cJSON_Delete(row);
        memorySecureZero(password, n);
        memoryFree(password);
    }
    producerResponse(kAuthenticationServerRequestTypeGetUserByPassword, "", 0, "invalid-password");
    user_t *stored = usersLookupByIdentifier(&ts->store.users, 1024);
    size_t  required;
    twfRequire(userMeasureExportUpperBound(stored, &required) == kUserPublicOk, "producer export measurement");
    const size_t saved                = ts->max_user_export_bytes;
    ts->max_user_export_bytes         = required;
    ts->sessions[0]->allow_user_write = true;
    const uint64_t revision           = ts->store.config_revision;
    const char     update[]           = "{\"id\":\"1024\",\"notes\":\"x\"}";
    producerResponse(kAuthenticationServerRequestTypeUpdateUser, update, sizeof(update) - 1, "user-too-large");
    twfRequire(ts->store.config_revision == revision && ! ts->database_dirty &&
                   (stored->notes == NULL || stored->notes[0] == 0),
               "producer policy refusal changed state");
    const char add[]          = "{\"id\":\"909\",\"password\":\"oversize-add\"}";
    ts->max_user_export_bytes = 0;
    producerResponse(kAuthenticationServerRequestTypeAddNewUser, add, sizeof(add) - 1, "user-too-large");
    ts->max_user_export_bytes = saved;
    teardown();
}

static void testMaximumSynchronizableRecord(void)
{
    setup();
    producerSession();
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    user_t                         source;
    twfRequire(userCreate(&source, "maximum-sync"), "maximum sync candidate");
    userSetId(&source, 1);
    size_t fixed;
    twfRequire(userMeasureExportUpperBound(&source, &fixed) == kUserPublicOk && fixed < ts->max_user_export_bytes,
               "maximum sync geometry");
    const size_t length = ts->max_user_export_bytes - fixed;
    memoryFree(source.notes);
    source.notes = memoryAllocate(length + 2);
    memset(source.notes, 'x', length + 1);
    source.notes[length]        = 0;
    source.export_strings.notes = userMeasureExportString(source.notes);
    size_t measured;
    twfRequire(userMeasureExportUpperBound(&source, &measured) == kUserPublicOk &&
                   measured == ts->max_user_export_bytes && usersAddUser(&ts->store.users, &source),
               "admission boundary row did not fit");
    user_t *stored = usersLookupByIdentifier(&ts->store.users, 1);
    userMergeFirstUsage(stored, UINT64_MAX);
    userAddTraffic(stored, UINT64_MAX, UINT64_MAX);
    char request_text[512];
    pageRequest(request_text, NULL, 0, false);
    cJSON *page =
        producerResponse(kAuthenticationServerRequestTypeGetUsersPage, request_text, strlen(request_text), NULL);
    twfRequire(pageValue(page, "count") == 1 && received_length <= kAuthenticationServerMaxResponsePayload +
                                                                       kAuthenticationServerResponseEnvelopeHeaderSize,
               "maximum-growth admitted row failed synchronization");
    cJSON_Delete(page);
    /* A valid producer request still fits its wire cap while the conservative
     * complete-page allowance rejects this one-byte-larger candidate. */
    source.notes[length]        = 'x';
    source.notes[length + 1]    = 0;
    source.export_strings.notes = userMeasureExportString(source.notes);
    userSetId(&source, 2);
    cJSON *json = userToJson(&source);
    char  *text = cJSON_PrintUnformatted(json);
    twfRequire(strlen(text) < kAuthenticationServerMaxRequestData, "oversized row fixture exceeded request cap");
    ts->sessions[0]->allow_user_write = true;
    producerResponse(kAuthenticationServerRequestTypeAddNewUser, text, strlen(text), "user-too-large");
    twfRequire(usersCount(&ts->store.users) == 1 && ! ts->database_dirty, "policy rejection published account");
    memorySecureZero(text, strlen(text));
    cJSON_free(text);
    authenticationserverWipeJsonStrings(json);
    cJSON_Delete(json);
    userDestroy(&source);
    teardown();
}

static void testBoundedProducerLookups(void)
{
    setup();
    producerSession();
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    user_t                         source;
    twfRequire(userCreate(&source, "bounded-lookup"), "bounded lookup user failed");
    userSetId(&source, 1);
    memoryFree(source.notes);
    source.notes                = stringDuplicate("x");
    source.export_strings.notes = userMeasureExportString(source.notes);
    twfRequire(usersAddUser(&ts->store.users, &source), "bounded lookup insertion failed");
    userDestroy(&source);
    user_t      *stored       = usersLookupByIdentifier(&ts->store.users, 1);
    cJSON       *json         = userToJson(stored);
    char        *text         = cJSON_PrintUnformatted(json);
    const size_t maximum      = kAuthenticationServerMaxResponsePayload - kAuthenticationServerResponseHeaderSize;
    const size_t notes_length = maximum - strlen(text) + 1U;
    cJSON_free(text);
    cJSON_Delete(json);
    memoryFree(stored->notes);
    stored->notes = memoryAllocate(notes_length + 2U);
    memset(stored->notes, 'x', notes_length + 1U);
    stored->notes[notes_length]  = '\0';
    stored->export_strings.notes = userMeasureExportString(stored->notes);
    lookup_text_watch            = stored->notes;
    lookup_text_copies           = 0;
    json = producerResponse(kAuthenticationServerRequestTypeGetUserByPassword, "bounded-lookup", 14, NULL);
    twfRequire(received_length == maximum + kAuthenticationServerResponseEnvelopeHeaderSize +
                                      kAuthenticationServerResponseHeaderSize &&
                   lookup_text_copies == 1 &&
                   strlen(cJSON_GetObjectItemCaseSensitive(json, "notes")->valuestring) == notes_length,
               "exact-fit point record was refused, changed or copied before admission");
    cJSON_Delete(json);

    stored->notes[notes_length]     = 'x';
    stored->notes[notes_length + 1] = '\0';
    stored->export_strings.notes    = userMeasureExportString(stored->notes);
    lookup_text_copies              = 0;
    producerResponse(kAuthenticationServerRequestTypeGetUserByPassword, "bounded-lookup", 14, "response-too-large");
    producerResponse(kAuthenticationServerRequestTypeGetUserBySHA224,
                     stored->sha224_pass.bytes,
                     sizeof(stored->sha224_pass.bytes),
                     "response-too-large");
    producerResponse(kAuthenticationServerRequestTypeGetUserBySHA256,
                     stored->sha256_pass.bytes,
                     sizeof(stored->sha256_pass.bytes),
                     "response-too-large");
    twfRequire(lookup_text_copies == 0, "oversized point record copied arbitrary text before refusing");
    lookup_text_watch = NULL;
    teardown();
}

static void testCombinedResponseOverflow(void)
{
    setup();
    producerSession();
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    ts->sessions[0]->allow_user_write = true;
    user_t source;
    twfRequire(userCreate(&source, "aggregate-overflow"), "aggregate user failed");
    userSetId(&source, 1);
    source.notes = memoryAllocate(9U * 1024U * 1024U + 1U);
    memset(source.notes, 'x', 9U * 1024U * 1024U);
    source.notes[9U * 1024U * 1024U] = 0;
    source.export_strings.notes      = userMeasureExportString(source.notes);
    twfRequire(usersAddUser(&ts->store.users, &source), "aggregate insertion failed");
    userDestroy(&source);
    const uint8_t operations[] = {kAuthenticationServerRequestTypeUpdateUser,
                                  kAuthenticationServerRequestTypeGetUserByPassword,
                                  kAuthenticationServerRequestTypeGetUserByPassword};
    const char   *data[]       = {"{\"id\":1,\"enabled\":false}", "aggregate-overflow", "aggregate-overflow"};
    size_t        size         = kAuthenticationServerRequestEnvelopeHeaderSize;
    for (size_t i = 0; i < ARRAY_SIZE(data); ++i)
        size += kAuthenticationServerRequestHeaderSize + strlen(data[i]);
    sbuf_t *input = bufferpoolGetBestFit(env.pool, (uint32_t) size, 64);
    sbufSetLength(input, (uint32_t) size);
    uint8_t *bytes  = sbufGetMutablePtr(input);
    uint32_t number = htonl((uint32_t) size - 4U);
    memoryCopy(bytes, &number, 4);
    memoryCopy(bytes + 4, ts->sessions[0]->token, 64);
    size_t offset = kAuthenticationServerRequestEnvelopeHeaderSize;
    for (size_t i = 0; i < ARRAY_SIZE(data); ++i)
    {
        bytes[offset] = operations[i];
        number        = htonl((uint32_t) i + 1U);
        memoryCopy(bytes + offset + 1, &number, 4);
        number = htonl((uint32_t) strlen(data[i]));
        memoryCopy(bytes + offset + 5, &number, 4);
        memoryCopy(bytes + offset + 9, data[i], strlen(data[i]));
        offset += 9U + strlen(data[i]);
    }
    memoryFree(received);
    received        = NULL;
    received_length = 0;
    tunnelUpStreamPayload(server, line, input);
    twfRequire(lineIsAlive(line) && ! usersLookupByIdentifier(&ts->store.users, 1)->enabled,
               "aggregate response failure lost committed mutation or closed line");
    offset = kAuthenticationServerResponseEnvelopeHeaderSize;
    for (size_t i = 0; i < 3; ++i)
    {
        twfRequire(received_length - offset >= 9U, "aggregate response lost a correlation");
        uint32_t id, length;
        memoryCopy(&id, received + offset + 1, 4);
        memoryCopy(&length, received + offset + 5, 4);
        length                 = ntohl(length);
        const uint8_t expected = i == 0   ? kAuthenticationServerResponseTypeOk
                                 : i == 1 ? kAuthenticationServerResponseTypeUser
                                          : kAuthenticationServerResponseTypeError;
        twfRequire(ntohl(id) == i + 1U && received[offset] == expected && length <= received_length - offset - 9U,
                   "aggregate response changed outcome or correlation");
        if (i == 2)
            twfRequire(length == strlen("response-too-large") &&
                           memcmp(received + offset + 9, "response-too-large", length) == 0,
                       "aggregate overflow was not a correlated refusal");
        offset += 9U + length;
    }
    twfRequire(offset == received_length, "aggregate response has unexpected trailing bytes");
    teardown();
}

static void testProducerDirtyBoundaries(void)
{
    setup();
    producerSession();
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    twfRequire(! ts->database_dirty, "session enrollment dirtied the database");
    user_t source;
    twfRequire(userCreate(&source, "dirty-boundary"), "dirty-boundary user failed");
    userSetId(&source, 1);
    twfRequire(usersAddUser(&ts->store.users, &source), "dirty-boundary insertion failed");
    userDestroy(&source);
    authenticationserver_session_t *session = ts->sessions[0];
    session->allow_user_write = session->allow_stats_push = true;
    const uint8_t     correlation[4]                      = {0};
    static const char update[]                            = "{\"id\":\"1\",\"name\":\"changed\"}";
    rwlockWriteLock(&ts->state_lock);
    sbuf_t *reply = authenticationserverDispatchRequest(kAuthenticationServerRequestTypeUpdateUser,
                                                        correlation,
                                                        server,
                                                        line,
                                                        session,
                                                        (const uint8_t *) update,
                                                        sizeof(update) - 1);
    twfRequire(reply != NULL && sbufReadUI8(reply) == kAuthenticationServerResponseTypeOk && ts->database_dirty,
               "producer update did not dirty the database");
    lineReuseBuffer(line, reply);
    ts->database_dirty = false;
    char epoch[65]     = {0}, batch[512];
    memoryCopy(epoch, ts->auth_clients[0].accounting_epoch, 64);
    const int size = snprintf(batch,
                              sizeof(batch),
                              "{\"epoch\":\"%s\",\"sequence\":\"1\",\"users\":[{\"id\":\"1\",\"up\":\"0\","
                              "\"down\":\"0\",\"first-usage-at-ms\":\"1\"}]}",
                              epoch);
    twfRequire(size > 0 && (size_t) size < sizeof(batch), "usage dirty fixture overflow");
    for (unsigned replay = 0; replay < 2; ++replay)
    {
        reply = authenticationserverDispatchRequest(kAuthenticationServerRequestTypePushUserStats,
                                                    correlation,
                                                    server,
                                                    line,
                                                    session,
                                                    (const uint8_t *) batch,
                                                    (uint32_t) size);
        twfRequire(reply != NULL && sbufReadUI8(reply) == kAuthenticationServerResponseTypeOk &&
                       ts->database_dirty == (replay == 0),
                   "new usage or exact replay changed dirty state incorrectly");
        lineReuseBuffer(line, reply);
        ts->database_dirty = false;
    }
    rwlockWriteUnlock(&ts->state_lock);
    teardown();
}

static void testOwnedProducerSecretWiping(void)
{
    for (unsigned rejected = 0; rejected < 2; ++rejected)
    {
        setup();
        configureCredentials();
        authenticationserver_tstate_t *ts = tunnelGetState(server);
        secret_watch                      = ts->auth_clients[0].secret;
        secret_watch_length               = strlen(secret_watch);
        const unsigned old_secret = secret_wiped, old_decoded = decoded_wiped;
        const char    *auth =
            rejected ? "{\"name\":\"edge\",\"secret\":\"wrong\"}" : "{\"name\":\"edge\",\"secret\":\"secret\"}";
        inspect_auth_secret = true;
        tunnelUpStreamPayload(
            server, line, envelope(kAuthenticationServerRequestTypeAuthenticate, auth, strlen(auth), 1));
        inspect_auth_secret = false;
        twfRequire(decoded_watch == NULL && decoded_wiped == old_decoded + 1,
                   "decoded auth secret did not reach wiped release");
        teardown();
        twfRequire(secret_watch == NULL && secret_wiped == old_secret + 1, "producer secret was not wiped on destroy");
    }
}

static void testOwnedLookupSecretWiping(void)
{
    setup();
    for (unsigned refused = 0; refused < 2; ++refused)
    {
        cJSON         *user = cJSON_CreateObject();
        discard        cJSON_AddStringToObject(user, "password", "owned-lookup-secret");
        const unsigned old_decoded = decoded_wiped, old_serialized = serialized_wiped;
        inspect_user_json            = true;
        refuse_serialization         = refused != 0;
        const uint8_t correlation[4] = {0};
        sbuf_t *response  = authenticationserverCreateUserJsonResponseFrame(line, correlation, user, "lookup-test");
        inspect_user_json = refuse_serialization = false;
        twfRequire(response != NULL && decoded_watch == NULL && serialized_watch == NULL &&
                       decoded_wiped == old_decoded + 1 && serialized_wiped > old_serialized,
                   "owned lookup credential or serialized attempt was released unwiped");
        twfRequire(sbufReadUI8(response) ==
                       (refused ? kAuthenticationServerResponseTypeError : kAuthenticationServerResponseTypeUser),
                   "lookup serialization refusal fixture did not run");
        lineReuseBuffer(line, response);
    }
    teardown();
}

int main(void)
{
    twfSetCase("authenticationserver response bounds and FIFO");
    twfRequire(createNetworkLogger(NULL, false) != NULL, "logger initialization failed");
    twfRequire(userTestRuntimeInitialize(), "crypto initialization failed");
    testTinyRequestsAndBounds();
    testMaximumAndReentry(false, false);
    testMaximumAndReentry(true, false);
    testMaximumAndReentry(false, true);
    testPreauthBounds();
    testFrameCount();
    testAuthenticateValidation();
    testGeometricConstruction();
    testSessionAtEnvelopeEntry();
    testProducerParserBudgets();
    testSnapshotBudgetAndLease();
    testProducerPages();
    testCanonicalProducerLookups();
    testLongPasswordsAndAdmission();
    testMaximumSynchronizableRecord();
    testBoundedProducerLookups();
    testCombinedResponseOverflow();
    testProducerDirtyBoundaries();
    testOwnedProducerSecretWiping();
    testOwnedLookupSecretWiping();
    userTestRuntimeCleanup();
    networkloggerDestroy();
    return 0;
}
