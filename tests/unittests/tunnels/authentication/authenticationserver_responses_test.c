/* CTest: waterwall.authenticationserver_responses_unit
 * Real request parsing and response FIFO; bounded charge, reentry and terminal ownership. */
#include "../../../../tunnels/Internals/AuthenticationCommon/stream.h"
#include "AuthenticationServer/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "loggers/network_logger.h"

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
                twfRequire(lineIsAlive(line) && authenticationStreamCharge(&ls->read_stream) <= 128U * 1024U,
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
        twfRequire(lineIsAlive(line) && authenticationStreamCharge(&ls->read_stream) <= 128U * 1024U &&
                       bs_doublequeue_t_size(&ls->read_stream.q) <= 64,
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

int main(void)
{
    twfSetCase("authenticationserver response bounds and FIFO");
    twfRequire(createNetworkLogger(NULL, false) != NULL, "logger initialization failed");
    twfRequire(globalstateInitializeSecureRandom() && wCryptoGlobalInit() == kWCryptoOk,
               "crypto initialization failed");
    testTinyRequestsAndBounds();
    testMaximumAndReentry(false, false);
    testMaximumAndReentry(true, false);
    testMaximumAndReentry(false, true);
    testPreauthBounds();
    testFrameCount();
    testAuthenticateValidation();
    testGeometricConstruction();
    testSessionAtEnvelopeEntry();
    wCryptoGlobalCleanup();
    globalstateDestroySecureRandom();
    networkloggerDestroy();
    return 0;
}
