/* CTest: waterwall.authenticationserver_responses_unit
 * Real request parsing and response FIFO; bounded charge, reentry and terminal ownership. */
#include "AuthenticationServer/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "loggers/network_logger.h"

static twf_worker_env_t env;
static twf_line_pool_t  lines;
static tunnel_t        *server, *owner;
static line_t          *line;
static unsigned         closes, callbacks, depth, maximum_depth;
static bool             pause_once, close_once, nested_request;
static uint8_t         *received;
static size_t           received_length;

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
    rwlockDestroy(&ts->state_lock);
    tunnelDestroy(owner);
    tunnelDestroy(server);
    memoryFree(received);
    twfWorkerEnvTeardown(&env);
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
    for (uint32_t i = 0; i < length; ++i)
        sbufGetMutablePtr(message)[i] = (uint8_t) (i % 251U);
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
            twfRequire(received[i] == (uint8_t) (i % 251U), "maximum response or FIFO order was corrupted");
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
    testTinyRequestsAndBounds();
    testMaximumAndReentry(false, false);
    testMaximumAndReentry(true, false);
    testMaximumAndReentry(false, true);
    networkloggerDestroy();
    return 0;
}
