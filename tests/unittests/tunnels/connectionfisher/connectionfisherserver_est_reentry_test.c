/*
 * Covers: connectionfisherserver est reentry; the explicit inputs, callbacks and expected results below
 * define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: payload
 * Checks: Assertion labels include: exact temporary input bound rejected; active Init body was omitted from
 * the pending bound; probe reply changed; server state survived close
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.connectionfisherserver_est_reentry_unit
 */
#include "ConnectionFisherServer/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

typedef struct fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    twf_trace_t      trace;
    tunnel_t        *server, *prev, *next;
    line_t          *line;
    unsigned         inits, ests, replies, bodies, finishes, pauses[2], resumes[2];
    bool             close_on_est, nested_reply, nested_est, close_on_init;
    bool             overflow_at_est, resume_on_init, nested_pause, finish_on_pause;
    char             body[32];
    size_t           body_len;
} fixture_t;
static fixture_t f;

static sbuf_t *payload(const char *text)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(f.env.pool);
    sbufWrite(buf, text, (uint32_t) strlen(text));
    sbufSetLength(buf, (uint32_t) strlen(text));
    return buf;
}
static void ownerFinish(tunnel_t *t, line_t *l)
{
    discard t;
    ++f.finishes;
    lineDestroy(l);
}
static void onEst(tunnel_t *t, line_t *l)
{
    discard t;
    ++f.ests;
    if (f.overflow_at_est)
    {
        sbuf_t *buf = bufferpoolGetBestFit(f.env.pool, kConnectionFisherServerMaxPendingBytes - 1, 0);
        sbufSetLength(buf, kConnectionFisherServerMaxPendingBytes - 1);
        memoryZero(sbufGetMutablePtr(buf), kConnectionFisherServerMaxPendingBytes - 1);
        tunnelUpStreamPayload(f.server, l, buf);
        twfRequire(lineIsAlive(l), "exact temporary input bound rejected");
        tunnelUpStreamPayload(f.server, l, payload("X"));
        twfRequire(! lineIsAlive(l), "active Init body was omitted from the pending bound");
        return;
    }
    if (f.close_on_est)
    {
        tunnelUpStreamFin(f.server, l);
        lineDestroy(l);
        return;
    }
    if (f.nested_est)
        tunnelUpStreamPayload(f.server, l, payload("C"));
}
static void onReply(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    twfRequire(sbufGetLength(buf) == 5 && memcmp(sbufGetRawPtr(buf), "FISH!", 5) == 0, "probe reply changed");
    ++f.replies;
    lineReuseBuffer(l, buf);
    if (f.nested_reply)
        tunnelUpStreamPayload(f.server, l, payload("B"));
}
static void onInit(tunnel_t *t, line_t *l)
{
    discard t;
    ++f.inits;
    twfRequire(tunnelIsActiveForLine(f.server, l), "server bypassed before Init completed");
    if (f.resume_on_init)
        tunnelUpStreamResume(f.server, l);
    if (f.close_on_init)
    {
        tunnelDownStreamFin(f.server, l);
        return;
    }
    tunnelDownStreamEst(f.server, l);
    if (lineIsAlive(l))
        tunnelDownStreamEst(f.server, l);
}
static void onBody(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    size_t  n = sbufGetLength(buf);
    twfRequire(f.body_len + n < sizeof(f.body), "body fixture overflow");
    memoryCopy(f.body + f.body_len, sbufGetRawPtr(buf), n);
    f.body_len += n;
    ++f.bodies;
    lineReuseBuffer(l, buf);
}
static void onPause(tunnel_t *t, line_t *l)
{
    ++f.pauses[t == f.prev];
    if (t != f.next)
        return;
    twfRequire(f.inits == 1, "Pause reached an uninitialized next side");
    if (f.finish_on_pause)
    {
        tunnelUpStreamFin(f.server, l);
        return;
    }
    if (f.nested_pause)
    {
        f.nested_pause = false;
        tunnelUpStreamPayload(f.server, l, payload("P"));
    }
}
static void onResume(tunnel_t *t, line_t *l)
{
    discard l;
    ++f.resumes[t == f.prev];
    if (t == f.next)
        twfRequire(f.inits == 1, "Resume reached an uninitialized next side");
}
static void setup(void)
{
    memoryZero(&f, sizeof(f));
    twfWorkerEnvSetup(&f.env, 8192, 0);
    f.server = connectionfisherserverTunnelCreate(NULL);
    f.prev   = twfCreatePrevTunnel(&f.trace);
    f.next   = twfCreateNextTunnel(&f.trace);
    tunnelBind(f.prev, f.server);
    tunnelBind(f.server, f.next);
    f.prev->chain_index   = 0;
    f.server->chain_index = 1;
    f.next->chain_index   = 2;
    f.prev->fnEstD        = onEst;
    f.prev->fnPayloadD    = onReply;
    f.prev->fnFinD        = ownerFinish;
    f.next->fnInitU       = onInit;
    f.next->fnPayloadU    = onBody;
    f.prev->fnPauseD = f.next->fnPauseU = onPause;
    f.prev->fnResumeD = f.next->fnResumeU = onResume;
    twfLinePoolSetup(&f.lines, f.server->lstate_size, 8);
    f.line = twfLinePoolCreateLine(&f.lines);
    lineRef(f.line);
    tunnelUpStreamInit(f.server, f.line);
}
static void teardown(void)
{
    if (lineIsAlive(f.line))
    {
        tunnelUpStreamFin(f.server, f.line);
        lineDestroy(f.line);
    }
    twfRequireLineStateZeroed(f.line, f.server, "server state survived close");
    twfRequire(twfLineRefCount(f.line) == 1, "server line reference leaked");
    lineUnref(f.line);
    twfLinePoolTeardown(&f.lines);
    tunnelDestroy(f.next);
    tunnelDestroy(f.server);
    tunnelDestroy(f.prev);
    twfWorkerEnvTeardown(&f.env);
}
int main(void)
{
    twfSetCase("Fisher server publishes continuing state and oldest body before reply/Init Est reentry");
    for (unsigned coalesced = 0; coalesced < 2; ++coalesced)
    {
        setup();
        f.nested_reply = coalesced != 0;
        f.nested_est   = true;
        tunnelUpStreamPayload(f.server, f.line, payload(coalesced ? "FISH?A" : "FISH?"));
        if (! coalesced)
            tunnelUpStreamPayload(f.server, f.line, payload("A"));
        twfRequire(f.inits == 1 && f.ests == 2 && f.replies == 1, "repeated Init Est did not forward");
        twfRequire(strcmp(f.body, coalesced ? "ABCC" : "ACC") == 0, "nested application input overtook older body");
        twfRequire(! tunnelIsActiveForLine(f.server, f.line), "completed server remained active");
        twfRequireLineStateZeroed(f.line, f.server, "bypassed server retained state");
        tunnelDownStreamEst(f.server, f.line);
        twfRequire(f.ests == 3, "bypassed server suppressed later Est");
        teardown();
    }
    twfSetCase("Fisher server Init/Est close releases retained body and stops callbacks");
    for (unsigned mode = 0; mode < 2; ++mode)
    {
        setup();
        f.close_on_est  = mode == 0;
        f.close_on_init = mode != 0;
        tunnelUpStreamPayload(f.server, f.line, payload("FISH?A"));
        twfRequire(! lineIsAlive(f.line) && f.bodies == 0, "Init/Est close submitted the retained body");
        teardown();
    }
    twfSetCase("Fisher server temporary FIFO charges the active Init body");
    setup();
    f.overflow_at_est = true;
    tunnelUpStreamPayload(f.server, f.line, payload("FISH?A"));
    twfRequire(! lineIsAlive(f.line) && f.bodies == 0 && f.finishes == 1,
               "temporary FIFO overflow did not settle line");
    teardown();
    twfSetCase("Fisher server reconciles pre-Init Pause, drains through pressure and bypasses");
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        setup();
        tunnelUpStreamPause(f.server, f.line);
        tunnelUpStreamPause(f.server, f.line);
        twfRequire(f.pauses[0] == 0, "pre-Init Pause escaped");
        f.nested_pause = mode == 0;
        if (mode == 1)
            tunnelUpStreamResume(f.server, f.line);
        f.resume_on_init = mode == 2;
        tunnelUpStreamPayload(f.server, f.line, payload("FISH?A"));
        twfRequire(f.pauses[0] == (mode == 0) && f.resumes[0] == (mode == 2),
                   "startup Pause replay ignored latest notification");
        twfRequire(strcmp(f.body, mode == 0 ? "AP" : "A") == 0,
                   "Pause callback overtook original input or stopped ready replay");
        twfRequire(! tunnelIsActiveForLine(f.server, f.line), "Pause prevented server bypass");
        const unsigned prior_pauses = f.pauses[0], prior_resumes = f.resumes[0];
        for (unsigned repeat = 0; repeat < 2; ++repeat)
        {
            tunnelUpStreamPause(f.server, f.line);
            tunnelUpStreamResume(f.server, f.line);
            tunnelDownStreamPause(f.server, f.line);
            tunnelDownStreamResume(f.server, f.line);
        }
        twfRequire(f.pauses[0] == prior_pauses + 2 && f.resumes[0] == prior_resumes + 2 && f.pauses[1] == 2 &&
                       f.resumes[1] == 2,
                   "bypass lost repeated pressure notifications");
        teardown();
    }
    twfSetCase("Fisher server releases retained first body when Pause replay finishes borrowed state");
    setup();
    f.finish_on_pause = true;
    tunnelUpStreamPause(f.server, f.line);
    tunnelUpStreamPayload(f.server, f.line, payload("FISH?A"));
    twfRequire(lineIsAlive(f.line) && f.bodies == 0 && tunnelIsActiveForLine(f.server, f.line),
               "borrowed Finish during Pause submitted body or bypassed closed state");
    twfRequireLineStateZeroed(f.line, f.server, "borrowed Finish retained server state");
    lineDestroy(f.line);
    teardown();
    puts("connectionfisherserver_est_reentry_test: all cases passed");
    return 0;
}
