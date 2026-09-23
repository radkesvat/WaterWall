#include "ConnectionFisherServer/structure.h"
#include "tunnel_line_failure_harness.h"

typedef struct fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    twf_trace_t      trace;
    tunnel_t        *server, *prev, *next;
    line_t          *line;
    unsigned         inits, ests, replies, bodies, finishes;
    bool             close_on_est, nested_reply, nested_est, close_on_init;
    bool             overflow_at_est;
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
        connectionfisherserverTunnelUpStreamPayload(f.server, l, buf);
        twfRequire(lineIsAlive(l), "exact temporary input bound rejected");
        connectionfisherserverTunnelUpStreamPayload(f.server, l, payload("X"));
        twfRequire(! lineIsAlive(l), "active Init body was omitted from the pending bound");
        return;
    }
    if (f.close_on_est)
    {
        connectionfisherserverTunnelUpStreamFinish(f.server, l);
        lineDestroy(l);
        return;
    }
    if (f.nested_est)
        connectionfisherserverTunnelUpStreamPayload(f.server, l, payload("C"));
}
static void onReply(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    twfRequire(sbufGetLength(buf) == 5 && memcmp(sbufGetRawPtr(buf), "FISH!", 5) == 0, "probe reply changed");
    ++f.replies;
    lineReuseBuffer(l, buf);
    if (f.nested_reply)
        connectionfisherserverTunnelUpStreamPayload(f.server, l, payload("B"));
}
static void onInit(tunnel_t *t, line_t *l)
{
    discard t;
    ++f.inits;
    if (f.close_on_init)
    {
        connectionfisherserverTunnelDownStreamFinish(f.server, l);
        return;
    }
    connectionfisherserverTunnelDownStreamEst(f.server, l);
    if (lineIsAlive(l))
        connectionfisherserverTunnelDownStreamEst(f.server, l);
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
static void setup(void)
{
    memoryZero(&f, sizeof(f));
    twfWorkerEnvSetup(&f.env, 8192, 0);
    f.server = tunnelCreate(NULL, sizeof(connectionfisherserver_tstate_t), sizeof(connectionfisherserver_lstate_t));
    f.prev   = twfCreatePrevTunnel(&f.trace);
    f.next   = twfCreateNextTunnel(&f.trace);
    tunnelBind(f.prev, f.server);
    tunnelBind(f.server, f.next);
    f.prev->fnEstD     = onEst;
    f.prev->fnPayloadD = onReply;
    f.prev->fnFinD     = ownerFinish;
    f.next->fnInitU    = onInit;
    f.next->fnPayloadU = onBody;
    twfLinePoolSetup(&f.lines, f.server->lstate_size, 8);
    f.line = twfLinePoolCreateLine(&f.lines);
    lineRef(f.line);
    connectionfisherserverTunnelUpStreamInit(f.server, f.line);
}
static void teardown(void)
{
    if (lineIsAlive(f.line))
    {
        connectionfisherserverTunnelUpStreamFinish(f.server, f.line);
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
        connectionfisherserverTunnelUpStreamPayload(f.server, f.line, payload(coalesced ? "FISH?A" : "FISH?"));
        if (! coalesced)
            connectionfisherserverTunnelUpStreamPayload(f.server, f.line, payload("A"));
        twfRequire(f.inits == 1 && f.ests == 1 && f.replies == 1, "Init Est was lost or duplicated");
        twfRequire(strcmp(f.body, coalesced ? "ABC" : "AC") == 0, "nested application input overtook older body");
        teardown();
    }
    twfSetCase("Fisher server Init/Est close releases retained body and stops callbacks");
    for (unsigned mode = 0; mode < 2; ++mode)
    {
        setup();
        f.close_on_est  = mode == 0;
        f.close_on_init = mode != 0;
        connectionfisherserverTunnelUpStreamPayload(f.server, f.line, payload("FISH?A"));
        twfRequire(! lineIsAlive(f.line) && f.bodies == 0, "Init/Est close submitted the retained body");
        teardown();
    }
    twfSetCase("Fisher server temporary FIFO charges the active Init body");
    setup();
    f.overflow_at_est = true;
    connectionfisherserverTunnelUpStreamPayload(f.server, f.line, payload("FISH?A"));
    twfRequire(! lineIsAlive(f.line) && f.bodies == 0 && f.finishes == 1,
               "temporary FIFO overflow did not settle line");
    teardown();
    puts("connectionfisherserver_est_reentry_test: all cases passed");
    return 0;
}
