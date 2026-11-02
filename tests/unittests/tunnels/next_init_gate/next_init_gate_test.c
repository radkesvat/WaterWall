/*
 * Covers: deferred next Init, early pressure and bounded startup FIFO ownership.
 * Setup: Existing worker/line and buffer-ledger fixture; the previous mock owns
 * the normal line, while the gate and next mock borrow it. An observation
 * reference permits assertions after the owner closes the line.
 * Cases: nested input from Init/Pause/Payload, latest early pressure, repeated
 * open signals, direct open input, byte/charge boundaries, nullable first input,
 * and Init/Pause/Payload closing either local state or the whole line.
 * CTest: waterwall.next_init_gate_unit
 */
#include "NextInitGate/next_init_gate.h"
#include "fixtures/protocols/protocol_est_ordering_fixture.h"

typedef struct gate_state_s
{
    tunnel_t        *owner;
    next_init_gate_t gate;
} gate_state_t;

static char   trace[32];
static size_t trace_length;
static void (*pause_hook)(est_fixture_t *, line_t *);

static gate_state_t *gateState(est_fixture_t *f)
{
    return lineGetState(f->line, f->node);
}

static void event(char value)
{
    twfRequire(trace_length + 1 < sizeof(trace), "startup trace overflow");
    trace[trace_length++] = value;
    trace[trace_length]   = '\0';
}

static bool stillMine(tunnel_t *t, line_t *l)
{
    twfRequire(lineIsAlive(l), "local-state predicate called for a dead line");
    return ((gate_state_t *) lineGetState(l, t))->owner == t;
}

static void retire(est_fixture_t *f)
{
    nextinitgateDestroy(&gateState(f)->gate, lineGetBufferPool(f->line));
    memoryZero(lineGetState(f->line, f->node), f->node->lstate_size);
}

static void signalGate(est_fixture_t *f, bool paused)
{
    if (nextinitgateSignal(&gateState(f)->gate, paused))
    {
        if (paused)
            tunnelNextUpStreamPause(f->node, f->line);
        else
            tunnelNextUpStreamResume(f->node, f->line);
    }
}

static void submit(est_fixture_t *f, const char *bytes)
{
    sbuf_t                      *buf      = estBytes(f->line, bytes, strlen(bytes));
    sbuf_t                      *original = buf;
    const bool                   starting = gateState(f)->gate.phase == kNextInitGateStarting;
    const next_init_gate_input_t result   = nextinitgateSubmit(&gateState(f)->gate, &buf);
    if (starting)
    {
        twfRequire(result == kNextInitGateQueued && buf == NULL, "startup input did not transfer into FIFO");
        return;
    }
    twfRequire(result == kNextInitGateForward && buf == original, "open input did not retain caller ownership");
    tunnelNextUpStreamPayload(f->node, f->line, buf);
}

static void paused(tunnel_t *t, line_t *l)
{
    est_fixture_t *f = estContext(t);
    twfRequire(f->init_count == 1, "Pause reached next before its Init");
    twfRequire(! gateState(f)->gate.pause_latched, "pending Pause was not cleared before callback");
    event('U');
    if (pause_hook != NULL)
        pause_hook(f, l);
}

static void resumed(tunnel_t *t, line_t *l)
{
    discard        l;
    est_fixture_t *f = estContext(t);
    twfRequire(f->init_count == 1, "Resume reached next before its Init");
    twfRequire(! gateState(f)->gate.pause_latched, "Resume retained an obsolete early Pause");
    event('R');
}

static void initialized(est_fixture_t *f, line_t *l)
{
    twfRequire(gateState(f)->gate.phase == kNextInitGateStarting, "startup guard was not published before Init");
    twfRequire(twfLineRefCount(l) >= 3, "startup has no temporary line reference");
    event('I');
}

static void payload(est_fixture_t *f, line_t *l)
{
    discard l;
    twfRequire(f->init_count == 1, "payload reached next without exactly one Init");
    event((char) f->up[f->up_len - 1]);
}

static void setup(est_fixture_t *f, size_t bytes, size_t charge)
{
    estFixtureSetup(f, 0, sizeof(gate_state_t));
    gate_state_t *state = gateState(f);
    state->owner        = f->node;
    nextinitgateInit(&state->gate, bytes, charge);
    twfRequire(state->gate.phase == kNextInitGateWaiting, "new gate is not waiting for next Init");
    f->on_init         = initialized;
    f->on_up           = payload;
    f->next->fnPauseU  = paused;
    f->next->fnResumeU = resumed;
    trace_length       = 0;
    trace[0]           = '\0';
    pause_hook         = NULL;
}

static void teardown(est_fixture_t *f)
{
    if (lineIsAlive(f->line))
    {
        if (stillMine(f->node, f->line))
            retire(f);
        lineDestroy(f->line);
    }
    twfRequireLineStateZeroed(f->line, f->node, "gate state survived cleanup");
    estFixtureDestroy(f);
}

static void openReady(est_fixture_t *f, const char *first)
{
    const uint32_t refs = twfLineRefCount(f->line);
    sbuf_t        *buf  = first == NULL ? NULL : estBytes(f->line, first, strlen(first));
    twfRequire(nextinitgateOpen(&gateState(f)->gate, f->node, f->line, buf, stillMine) == kNextInitGateReady,
               "valid startup did not become ready");
    twfRequire(gateState(f)->gate.phase == kNextInitGateOpen && f->init_count == 1,
               "startup did not initialize next exactly once");
    twfRequire(bufferqueueGetBufCount(&gateState(f)->gate.pending) == 0 &&
                   bufferqueueGetBufLen(&gateState(f)->gate.pending) == 0 &&
                   bufferqueueGetCharge(&gateState(f)->gate.pending) == 0,
               "completed startup retained queued buffers or accounting");
    twfRequire(twfLineRefCount(f->line) == refs, "startup leaked a line reference");
}

static void nestedInit(est_fixture_t *f, line_t *l)
{
    initialized(f, l);
    submit(f, "B");
}

static void nestedPause(est_fixture_t *f, line_t *l)
{
    discard l;
    submit(f, "C");
}

static void nestedPayload(est_fixture_t *f, line_t *l)
{
    payload(f, l);
    twfRequire(gateState(f)->gate.phase == kNextInitGateStarting, "startup opened before FIFO replay finished");
    if (f->up_len == 1)
        submit(f, "D");
    else if (f->up_len == 2)
        submit(f, "E");
}

static void testNestedOrder(void)
{
    est_fixture_t f;
    setup(&f, 16, 65536);
    f.on_init  = nestedInit;
    f.on_up    = nestedPayload;
    pause_hook = nestedPause;
    signalGate(&f, true);
    signalGate(&f, true);
    twfRequire(trace_length == 0, "waiting gate called its uninitialized next");
    openReady(&f, "A");
    twfRequire(stringCompare(trace, "IUABCDE") == 0 && memoryCompare(f.up, "ABCDE", 5) == 0,
               "nested Init/Pause/Payload input violated startup FIFO order");
    f.on_up    = payload;
    pause_hook = NULL;
    signalGate(&f, true);
    signalGate(&f, true);
    signalGate(&f, false);
    signalGate(&f, false);
    submit(&f, "F");
    twfRequire(stringCompare(trace, "IUABCDEUURRF") == 0 && f.init_count == 1,
               "open gate suppressed repeated signals or restarted next");
    teardown(&f);
}

static bool pause_in_init;
static void signalInInit(est_fixture_t *f, line_t *l)
{
    initialized(f, l);
    signalGate(f, pause_in_init);
}

static void testLatestPressureAndNullFirst(void)
{
    for (unsigned scenario = 0; scenario < 4; ++scenario)
    {
        est_fixture_t f;
        setup(&f, 16, 65536);
        signalGate(&f, true);
        signalGate(&f, true);
        if (scenario == 0)
            signalGate(&f, false);
        else if (scenario < 3)
        {
            pause_in_init = scenario == 2;
            f.on_init     = signalInInit;
        }
        openReady(&f, scenario == 3 ? NULL : "A");
        const char *expected[] = {"IA", "IRA", "IUA", "IU"};
        twfRequire(stringCompare(trace, expected[scenario]) == 0, "startup replayed stale or duplicate pressure");
        teardown(&f);
    }
}

static bool charge_boundary;
static void boundaryInit(est_fixture_t *f, line_t *l)
{
    initialized(f, l);
    sbuf_t      *accepted = estBytes(l, charge_boundary ? "" : "XYZ", charge_boundary ? 0 : 3);
    const size_t charge   = sbufGetQueueCharge(accepted);
    twfRequire(nextinitgateSubmit(&gateState(f)->gate, &accepted) == kNextInitGateQueued && accepted == NULL,
               "exact startup budget boundary was refused");
    sbuf_t        *rejected = estBytes(l, charge_boundary ? "" : "!", charge_boundary ? 0 : 1);
    sbuf_t        *original = rejected;
    const uint32_t recycled = twfRecycleCount();
    twfRequire(nextinitgateSubmit(&gateState(f)->gate, &rejected) == kNextInitGateRejected && rejected == original,
               "startup refusal consumed or changed caller buffer");
    twfRequire(twfRecycleCount() == recycled && lineIsAlive(l) && stillMine(f->node, l),
               "startup refusal recycled a buffer or chose the node's close policy");
    twfRequire(bufferqueueGetBufLen(&gateState(f)->gate.pending) == (charge_boundary ? 0U : 3U) &&
                   bufferqueueGetCharge(&gateState(f)->gate.pending) == charge,
               "refusal changed previously admitted queue cost");
    lineReuseBuffer(l, rejected);
}

static void refillBoundary(est_fixture_t *f, line_t *l)
{
    discard l;
    twfRequire(bufferqueueGetBufLen(&gateState(f)->gate.pending) == 0 &&
                   bufferqueueGetCharge(&gateState(f)->gate.pending) == 0,
               "handed-off input remained charged during reentry");
    f->on_up = NULL;
    submit(f, charge_boundary ? "" : "XYZ");
}

static void testAdmissionOwnership(void)
{
    next_init_gate_t empty = {0};
    nextinitgateDestroy(&empty, NULL);
    nextinitgateInit(&empty, 0, 0);
    nextinitgateDestroy(&empty, NULL);
    for (unsigned scenario = 0; scenario < 2; ++scenario)
    {
        est_fixture_t f;
        setup(&f, 3, 65536);
        charge_boundary = scenario != 0;
        if (charge_boundary)
        {
            sbuf_t      *sample = estBytes(f.line, "", 0);
            const size_t charge = sbufGetQueueCharge(sample);
            lineReuseBuffer(f.line, sample);
            nextinitgateDestroy(&gateState(&f)->gate, NULL);
            nextinitgateInit(&gateState(&f)->gate, 3, charge);
        }
        f.on_init = boundaryInit;
        f.on_up   = refillBoundary;
        openReady(&f, NULL);
        twfRequire(f.up_len == (charge_boundary ? 0U : 6U), "admission boundary changed payload bytes");
        teardown(&f);
    }
}

static unsigned close_at;
static bool     close_owner;

static void closeHere(est_fixture_t *f, unsigned point)
{
    if (point != close_at)
        return;
    retire(f);
    if (close_owner)
        lineDestroy(f->line); // The fixture acts for the normal line's owning previous endpoint.
}

static void closingInit(est_fixture_t *f, line_t *l)
{
    nestedInit(f, l);
    closeHere(f, 0);
}

static void closingPause(est_fixture_t *f, line_t *l)
{
    nestedPause(f, l);
    closeHere(f, 1);
}

static void closingPayload(est_fixture_t *f, line_t *l)
{
    payload(f, l);
    closeHere(f, 2);
}

static void testCallbackRetirement(void)
{
    for (unsigned point = 0; point < 3; ++point)
        for (unsigned owner = 0; owner < 2; ++owner)
        {
            est_fixture_t f;
            setup(&f, 16, 65536);
            close_at    = point;
            close_owner = owner != 0;
            f.on_init   = closingInit;
            f.on_up     = closingPayload;
            pause_hook  = closingPause;
            signalGate(&f, true);
            sbuf_t *first = estBytes(f.line, "A", 1);
            twfRequire(nextinitgateOpen(&gateState(&f)->gate, f.node, f.line, first, stillMine) == kNextInitGateGone,
                       "startup continued after callback retired its state");
            // The fixture's independent observation reference permits these postconditions.
            twfRequire(lineIsAlive(f.line) == ! close_owner && twfLineRefCount(f.line) == (close_owner ? 1U : 2U),
                       "startup changed line ownership or leaked its reference after retirement");
            const char *expected[] = {"I", "IU", "IUA"};
            twfRequire(stringCompare(trace, expected[point]) == 0 && f.up_len == (point == 2 ? 1U : 0U),
                       "startup called next after callback retirement");
            twfRequireLineStateZeroed(f.line, f.node, "startup touched retired state after callback");
            twfRequireNoLeakedBuffers();
            teardown(&f);
        }
}

int main(void)
{
    TEST_RUN_CASE(testNestedOrder);
    TEST_RUN_CASE(testLatestPressureAndNullFirst);
    TEST_RUN_CASE(testAdmissionOwnership);
    TEST_RUN_CASE(testCallbackRetirement);
    puts("next_init_gate_test: all cases passed");
    return 0;
}
