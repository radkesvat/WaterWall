/*
 * TcpOverUdpServer line-state initialization failure injection.
 *
 * Every resource the KCP line needs - the KCP handle, its frame buffer, the interval timer and the optional FEC
 * pair - is a per-line allocation. Losing one of them may close that line and nothing else: the partial state has
 * to be released exactly once, the line state has to come back zeroed, and only the previous side may be closed
 * because the next tunnel never received Init.
 *
 * The one branch that is deliberately fatal, ikcp_setmtu() rejecting an MTU that tunnel creation already
 * validated, lives in tunnels_abort_runtime_test instead.
 */
#include "TcpOverUdpServer/structure.h"

#include "tunnel_line_failure_harness.h"

// ---------------------------------------------------------------------------
// injection
// ---------------------------------------------------------------------------

typedef enum tcpoverudp_injection_e
{
    kInjectNothing = 0,
    kInjectKcpHandle,
    kInjectKcpBuffer,
    kInjectKcpTimer,
    kInjectFecEncoder,
    kInjectFecDecoder
} tcpoverudp_injection_t;

static tcpoverudp_injection_t g_injection = kInjectNothing;

// Every real resource that gets created is counted, so a failure path that forgets to release one is visible.
static int32_t g_live_kcp_handles  = 0;
static int32_t g_live_timers       = 0;
static int32_t g_live_fec_encoders = 0;
static int32_t g_live_fec_decoders = 0;

static bool      g_reject_pause_submission;
static tunnel_t *g_expected_schedule_tunnel;
static line_t   *g_expected_schedule_line;
static uint32_t  g_pause_schedule_calls;

ikcpcb *__real_ikcp_create(IUINT32 conv, void *user);
ikcpcb *__wrap_ikcp_create(IUINT32 conv, void *user);
int     __real_ikcp_setmtu(ikcpcb *kcp, int mtu);
int     __wrap_ikcp_setmtu(ikcpcb *kcp, int mtu);

wtimer_t *__real_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);

tcpoverudp_fec_encoder_t *__real_tcpoverudpFecEncoderCreate(uint8_t data_shards, uint8_t parity_shards);
tcpoverudp_fec_encoder_t *__wrap_tcpoverudpFecEncoderCreate(uint8_t data_shards, uint8_t parity_shards);
tcpoverudp_fec_decoder_t *__real_tcpoverudpFecDecoderCreate(uint8_t data_shards, uint8_t parity_shards);
tcpoverudp_fec_decoder_t *__wrap_tcpoverudpFecDecoderCreate(uint8_t data_shards, uint8_t parity_shards);

line_task_submit_result_e __wrap_lineScheduleTask(line_t *line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel);

line_task_submit_result_e __wrap_lineScheduleTask(line_t *line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel)
{
    twfRequire(g_reject_pause_submission, "TcpOverUdpServer submitted an unexpected line task");
    twfRequire(line == g_expected_schedule_line && t == g_expected_schedule_tunnel && task != NULL,
               "TcpOverUdpServer submitted the queued Pause against the wrong line or tunnel");
    twfRequire(on_cancel == NULL, "TcpOverUdpServer queued Pause unexpectedly installed cancellation work");
    lineRef(line);
    lineUnref(line);
    ++g_pause_schedule_calls;
    return kLineTaskSubmitRejectedSettled;
}

// ikcp_release() is not wrapped, so the live-handle counter is decremented through the release seam below.
void __real_ikcp_release(ikcpcb *kcp);
void __wrap_ikcp_release(ikcpcb *kcp);

ikcpcb *__wrap_ikcp_create(IUINT32 conv, void *user)
{
    if (g_injection == kInjectKcpHandle)
    {
        return NULL;
    }

    ikcpcb *handle = __real_ikcp_create(conv, user);
    if (handle != NULL)
    {
        ++g_live_kcp_handles;
    }
    return handle;
}

void __wrap_ikcp_release(ikcpcb *kcp)
{
    if (kcp != NULL)
    {
        --g_live_kcp_handles;
    }
    __real_ikcp_release(kcp);
}

int __wrap_ikcp_setmtu(ikcpcb *kcp, int mtu)
{
    if (g_injection == kInjectKcpBuffer)
    {
        return -2; // the documented allocation failure, which is per-line and must not be fatal
    }
    return __real_ikcp_setmtu(kcp, mtu);
}

wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat)
{
    if (g_injection == kInjectKcpTimer)
    {
        return NULL;
    }

    wtimer_t *timer = __real_wtimerAdd(loop, cb, timeout_ms, repeat);
    if (timer != NULL)
    {
        ++g_live_timers;
    }
    return timer;
}

void __real_wtimerDelete(wtimer_t *timer);
void __wrap_wtimerDelete(wtimer_t *timer);

void __wrap_wtimerDelete(wtimer_t *timer)
{
    if (timer != NULL)
    {
        --g_live_timers;
    }
    __real_wtimerDelete(timer);
}

tcpoverudp_fec_encoder_t *__wrap_tcpoverudpFecEncoderCreate(uint8_t data_shards, uint8_t parity_shards)
{
    if (g_injection == kInjectFecEncoder)
    {
        return NULL;
    }

    tcpoverudp_fec_encoder_t *encoder = __real_tcpoverudpFecEncoderCreate(data_shards, parity_shards);
    if (encoder != NULL)
    {
        ++g_live_fec_encoders;
    }
    return encoder;
}

tcpoverudp_fec_decoder_t *__wrap_tcpoverudpFecDecoderCreate(uint8_t data_shards, uint8_t parity_shards)
{
    if (g_injection == kInjectFecDecoder)
    {
        return NULL;
    }

    tcpoverudp_fec_decoder_t *decoder = __real_tcpoverudpFecDecoderCreate(data_shards, parity_shards);
    if (decoder != NULL)
    {
        ++g_live_fec_decoders;
    }
    return decoder;
}

void __real_tcpoverudpFecEncoderDestroy(tcpoverudp_fec_encoder_t **encoder);
void __wrap_tcpoverudpFecEncoderDestroy(tcpoverudp_fec_encoder_t **encoder);
void __real_tcpoverudpFecDecoderDestroy(tcpoverudp_fec_decoder_t **decoder);
void __wrap_tcpoverudpFecDecoderDestroy(tcpoverudp_fec_decoder_t **decoder);

void __wrap_tcpoverudpFecEncoderDestroy(tcpoverudp_fec_encoder_t **encoder)
{
    if (encoder != NULL && *encoder != NULL)
    {
        --g_live_fec_encoders;
    }
    __real_tcpoverudpFecEncoderDestroy(encoder);
}

void __wrap_tcpoverudpFecDecoderDestroy(tcpoverudp_fec_decoder_t **decoder)
{
    if (decoder != NULL && *decoder != NULL)
    {
        --g_live_fec_decoders;
    }
    __real_tcpoverudpFecDecoderDestroy(decoder);
}

static void requireNoLiveKcpResources(void)
{
    twfRequireEqualU32((uint32_t) g_live_kcp_handles, 0, "a KCP handle survived the failure path");
    twfRequireEqualU32((uint32_t) g_live_timers, 0, "a KCP interval timer survived the failure path");
    twfRequireEqualU32((uint32_t) g_live_fec_encoders, 0, "a FEC encoder survived the failure path");
    twfRequireEqualU32((uint32_t) g_live_fec_decoders, 0, "a FEC decoder survived the failure path");
}

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

enum
{
    kTestLargeBufferSize = 8192,
    kTestMtu             = 1500
};

typedef struct tcpoverudp_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *kcp;
    tunnel_t        *next;
} tcpoverudp_fixture_t;

static void fixtureSetup(tcpoverudp_fixture_t *fixture, bool fec_enabled)
{
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, kFrameHeaderLength);

    GLOBAL_MTU_SIZE = kTestMtu;

    g_live_kcp_handles  = 0;
    g_live_timers       = 0;
    g_live_fec_encoders = 0;
    g_live_fec_decoders = 0;

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->kcp  = tunnelCreate(NULL, sizeof(tcpoverudpserver_tstate_t), sizeof(tcpoverudpserver_lstate_t));
    twfRequire(fixture->kcp != NULL, "failed to create the TcpOverUdpServer tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->prev, fixture->kcp);
    tunnelBind(fixture->kcp, fixture->next);

    fixture->kcp->fnInitU = &tcpoverudpserverTunnelUpStreamInit;

    tcpoverudpserver_tstate_t *ts = tunnelGetState(fixture->kcp);

    ts->kcp_nodelay               = true;
    ts->kcp_no_congestion_control = true;
    ts->kcp_interval_ms           = kTcpOverUdpServerKcpIntervalDefault;
    ts->kcp_resend                = kTcpOverUdpServerKcpResendDefault;
    ts->kcp_send_window           = kTcpOverUdpServerKcpSendWindowDefault;
    ts->kcp_recv_window           = kTcpOverUdpServerKcpRecvWindowDefault;
    ts->kcp_initial_cwnd          = kTcpOverUdpServerKcpInitialCwndDefault;
    ts->kcp_rx_minrto_ms          = kTcpOverUdpServerKcpRxMinRtoDefault;
    ts->ping_interval_ms          = kTcpOverUdpServerPingintervalMsDefault;
    ts->no_recv_timeout_ms        = kTcpOverUdpServerNoRecvTimeOutDefault;
    ts->fec_enabled               = fec_enabled;
    ts->fec_data_shards           = kTcpOverUdpServerFecDefaultDataShards;
    ts->fec_parity_shards         = kTcpOverUdpServerFecDefaultParityShards;
    atomic_init(&ts->stopping, false);
}

static void fixtureTeardown(tcpoverudp_fixture_t *fixture)
{
    twfRequireNoLeakedBuffers();
    memoryFree(fixture->prev);
    memoryFree(fixture->kcp);
    memoryFree(fixture->next);
}

static void caseInitializationFails(tcpoverudp_injection_t injection, bool fec_enabled, const char *case_name)
{
    twfSetCase(case_name);

    tcpoverudp_fixture_t fixture;
    fixtureSetup(&fixture, fec_enabled);

    line_t        *l             = twfLineCreate(fixture.kcp->lstate_size);
    const uint32_t refc_at_start = twfLineRefCount(l);

    g_injection = injection;
    tcpoverudpserverTunnelUpStreamInit(fixture.kcp, l);
    g_injection = kInjectNothing;

    twfRequireEqualText(fixture.trace.seq, "f", "the failing line did not close exactly the previous side");
    twfRequireEqualU32(fixture.trace.next_init, 0, "the next tunnel received Init after the allocation failure");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "the next tunnel received Finish it never opened");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "the previous side was not finished exactly once");
    twfRequireLineStateZeroed(l, fixture.kcp, "the failing TcpOverUdpServer line state was not zeroed");
    twfRequireEqualU32(twfLineRefCount(l), refc_at_start, "the line reference count did not return to its start");
    requireNoLiveKcpResources();
    twfRequireNoLeakedBuffers();

    twfLineDestroy(l);

    // A second line must still come up once the allocator recovers.
    memoryZero(&fixture.trace, sizeof(fixture.trace));
    line_t *sibling = twfLineCreate(fixture.kcp->lstate_size);
    tcpoverudpserverTunnelUpStreamInit(fixture.kcp, sibling);

    twfRequireEqualU32(fixture.trace.prev_finish, 0, "the sibling line was closed even though nothing failed");
    twfRequireEqualU32(fixture.trace.next_init, 1, "the sibling line did not reach the next tunnel");

    tcpoverudpserver_lstate_t *sibling_ls = lineGetState(sibling, fixture.kcp);
    twfRequire(sibling_ls->k_handle != NULL && sibling_ls->k_timer != NULL,
               "the sibling line did not build its KCP resources");

    tcpoverudpserverLinestateDestroy(sibling_ls);
    twfRequireLineStateZeroed(sibling, fixture.kcp, "the sibling line state was not zeroed");
    requireNoLiveKcpResources();
    twfLineDestroy(sibling);

    fixtureTeardown(&fixture);
}

static tcpoverudp_fixture_t *g_pause_fixture;
static uint32_t              g_inline_pause_calls;

static void serverOwnerFinishesReentrantClose(tunnel_t *prev, line_t *line)
{
    tcpoverudp_fixture_t *fixture = g_pause_fixture;
    twfRequire(fixture != NULL && prev == fixture->prev && line == g_expected_schedule_line,
               "TcpOverUdpServer finished an unexpected previous-side line");
    ++fixture->trace.prev_finish;
    twfRecord(&fixture->trace, 'f');
    twfRequireLineStateZeroed(line, fixture->kcp, "TcpOverUdpServer left line state alive before its owner Finish");
    lineDestroy(line);
}

static void serverNextClosesReentrantlyOnPause(tunnel_t *next, line_t *line)
{
    tcpoverudp_fixture_t *fixture = g_pause_fixture;
    twfRequire(fixture != NULL && next == fixture->next && line == g_expected_schedule_line,
               "TcpOverUdpServer called Pause on an unexpected next-side line");

    ++g_inline_pause_calls;
    twfRecord(&fixture->trace, 'U');

    tcpoverudpserver_tstate_t *state = tunnelGetState(fixture->kcp);
    atomicStoreRelaxed(&state->stopping, true);
    tcpoverudpserverTunnelDownStreamFinish(fixture->kcp, line);
}

static void caseRejectedPauseFallsBackInlineAcrossReentrantLineDeath(void)
{
    twfSetCase("TcpOverUdpServer queued Pause rejection with re-entrant owner close");

    tcpoverudp_fixture_t fixture;
    fixtureSetup(&fixture, false);

    twf_line_pool_t line_pool;
    twfLinePoolSetup(&line_pool, fixture.kcp->lstate_size, 1);
    line_t *line = twfLinePoolCreateLine(&line_pool);

    tcpoverudpserverTunnelUpStreamInit(fixture.kcp, line);
    tcpoverudpserver_lstate_t *ls = lineGetState(line, fixture.kcp);
    twfRequire(ls->k_handle != NULL && ls->k_timer != NULL,
               "TcpOverUdpServer did not initialize the rejection-case line");
    twfRequireEqualU32(fixture.trace.next_init, 1, "TcpOverUdpServer did not initialize its next neighbor");

    tcpoverudpserver_tstate_t *state = tunnelGetState(fixture.kcp);
    state->kcp_send_buffer_limit     = 1;
    twfRequire(ikcp_send(ls->k_handle, "x", 1) == 1, "TcpOverUdpServer could not prime its KCP send queue");
    twfRequire(ikcp_waitsnd(ls->k_handle) > state->kcp_send_buffer_limit,
               "TcpOverUdpServer did not reach the queued-Pause threshold");

    sbuf_t *input = bufferpoolGetLargeBuffer(fixture.env.pool);
    twfRequire(input != NULL, "failed to allocate the TcpOverUdpServer input buffer");
    sbufSetLength(input, 3);

    fixture.next->fnPauseU     = serverNextClosesReentrantlyOnPause;
    fixture.prev->fnFinD       = serverOwnerFinishesReentrantClose;
    g_pause_fixture            = &fixture;
    g_expected_schedule_tunnel = fixture.kcp;
    g_expected_schedule_line   = line;
    g_pause_schedule_calls     = 0;
    g_inline_pause_calls       = 0;
    g_reject_pause_submission  = true;
    const uint32_t recycled    = twfRecycleCount();

    tcpoverudpserverTunnelDownStreamPayload(fixture.kcp, line, input);

    g_reject_pause_submission  = false;
    g_expected_schedule_line   = NULL;
    g_expected_schedule_tunnel = NULL;
    g_pause_fixture            = NULL;

    twfRequireEqualU32(g_pause_schedule_calls, 1, "TcpOverUdpServer did not reject exactly one queued Pause");
    twfRequireEqualU32(g_inline_pause_calls, 1, "TcpOverUdpServer did not run the inline Pause fallback once");
    twfRequireEqualU32(
        fixture.trace.prev_finish, 1, "TcpOverUdpServer did not finish its previous-side owner once during re-entry");
    twfRequireEqualU32(
        twfRecycleCount(), recycled + 1U, "TcpOverUdpServer did not settle only its still-local input buffer");
    twfRequireLastRecycle(
        input, fixture.env.pool, "TcpOverUdpServer did not recycle input through the pool captured before re-entry");
    requireNoLiveKcpResources();
    twfRequireNoLeakedBuffers();

    twfLinePoolTeardown(&line_pool);
    twfWorkerEnvTeardown(&fixture.env);
    fixtureTeardown(&fixture);
}

int main(void)
{
    caseInitializationFails(kInjectKcpHandle, false, "KCP handle allocation fails");
    caseInitializationFails(kInjectKcpBuffer, false, "ikcp_setmtu reports an allocation failure");
    caseInitializationFails(kInjectKcpTimer, false, "KCP interval timer creation fails");
    caseInitializationFails(kInjectFecEncoder, true, "FEC encoder creation fails");
    caseInitializationFails(kInjectFecDecoder, true, "FEC decoder creation fails");
    caseRejectedPauseFallsBackInlineAcrossReentrantLineDeath();

    printf("tcpoverudpserver_line_failure_test: all cases passed\n");
    return 0;
}
