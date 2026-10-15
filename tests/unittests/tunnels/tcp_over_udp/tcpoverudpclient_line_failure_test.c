/*
 * Covers: tcpoverudpclient line failure; the explicit inputs, callbacks and expected results below
 * define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseInitializationFails, casePauseAfterAdmissionClosesReentrantly,
 * caseAdvisorySignalsAndAckOnlyResume, caseMtuConfigurationAndOutput
 * Checks: Resource settlement, advisory signal relay, post-admission pressure callbacks,
 * ACK-only Resume, and configured KCP/FEC packet bounds.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tcpoverudpclient_line_failure_test_unit
 */
/*
 * TcpOverUdpClient line-state initialization failure injection.
 *
 * Timer admission and FEC initialization can still refuse a line. Partial resources must be released exactly
 * once, the line state must return to zero, and only the previous side may be closed because the next tunnel
 * never received Init. KCP heap failures terminate at the WaterWall allocator and are not injected here.
 *
 * The one branch that is deliberately fatal, ikcp_setmtu() rejecting an MTU that tunnel creation already
 * validated, lives in tunnels_abort_runtime_test instead.
 */
#include "TcpOverUdpClient/structure.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"

// ---------------------------------------------------------------------------
// injection
// ---------------------------------------------------------------------------

typedef enum tcpoverudp_injection_e
{
    kInjectNothing = 0,
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

ikcpcb *__real_ikcp_create(IUINT32 conv, void *user);
ikcpcb *__wrap_ikcp_create(IUINT32 conv, void *user);

wtimer_t *__real_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);

tcpoverudp_fec_encoder_t *__real_tcpoverudpFecEncoderCreate(uint8_t data_shards, uint8_t parity_shards);
tcpoverudp_fec_encoder_t *__wrap_tcpoverudpFecEncoderCreate(uint8_t data_shards, uint8_t parity_shards);
tcpoverudp_fec_decoder_t *__real_tcpoverudpFecDecoderCreate(uint8_t data_shards, uint8_t parity_shards);
tcpoverudp_fec_decoder_t *__wrap_tcpoverudpFecDecoderCreate(uint8_t data_shards, uint8_t parity_shards);

// ikcp_release() is not wrapped, so the live-handle counter is decremented through the release seam below.
void __real_ikcp_release(ikcpcb *kcp);
void __wrap_ikcp_release(ikcpcb *kcp);

ikcpcb *__wrap_ikcp_create(IUINT32 conv, void *user)
{
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
    kTestLargeBufferSize = 262144,
    kTestMtu             = 1500
};

typedef struct tcpoverudp_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    master_pool_t   *context_master;
    generic_pool_t  *contexts;
    tunnel_t        *prev;
    tunnel_t        *kcp;
    tunnel_t        *next;
} tcpoverudp_fixture_t;

static void fixtureSetup(tcpoverudp_fixture_t *fixture, bool fec_enabled)
{
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, kFrameHeaderLength);
    fixture->context_master = masterpoolCreateWithCapacity(8);
    fixture->contexts = genericpoolCreateWithDefaultAllocatorAndCapacity(fixture->context_master, sizeof(context_t), 8);
    GSTATE.shortcut_context_pools = &fixture->contexts;

    g_live_kcp_handles  = 0;
    g_live_timers       = 0;
    g_live_fec_encoders = 0;
    g_live_fec_decoders = 0;

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->kcp  = tunnelCreate(NULL, sizeof(tcpoverudpclient_tstate_t), sizeof(tcpoverudpclient_lstate_t));
    twfRequire(fixture->kcp != NULL, "failed to create the TcpOverUdpClient tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->prev, fixture->kcp);
    tunnelBind(fixture->kcp, fixture->next);

    fixture->prev->chain_index = 0;
    fixture->kcp->chain_index  = 1;
    fixture->next->chain_index = 2;
    fixture->kcp->fnInitU = &tcpoverudpclientTunnelUpStreamInit;
    fixture->kcp->fnFinU       = &tcpoverudpclientTunnelUpStreamFinish;
    fixture->kcp->fnPayloadU   = &tcpoverudpclientTunnelUpStreamPayload;
    fixture->kcp->fnPayloadD   = &tcpoverudpclientTunnelDownStreamPayload;
    fixture->kcp->fnPauseD     = &tcpoverudpclientTunnelDownStreamPause;
    fixture->kcp->fnResumeD    = &tcpoverudpclientTunnelDownStreamResume;

    tcpoverudpclient_tstate_t *ts = tunnelGetState(fixture->kcp);

    ts->mtu                       = kTestMtu;
    ts->kcp_nodelay               = true;
    ts->kcp_no_congestion_control = true;
    ts->kcp_interval_ms           = kTcpOverUdpClientKcpIntervalDefault;
    ts->kcp_resend                = kTcpOverUdpClientKcpResendDefault;
    ts->kcp_send_window           = kTcpOverUdpClientKcpSendWindowDefault;
    ts->kcp_recv_window           = kTcpOverUdpClientKcpRecvWindowDefault;
    ts->kcp_initial_cwnd          = kTcpOverUdpClientKcpInitialCwndDefault;
    ts->kcp_rx_minrto_ms          = kTcpOverUdpClientKcpRxMinRtoDefault;
    ts->ping_interval_ms          = kTcpOverUdpClientPingintervalMsDefault;
    ts->no_recv_timeout_ms        = kTcpOverUdpClientNoRecvTimeOutDefault;
    ts->fec_enabled               = fec_enabled;
    ts->fec_data_shards           = kTcpOverUdpClientFecDefaultDataShards;
    ts->fec_parity_shards         = kTcpOverUdpClientFecDefaultParityShards;
    atomic_init(&ts->stopping, false);
}

static void fixtureTeardown(tcpoverudp_fixture_t *fixture)
{
    twfRequireNoLeakedBuffers();
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->kcp);
    tunnelDestroy(fixture->next);
    GSTATE.shortcut_context_pools = NULL;
    genericpoolDestroy(fixture->contexts);
    masterpoolMakeEmpty(fixture->context_master);
    masterpoolDestroy(fixture->context_master);
}

static void caseInitializationFails(tcpoverudp_injection_t injection, bool fec_enabled, const char *case_name)
{
    twfSetCase(case_name);

    tcpoverudp_fixture_t fixture;
    fixtureSetup(&fixture, fec_enabled);

    line_t        *l             = twfLineCreate(fixture.kcp->lstate_size);
    const uint32_t refc_at_start = twfLineRefCount(l);

    g_injection = injection;
    tcpoverudpclientTunnelUpStreamInit(fixture.kcp, l);
    g_injection = kInjectNothing;

    twfRequireEqualText(fixture.trace.seq, "f", "the failing line did not close exactly the previous side");
    twfRequireEqualU32(fixture.trace.next_init, 0, "the next tunnel received Init after initialization refusal");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "the next tunnel received Finish it never opened");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "the previous side was not finished exactly once");
    twfRequireLineStateZeroed(l, fixture.kcp, "the failing TcpOverUdpClient line state was not zeroed");
    twfRequireEqualU32(twfLineRefCount(l), refc_at_start, "the line reference count did not return to its start");
    requireNoLiveKcpResources();
    twfRequireNoLeakedBuffers();

    twfLineDestroy(l);

    // A second line must still come up once the allocator recovers.
    memoryZero(&fixture.trace, sizeof(fixture.trace));
    line_t *sibling = twfLineCreate(fixture.kcp->lstate_size);
    tcpoverudpclientTunnelUpStreamInit(fixture.kcp, sibling);

    twfRequireEqualU32(fixture.trace.prev_finish, 0, "the sibling line was closed even though nothing failed");
    twfRequireEqualU32(fixture.trace.next_init, 1, "the sibling line did not reach the next tunnel");

    tcpoverudpclient_lstate_t *sibling_ls = lineGetState(sibling, fixture.kcp);
    twfRequire(sibling_ls->k_handle != NULL && sibling_ls->k_timer != NULL,
               "the sibling line did not build its KCP resources");

    tcpoverudpclientLinestateDestroy(sibling_ls);
    twfRequireLineStateZeroed(sibling, fixture.kcp, "the sibling line state was not zeroed");
    requireNoLiveKcpResources();
    twfLineDestroy(sibling);

    fixtureTeardown(&fixture);
}

static tcpoverudp_fixture_t *g_pressure_fixture;
static line_t               *g_pressure_line;
static uint32_t              g_pressure_calls;

static void clientOwnerClosesOnPressure(tunnel_t *prev, line_t *line)
{
    tcpoverudp_fixture_t *fixture = g_pressure_fixture;
    twfRequire(fixture != NULL && prev == fixture->prev && line == g_pressure_line,
               "TcpOverUdpClient called pressure on an unexpected previous-side line");
    tcpoverudpclient_lstate_t *ls = lineGetState(line, fixture->kcp);
    ++g_pressure_calls;
    const bool destroy_line = ls->source_paused;
    if (ls->source_paused)
    {
        twfRequire(ikcp_waitsnd(ls->k_handle) == 3,
                   "Pause reached the source before the original payload was fully admitted");
    }
    else
    {
        twfRequire(ikcp_waitsnd(ls->k_handle) == 0, "Resume preceded cumulative acknowledgement");
    }

    tcpoverudpclient_tstate_t *state = tunnelGetState(fixture->kcp);
    atomicStoreRelaxed(&state->stopping, true);
    tunnelNextUpStreamFinish(prev, line);
    twfRequire(lineIsAlive(line), "the borrowed TcpOverUdpClient line died before its owner reclaimed it");
    twfRequireLineStateZeroed(line, fixture->kcp, "TcpOverUdpClient kept state alive during reentrant Finish");
    if (destroy_line)
    {
        lineDestroy(line);
    }
}

static void casePauseAfterAdmissionClosesReentrantly(void)
{
    twfSetCase("TcpOverUdpClient post-admission Pause with reentrant owner close");
    tcpoverudp_fixture_t fixture;
    fixtureSetup(&fixture, false);
    twf_line_pool_t line_pool;
    twfLinePoolSetup(&line_pool, fixture.kcp->lstate_size, 1);
    line_t *line = twfLinePoolCreateLine(&line_pool);
    tunnelNextUpStreamInit(fixture.prev, line);
    tcpoverudpclient_tstate_t *state = tunnelGetState(fixture.kcp);
    state->kcp_send_buffer_limit     = 1;
    fixture.prev->fnPauseD           = clientOwnerClosesOnPressure;
    g_pressure_fixture               = &fixture;
    g_pressure_line                  = line;
    g_pressure_calls                 = 0;

    sbuf_t *input = bufferpoolGetLargeBuffer(fixture.env.pool);
    sbufSetLength(input, (uint32_t) tcpoverudpclientGetKcpWriteMtu(state) + 1U);
    memoryZero(sbufGetMutablePtr(input), sbufGetLength(input));
    tunnelNextUpStreamPayload(fixture.prev, line, input);

    twfRequireEqualU32(g_pressure_calls, 1, "the admitted burst did not synchronously request one Pause");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "reentrant Finish did not close the next side exactly once");
    requireNoLiveKcpResources();
    twfRequireNoLeakedBuffers();
    g_pressure_fixture = NULL;
    g_pressure_line    = NULL;
    twfLinePoolTeardown(&line_pool);
    twfWorkerEnvTeardown(&fixture.env);
    fixtureTeardown(&fixture);
}

static void caseAdvisorySignalsAndAckOnlyResume(void)
{
    for (unsigned close_on_resume = 0; close_on_resume < 2; ++close_on_resume)
    {
        twfSetCase(close_on_resume ? "TcpOverUdpClient ACK-only Resume with owner close"
                                   : "TcpOverUdpClient repeated advisory signals and ACK-only Resume");
        tcpoverudp_fixture_t fixture;
        fixtureSetup(&fixture, false);
        twf_line_pool_t line_pool;
        twfLinePoolSetup(&line_pool, fixture.kcp->lstate_size, 1);
        line_t *line = twfLinePoolCreateLine(&line_pool);
        tunnelNextUpStreamInit(fixture.prev, line);
        tcpoverudpclient_tstate_t *state = tunnelGetState(fixture.kcp);
        tcpoverudpclient_lstate_t *ls    = lineGetState(line, fixture.kcp);
        state->kcp_send_buffer_limit     = 1;

        tunnelNextUpStreamPause(fixture.prev, line);
        tunnelNextUpStreamPause(fixture.prev, line);
        tunnelPrevDownStreamPause(fixture.next, line);
        tunnelPrevDownStreamPause(fixture.next, line);
        twfRequireEqualText(fixture.trace.seq, "IUUuu", "repeated Pause was suppressed");
        tcpoverudpclientKcpLoopIntervalCallback(ls->k_timer);
        twfRequire(fixture.trace.next_payload > 0, "scheduled KCP output waited for Resume");
        twfRequire(! ls->source_paused, "received Pause changed our own-pressure latch");

        sbuf_t *input = bufferpoolGetLargeBuffer(fixture.env.pool);
        sbufSetLength(input, (uint32_t) tcpoverudpclientGetKcpWriteMtu(state) + 1U);
        memoryZero(sbufGetMutablePtr(input), sbufGetLength(input));
        tunnelNextUpStreamPayload(fixture.prev, line, input);
        twfRequire(ls->source_paused, "KCP backlog did not establish its own source hold");
        twfRequire(tcpoverudpclientUpdateKcp(ls, true), "KCP data flush destroyed a live line");
        const uint32_t output_before_ack = fixture.trace.next_payload;
        const uint32_t events_before_ack = fixture.trace.len;
        const uint32_t next_sequence     = ls->k_handle->snd_nxt;
        twfRequire(next_sequence > 0, "ACK fixture has no transmitted segments");

        if (close_on_resume)
        {
            fixture.prev->fnResumeD = clientOwnerClosesOnPressure;
            g_pressure_fixture      = &fixture;
            g_pressure_line         = line;
            g_pressure_calls        = 0;
        }

        sbuf_t *ack = bufferpoolGetSmallBuffer(fixture.env.pool);
        sbufSetLength(ack, 24);
        uint8_t *bytes = sbufGetMutablePtr(ack);
        memoryZero(bytes, 24);
        bytes[4] = 82; // ACK: no PUSH input or outgoing acknowledgement needed.
        bytes[6] = 128;
        for (unsigned i = 0; i < 4; ++i)
        {
            bytes[12 + i] = (uint8_t) ((next_sequence - 1U) >> (8U * i));
            bytes[16 + i] = (uint8_t) (next_sequence >> (8U * i));
        }
        tunnelPrevDownStreamPayload(fixture.next, line, ack);
        twfRequireEqualU32(fixture.trace.next_payload,
                           output_before_ack,
                           "ACK-only input unexpectedly needed outbound packet progress");
        if (close_on_resume)
        {
            twfRequireEqualU32(g_pressure_calls, 1, "ACK-only input did not emit Resume before closure");
            twfRequireEqualU32(fixture.trace.next_finish, 1, "Resume reentry did not finish exactly once");
            twfRequire(lineIsAlive(line), "borrowed line unexpectedly died after Resume Finish");
            twfRequireLineStateZeroed(line, fixture.kcp, "Resume Finish left KCP state alive");
            lineDestroy(line);
            g_pressure_fixture = NULL;
            g_pressure_line    = NULL;
        }
        else
        {
            twfRequire(! ls->source_paused, "ACK-only input left the source paused");
            twfRequireEqualU32(fixture.trace.len, events_before_ack + 1U, "ACK-only input emitted extra callbacks");
            twfRequire(fixture.trace.seq[events_before_ack] == 'r', "ACK-only input did not resume the source");
            const uint32_t relay_start = fixture.trace.len;
            tunnelNextUpStreamResume(fixture.prev, line);
            tunnelNextUpStreamResume(fixture.prev, line);
            tunnelPrevDownStreamResume(fixture.next, line);
            tunnelPrevDownStreamResume(fixture.next, line);
            twfRequireEqualText(fixture.trace.seq + relay_start, "RRrr", "repeated Resume was suppressed");
            tcpoverudpclientLinestateDestroy(ls);
            lineDestroy(line);
        }
        requireNoLiveKcpResources();
        twfRequireNoLeakedBuffers();
        twfLinePoolTeardown(&line_pool);
        twfWorkerEnvTeardown(&fixture.env);
        fixtureTeardown(&fixture);
    }
}

static uint32_t g_mtu_output_count;
static uint32_t g_mtu_max_output;
static uint32_t g_mtu_budget;
static uint32_t g_mtu_effective;
static uint32_t g_mtu_fec;

static void captureMtuOutput(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard        t;
    const uint32_t length = sbufGetLength(buf);
    twfRequire(length <= g_mtu_effective + g_mtu_fec, "KCP/FEC output exceeds effective limit");
    twfRequire(length + 28 <= g_mtu_budget, "output exceeds configured IPv4 packet budget");
    g_mtu_max_output = max(g_mtu_max_output, length);
    ++g_mtu_output_count;
    lineReuseBuffer(line, buf);
}

static tunnel_t *createMtuTunnel(const char *json)
{
    cJSON        *settings = json != NULL ? cJSON_Parse(json) : NULL;
    static node_t node;
    node.node_settings_json = settings;
    tunnel_t *t             = tcpoverudpclientTunnelCreate(&node);
    cJSON_Delete(settings);
    return t;
}

static void caseAutomaticSendBufferLimit(void)
{
    twfSetCase("automatic KCP pressure limit stays positive for a maximum send window");
    tunnel_t *configured = createMtuTunnel("{\"mtu\":1500,\"kcp-send-window\":2147483647}");
    twfRequire(configured != NULL, "maximum positive KCP window was rejected");
    tcpoverudpclient_tstate_t *ts     = tunnelGetState(configured);
    ikcpcb                     handle = {.snd_wnd = (IUINT32) ts->kcp_send_window, .rmt_wnd = 128};
    tcpoverudpclient_lstate_t  ls     = {.tunnel = configured, .k_handle = &handle};
    twfRequire(tcpoverudpclientGetKcpSendBufferLimit(&ls) == INT_MAX,
               "automatic pressure limit wrapped at the maximum configured window");
    handle.snd_wnd = INT_MAX - 138U;
    twfRequire(tcpoverudpclientGetKcpSendBufferLimit(&ls) == INT_MAX, "exact automatic limit changed");
    handle.snd_wnd = INT_MAX - 139U;
    twfRequire(tcpoverudpclientGetKcpSendBufferLimit(&ls) == INT_MAX - 1, "near-maximum automatic limit changed");
    handle.snd_wnd = 128;
    twfRequire(tcpoverudpclientGetKcpSendBufferLimit(&ls) == 266, "ordinary automatic limit changed");
    handle.snd_wnd            = INT_MAX;
    ts->kcp_send_buffer_limit = 7;
    twfRequire(tcpoverudpclientGetKcpSendBufferLimit(&ls) == 7, "explicit positive limit was not preserved");
    tunnelDestroy(configured);
}

static void caseFecShardBounds(void)
{
    static const struct
    {
        int  data, parity;
        bool valid;
    } cases[] = {{1, 254, true},
                 {254, 1, true},
                 {1, 255, false},
                 {255, 1, false},
                 {INT_MAX, 1, false},
                 {1, INT_MAX, false},
                 {INT_MAX, INT_MAX, false},
                 {0, 1, false},
                 {1, 0, false}};
    for (unsigned enabled = 0; enabled < 2; ++enabled)
        for (unsigned i = 0; i < ARRAY_SIZE(cases); ++i)
        {
            char label[128], json[192];
            snprintf(
                label, sizeof(label), "FEC enabled=%u, data=%d, parity=%d", enabled, cases[i].data, cases[i].parity);
            twfSetCase(label);
            snprintf(json,
                     sizeof(json),
                     "{\"mtu\":1500,\"fec\":%s,\"fec-data-shards\":%d,\"fec-parity-shards\":%d}",
                     enabled ? "true" : "false",
                     cases[i].data,
                     cases[i].parity);
            tunnel_t  *created  = createMtuTunnel(json);
            const bool accepted = created != NULL;
            if (created != NULL)
            {
                const tcpoverudpclient_tstate_t *ts = tunnelGetState(created);
                twfRequire(ts->fec_enabled == (bool) enabled, "FEC enabled setting changed");
                if (enabled && cases[i].valid)
                    twfRequire(ts->fec_data_shards == cases[i].data && ts->fec_parity_shards == cases[i].parity,
                               "valid 255-shard boundary was altered");
                tunnelDestroy(created);
            }
            twfRequire(accepted == (! enabled || cases[i].valid), "FEC shard count validation changed");
        }
}

static void caseMtuConfigurationAndOutput(void)
{
    twfSetCase("instance MTU settings, lazy KCP handles and output bounds");
    const uint16_t saved_default = CORE_DEFAULT_MTU;
    CORE_DEFAULT_MTU             = 1420;
    tunnel_t *inherited          = createMtuTunnel(NULL);
    twfRequire(inherited != NULL, "missing settings rejected valid default");
    const tcpoverudpclient_tstate_t *inherited_state = tunnelGetState(inherited);
    twfRequire(inherited_state->mtu == 1420, "missing MTU did not inherit core default");
    static const char *invalid[] = {
        "null", "true", "false", "\"1500\"", "[]", "{}", "1500.5", "0", "-1", "65536", "70000", "9223372036854775807"};
    char json[256];
    for (uint32_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        snprintf(json, sizeof(json), "{\"mtu\":%s}", invalid[i]);
        twfRequire(createMtuTunnel(json) == NULL, "invalid MTU accepted");
    }
    CORE_DEFAULT_MTU = 68;
    twfRequire(createMtuTunnel(NULL) == NULL, "absent settings bypassed inherited MTU validation");
    twfRequire(createMtuTunnel("{}") == NULL, "empty settings bypassed inherited MTU validation");
    for (unsigned fec = 0; fec < 2; ++fec)
    {
        const unsigned minimum = fec ? 86 : 78;
        snprintf(json, sizeof(json), "{\"mtu\":%u,\"fec\":%s}", minimum - 1, fec ? "true" : "false");
        twfRequire(createMtuTunnel(json) == NULL, "below-minimum MTU accepted");
        const unsigned budgets[] = {
            minimum, 1420, 1500, fec ? 64035 : 64027, fec ? 64036 : 64028, fec ? 64037 : 64029, 65535};
        for (unsigned i = 0; i < ARRAY_SIZE(budgets); ++i)
        {
            snprintf(json,
                     sizeof(json),
                     "{\"mtu\":%u,\"fec\":%s,\"fec-data-shards\":2,\"fec-parity-shards\":1}",
                     budgets[i],
                     fec ? "true" : "false");
            if (budgets[i] == 1420)
            {
                CORE_DEFAULT_MTU = 1420;
                snprintf(json,
                         sizeof(json),
                         "{\"fec\":%s,\"fec-data-shards\":2,\"fec-parity-shards\":1}",
                         fec ? "true" : "false");
            }
            tunnel_t *configured = createMtuTunnel(json);
            twfRequire(configured != NULL, "valid override of unusable inherited MTU failed");
            tcpoverudpclient_tstate_t *ts        = tunnelGetState(configured);
            const unsigned             effective = min(budgets[i] - 28 - 8 * fec, 64000U);
            twfRequire(ts->mtu == budgets[i], "configured budget was narrowed or capped");
            twfRequire(tcpoverudpclientGetKcpMtu(ts) == (int) effective, "effective KCP MTU is incorrect");
            twfRequire(tcpoverudpclientGetKcpWriteMtu(ts) == (int) effective - 25, "application chunk is incorrect");
            twfRequire(tcpoverudpclientGetKcpMtu(inherited_state) == 1392, "another instance changed inherited MTU");

            tcpoverudp_fixture_t fixture;
            fixtureSetup(&fixture, fec != 0);
            tunnelDestroy(fixture.kcp);
            fixture.kcp = configured;
            tunnelBind(fixture.prev, fixture.kcp);
            tunnelBind(fixture.kcp, fixture.next);
            fixture.prev->fnPayloadD        = captureMtuOutput;
            fixture.next->fnPayloadU        = captureMtuOutput;
            CORE_DEFAULT_MTU                = 1000;
            line_t                    *line = twfLineCreate(configured->lstate_size);
            tcpoverudpclient_lstate_t *ls   = lineGetState(line, configured);
            twfRequire(tcpoverudpclientLinestateInitialize(ls, line, configured), "KCP line initialization failed");
            twfRequire(ls->k_handle->mtu == effective, "lazy KCP handle read global MTU or omitted outer headers");
            twfRequire(ls->k_handle->mss == effective - 24, "KCP MSS is incorrect");
            g_mtu_budget       = budgets[i];
            g_mtu_effective    = effective;
            g_mtu_fec          = fec * 8;
            g_mtu_output_count = g_mtu_max_output = 0;
            sbuf_t *input                         = bufferpoolGetLargeBuffer(fixture.env.pool);
            sbufSetLength(input, 2 * (effective - 25) + 1);
            memoryZero(sbufGetMutablePtr(input), sbufGetLength(input));
            tcpoverudpclientTunnelUpStreamPayload(configured, line, input);
            twfRequire(tcpoverudpclientUpdateKcp(ls, true), "data flush killed borrowed line");
            twfRequire(g_mtu_output_count >= (fec ? 4U : 3U), "data/parity output missing");
            twfRequire(g_mtu_max_output == effective + fec * 8, "full application chunk did not fill KCP packet");

            /* Feed many empty PUSH records: ACK aggregation must obey the same packet limit. */
            g_mtu_output_count = g_mtu_max_output = 0;
            for (unsigned seq = 0; seq < 100; ++seq)
            {
                uint8_t push[24] = {0};
                push[4]          = 81;
                push[6]          = 128;
                push[12]         = (uint8_t) seq;
                twfRequire(ikcp_input(ls->k_handle, (const char *) push, sizeof(push)) == 0, "ACK fixture rejected");
            }
            twfRequire(tcpoverudpclientUpdateKcp(ls, true), "ACK flush killed borrowed line");
            twfRequire(g_mtu_output_count > 0 && g_mtu_max_output > 24 + fec * 8, "aggregated ACK output missing");
            tcpoverudpclientLinestateDestroy(ls);
            twfLineDestroy(line);
            requireNoLiveKcpResources();
            twfWorkerEnvTeardown(&fixture.env);
            fixtureTeardown(&fixture);
            CORE_DEFAULT_MTU = 68;
        }
    }
    tunnelDestroy(inherited);
    CORE_DEFAULT_MTU = saved_default;
}

int main(void)
{
    caseAutomaticSendBufferLimit();
    caseFecShardBounds();
    caseMtuConfigurationAndOutput();
    caseInitializationFails(kInjectKcpTimer, false, "KCP interval timer creation fails");
    caseInitializationFails(kInjectFecEncoder, true, "FEC encoder creation fails");
    caseInitializationFails(kInjectFecDecoder, true, "FEC decoder creation fails");
    casePauseAfterAdmissionClosesReentrantly();
    caseAdvisorySignalsAndAckOnlyResume();

    printf("tcpoverudpclient_line_failure_test: all cases passed\n");
    return 0;
}
