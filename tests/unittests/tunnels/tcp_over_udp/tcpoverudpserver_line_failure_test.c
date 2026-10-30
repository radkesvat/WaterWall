/*
 * Covers: tcpoverudpserver line failure; the explicit inputs, callbacks and expected results below
 * define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseInitializationFails, caseAdvisoryPressure,
 * caseMtuConfigurationAndOutput
 * Checks: KCP resource settlement, repeated advisory notifications, complete payload ordering,
 * ACK-only pressure release, and reentrant Finish from locally generated Pause/Resume.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tcpoverudpserver_line_failure_test_unit
 */
/*
 * TcpOverUdpServer line-state initialization failure injection.
 *
 * Timer admission and FEC initialization can still refuse a line. Partial resources must be released exactly
 * once, the line state must return to zero, and only the previous side may be closed because the next tunnel
 * never received Init. KCP heap failures terminate at the WaterWall allocator and are not injected here.
 *
 * The one branch that is deliberately fatal, ikcp_setmtu() rejecting an MTU that tunnel creation already
 * validated, lives in tunnels_abort_runtime_test instead.
 */
#include "TcpOverUdpServer/structure.h"

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
    tunnel_t        *prev;
    tunnel_t        *kcp;
    tunnel_t        *next;
} tcpoverudp_fixture_t;

static void fixtureSetup(tcpoverudp_fixture_t *fixture, bool fec_enabled)
{
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, kFrameHeaderLength);

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

    fixture->prev->chain_index = 0;
    fixture->kcp->chain_index  = 1;
    fixture->next->chain_index = 2;
    fixture->kcp->fnInitU      = &tcpoverudpserverTunnelUpStreamInit;
    fixture->kcp->fnPauseU     = &tcpoverudpserverTunnelUpStreamPause;
    fixture->kcp->fnResumeU    = &tcpoverudpserverTunnelUpStreamResume;
    fixture->kcp->fnPayloadU   = &tcpoverudpserverTunnelUpStreamPayload;
    fixture->kcp->fnPayloadD   = &tcpoverudpserverTunnelDownStreamPayload;
    fixture->kcp->fnFinD       = &tcpoverudpserverTunnelDownStreamFinish;

    tcpoverudpserver_tstate_t *ts = tunnelGetState(fixture->kcp);

    ts->mtu                       = kTestMtu;
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
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->kcp);
    tunnelDestroy(fixture->next);
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
    twfRequireEqualU32(fixture.trace.next_init, 0, "the next tunnel received Init after initialization refusal");
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

static tcpoverudp_fixture_t *g_pressure_fixture;
static line_t               *g_pressure_line;
static unsigned              g_close_on_pressure;
static uint32_t              g_source_pauses;
static uint32_t              g_source_resumes;
static uint32_t              g_pressure_packets;
static char                  g_pressure_data[8];
static uint32_t              g_pressure_data_len;

static uint32_t readKcpU32(const uint8_t *p)
{
    return (uint32_t) p[0] | (uint32_t) p[1] << 8 | (uint32_t) p[2] << 16 | (uint32_t) p[3] << 24;
}

static void writeKcpU32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i)
    {
        p[i] = (uint8_t) (value >> (8 * i));
    }
}

static void serverCapturePressureOutput(tunnel_t *prev, line_t *line, sbuf_t *buf)
{
    discard        prev;
    const uint8_t *p         = sbufGetRawPtr(buf);
    uint32_t       remaining = sbufGetLength(buf);
    ++g_pressure_packets;
    while (remaining > 0)
    {
        twfRequire(remaining >= 24, "truncated KCP packet");
        uint32_t length = readKcpU32(p + 20);
        twfRequire(length <= remaining - 24, "truncated KCP frame");
        if (p[4] == 81 && length > 0 && p[24] == kFrameFlagData)
        {
            twfRequire(g_pressure_data_len + length - 1 < sizeof(g_pressure_data), "pressure capture overflow");
            memoryCopy(g_pressure_data + g_pressure_data_len, p + 25, length - 1);
            g_pressure_data_len += length - 1;
        }
        p += 24 + length;
        remaining -= 24 + length;
    }
    lineReuseBuffer(line, buf);
}

static void serverOwnerFinishesPressureClose(tunnel_t *prev, line_t *line)
{
    tcpoverudp_fixture_t *fixture = g_pressure_fixture;
    twfRequire(prev == fixture->prev && line == g_pressure_line, "unexpected pressure-close owner");
    ++fixture->trace.prev_finish;
    twfRequireLineStateZeroed(line, fixture->kcp, "pressure close left KCP state alive");
    lineDestroy(line);
}

static void serverCloseFromPressure(void)
{
    tcpoverudpserver_tstate_t *state = tunnelGetState(g_pressure_fixture->kcp);
    atomicStoreRelaxed(&state->stopping, true);
    tunnelDownStreamFin(g_pressure_fixture->kcp, g_pressure_line);
}

static void serverSourcePause(tunnel_t *next, line_t *line)
{
    tcpoverudp_fixture_t *fixture = g_pressure_fixture;
    twfRequire(next == fixture->next && line == g_pressure_line, "unexpected pressure Pause");
    ++g_source_pauses;
    twfRequireEqualText(g_pressure_data, "AB", "Pause re-entered before the complete original payload was sent");
    if (g_close_on_pressure == 1)
    {
        serverCloseFromPressure();
        return;
    }
    sbuf_t *nested = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    sbufSetLength(nested, 1);
    sbufWrite(nested, "C", 1);
    tunnelDownStreamPayload(fixture->kcp, line, nested);
}

static void serverSourceResume(tunnel_t *next, line_t *line)
{
    tcpoverudp_fixture_t *fixture = g_pressure_fixture;
    twfRequire(next == fixture->next && line == g_pressure_line, "unexpected pressure Resume");
    ++g_source_resumes;
    tcpoverudpserver_lstate_t *ls = lineGetState(line, fixture->kcp);
    twfRequire(! ls->source_paused && ikcp_waitsnd(ls->k_handle) == 0, "Resume preceded release of local KCP pressure");
    if (g_close_on_pressure == 2)
    {
        serverCloseFromPressure();
    }
}

static void caseAdvisoryPressure(unsigned close_on_pressure)
{
    twfSetCase("TcpOverUdpServer advisory pressure, ACK-only release and callback close");
    tcpoverudp_fixture_t fixture;
    fixtureSetup(&fixture, false);
    master_pool_t  *context_master = masterpoolCreateWithCapacity(8);
    generic_pool_t *contexts = genericpoolCreateWithDefaultAllocatorAndCapacity(context_master, sizeof(context_t), 8);
    GSTATE.shortcut_context_pools = &contexts;
    twf_line_pool_t line_pool;
    twfLinePoolSetup(&line_pool, fixture.kcp->lstate_size, 1);
    line_t *line = twfLinePoolCreateLine(&line_pool);
    tunnelUpStreamInit(fixture.kcp, line);
    tcpoverudpserver_lstate_t *ls = lineGetState(line, fixture.kcp);
    const uint32_t             initial_refs = twfLineRefCount(line);

    tunnelUpStreamPause(fixture.kcp, line);
    tunnelUpStreamPause(fixture.kcp, line);
    tunnelDownStreamPause(fixture.kcp, line);
    tunnelDownStreamPause(fixture.kcp, line);
    twfRequireEqualText(fixture.trace.seq, "IUUuu", "received Pause did not pass through repeatedly");
    twfRequire(! ls->source_paused, "received Pause changed locally generated pressure");

    g_pressure_fixture  = &fixture;
    g_pressure_line     = line;
    g_close_on_pressure = close_on_pressure;
    g_source_pauses = g_source_resumes = g_pressure_packets = g_pressure_data_len = 0;
    memoryZero(g_pressure_data, sizeof(g_pressure_data));
    fixture.prev->fnPayloadD         = serverCapturePressureOutput;
    fixture.prev->fnFinD             = serverOwnerFinishesPressureClose;
    fixture.next->fnPauseU           = serverSourcePause;
    fixture.next->fnResumeU          = serverSourceResume;
    tcpoverudpserver_tstate_t *state = tunnelGetState(fixture.kcp);
    state->kcp_send_buffer_limit     = 1;
    sbuf_t *input                    = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(input, 2);
    sbufWrite(input, "AB", 2);
    tunnelDownStreamPayload(fixture.kcp, line, input);
    twfRequireEqualU32(g_source_pauses, 1, "KCP pressure did not pause once after admission");

    if (close_on_pressure != 1)
    {
        twfRequire(tcpoverudpserverUpdateKcp(ls, true), "reentrant input flush closed the line");
        twfRequireEqualText(g_pressure_data, "ABC", "Pause re-entry reordered admitted KCP data");
        twfRequireEqualU32(g_source_pauses, 1, "ongoing local pressure duplicated Pause");
        const uint32_t packet_count = g_pressure_packets;
        sbuf_t        *ack          = bufferpoolGetSmallBuffer(fixture.env.pool);
        sbufSetLength(ack, 24);
        sbufWriteZeros(ack, 24);
        uint8_t *p = sbufGetMutablePtr(ack);
        p[4]       = 82;
        p[6]       = 128;
        writeKcpU32(p + 12, ls->k_handle->snd_nxt - 1);
        writeKcpU32(p + 16, ls->k_handle->snd_nxt);
        tunnelUpStreamPayload(fixture.kcp, line, ack);
        twfRequireEqualU32(g_pressure_packets, packet_count, "ACK-only release unexpectedly emitted a KCP packet");
        twfRequireEqualU32(g_source_resumes, 1, "ACK-only input failed to release local Pause");
    }

    if (close_on_pressure == 0)
    {
        twfRequire(tcpoverudpserverUpdateKcp(ls, false), "settled KCP update failed");
        twfRequireEqualU32(g_source_resumes, 1, "settled pressure duplicated Resume");
        fixture.next->fnResumeU = twfNextResume;
        tunnelUpStreamResume(fixture.kcp, line);
        tunnelUpStreamResume(fixture.kcp, line);
        tunnelDownStreamResume(fixture.kcp, line);
        tunnelDownStreamResume(fixture.kcp, line);
        twfRequireEqualText(fixture.trace.seq, "IUUuuRRrr", "received Resume did not pass through repeatedly");
        twfRequireEqualU32(twfLineRefCount(line), initial_refs, "pressure reconciliation leaked a line reference");
        twfRequire(tunnelIsActiveForLine(fixture.kcp, line), "KCP transform bypassed its ongoing protocol work");
        serverCloseFromPressure();
    }
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "pressure callback did not close the owned line exactly once");
    requireNoLiveKcpResources();
    twfRequireNoLeakedBuffers();
    g_pressure_fixture = NULL;
    g_pressure_line    = NULL;
    twfLinePoolTeardown(&line_pool);
    GSTATE.shortcut_context_pools = NULL;
    genericpoolDestroy(contexts);
    masterpoolMakeEmpty(context_master);
    masterpoolDestroy(context_master);
    twfWorkerEnvTeardown(&fixture.env);
    fixtureTeardown(&fixture);
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
    tunnel_t *t             = tcpoverudpserverTunnelCreate(&node);
    cJSON_Delete(settings);
    return t;
}

static void caseAutomaticSendBufferLimit(void)
{
    twfSetCase("automatic KCP pressure limit stays positive for a maximum send window");
    tunnel_t *configured = createMtuTunnel("{\"mtu\":1500,\"kcp-send-window\":2147483647}");
    twfRequire(configured != NULL, "maximum positive KCP window was rejected");
    tcpoverudpserver_tstate_t *ts     = tunnelGetState(configured);
    ikcpcb                     handle = {.snd_wnd = (IUINT32) ts->kcp_send_window, .rmt_wnd = 128};
    tcpoverudpserver_lstate_t  ls     = {.tunnel = configured, .k_handle = &handle};
    twfRequire(tcpoverudpserverGetKcpSendBufferLimit(&ls) == INT_MAX,
               "automatic pressure limit wrapped at the maximum configured window");
    handle.snd_wnd = INT_MAX - 138U;
    twfRequire(tcpoverudpserverGetKcpSendBufferLimit(&ls) == INT_MAX, "exact automatic limit changed");
    handle.snd_wnd = INT_MAX - 139U;
    twfRequire(tcpoverudpserverGetKcpSendBufferLimit(&ls) == INT_MAX - 1, "near-maximum automatic limit changed");
    handle.snd_wnd = 128;
    twfRequire(tcpoverudpserverGetKcpSendBufferLimit(&ls) == 266, "ordinary automatic limit changed");
    handle.snd_wnd            = INT_MAX;
    ts->kcp_send_buffer_limit = 7;
    twfRequire(tcpoverudpserverGetKcpSendBufferLimit(&ls) == 7, "explicit positive limit was not preserved");
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
                const tcpoverudpserver_tstate_t *ts = tunnelGetState(created);
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
    const tcpoverudpserver_tstate_t *inherited_state = tunnelGetState(inherited);
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
            tcpoverudpserver_tstate_t *ts        = tunnelGetState(configured);
            const unsigned             effective = min(budgets[i] - 28 - 8 * fec, 64000U);
            twfRequire(ts->mtu == budgets[i], "configured budget was narrowed or capped");
            twfRequire(tcpoverudpserverGetKcpMtu(ts) == (int) effective, "effective KCP MTU is incorrect");
            twfRequire(tcpoverudpserverGetKcpWriteMtu(ts) == (int) effective - 25, "application chunk is incorrect");
            twfRequire(tcpoverudpserverGetKcpMtu(inherited_state) == 1392, "another instance changed inherited MTU");

            tcpoverudp_fixture_t fixture;
            fixtureSetup(&fixture, fec != 0);
            master_pool_t  *context_master = masterpoolCreateWithCapacity(8);
            generic_pool_t *contexts =
                genericpoolCreateWithDefaultAllocatorAndCapacity(context_master, sizeof(context_t), 8);
            twfRequire(contexts != NULL, "context pool allocation failed");
            GSTATE.shortcut_context_pools = &contexts;

            tunnelDestroy(fixture.kcp);
            fixture.kcp = configured;
            tunnelBind(fixture.prev, fixture.kcp);
            tunnelBind(fixture.kcp, fixture.next);
            fixture.prev->fnPayloadD        = captureMtuOutput;
            fixture.next->fnPayloadU        = captureMtuOutput;
            CORE_DEFAULT_MTU                = 1000;
            line_t                    *line = twfLineCreate(configured->lstate_size);
            tcpoverudpserver_lstate_t *ls   = lineGetState(line, configured);
            twfRequire(tcpoverudpserverLinestateInitialize(ls, line, configured), "KCP line initialization failed");
            twfRequire(ls->k_handle->mtu == effective, "lazy KCP handle read global MTU or omitted outer headers");
            twfRequire(ls->k_handle->mss == effective - 24, "KCP MSS is incorrect");
            g_mtu_budget       = budgets[i];
            g_mtu_effective    = effective;
            g_mtu_fec          = fec * 8;
            g_mtu_output_count = g_mtu_max_output = 0;
            sbuf_t *input                         = bufferpoolGetLargeBuffer(fixture.env.pool);
            sbufSetLength(input, 2 * (effective - 25) + 1);
            memoryZero(sbufGetMutablePtr(input), sbufGetLength(input));
            tcpoverudpserverTunnelDownStreamPayload(configured, line, input);
            twfRequire(tcpoverudpserverUpdateKcp(ls, true), "data flush killed borrowed line");
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
            twfRequire(tcpoverudpserverUpdateKcp(ls, true), "ACK flush killed borrowed line");
            twfRequire(g_mtu_output_count > 0 && g_mtu_max_output > 24 + fec * 8, "aggregated ACK output missing");
            tcpoverudpserverLinestateDestroy(ls);
            twfLineDestroy(line);
            requireNoLiveKcpResources();
            GSTATE.shortcut_context_pools = NULL;
            genericpoolDestroy(contexts);
            masterpoolMakeEmpty(context_master);
            masterpoolDestroy(context_master);
            twfWorkerEnvTeardown(&fixture.env);
            fixtureTeardown(&fixture);
            CORE_DEFAULT_MTU = 68;
        }
    }
    tunnelDestroy(inherited);
    CORE_DEFAULT_MTU = saved_default;
}

#define TEST_RECEIVE_SERVER 1
#include "receive_cases.h"

int main(void)
{
    caseReceiveMessages();
    caseAutomaticSendBufferLimit();
    caseFecShardBounds();
    caseMtuConfigurationAndOutput();
    caseInitializationFails(kInjectKcpTimer, false, "KCP interval timer creation fails");
    caseInitializationFails(kInjectFecEncoder, true, "FEC encoder creation fails");
    caseInitializationFails(kInjectFecDecoder, true, "FEC decoder creation fails");
    caseAdvisoryPressure(0);
    caseAdvisoryPressure(1);
    caseAdvisoryPressure(2);

    printf("tcpoverudpserver_line_failure_test: all cases passed\n");
    return 0;
}
