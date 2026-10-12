/*
 * Covers: socks est flow; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: pendingBoundary, run
 * Checks: Transparent repeated TCP signals, ready output through Pause, handshake/FIFO ordering,
 * TCP retirement after setup, UDP boundary pressure, pending limits and callback-driven closure.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.socks5client_est_flow_unit; waterwall.socks5server_est_flow_unit
 */
#ifdef SOCKS_EST_SERVER
#include "Socks5Server/internal.h"
#define socksInit          socks5serverTunnelUpStreamInit
#define socksFinish        socks5serverTunnelUpStreamFinish
#define socksDownFinish    socks5serverTunnelDownStreamFinish
#define socksUp            socks5serverTunnelUpStreamPayload
#define socksDown          socks5serverTunnelDownStreamPayload
#define socksEst           socks5serverTunnelDownStreamEst
#define socksPause         socks5serverTunnelDownStreamPause
#define socksResume        socks5serverTunnelDownStreamResume
#define socksReceivePause  socks5serverTunnelUpStreamPause
#define socksReceiveResume socks5serverTunnelUpStreamResume
#define socksTstate        socks5server_tstate_t
#define socksLstate        socks5server_lstate_t
#else
#include "Socks5Client/internal.h"
#define socksInit          socks5clientTunnelUpStreamInit
#define socksFinish        socks5clientTunnelUpStreamFinish
#define socksDownFinish    socks5clientTunnelDownStreamFinish
#define socksUp            socks5clientTunnelUpStreamPayload
#define socksDown          socks5clientTunnelDownStreamPayload
#define socksEst           socks5clientTunnelDownStreamEst
#define socksPause         socks5clientTunnelDownStreamPause
#define socksResume        socks5clientTunnelDownStreamResume
#define socksReceivePause  socks5clientTunnelUpStreamPause
#define socksReceiveResume socks5clientTunnelUpStreamResume
#define socksTstate        socks5client_tstate_t
#define socksLstate        socks5client_lstate_t
#endif
#include "fixtures/failure/tunnel_line_failure_harness.h"

static tunnel_t *node, *prev, *next;
static line_t   *application, *transport;
static char      upstream[32], downstream[32];
static size_t    up_len, down_len;
static unsigned  est_count, greeting_count, command_count, reply_count, read_pause_count, read_resume_count;
static unsigned  source_pauses, source_resumes;
static unsigned  next_finishes;
static bool      close_in_est, pause_in_est, reenter_data, udp_case;
#ifndef SOCKS_EST_SERVER
static bool close_in_relay_pause, close_in_source_pause, reenter_source_pause, complete_in_source_pause;
#endif

static void repeatedSignals(void);

static void createTunnels(void)
{
    node = tunnelCreate(NULL, sizeof(socksTstate), sizeof(socksLstate));
    prev = tunnelCreate(NULL, 0, 0);
    next = tunnelCreate(NULL, 0, 0);
    twfRequire(node != NULL && prev != NULL && next != NULL, "SOCKS fixture tunnel allocation failed");
    prev->chain_index = 0;
    node->chain_index = 1;
    next->chain_index = 2;
    node->fnInitU     = socksInit;
    node->fnFinU      = socksFinish;
    node->fnFinD      = socksDownFinish;
    node->fnPayloadU  = socksUp;
    node->fnPayloadD  = socksDown;
    node->fnEstD      = socksEst;
    node->fnPauseD    = socksPause;
    node->fnResumeD   = socksResume;
    node->fnPauseU    = socksReceivePause;
    node->fnResumeU   = socksReceiveResume;
    tunnelBind(prev, node);
    tunnelBind(node, next);
}

static sbuf_t *bytes(line_t *l, const void *data, uint32_t len)
{
    sbuf_t *buf = bufferpoolGetBestFit(lineGetBufferPool(l), len, 300);
    sbufSetLength(buf, len);
    if (len)
        sbufWriteLarge(buf, data, len);
    return buf;
}

static void noop(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}
static void ownerFinish(tunnel_t *t, line_t *l)
{
    discard t;
    lineDestroy(l);
}
static void nextFinish(tunnel_t *t, line_t *l)
{
    discard t;
    ++next_finishes;
    if (! tunnelIsActiveForLine(node, l))
        twfRequireLineStateZeroed(l, node, "Finish revived retired SOCKS state");
}
static void readPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++read_pause_count;
#ifndef SOCKS_EST_SERVER
    if (close_in_relay_pause && lineGetDestinationAddressContext(l)->proto_udp)
        tunnelDownStreamFin(node, l);
#endif
}

static void readResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++read_resume_count;
}

static void sourcePause(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == application, "source Pause escaped on an internal SOCKS line");
    ++source_pauses;
#ifndef SOCKS_EST_SERVER
    if (source_pauses != 1)
        return;
    twfRequire(tunnelIsActiveForLine(node, l), "SOCKS retired before publishing its protocol hold");
    socksLstate *ls = lineGetState(l, node);
    twfRequire(ls->source_pause_sent, "source Pause preceded notification publication");
    if (close_in_source_pause)
    {
        tunnelUpStreamFin(node, l);
        lineDestroy(l);
        return;
    }
    if (complete_in_source_pause)
    {
        tunnelDownStreamEst(node, transport);
        const uint8_t method[] = {5, 0};
        tunnelDownStreamPayload(node, transport, bytes(transport, method, sizeof(method)));
        const uint8_t response[] = {5, 0, 0, 1, 127, 0, 0, 1, 0, 80};
        tunnelDownStreamPayload(node, transport, bytes(transport, response, sizeof(response)));
        twfRequire(! tunnelIsActiveForLine(node, l), "nested SOCKS setup did not retire before source Pause returned");
        twfRequireLineStateZeroed(l, node, "nested retirement left SOCKS state live");
        return;
    }
    if (reenter_source_pause)
    {
        twfRequire(bufferqueueGetBufCount(&ls->pending_up) == 1, "source Pause preceded older input admission");
        tunnelUpStreamPayload(node, l, bytes(l, "D", 1));
        tunnelDownStreamResume(node, transport);
        twfRequire(source_resumes == (udp_case ? 0U : 1U), "transport Resume violated exact-line pressure mapping");
    }
#endif
}
static void sourceResume(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == application, "source Resume escaped on an internal SOCKS line");
#ifndef SOCKS_EST_SERVER
    socksLstate *ls = lineGetState(l, node);
    if (udp_case)
        twfRequire(! ls->source_pause_sent && ! ls->next_paused && ! ls->draining_up &&
                       bufferqueueGetBufCount(&ls->pending_up) == 0 && ls->phase == kSocks5ClientPhaseEstablished,
                   "UDP source resumed before protocol backlog/transport hold cleared");
#endif
    ++source_resumes;
}

static void upstreamData(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard        t;
    const uint8_t *p      = sbufGetRawPtr(buf);
    uint32_t       length = sbufGetLength(buf);
#ifndef SOCKS_EST_SERVER
    if (length >= 3 && p[0] == 5)
    {
        twfRequire(est_count != 0, "SOCKS greeting preceded transport Est");
        if (length <= 4)
            ++greeting_count;
        else
            ++command_count;
        lineReuseBuffer(l, buf);
        return;
    }
    if (udp_case)
    {
        twfRequire(length == 11, "UDP application payload lost SOCKS wrapping");
        p += 10;
        length = 1;
    }
#endif
    twfRequire(up_len + length <= sizeof(upstream), "upstream capture overflow");
    memoryCopy(upstream + up_len, p, length);
    up_len += length;
    lineReuseBuffer(l, buf);
    if (reenter_data)
    {
        reenter_data = false;
        twfRequire(tunnelIsActiveForLine(node, application), "SOCKS retired inside its FIFO drain");
        tunnelUpStreamPayload(node, application, bytes(application, "C", 1));
        tunnelDownStreamPause(node, l);
        twfRequire(tunnelIsActiveForLine(node, application), "nested FIFO input retired an active drain");
    }
}

static void downstreamData(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard        t;
    const uint32_t length = sbufGetLength(buf);
    const uint8_t *p      = sbufGetRawPtr(buf);
#ifdef SOCKS_EST_SERVER
    if (length >= 2 && p[0] == 5)
    {
        twfRequire(tunnelIsActiveForLine(node, l), "SOCKS server retired before protocol reply delivery");
        if (length == 10)
        {
            twfRequire(est_count == 1 && down_len == 0, "SOCKS reply order changed");
            ++reply_count;
        }
        lineReuseBuffer(l, buf);
        return;
    }
    twfRequire(reply_count == 1, "backend body preceded command reply");
#endif
    twfRequire(down_len + length <= sizeof(downstream), "downstream capture overflow");
    memoryCopy(downstream + down_len, p, length);
    down_len += length;
    lineReuseBuffer(l, buf);
}

static void established(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == application, "Est escaped on an internal line");
    ++est_count;
    if (est_count != 1)
        return;
    twfRequire(tunnelIsActiveForLine(node, l), "SOCKS retired before first transport Est");
    if (close_in_est)
    {
        tunnelUpStreamFin(node, l);
        lineDestroy(l);
        return;
    }
    if (pause_in_est)
        tunnelUpStreamPause(node, application);
    tunnelUpStreamPayload(node, application, bytes(application, "B", 1));
}

static void initializeNext(tunnel_t *t, line_t *l)
{
    discard t;
    transport = l;
#ifdef SOCKS_EST_SERVER
    // A real synchronous Init may deliver backend bytes and Est before returning.
    tunnelDownStreamPayload(node, l, bytes(l, "D", 1));
    tunnelDownStreamEst(node, l);
    if (lineIsAlive(l))
    {
        twfRequire(tunnelIsActiveForLine(node, l), "SOCKS server retired inside next Init");
        repeatedSignals();
    }
#else
    if (lineGetDestinationAddressContext(l)->proto_udp)
        tunnelDownStreamEst(node, l);
#endif
}

static void repeatedSignals(void)
{
    unsigned pauses = source_pauses, resumes = source_resumes;
    tunnelDownStreamPause(node, application);
    tunnelDownStreamPause(node, application);
    tunnelDownStreamResume(node, application);
    tunnelDownStreamResume(node, application);
    twfRequire(source_pauses == pauses + 2 && source_resumes == resumes + 2,
               "TCP downstream Pause/Resume suppressed repeated notifications");
    pauses  = read_pause_count;
    resumes = read_resume_count;
    tunnelUpStreamPause(node, application);
    tunnelUpStreamPause(node, application);
    tunnelUpStreamResume(node, application);
    tunnelUpStreamResume(node, application);
    twfRequire(read_pause_count == pauses + 2 && read_resume_count == resumes + 2,
               "TCP upstream Pause/Resume suppressed repeated notifications");
}

static void bypassedTraffic(void)
{
    twfRequire(! tunnelIsActiveForLine(node, application), "settled TCP SOCKS setup did not retire");
    twfRequireLineStateZeroed(application, node, "retired SOCKS retained protocol state");
    size_t previous_up = up_len, previous_down = down_len;
    tunnelUpStreamPayload(node, application, bytes(application, "Q", 1));
    tunnelDownStreamPayload(node, application, bytes(application, "R", 1));
    twfRequire(up_len == previous_up + 1 && upstream[previous_up] == 'Q' && down_len == previous_down + 1 &&
                   downstream[previous_down] == 'R',
               "retired SOCKS changed subsequent payload delivery");
    twfRequireLineStateZeroed(application, node, "subsequent payload revived retired SOCKS state");
}

static void run(bool close_now, bool udp)
{
    twfSetCase("SOCKS TCP advisory signals and ready FIFO release preserve UDP boundary control");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 300);
    createTunnels();
    prev->fnEstD     = established;
    prev->fnFinD     = ownerFinish;
    prev->fnPayloadD = downstreamData;
    prev->fnPauseD  = sourcePause;
    prev->fnResumeD = sourceResume;
    source_pauses = source_resumes = next_finishes = 0;
    next->fnInitU = initializeNext;
    next->fnFinU                                   = nextFinish;
    next->fnResumeU                                = readResume;
    next->fnPauseU                 = readPause;
    next->fnPayloadU               = upstreamData;
    tunnel_chain_t *chain          = tunnelchainCreate(1);
    chain->sum_line_state_size     = node->lstate_size;
    tunnelchainFinalize(chain);
    node->chain = chain;
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, node->lstate_size, 1);
    application = twfLinePoolCreateLine(&lines);
    lineRef(application);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(application), IP_PROTO_TCP);
    up_len = down_len = est_count = greeting_count = command_count = reply_count                    = read_pause_count =
        read_resume_count                                                                           = 0;
    close_in_est                                                                                    = close_now;
    pause_in_est                                                                                    = true;
    reenter_data                                                                                    = false;
    udp_case                                                                                        = udp;
    socksTstate *ts = tunnelGetState(node);
#ifdef SOCKS_EST_SERVER
    ts->no_auth       = true;
    ts->allow_connect = true;
    tunnelUpStreamInit(node, application);
    const uint8_t method[] = {5, 1, 0};
    tunnelUpStreamPayload(node, application, bytes(application, method, sizeof(method)));
    twfRequire(tunnelIsActiveForLine(node, application), "SOCKS server retired before CONNECT request");
    const uint8_t request[] = {5, 1, 0, 1, 127, 0, 0, 1, 0, 80, 'A'};
    tunnelUpStreamPayload(node, application, bytes(application, request, sizeof(request)));
    if (! close_now)
    {
        twfRequire(est_count == 1 && reply_count == 1 && down_len == 1 && downstream[0] == 'D',
                   "advisory Pause withheld command reply or backend body");
        twfRequire(up_len == 2 && memoryEqual(upstream, "AB", 2), "Init/Est reentry overtook original request tail");
        tunnelDownStreamEst(node, application);
        twfRequire(est_count == 2 && reply_count == 1 && down_len == 1, "repeated Est changed SOCKS reply/body work");
        bypassedTraffic();
        repeatedSignals();
    }
#else
    ts->target_addr_source = ts->target_port_source = kDvsConstant;
    ts->protocol                                    = udp ? kSocks5ClientProtocolUdp : kSocks5ClientProtocolTcp;
    ip_addr_t ip;
    twfRequire(ipaddr_aton("127.0.0.1", &ip), "fixture address");
    addresscontextSetIpPort(&ts->target_addr, &ip, 80);
    tunnelUpStreamInit(node, application);
    line_t *control = transport;
    tunnelUpStreamPayload(node, application, bytes(application, "A", 1));
    if (close_in_source_pause)
    {
        twfRequire(! lineIsAlive(application) && source_pauses == 1 && est_count == 0,
                   "source Pause close did not settle exact association");
        goto client_done;
    }
    if (complete_in_source_pause)
    {
        twfRequire(up_len == 2 && memoryEqual(upstream, "AB", 2) && source_pauses == 1 && source_resumes == 1 &&
                       greeting_count == 1 && command_count == 1,
                   "nested setup lost queued input or protocol hold release");
        bypassedTraffic();
        repeatedSignals();
        goto client_done;
    }
    twfRequire(source_pauses == 1 && source_resumes == (reenter_source_pause && ! udp ? 1U : 0U),
               "protocol wait lost its advisory source pressure");
    twfRequire(up_len == 0 && greeting_count == 0, "application escaped before negotiation");
    if (! udp)
        tunnelDownStreamPause(node, control);
    tunnelDownStreamEst(node, control);
    if (! close_now)
    {
        twfRequire(est_count == 1 && greeting_count == 1 && up_len == 0, "transport Est waited for handshake");
        tunnelDownStreamEst(node, control);
        twfRequire(est_count == (udp ? 1U : 2U) && greeting_count == 1,
                   "repeated Est lost exact-line notification mapping or repeated greeting");
        const uint8_t method[] = {5, 0};
        tunnelDownStreamPayload(node, control, bytes(control, method, sizeof(method)));
        twfRequire(tunnelIsActiveForLine(node, application), "SOCKS client retired before command reply");
        twfRequire(command_count == 1 && read_pause_count == (udp ? 0U : 1U),
                   "application Pause violated exact-line handshake mapping");
        if (! udp)
            repeatedSignals();
        tunnelDownStreamPause(node, control);
        const uint8_t response[] = {5, 0, 0, 1, 127, 0, 0, 1, 0, 80};
        reenter_data             = ! udp;
        tunnelDownStreamPayload(node, control, bytes(control, response, sizeof(response)));
        if (close_in_relay_pause)
        {
            twfRequire(! lineIsAlive(application), "relay Pause Finish did not close the association");
            goto client_done;
        }
        if (udp)
        {
            twfRequire(tunnelIsActiveForLine(node, application) && tunnelIsActiveForLine(node, control) &&
                           tunnelIsActiveForLine(node, transport),
                       "SOCKS UDP boundary retired protocol state");
            twfRequire(up_len == 0 && est_count == 1, "UDP protocol completion ignored owned transport pressure");
            reenter_data = true;
            tunnelDownStreamResume(node, control);
            twfRequire(up_len == 1 && upstream[0] == 'A', "UDP drain ignored nested Pause");
            tunnelDownStreamResume(node, transport);
        }
        twfRequire(up_len == (reenter_source_pause ? 4U : 3U) &&
                       memoryEqual(upstream, reenter_source_pause ? "ADBC" : "ABC", up_len),
                   "nested application input overtook FIFO");
        twfRequire(source_pauses == (udp ? 1U : 6U) && source_resumes == (udp                    ? 1U
                                                                          : reenter_source_pause ? 4U
                                                                                                 : 3U),
                   "protocol backlog lost local pressure release or external notifications");
        if (! udp)
        {
            bypassedTraffic();
            repeatedSignals();
        }
    }
client_done:
    addresscontextReset(&ts->target_addr);
#endif
    if (lineIsAlive(application))
    {
        tunnelUpStreamFin(node, application);
        if (! udp)
            twfRequire(next_finishes == 1, "TCP Finish did not reach the next tunnel exactly once");
        lineDestroy(application);
    }
    twfRequire(! lineIsAlive(application), "Est callback close left line alive");
    lineUnref(application);
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&lines);
    tunnelchainDestroy(chain);
    tunnelDestroy(next);
    tunnelDestroy(prev);
    tunnelDestroy(node);
    twfWorkerEnvTeardown(&env);
}

static void discardPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    lineReuseBuffer(l, buf);
}

static void pendingBoundary(bool entries)
{
    twfSetCase("SOCKS pending queue accepts equality and settles one-over refusal");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 300);
    createTunnels();
    prev->fnFinD   = ownerFinish;
    prev->fnPauseD = prev->fnResumeD = noop;
    prev->fnPayloadD                 = discardPayload;
    next->fnFinU                     = noop;
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, node->lstate_size, 1);
    application = twfLinePoolCreateLine(&lines);
    lineRef(application);
    socksLstate *ls = lineGetState(application, node);
#ifdef SOCKS_EST_SERVER
    socks5serverLinestateInitialize(ls, node, application, kSocks5ServerLineKindControlTcp);
    ls->phase             = kSocks5ServerPhaseConnectWaitEst;
    ls->next_initializing = true;
    const uint32_t byte_limit = 1024U * 1024U;
#else
    socks5clientLinestateInitialize(
        ls, node, application, entries ? kSocks5ClientLineKindUdpApplication : kSocks5ClientLineKindDirect);
    // Empty UDP is valid and must consume an entry even though its byte cost is zero.
    ls->kind                  = entries ? kSocks5ClientLineKindUdpApplication : kSocks5ClientLineKindDirect;
    const uint32_t byte_limit = 2U * 1024U * 1024U;
#endif
    const unsigned count = entries ? 1024 : 1;
    for (unsigned i = 0; i < count; ++i)
    {
#ifdef SOCKS_EST_SERVER
        const uint32_t length = entries ? 1 : byte_limit;
#else
        const uint32_t length = entries ? 0 : byte_limit;
#endif
        sbuf_t *buf = bufferpoolGetBestFit(env.pool, length, 300);
        sbufSetLength(buf, length);
        tunnelUpStreamPayload(node, application, buf);
    }
    twfRequire(lineIsAlive(application) && bufferqueueGetBufCount(&ls->pending_up) == count,
               "SOCKS refused exact pending boundary");
#ifdef SOCKS_EST_SERVER
    const size_t expected_bytes = entries ? count : byte_limit;
#else
    const size_t expected_bytes = entries ? 0 : byte_limit;
#endif
    twfRequire(bufferqueueGetBufLen(&ls->pending_up) == expected_bytes, "SOCKS pending byte accounting changed");
    tunnelUpStreamPayload(node, application, bytes(application, "X", 1));
    twfRequire(! lineIsAlive(application), "SOCKS overflow left borrowed owner alive");
    twfRequireLineStateZeroed(application, node, "SOCKS overflow left protocol state alive");
    lineUnref(application);
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&lines);
    tunnelDestroy(next);
    tunnelDestroy(prev);
    tunnelDestroy(node);
    twfWorkerEnvTeardown(&env);
}

int main(void)
{
    pendingBoundary(false);
    pendingBoundary(true);
    run(false, false);
    run(true, false);
#ifndef SOCKS_EST_SERVER
    run(false, true);
    run(true, true);
    complete_in_source_pause = true;
    run(false, false);
    complete_in_source_pause = false;
    reenter_source_pause = true;
    run(false, false);
    run(false, true);
    reenter_source_pause  = false;
    close_in_source_pause = true;
    run(false, false);
    run(false, true);
    close_in_source_pause = false;
    close_in_relay_pause  = true;
    run(false, true);
#endif
    return 0;
}
