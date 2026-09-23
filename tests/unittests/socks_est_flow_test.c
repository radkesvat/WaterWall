#ifdef SOCKS_EST_SERVER
#include "Socks5Server/structure.h"
#define socksInit          socks5serverTunnelUpStreamInit
#define socksFinish        socks5serverTunnelUpStreamFinish
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
#include "Socks5Client/structure.h"
#define socksInit          socks5clientTunnelUpStreamInit
#define socksFinish        socks5clientTunnelUpStreamFinish
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
#include "tunnel_line_failure_harness.h"

static tunnel_t *node, *prev, *next;
static line_t   *app, *transport;
static char      upstream[32], downstream[32];
static size_t    up_len, down_len;
static unsigned  est_count, greeting_count, command_count, reply_count, read_pause_count;
static bool      close_in_est, pause_in_est, reenter_data, udp_case;
#ifndef SOCKS_EST_SERVER
static bool     close_in_relay_pause, close_in_source_pause, reenter_source_pause;
static unsigned source_pauses, source_resumes;
#endif

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
static void readPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++read_pause_count;
#ifndef SOCKS_EST_SERVER
    if (close_in_relay_pause && lineGetDestinationAddressContext(l)->proto_udp)
        socks5clientTunnelDownStreamFinish(node, l);
#endif
}

#ifndef SOCKS_EST_SERVER
static void sourcePause(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == app, "source Pause escaped on an internal SOCKS line");
    ++source_pauses;
    socksLstate *ls = lineGetState(l, node);
    twfRequire(ls->source_pause_sent, "source Pause preceded notification publication");
    if (close_in_source_pause)
    {
        socksFinish(node, l);
        lineDestroy(l);
        return;
    }
    if (reenter_source_pause)
    {
        twfRequire(bufferqueueGetBufCount(&ls->pending_up) == 1, "source Pause preceded older input admission");
        socksUp(node, l, bytes(l, "D", 1));
        socksResume(node, transport);
        twfRequire(source_resumes == 0, "transport Resume released source before protocol readiness");
    }
}
static void sourceResume(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == app, "source Resume escaped on an internal SOCKS line");
    socksLstate *ls = lineGetState(l, node);
    twfRequire(! ls->source_pause_sent && ! ls->next_paused && ! ls->draining_up &&
                   bufferqueueGetBufCount(&ls->pending_up) == 0 && ls->phase == kSocks5ClientPhaseEstablished,
               "source resumed before protocol backlog/transport hold cleared");
    ++source_resumes;
}
#endif

static void upstreamData(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard        t;
    const uint8_t *p      = sbufGetRawPtr(buf);
    uint32_t       length = sbufGetLength(buf);
#ifndef SOCKS_EST_SERVER
    if (length >= 3 && p[0] == 5)
    {
        twfRequire(est_count == 1, "SOCKS greeting preceded transport Est");
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
        socksUp(node, app, bytes(app, "C", 1));
        socksPause(node, l);
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
    twfRequire(l == app, "Est escaped on an internal line");
    ++est_count;
    if (close_in_est)
    {
        socksFinish(node, l);
        lineDestroy(l);
        return;
    }
    if (pause_in_est)
        socksReceivePause(node, app);
    socksUp(node, app, bytes(app, "B", 1));
}

static void initializeNext(tunnel_t *t, line_t *l)
{
    discard t;
    transport = l;
#ifdef SOCKS_EST_SERVER
    // A real synchronous Init may deliver backend bytes and Est before returning.
    socksDown(node, l, bytes(l, "D", 1));
    socksEst(node, l);
#else
    if (lineGetDestinationAddressContext(l)->proto_udp)
        socksEst(node, l);
#endif
}

static void run(bool close_now, bool udp)
{
    twfSetCase("SOCKS transport Est is independent of handshake and Pause-aware FIFO release");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 300);
    node = tunnelCreate(NULL, sizeof(socksTstate), sizeof(socksLstate));
    prev = tunnelCreate(NULL, 0, 0);
    next = tunnelCreate(NULL, 0, 0);
    tunnelBind(prev, node);
    tunnelBind(node, next);
    prev->fnEstD     = established;
    prev->fnFinD     = ownerFinish;
    prev->fnPayloadD = downstreamData;
    prev->fnPauseD = prev->fnResumeD = noop;
#ifndef SOCKS_EST_SERVER
    prev->fnPauseD  = sourcePause;
    prev->fnResumeD = sourceResume;
    source_pauses = source_resumes = 0;
#endif
    next->fnInitU = initializeNext;
    next->fnFinU = next->fnResumeU = noop;
    next->fnPauseU                 = readPause;
    next->fnPayloadU               = upstreamData;
    tunnel_chain_t *chain          = tunnelchainCreate(1);
    chain->sum_line_state_size     = node->lstate_size;
    tunnelchainFinalize(chain);
    node->chain = chain;
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, node->lstate_size, 1);
    app = twfLinePoolCreateLine(&lines);
    lineRef(app);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(app), IP_PROTO_TCP);
    up_len = down_len = est_count = greeting_count = command_count = reply_count = read_pause_count = 0;
    close_in_est                                                                                    = close_now;
    pause_in_est                                                                                    = true;
    reenter_data                                                                                    = false;
    udp_case                                                                                        = udp;
    socksTstate *ts = tunnelGetState(node);
#ifdef SOCKS_EST_SERVER
    ts->no_auth       = true;
    ts->allow_connect = true;
    socksInit(node, app);
    const uint8_t method[] = {5, 1, 0};
    socksUp(node, app, bytes(app, method, sizeof(method)));
    const uint8_t request[] = {5, 1, 0, 1, 127, 0, 0, 1, 0, 80, 'A'};
    socksUp(node, app, bytes(app, request, sizeof(request)));
    if (! close_now)
    {
        twfRequire(est_count == 1 && reply_count == 0 && down_len == 0, "paused Est emitted command reply/body");
        twfRequire(up_len == 2 && memoryEqual(upstream, "AB", 2), "Init/Est reentry overtook original request tail");
        socksEst(node, app);
        twfRequire(est_count == 1, "duplicate backend Est escaped");
        socksReceiveResume(node, app);
        twfRequire(reply_count == 1 && down_len == 1 && downstream[0] == 'D', "Resume lost reply/body order");
    }
#else
    ts->target_addr_source = ts->target_port_source = kDvsConstant;
    ts->protocol                                    = udp ? kSocks5ClientProtocolUdp : kSocks5ClientProtocolTcp;
    ip_addr_t ip;
    twfRequire(ipaddr_aton("127.0.0.1", &ip), "fixture address");
    addresscontextSetIpPort(&ts->target_addr, &ip, 80);
    socksInit(node, app);
    line_t *control = transport;
    socksUp(node, app, bytes(app, "A", 1));
    if (close_in_source_pause)
    {
        twfRequire(! lineIsAlive(app) && source_pauses == 1 && est_count == 0,
                   "source Pause close did not settle exact association");
        goto client_done;
    }
    twfRequire(source_pauses == 1 && source_resumes == 0, "protocol wait did not stop new source work");
    twfRequire(up_len == 0 && greeting_count == 0, "application escaped before negotiation");
    socksEst(node, control);
    if (! close_now)
    {
        twfRequire(est_count == 1 && greeting_count == 1 && up_len == 0, "transport Est waited for handshake");
        socksEst(node, control);
        twfRequire(est_count == 1 && greeting_count == 1, "duplicate transport Est repeated greeting");
        const uint8_t method[] = {5, 0};
        socksDown(node, control, bytes(control, method, sizeof(method)));
        twfRequire(command_count == 1 && read_pause_count == 0, "application Pause blocked handshake progress");
        socksPause(node, control);
        const uint8_t response[] = {5, 0, 0, 1, 127, 0, 0, 1, 0, 80};
        socksDown(node, control, bytes(control, response, sizeof(response)));
        if (close_in_relay_pause)
        {
            twfRequire(! lineIsAlive(app), "relay Pause Finish did not close the association");
            goto client_done;
        }
        twfRequire(up_len == 0 && est_count == 1, "protocol completion drained through Pause or repeated Est");
        reenter_data = true;
        socksResume(node, control);
        twfRequire(up_len == 1 && upstream[0] == 'A', "first drain ignored nested Pause");
        socksResume(node, transport);
        twfRequire(up_len == (reenter_source_pause ? 4U : 3U) &&
                       memoryEqual(upstream, reenter_source_pause ? "ADBC" : "ABC", up_len),
                   "nested application input overtook FIFO");
        twfRequire(source_pauses == 1 && source_resumes == 1, "protocol backlog lost aggregate pressure release");
    }
client_done:
    addresscontextReset(&ts->target_addr);
#endif
    if (lineIsAlive(app))
    {
        socksFinish(node, app);
        lineDestroy(app);
    }
    twfRequire(! lineIsAlive(app), "Est callback close left line alive");
    lineUnref(app);
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
    node = tunnelCreate(NULL, sizeof(socksTstate), sizeof(socksLstate));
    prev = tunnelCreate(NULL, 0, 0);
    next = tunnelCreate(NULL, 0, 0);
    tunnelBind(prev, node);
    tunnelBind(node, next);
    prev->fnFinD   = ownerFinish;
    prev->fnPauseD = prev->fnResumeD = noop;
    prev->fnPayloadD                 = discardPayload;
    next->fnFinU                     = noop;
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, node->lstate_size, 1);
    app = twfLinePoolCreateLine(&lines);
    lineRef(app);
    socksLstate *ls = lineGetState(app, node);
#ifdef SOCKS_EST_SERVER
    socks5serverLinestateInitialize(ls, node, app, kSocks5ServerLineKindControlTcp);
    ls->phase             = kSocks5ServerPhaseConnectWaitEst;
    ls->next_initializing = true;
    const uint32_t byte_limit = 1024U * 1024U;
#else
    socks5clientLinestateInitialize(ls, node, app);
    // Empty UDP is valid and must consume an entry even though its byte cost is zero.
    ls->kind = entries ? kSocks5ClientLineKindUdpApp : kSocks5ClientLineKindDirect;
    const uint32_t byte_limit = 2U * 1024U * 1024U;
#endif
    const unsigned count = entries ? 1024 : 1;
    for (unsigned i = 0; i < count; ++i)
    {
        sbuf_t *buf = bufferpoolGetBestFit(env.pool, entries ? 0 : byte_limit, 300);
        sbufSetLength(buf, entries ? 0 : byte_limit);
        socksUp(node, app, buf);
    }
    twfRequire(lineIsAlive(app) && bufferqueueGetBufCount(&ls->pending_up) == count,
               "SOCKS refused exact pending boundary");
    twfRequire(bufferqueueGetBufLen(&ls->pending_up) == (entries ? 0 : byte_limit),
               "SOCKS pending byte accounting changed");
    socksUp(node, app, bytes(app, "X", 1));
    twfRequire(! lineIsAlive(app), "SOCKS overflow left borrowed owner alive");
    twfRequireLineStateZeroed(app, node, "SOCKS overflow left protocol state alive");
    lineUnref(app);
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
