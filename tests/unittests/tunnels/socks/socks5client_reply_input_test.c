/*
 * Covers: socks5client reply input; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: Large/reentrant bodies, split address/reply boundaries, UDP frames, malformed replies and mixed
 * pipe-prefix handshakes.
 * Checks: Exact greeting/auth/command and body bytes, FIFO release, capacity refusal, same splice buffer
 * in ready TCP and ordinary UDP/control read preferences.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.socks5client_reply_input_unit
 */
#include "Socks5Client/internal.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

#if WW_HAVE_SPLICE
#include <unistd.h>
#endif

static tunnel_t        *client, *prev, *next;
static twf_worker_env_t env;
static twf_line_pool_t  lines;
static tunnel_chain_t  *chain;
static line_t          *application, *control, *relay;
static bool             authenticate, automatic, pause_body, inject_body, close_body, close_request;
static bool             splice_replies, ordinary_up, ordinary_down;
static sbuf_t          *expected_up, *expected_down;
static unsigned         greetings, auths, commands, established, finishes, request_depth, max_request_depth;
static unsigned         body_depth, max_body_depth, response_rounds, read_pauses, read_resumes;
static size_t           down_length, up_length;
static uint8_t          downstream[3 * 1024 * 1024];
static uint8_t          upstream[3 * 1024 * 1024];
static const uint8_t    command_reply[] = {5, 0, 0, 1, 127, 0, 0, 1, 0x23, 0x28};

static sbuf_t *bytes(const void *data, size_t len)
{
    sbuf_t *b = bufferpoolGetBestFit(env.pool, (uint32_t) len, 300);
    sbufSetLength(b, (uint32_t) len);
    if (len)
        memoryCopy(sbufGetMutablePtr(b), data, len);
    return b;
}
#if WW_HAVE_SPLICE
static sbuf_t *spliceBytes(const void *data, uint32_t length, uint32_t prefix)
{
    sbuf_t *b = bufferpoolGetSpliceBuffer(env.pool);
    twfRequire(b != NULL && prefix <= length && prefix <= sbufGetLeftCapacity(b), "splice buffer geometry");
    const uint8_t *raw  = data;
    uint32_t       body = length - prefix;
    uint32_t       sent = 0;
    while (sent < body)
    {
        ssize_t n = write(sbufSpliceMetadata(b).pipefd[1], raw + prefix + sent, body - sent);
        if (n < 0 && errno == EINTR)
            continue;
        twfRequire(n > 0, "populate private payload pipe");
        sent += (uint32_t) n;
    }
    b->capacity = b->l_pad + body;
    sbufSetLength(b, body);
    if (prefix)
    {
        sbufShiftLeft(b, prefix);
        memoryCopy(sbufGetMutablePtr(b), raw, prefix);
    }
    return b;
}
static void deliverSplice(const void *data, uint32_t length, uint32_t prefix)
{
    socks5clientTunnelDownStreamPayload(client, control, spliceBytes(data, length, prefix));
}
#endif
static void deliver(const void *data, size_t len)
{
#if WW_HAVE_SPLICE
    if (splice_replies)
    {
        deliverSplice(data, (uint32_t) len, (uint32_t) min(len / 2, 32));
        return;
    }
#endif
    socks5clientTunnelDownStreamPayload(client, control, bytes(data, len));
}
static void noop(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}
static void ownerFinish(tunnel_t *t, line_t *l)
{
    discard t;
    ++finishes;
    lineDestroy(l);
}
static void est(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == application, "Est escaped on internal line");
    ++established;
}
static void readPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++read_pauses;
}
static void readResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++read_resumes;
}
static void down(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    ++body_depth;
    if (body_depth > max_body_depth)
        max_body_depth = body_depth;
    size_t n = sbufGetLength(b);
    twfRequire(n <= sizeof(downstream) - down_length, "capture overflow");
    if (expected_down)
    {
        twfRequire(b == expected_down && sbufIsSplice(b), "ready downstream replaced opaque splice buffer");
        expected_down = NULL;
    }
    if (ordinary_down)
        twfRequire(! sbufIsSplice(b), "parsed payload was not materialized");
    sbufReadRangeToMemory(b, downstream + down_length, (uint32_t) n);
    down_length += n;
    lineReuseBuffer(l, b);
    if (close_body)
    {
        socks5clientTunnelUpStreamFinish(client, l);
        lineDestroy(l);
    }
    else
    {
        if (pause_body)
        {
            pause_body = false;
            socks5clientTunnelUpStreamPause(client, l);
        }
        if (inject_body)
        {
            inject_body = false;
            deliver("B", 1);
        }
        if (response_rounds)
        {
            --response_rounds;
            socks5clientTunnelUpStreamPayload(client, l, bytes("Q", 1));
        }
    }
    --body_depth;
}
static void up(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    ++request_depth;
    if (request_depth > max_request_depth)
        max_request_depth = request_depth;
    size_t n = sbufGetLength(b);
    twfRequire(n <= sizeof(upstream) - up_length, "upstream capture overflow");
    if (ordinary_up)
        twfRequire(! sbufIsSplice(b), "UDP framing retained splice storage");
    sbufReadRangeToMemory(b, upstream + up_length, (uint32_t) n);
    const uint8_t *p        = upstream + up_length;
    bool           greeting = n >= 3 && n <= 4 && p[0] == 5;
    bool           auth     = n >= 3 && p[0] == 1;
    bool           command  = n >= 10 && p[0] == 5;
    if (greeting)
        ++greetings;
    else if (auth)
        ++auths;
    else if (command)
        ++commands;
    else
    {
        if (expected_up)
        {
            twfRequire(b == expected_up && sbufIsSplice(b), "upstream replaced opaque splice buffer");
            expected_up = NULL;
        }
        up_length += n;
    }
    lineReuseBuffer(l, b);
    if (close_request && command)
        socks5clientTunnelDownStreamFinish(client, l);
    else if (automatic)
    {
        if (greeting)
        {
            const uint8_t r[] = {5, authenticate ? 2 : 0};
            deliver(r, sizeof(r));
        }
        else if (auth)
        {
            const uint8_t r[] = {1, 0};
            deliver(r, sizeof(r));
        }
        else if (command)
            deliver(command_reply, sizeof(command_reply));
        else
            deliver("R", 1);
    }
    --request_depth;
}
static void nextInit(tunnel_t *t, line_t *l)
{
    discard t;
    if (lineGetDestinationAddressContext(l)->proto_udp)
    {
        relay = l;
        socks5clientTunnelDownStreamEst(client, l);
    }
    else
    {
        control = l;
        socks5clientTunnelDownStreamEst(client, l);
    }
}
static void setup(bool auth, bool udp)
{
    twfWorkerEnvSetup(&env, 16384, 300);
    client = tunnelCreate(NULL, sizeof(socks5client_tstate_t), sizeof(socks5client_lstate_t));
    prev   = tunnelCreate(NULL, 0, 0);
    next   = tunnelCreate(NULL, 0, 0);
    tunnelBind(prev, client);
    tunnelBind(client, next);
    prev->fnEstD     = est;
    prev->fnFinD     = ownerFinish;
    prev->fnPayloadD = down;
    prev->fnPauseD = prev->fnResumeD = noop;
    next->fnInitU                    = nextInit;
    next->fnPayloadU                 = up;
    next->fnFinU                     = noop;
    next->fnPauseU                   = readPause;
    next->fnResumeU                  = readResume;
    chain                            = tunnelchainCreate(1);
    chain->sum_line_state_size       = client->lstate_size;
    tunnelchainFinalize(chain);
    client->chain = chain;
    twfLinePoolSetup(&lines, client->lstate_size, 1);
    application = twfLinePoolCreateLine(&lines);
    lineRef(application);
    socks5client_tstate_t *ts = tunnelGetState(client);
    ts->target_addr_source = ts->target_port_source = kDvsConstant;
    ts->protocol                                    = udp ? kSocks5ClientProtocolUdp : kSocks5ClientProtocolTcp;
    addresscontextSetIpAddressPort(&ts->target_addr, "127.0.0.1", 80);
    if (auth)
    {
        ts->username     = stringDuplicate("u");
        ts->password     = stringDuplicate("p");
        ts->username_len = ts->password_len = 1;
    }
    authenticate = auth;
    automatic = pause_body = inject_body = close_body = close_request = false;
    splice_replies = ordinary_up = ordinary_down = false;
    expected_up = expected_down = NULL;
    greetings = auths = commands = established = finishes = request_depth = max_request_depth = 0;
    body_depth = max_body_depth = response_rounds = read_pauses = read_resumes = 0;
    down_length = up_length = 0;
    relay                   = NULL;
    socks5clientTunnelUpStreamInit(client, application);
    twfRequire(established == 1 && greetings == 1, "transport Est or greeting missing");
}
static void negotiate(void)
{
    const uint8_t method[] = {5, authenticate ? 2 : 0}, auth[] = {1, 0};
    deliver(method, sizeof(method));
    if (authenticate)
        deliver(auth, sizeof(auth));
    twfRequire(commands == 1, "missing CONNECT/ASSOCIATE");
}
static void teardown(void)
{
    if (lineIsAlive(application))
    {
        socks5clientTunnelUpStreamFinish(client, application);
        lineDestroy(application);
    }
    twfRequire(twfLineRefCount(application) == 1, "temporary application reference leaked");
    lineUnref(application);
    socks5clientTunnelstateDestroy(tunnelGetState(client));
    twfLinePoolTeardown(&lines);
    tunnelchainDestroy(chain);
    tunnelDestroy(client);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    twfWorkerEnvTeardown(&env);
}
static void largeBody(unsigned mode)
{
    twfSetCase("large proxy reply body, coalesced/split/fragmented");
    setup(false, false);
    negotiate();
    uint8_t wire[sizeof(command_reply) + 8192];
    memoryCopy(wire, command_reply, sizeof(command_reply));
    memset(wire + sizeof(command_reply), 'A', 8192);
    size_t split = mode == 0 ? 0 : mode == 1 ? sizeof(command_reply) : 5;
    if (split)
        deliver(wire, split);
    deliver(wire + split, sizeof(wire) - split);
    twfRequire(lineIsAlive(application) && down_length == 8192 &&
                   memoryEqual(downstream, wire + sizeof(command_reply), 8192),
               "complete reply body hit incomplete-handshake limit");
    teardown();
}
static void nestedBodies(void)
{
    twfSetCase("reply tail serializes synchronous request/response reentry");
    setup(false, false);
    negotiate();
    automatic       = true;
    response_rounds = 100;
    uint8_t wire[sizeof(command_reply) + 1];
    memoryCopy(wire, command_reply, sizeof(command_reply));
    wire[sizeof(command_reply)] = 'A';
    deliver(wire, sizeof(wire));
    twfRequire(lineIsAlive(application) && down_length == 101 && downstream[0] == 'A' && up_length == 100,
               "nested replies lost bytes");
    twfRequire(max_body_depth == 1, "response reentry recursively advanced active input");
    teardown();
}
static unsigned nested_entries;
static size_t   nested_bytes;
static void     fillBacklog(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    lineReuseBuffer(l, b);
    socks5clientTunnelUpStreamPause(client, l);
    uint8_t *data = memoryAllocate(nested_bytes ? nested_bytes : 1);
    memset(data, 'B', nested_bytes ? nested_bytes : 1);
    for (unsigned i = 0; i < nested_entries && lineIsAlive(l); ++i)
        deliver(data, nested_bytes);
    memoryFree(data);
}
static void boundaries(void)
{
    for (unsigned entries = 0; entries < 2; ++entries)
    {
        twfSetCase("downstream retained byte/entry equality and refusal");
        setup(false, false);
        negotiate();
        prev->fnPayloadD = fillBacklog;
        nested_entries   = entries ? kSocks5ClientMaxPendingBuffers : 1;
        nested_bytes     = entries ? 1 : kSocks5ClientMaxPendingDownBytes;
        uint8_t wire[sizeof(command_reply) + 1];
        memoryCopy(wire, command_reply, sizeof(command_reply));
        wire[sizeof(command_reply)] = 'A';
        deliver(wire, sizeof(wire));
        socks5client_lstate_t *ls = lineGetState(control, client);
        twfRequire(lineIsAlive(application) && bufferqueueGetBufCount(&ls->pending_down) == nested_entries &&
                       bufferqueueGetBufLen(&ls->pending_down) == nested_entries * nested_bytes,
                   "exact downstream backlog bound refused");
        for (unsigned i = 0; i < 2000; ++i)
            deliver(NULL, 0);
        twfRequire(bufferqueueGetBufCount(&ls->pending_down) == nested_entries, "empty TCP consumed retained entries");
        deliver("X", 1);
        twfRequire(! lineIsAlive(application) && finishes == 1, "downstream overflow did not settle once");
        teardown();
    }
    twfSetCase("ready reply tail is not capped as backlog");
    setup(false, false);
    negotiate();
    const size_t length = kSocks5ClientMaxPendingDownBytes + 1;
    uint8_t     *wire   = memoryAllocate(sizeof(command_reply) + length);
    memoryCopy(wire, command_reply, sizeof(command_reply));
    memset(wire + sizeof(command_reply), 'L', length);
    deliver(wire, sizeof(command_reply) + length);
    twfRequire(lineIsAlive(application) && down_length == length &&
                   memoryEqual(downstream, wire + sizeof(command_reply), length),
               "ready reply tail hit backlog limit");
    memoryFree(wire);
    teardown();
}
static void addressSplits(void)
{
    uint8_t wire[263] = {5, 0, 0, 3, 255};
    memset(wire + 5, 'd', 255);
    wire[260] = 0;
    wire[261] = 80;
    wire[262] = 'A';
    for (size_t split = 0; split <= sizeof(wire); ++split)
    {
        twfSetCase("maximum bound-domain reply split points");
        setup(false, false);
        negotiate();
        deliver(wire, split);
        deliver(wire + split, sizeof(wire) - split);
        twfRequire(lineIsAlive(application) && down_length == 1 && downstream[0] == 'A',
                   "domain reply framing changed");
        teardown();
    }
    const uint8_t empty_domain[] = {5, 0, 0, 3, 0, 0, 0, 'A'};
    twfSetCase("existing empty bound-domain CONNECT reply policy");
    setup(false, false);
    negotiate();
    deliver(empty_domain, sizeof(empty_domain));
    twfRequire(lineIsAlive(application) && down_length == 1 && downstream[0] == 'A',
               "client bound-address acceptance changed");
    teardown();
    for (unsigned auth = 0; auth < 2; ++auth)
    {
        twfSetCase("method/auth/command replies and body in one input");
        setup(auth != 0, false);
        uint8_t batch[8192 + sizeof(command_reply) + 4];
        size_t  offset  = 0;
        batch[offset++] = 5;
        batch[offset++] = auth ? 2 : 0;
        if (auth)
        {
            batch[offset++] = 1;
            batch[offset++] = 0;
        }
        memoryCopy(batch + offset, command_reply, sizeof(command_reply));
        offset += sizeof(command_reply);
        memset(batch + offset, 'A', 8192);
        deliver(batch, offset + 8192);
        twfRequire(lineIsAlive(application) && commands == 1 && auths == auth && down_length == 8192,
                   "coalesced handshake phases lost body");
        teardown();
    }
}
static void udpWireVectors(void)
{
    twfSetCase("client UDP encoder fixed vectors and headroom fallback");
    setup(false, false);
    const uint8_t vectors[][19] = {{1, 192, 0, 2, 1, 0x12, 0x34},
                                   {4, 0x20, 1, 0x0d, 0xb8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0xff, 0xff},
                                   {3, 1, 'x', 0, 1}};
    const size_t  lengths[]     = {7, 19, 5};
    for (unsigned i = 0; i < 3; ++i)
    {
        address_context_t address  = {0};
        size_t            consumed = 0;
        twfRequire(socks5clientParseAddressBytes(vectors[i], lengths[i], &address, &consumed) == 1 &&
                       consumed == lengths[i],
                   "wire vector parse");
        for (unsigned fallback = 0; fallback < 2; ++fallback)
        {
            sbuf_t *b = bytes("X", 1);
            if (fallback)
            {
                sbufShiftLeft(b, sbufGetLeftCapacity(b));
                sbufSetLength(b, 1);
                *(uint8_t *) sbufGetMutablePtr(b) = 'X';
            }
            twfRequire(socks5clientWrapUdpPayload(application, &b, &address), "UDP wrapping failed");
            const uint8_t *raw = sbufGetRawPtr(b);
            twfRequire(sbufGetLength(b) == lengths[i] + 4 && raw[0] == 0 && raw[1] == 0 && raw[2] == 0 &&
                           memoryEqual(raw + 3, vectors[i], lengths[i]) && raw[3 + lengths[i]] == 'X',
                       "UDP encoder changed wire bytes");
            lineReuseBuffer(application, b);
        }
        addresscontextReset(&address);
    }
    teardown();
}
static void rejection(void)
{
    for (unsigned scenario = 0; scenario < 4; ++scenario)
    {
        twfSetCase("proxy rejection disposes parser and queued application input");
        setup(scenario == 2, false);
        socks5clientTunnelUpStreamPayload(client, application, bytes("Q", 1));
        if (scenario < 2)
        {
            const uint8_t bad[] = {scenario == 0 ? 4 : 5, scenario == 0 ? 0 : 0xff};
            deliver(bad, sizeof(bad));
        }
        else if (scenario == 2)
        {
            const uint8_t method[] = {5, 2}, bad_auth[] = {1, 1};
            deliver(method, sizeof(method));
            deliver(bad_auth, sizeof(bad_auth));
        }
        else
        {
            negotiate();
            uint8_t bad[sizeof(command_reply)];
            memoryCopy(bad, command_reply, sizeof(bad));
            bad[1] = 1;
            deliver(bad, sizeof(bad));
        }
        twfRequire(! lineIsAlive(application) && finishes == 1 && up_length == 0,
                   "rejected proxy released application bytes");
        teardown();
    }
}
#if WW_HAVE_SPLICE
static void spliceHandshake(void)
{
    for (unsigned auth = 0; auth < 2; ++auth)
    {
        for (unsigned fragmented = 0; fragmented < 2; ++fragmented)
        {
            twfSetCase("splice handshake phases, large tail and opaque TCP forwarding");
            setup(auth != 0, false);
            twfRequire(! linePrefersOrdinaryReadUpstream(application) &&
                           ! linePrefersOrdinaryReadDownstream(application),
                       "TCP handshake permanently disabled splice reads");
            expected_up = spliceBytes("queued", 6, 2);
            socks5clientTunnelUpStreamPayload(client, application, expected_up);
            twfRequire(up_length == 0, "application body escaped before proxy acceptance");

            uint8_t wire[4 + sizeof(command_reply) + 4097];
            size_t  offset = 0;
            if (! fragmented)
            {
                wire[offset++] = 5;
                wire[offset++] = auth ? 2 : 0;
                if (auth)
                {
                    wire[offset++] = 1;
                    wire[offset++] = 0;
                }
            }
            else
            {
                const uint8_t method[] = {5, auth ? 2 : 0}, auth_reply[] = {1, 0};
                deliverSplice(method, 1, 0);
                deliver(method + 1, 1);
                if (auth)
                {
                    deliver(auth_reply, 1);
                    deliverSplice(auth_reply + 1, 1, 0);
                }
            }
            memoryCopy(wire + offset, command_reply, sizeof(command_reply));
            offset += sizeof(command_reply);
            memset(wire + offset, 'A', 4097);
            ordinary_down = true;
            if (fragmented)
            {
                deliver(wire, 5);
                deliverSplice(wire + 5, (uint32_t) (offset + 4097 - 5), 32);
            }
            else
                deliverSplice(wire, (uint32_t) (offset + 4097), 32);
            twfRequire(lineIsAlive(application) && commands == 1 && auths == auth && down_length == 4097 &&
                           memoryEqual(downstream, wire + offset, 4097) && up_length == 6 &&
                           memoryEqual(upstream, "queued", 6) && expected_up == NULL,
                       "splice handshake changed reply tail or retained application body");

            ordinary_down = false;
            expected_up   = spliceBytes("direct-up", 9, 2);
            socks5clientTunnelUpStreamPayload(client, application, expected_up);
            expected_down = spliceBytes("answer", 6, 3);
            socks5clientTunnelDownStreamPayload(client, control, expected_down);
            twfRequire(expected_up == NULL && expected_down == NULL && up_length == 15 && down_length == 4103 &&
                           memoryEqual(upstream + 6, "direct-up", 9) && memoryEqual(downstream + 4097, "answer", 6),
                       "ready splice TCP bytes changed");
            teardown();
        }
    }
}

static void spliceReentry(void)
{
    twfSetCase("nested splice authentication replies serialize behind active input");
    setup(true, false);
    expected_up = spliceBytes("Q", 1, 0);
    socks5clientTunnelUpStreamPayload(client, application, expected_up);
    automatic = splice_replies = true;
    const uint8_t method[]     = {5, 2};
    deliverSplice(method, sizeof(method), 0);
    twfRequire(lineIsAlive(application) && auths == 1 && commands == 1 && max_request_depth == 1 &&
                   max_body_depth == 1 && down_length == 1 && downstream[0] == 'R' && up_length == 1 &&
                   upstream[0] == 'Q' && expected_up == NULL,
               "nested splice handshake repeated requests or lost queued bytes");
    teardown();

    twfSetCase("ready nested splice response stays queued through Pause and Resume");
    setup(false, false);
    negotiate();
    splice_replies = pause_body = inject_body = true;
    uint8_t tail[sizeof(command_reply) + 1];
    memoryCopy(tail, command_reply, sizeof(command_reply));
    tail[sizeof(command_reply)] = 'A';
    deliverSplice(tail, sizeof(tail), 3);
    socks5client_lstate_t *ls = lineGetState(control, client);
    twfRequire(down_length == 1 && read_pauses == 1 && bufferqueueGetBufCount(&ls->pending_down) == 1,
               "nested splice backlog drained while paused");
    expected_down = (sbuf_t *) bufferqueueFront(&ls->pending_down);
    twfRequire(sbufIsSplice(expected_down), "ready nested splice backlog was materialized");
    socks5clientTunnelUpStreamResume(client, application);
    twfRequire(expected_down == NULL && down_length == 2 && memoryEqual(downstream, "AB", 2) && read_resumes == 1,
               "splice response Resume changed ordering or representation");
    teardown();

    twfSetCase("splice reply tail callback closes borrowed application");
    setup(false, false);
    negotiate();
    close_body = true;
    deliverSplice(tail, sizeof(tail), 2);
    twfRequire(! lineIsAlive(application) && down_length == 1, "splice reply callback close failed");
    teardown();

    twfSetCase("splice proxy rejection releases incomplete input and queued pipe");
    setup(false, false);
    socks5clientTunnelUpStreamPayload(client, application, spliceBytes("Q", 1, 0));
    const uint8_t bad_method[] = {5, 0xff};
    deliverSplice(bad_method, 1, 0);
    deliverSplice(bad_method + 1, 1, 0);
    twfRequire(! lineIsAlive(application) && finishes == 1 && up_length == 0,
               "splice rejection released queued application bytes");
    teardown();
}

static void requireUdpOrdinaryReads(line_t *l)
{
    twfRequire(linePrefersOrdinaryReadUpstream(l) && linePrefersOrdinaryReadDownstream(l),
               "UDP association role did not prefer ordinary reads");
}

static void spliceUdp(void)
{
    twfSetCase("UDP association materializes pipe datagrams and prefers ordinary reads");
    setup(false, true);
    requireUdpOrdinaryReads(application);
    requireUdpOrdinaryReads(control);
    ordinary_up = ordinary_down = true;
    const uint8_t method[]      = {5, 0};
    deliverSplice(method, sizeof(method), 0);
    uint8_t tail[sizeof(command_reply) + 1];
    memoryCopy(tail, command_reply, sizeof(command_reply));
    tail[sizeof(command_reply)] = 'A';
    deliverSplice(tail, sizeof(tail), 3);
    twfRequire(lineIsAlive(application) && relay != NULL && down_length == 0 &&
                   bufferstreamIsEmpty(&((socks5client_lstate_t *) lineGetState(control, client))->in_stream),
               "UDP control splice tail was not discarded");
    requireUdpOrdinaryReads(relay);

    socks5clientTunnelUpStreamPayload(client, application, spliceBytes("XY", 2, 1));
    const uint8_t encoded[] = {0, 0, 0, 1, 127, 0, 0, 1, 0, 80, 'X', 'Y'};
    twfRequire(up_length == sizeof(encoded) && memoryEqual(upstream, encoded, sizeof(encoded)),
               "UDP splice framing changed wire bytes");
    socks5clientTunnelDownStreamPayload(client, relay, spliceBytes(encoded, sizeof(encoded), 4));
    twfRequire(down_length == 2 && memoryEqual(downstream, "XY", 2), "UDP splice decoder changed datagram bytes");

    for (unsigned no_headroom = 0; no_headroom < 2; ++no_headroom)
    {
        uint8_t  payload[321];
        uint32_t prefix = no_headroom ? sbufAlignLeftPadding(bufferpoolGetLargeBufferPadding(env.pool)) : 1;
        uint32_t length = prefix + 1;
        twfRequire(length <= sizeof(payload), "UDP fixture padding changed");
        memset(payload, 'U', length);
        payload[length - 1] = 'X';
        sbuf_t *b           = spliceBytes(payload, length, prefix);
        if (no_headroom)
            twfRequire(sbufGetLeftCapacity(b) == 0, "UDP fixture retained headroom");
        twfRequire(socks5clientWrapUdpPayload(
                       application, &b, &((socks5client_lstate_t *) lineGetState(application, client))->target_addr),
                   "UDP splice wrapping failed");
        twfRequire(! sbufIsSplice(b) && sbufGetLength(b) == length + sizeof(encoded) - 2 &&
                       memoryEqual(sbufGetRawPtr(b), encoded, sizeof(encoded) - 2) &&
                       memoryEqual((const uint8_t *) sbufGetRawPtr(b) + sizeof(encoded) - 2, payload, length),
                   "UDP splice wrapping lost prefix or pipe body");
        lineReuseBuffer(application, b);
    }
    uint8_t rejected[sizeof(encoded)];
    memoryCopy(rejected, encoded, sizeof(rejected));
    rejected[2] = 1;
    socks5clientTunnelDownStreamPayload(client, relay, spliceBytes(rejected, sizeof(rejected), 0));
    twfRequire(lineIsAlive(application) && down_length == 2, "fragmented UDP splice datagram was forwarded");
    rejected[0] = 1;
    socks5clientTunnelDownStreamPayload(client, relay, spliceBytes(rejected, sizeof(rejected), 0));
    twfRequire(! lineIsAlive(application) && finishes == 1, "invalid UDP splice envelope did not close association");
    teardown();
}
#endif
int main(int argc, char **argv)
{
    if (argc > 1 && stringCompare(argv[1], "reentry") == 0)
    {
        nestedBodies();
        return 0;
    }
#if WW_HAVE_SPLICE
    spliceHandshake();
    spliceReentry();
    spliceUdp();
#endif
    udpWireVectors();
    rejection();
    boundaries();
    addressSplits();
    for (unsigned mode = 0; mode < 3; ++mode)
        largeBody(mode);
    nestedBodies();
    twfSetCase("auth response progression is serialized");
    setup(true, false);
    automatic              = true;
    const uint8_t method[] = {5, 2};
    deliver(method, sizeof(method));
    twfRequire(lineIsAlive(application) && auths == 1 && commands == 1 && max_request_depth == 1,
               "authentication parser recursed or repeated request");
    teardown();
    for (size_t split = 0; split <= sizeof(command_reply); ++split)
    {
        twfSetCase("every IPv4 command split and empty input");
        setup(false, false);
        negotiate();
        deliver(command_reply, split);
        deliver(command_reply + split, sizeof(command_reply) - split);
        twfRequire(lineIsAlive(application) && ((socks5client_lstate_t *) lineGetState(application, client))->phase ==
                                                   kSocks5ClientPhaseEstablished,
                   "fragmented reply failed");
        teardown();
    }
    twfSetCase("nested response backlog honors Pause/Resume");
    setup(false, false);
    negotiate();
    pause_body = inject_body = true;
    uint8_t tail[sizeof(command_reply) + 1];
    memoryCopy(tail, command_reply, sizeof(command_reply));
    tail[sizeof(command_reply)] = 'A';
    deliver(tail, sizeof(tail));
    twfRequire(down_length == 1 && read_pauses == 1, "paused nested backlog drained");
    socks5clientTunnelUpStreamResume(client, application);
    twfRequire(down_length == 2 && memoryEqual(downstream, "AB", 2) && read_resumes == 1,
               "Resume lost nested response");
    teardown();
    twfSetCase("reply callback closes borrowed application");
    setup(false, false);
    negotiate();
    close_body = true;
    deliver(tail, sizeof(tail));
    twfRequire(! lineIsAlive(application), "callback close failed");
    teardown();
    twfSetCase("request callback rejects line");
    setup(false, false);
    close_request          = true;
    const uint8_t noauth[] = {5, 0};
    deliver(noauth, sizeof(noauth));
    twfRequire(! lineIsAlive(application) && finishes == 1, "request close failed");
    teardown();
    twfSetCase("UDP control tail is discarded");
    setup(false, true);
    negotiate();
    deliver(tail, sizeof(tail));
    twfRequire(lineIsAlive(application) && relay != NULL && down_length == 0, "UDP association failed");
    socks5client_lstate_t *ls = lineGetState(control, client);
    twfRequire(bufferstreamIsEmpty(&ls->in_stream), "UDP control retained unused TCP tail");
    teardown();
    puts("SOCKS5 client reply-input tests passed");
    return 0;
}
