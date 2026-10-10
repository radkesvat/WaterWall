/*
 * Covers: socks5server control input; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: Method/auth/CONNECT reentry, retained limits, address boundaries, admitted ordering, mixed pipe
 * handshakes and UDP provider preferences.
 * Checks: Exact negotiation replies and coalesced tails, next-Init ordering, borrowed control-line
 * survival, rejection cleanup and ordinary UDP/control reads.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.socks5server_control_input_unit
 */
#include "AuthenticationClient/interface.h"
#include "Socks5Server/internal.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/protocols/splice_source.h"

static tunnel_t        *server, *prev, *next;
static line_t          *control;
static twf_worker_env_t env;
static twf_line_pool_t  lines;
static uint8_t          captured[2 * 1024 * 1024];
static size_t           captured_len;
static bool             long_auth, omit_est;
static unsigned         methods, auths, commands, inits, finishes, callback_depth, max_depth;
static bool             inject_method, inject_auth, inject_init, inject_payload, close_reply, reject_auth, pause_init;
static bool             splice_input, require_ordinary, independent_sources;
static sbuf_t          *expected_upstream_buffer, *expected_downstream_buffer;
static unsigned         provider_opens, provider_closes;
static const uint8_t    request[]     = {5, 1, 0, 1, 127, 0, 0, 1, 0, 80};
static const uint8_t    credentials[] = {1, 1, 'u', 1, 'p'};

authenticationclient_state_t              __wrap_authenticationclientGetState(tunnel_t *t);
authenticationclient_user_lookup_result_t __wrap_authenticationclientGetUserByPasswordWithResult(tunnel_t   *t,
                                                                                                 const char *password,
                                                                                                 user_handle_t *out);
authenticationclient_state_t              __wrap_authenticationclientGetState(tunnel_t *t)
{
    discard t;
    return kAuthenticationClientStateReady;
}
authenticationclient_user_lookup_result_t __wrap_authenticationclientGetUserByPasswordWithResult(tunnel_t   *t,
                                                                                                 const char *password,
                                                                                                 user_handle_t *out)
{
    discard t;
    if (long_auth)
    {
        twfRequire(stringLength(password) == 511 && password[255] == ':', "maximum credential length changed");
        for (unsigned i = 0; i < 255; ++i)
            twfRequire(password[i] == 'u' && password[256 + i] == 'p', "maximum credential bytes changed");
    }
    else
        twfRequire(stringCompare(password, "u:p") == 0, "credential bytes changed");
    *out = userHandleEmpty();
    return reject_auth ? kAuthenticationClientUserLookupUserNotFound : kAuthenticationClientUserLookupOk;
}
static sbuf_t *bytes(const void *data, size_t len)
{
    sbuf_t *b = bufferpoolGetBestFit(env.pool, (uint32_t) len, 300);
    sbufSetLength(b, (uint32_t) len);
    if (len)
        memoryCopy(sbufGetMutablePtr(b), data, len);
    return b;
}
static sbuf_t *spliceBytes(const void *data, size_t len, size_t prefix)
{
    twfRequire(prefix <= len && prefix <= 300, "invalid splice prefix");
    sbuf_t *b = independent_sources ? twfTrackAcquired(testSpliceSourceBuffer(
                                          bufferpoolGetSpliceBufferPadding(env.pool), (uint32_t) (len - prefix)))
                                    : bufferpoolGetSpliceBuffer(env.pool);
    twfRequire(b != NULL, "splice allocation failed");
    const size_t body = len - prefix;
    if (body)
        twfRequire(write(sbufSpliceMetadata(b).pipefd[1], (const uint8_t *) data + prefix, body) == (ssize_t) body,
                   "private pipe population failed");
    b->capacity = b->l_pad + (uint32_t) body;
    sbufSetLength(b, (uint32_t) body);
    sbufShiftLeft(b, (uint32_t) prefix);
    if (prefix)
        sbufWrite(b, data, (uint32_t) prefix);
    return b;
}
static void sendBytes(const void *data, size_t len)
{
    socks5serverTunnelUpStreamPayload(
        server, control, splice_input ? spliceBytes(data, len, min(len / 2, (size_t) 32)) : bytes(data, len));
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
static void upstream(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    size_t  len = sbufGetLength(b);
    twfRequire(len <= sizeof(captured) - captured_len, "capture overflow");
    if (require_ordinary)
        twfRequire(! sbufIsSplice(b), "early parsed payload retained splice representation");
    if (expected_upstream_buffer)
    {
        twfRequire(b == expected_upstream_buffer && sbufIsSplice(b), "ready upstream splice was replaced");
        expected_upstream_buffer = NULL;
    }
    sbufReadRangeToMemory(b, captured + captured_len, (uint32_t) len);
    captured_len += len;
    lineReuseBuffer(l, b);
    if (inject_payload)
    {
        inject_payload = false;
        sendBytes("P", 1);
    }
}
static void reply(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    if (expected_downstream_buffer)
    {
        twfRequire(b == expected_downstream_buffer && sbufIsSplice(b), "ready downstream splice was replaced");
        const size_t len = sbufGetLength(b);
        twfRequire(len <= sizeof(captured) - captured_len, "downstream capture overflow");
        sbufReadRangeToMemory(b, captured + captured_len, (uint32_t) len);
        captured_len += len;
        expected_downstream_buffer = NULL;
        lineReuseBuffer(l, b);
        return;
    }
    twfRequire(! sbufIsSplice(b), "generated SOCKS reply is pipe backed");
    ++callback_depth;
    if (callback_depth > max_depth)
        max_depth = callback_depth;
    size_t         n      = sbufGetLength(b);
    const uint8_t *p      = sbufGetRawPtr(b);
    bool           method = n == 2 && p[0] == 5;
    bool           auth   = n == 2 && p[0] == 1;
    if (method)
        ++methods;
    else if (auth)
        ++auths;
    else
    {
        twfRequire(n == 10 && p[0] == 5, "invalid command reply");
        ++commands;
    }
    lineReuseBuffer(l, b);
    if (close_reply)
    {
        socks5serverTunnelUpStreamFinish(server, l);
        lineDestroy(l);
    }
    else if (method && inject_method)
    {
        inject_method             = false;
        socks5server_tstate_t *ts = tunnelGetState(server);
        if (ts->no_auth)
            sendBytes(request, sizeof(request));
        else
            sendBytes(credentials, sizeof(credentials));
    }
    else if (auth && inject_auth)
    {
        inject_auth = false;
        sendBytes(request, sizeof(request));
    }
    --callback_depth;
}
static void initNext(tunnel_t *t, line_t *l)
{
    discard t;
    ++inits;
    twfRequire(lineGetDestinationAddressContext(l)->port == 80, "wrong destination");
    twfRequire(lineIsAuthenticated(l), "identity not published before Init");
    if (! ((socks5server_tstate_t *) tunnelGetState(server))->no_auth)
        twfRequire(stringLength(lineGetAuthenticatedUsername(l)) == (long_auth ? 255U : 1U),
                   "username unavailable in Init");
    if (inject_init)
        sendBytes("I", 1);
    if (pause_init)
        socks5serverTunnelDownStreamPause(server, l);
    if (! omit_est)
        socks5serverTunnelDownStreamEst(server, l);
}
static void setupMode(bool auth, bool udp_only)
{
    twfWorkerEnvSetup(&env, 16384, 300);
    twfBufferLedgerReset();
    server = tunnelCreate(NULL, sizeof(socks5server_tstate_t), sizeof(socks5server_lstate_t));
    prev   = tunnelCreate(NULL, 0, 0);
    next   = tunnelCreate(NULL, 0, 0);
    tunnelBind(prev, server);
    tunnelBind(server, next);
    prev->fnPayloadD = reply;
    prev->fnFinD     = ownerFinish;
    prev->fnEstD = prev->fnPauseD = prev->fnResumeD = noop;
    next->fnInitU                                   = initNext;
    next->fnPayloadU                                = upstream;
    next->fnFinU = next->fnPauseU = next->fnResumeU = noop;
    twfLinePoolSetup(&lines, server->lstate_size, 1);
    control = twfLinePoolCreateLine(&lines);
    lineRef(control);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(control), IP_PROTO_TCP);
    socks5server_tstate_t *ts = tunnelGetState(server);
    ts->no_auth               = ! auth;
    ts->allow_connect         = ! udp_only;
    ts->allow_udp             = udp_only;
    ts->auth_client_tunnel    = next;
    long_auth = omit_est = false;
    captured_len = methods = auths = commands = inits = finishes = callback_depth = max_depth = 0;
    inject_method = inject_auth = inject_init = inject_payload = close_reply = reject_auth = pause_init = false;
    splice_input = require_ordinary = false;
    expected_upstream_buffer = expected_downstream_buffer = NULL;
    socks5serverTunnelUpStreamInit(server, control);
    twfRequire(linePrefersOrdinaryReadUpstream(control) == udp_only &&
                   linePrefersOrdinaryReadDownstream(control) == udp_only,
               "TCP CONNECT or UDP-only initial read preference changed");
}
static void setup(bool auth)
{
    setupMode(auth, false);
}
static void teardown(void)
{
    if (lineIsAlive(control))
    {
        socks5serverTunnelUpStreamFinish(server, control);
        lineDestroy(control);
    }
    twfRequireEqualU32(twfLineRefCount(control), 1, "temporary reference leak");
    lineUnref(control);
    twfLinePoolTeardown(&lines);
    tunnelDestroy(server);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    twfWorkerEnvTeardown(&env);
}
static void method(bool auth)
{
    const uint8_t greeting[] = {5, 1, auth ? 2 : 0};
    sendBytes(greeting, sizeof(greeting));
}
static void reentry(bool auth)
{
    twfSetCase(auth ? "auth reply reentry" : "method reply reentry");
    setup(auth);
    inject_method = true;
    inject_auth   = auth;
    method(auth);
    twfRequire(lineIsAlive(control) && methods == 1 && inits == 1 && commands == 1,
               "reentry duplicated negotiation or lost CONNECT");
    twfRequire(auths == (unsigned) auth && max_depth == 1, "parser progressed recursively");
    teardown();
}
static void body(unsigned mode)
{
    twfSetCase("coalesced/split CONNECT body");
    setup(false);
    method(false);
    uint8_t data[sizeof(request) + 8192];
    memoryCopy(data, request, sizeof(request));
    memset(data + sizeof(request), 'A', 8192);
    if (mode == 0)
        sendBytes(data, sizeof(data));
    else if (mode == 1)
    {
        sendBytes(request, sizeof(request));
        sendBytes(data + sizeof(request), 8192);
    }
    else
    {
        sendBytes(data, 5);
        sendBytes(data + 5, sizeof(data) - 5);
    }
    twfRequire(lineIsAlive(control) && inits == 1 && captured_len == 8192, "large body classified as handshake");
    twfRequire(memoryEqual(captured, data + sizeof(request), 8192), "body changed");
    teardown();
}
static void retainedLimits(bool entries)
{
    twfSetCase("retained tail and nested entries share one budget");
    setup(false);
    method(false);
    pause_init            = true;
    const size_t body_len = entries ? 1 : kSocks5ServerMaxPendingBytes;
    uint8_t     *data     = memoryAllocate(sizeof(request) + body_len);
    memoryCopy(data, request, sizeof(request));
    memset(data + sizeof(request), 'A', body_len);
    sendBytes(data, sizeof(request) + body_len);
    memoryFree(data);
    twfRequire(lineIsAlive(control) && captured_len == 0,
               "exact retained tail boundary refused or drained after Pause");
    if (entries)
        for (unsigned i = 1; i < kSocks5ServerMaxPendingBuffers; ++i)
            sendBytes("B", 1);
    twfRequire(lineIsAlive(control), "exact shared entry limit refused");
    for (unsigned i = 0; i < 2000; ++i)
        sendBytes(NULL, 0);
    twfRequire(lineIsAlive(control), "empty TCP input consumed budget");
    sendBytes("X", 1);
    twfRequire(! lineIsAlive(control) && finishes == 1, "shared retention overflow was not closed once");
    teardown();
}
static void pausedResume(void)
{
    twfSetCase("Init Pause followed by Resume drains old tail first");
    setup(false);
    method(false);
    pause_init = inject_init = true;
    uint8_t data[sizeof(request) + 1];
    memoryCopy(data, request, sizeof(request));
    data[sizeof(request)] = 'A';
    sendBytes(data, sizeof(data));
    sendBytes("B", 1);
    twfRequire(captured_len == 0, "paused backlog drained");
    inject_payload = true;
    socks5serverTunnelDownStreamResume(server, control);
    twfRequire(captured_len == 4 && memoryEqual(captured, "AIBP", 4), "Resume/reentry lost ordering");
    teardown();
}
static void largeReadyTail(void)
{
    twfSetCase("ready coalesced body is not a backlog limit");
    setup(false);
    method(false);
    size_t   n    = kSocks5ServerMaxPendingBytes + 1;
    uint8_t *data = memoryAllocate(sizeof(request) + n);
    memoryCopy(data, request, sizeof(request));
    memset(data + sizeof(request), 'L', n);
    sendBytes(data, sizeof(request) + n);
    twfRequire(lineIsAlive(control) && captured_len == n && memoryEqual(captured, data + sizeof(request), n),
               "ready body received backlog cap");
    memoryFree(data);
    teardown();
}
static void malformed(void)
{
    for (unsigned i = 0; i < 4; ++i)
    {
        twfSetCase("malformed/unsupported request");
        setup(false);
        method(false);
        uint8_t bad[sizeof(request)];
        memoryCopy(bad, request, sizeof(bad));
        bad[i] = 0xff;
        sendBytes(bad, sizeof(bad));
        twfRequire(! lineIsAlive(control) && inits == 0 && commands == 1 && finishes == 1,
                   "malformed request admitted backend");
        teardown();
    }
}
static void maximumMetadataSplits(void)
{
    uint8_t wire[257 + 513 + 262 + 1];
    size_t  n = 0;
    wire[n++] = 5;
    wire[n++] = 255;
    memset(wire + n, 2, 255);
    n += 255;
    wire[n++] = 1;
    wire[n++] = 255;
    memset(wire + n, 'u', 255);
    n += 255;
    wire[n++] = 255;
    memset(wire + n, 'p', 255);
    n += 255;
    wire[n++] = 5;
    wire[n++] = 1;
    wire[n++] = 0;
    wire[n++] = 3;
    wire[n++] = 255;
    memset(wire + n, 'd', 255);
    n += 255;
    wire[n++] = 0;
    wire[n++] = 80;
    wire[n++] = 'A';
    twfRequire(n == sizeof(wire), "fixture length");
    for (size_t split = 0; split <= n; ++split)
    {
        twfSetCase("every split of maximum method/auth/domain metadata");
        setup(true);
        long_auth    = true;
        splice_input = split == 257 || split == 770;
        sendBytes(wire, split);
        splice_input = split == 1 || split == 512;
        sendBytes(wire + split, n - split);
        twfRequire(lineIsAlive(control) && inits == 1 && methods == 1 && auths == 1 && commands == 1 &&
                       captured_len == 1 && captured[0] == 'A',
                   "maximum metadata split changed output");
        const address_context_t *dest = lineGetDestinationAddressContext(control);
        twfRequire(addresscontextIsDomain(dest) && dest->domain_len == 255 &&
                       memoryEqual(dest->domain, wire + 775, 255),
                   "domain bytes changed");
        teardown();
    }
}
static void addressBoundaries(void)
{
    twfSetCase("empty TCP domain is immediately invalid");
    setup(false);
    method(false);
    const uint8_t empty[] = {5, 1, 0, 3, 0};
    sendBytes(empty, sizeof(empty));
    twfRequire(! lineIsAlive(control) && commands == 1 && inits == 0, "empty domain waited for more TCP input");
    teardown();
    twfSetCase("real reply encoders use independent IPv6/domain vectors");
    setup(false);
    const uint8_t wire[][19] = {{4, 0x20, 1, 0x0d, 0xb8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x12, 0x34},
                                {3, 3, 'a', 'B', 'c', 0, 80}};
    const size_t  lengths[]  = {19, 7};
    for (unsigned i = 0; i < 2; ++i)
    {
        address_context_t context  = {0};
        size_t            consumed = 0;
        twfRequire(socks5serverParseAddressBytes(wire[i], lengths[i], &context, &consumed) == kSocks5AddressComplete,
                   "real node address conversion failed");
        sbuf_t *command = socks5serverCreateCommandReply(control, 0, &context);
        twfRequire(command && sbufGetLength(command) == 3 + lengths[i] &&
                       memoryEqual((const uint8_t *) sbufGetRawPtr(command) + 3, wire[i], lengths[i]),
                   "command address bytes changed");
        lineReuseBuffer(control, command);
        sbuf_t *payload = bytes("X", 1);
        twfRequire(socks5serverWrapUdpPayloadForClient(control, &payload, &context), "UDP reply wrap failed");
        const uint8_t *raw = sbufGetRawPtr(payload);
        twfRequire(sbufGetLength(payload) == 4 + lengths[i] && raw[0] == 0 && raw[1] == 0 && raw[2] == 0 &&
                       memoryEqual(raw + 3, wire[i], lengths[i]) && raw[3 + lengths[i]] == 'X',
                   "UDP envelope bytes changed");
        lineReuseBuffer(control, payload);
        addresscontextReset(&context);
    }
    teardown();
}
static void admittedOrdering(void)
{
    twfSetCase("pre-Est application admission");
    setup(false);
    method(false);
    omit_est = true;
    uint8_t request_tail[sizeof(request) + 1];
    memoryCopy(request_tail, request, sizeof(request));
    request_tail[sizeof(request)] = 'A';
    sendBytes(request_tail, sizeof(request_tail));
    sendBytes("B", 1);
    twfRequire(captured_len == 2 && memoryEqual(captured, "AB", 2) && commands == 0, "pre-Est input was delayed");
    socks5serverTunnelDownStreamEst(server, control);
    twfRequire(commands == 1, "Est failed to send one success reply");
    teardown();
    for (unsigned auth = 0; auth < 2; ++auth)
    {
        twfSetCase("method/auth callback input follows original request tail");
        setup(auth != 0);
        uint8_t wire[sizeof(credentials) + sizeof(request_tail)];
        size_t  prefix;
        if (auth)
        {
            method(true);
            memoryCopy(wire, credentials, sizeof(credentials));
            prefix      = sizeof(credentials);
            inject_auth = true;
        }
        else
        {
            wire[0]       = 5;
            wire[1]       = 1;
            wire[2]       = 0;
            prefix        = 3;
            inject_method = true;
        }
        memoryCopy(wire + prefix, request_tail, sizeof(request_tail));
        sendBytes(wire, prefix + sizeof(request_tail));
        twfRequire(inits == 1 && methods == 1 && auths == auth && captured_len == sizeof(request) + 1 &&
                       captured[0] == 'A' && memoryEqual(captured + 1, request, sizeof(request)),
                   "handshake reentry overtook original tail");
        teardown();
    }
}
static void spliceNegotiation(void)
{
    for (unsigned auth = 0; auth < 2; ++auth)
    {
        twfSetCase("splice negotiation and nested parser input");
        setup(auth != 0);
        splice_input = require_ordinary = true;
        inject_method                   = true;
        inject_auth                     = auth != 0;
        const uint8_t greeting[]        = {5, 1, auth ? 2 : 0};
        socks5serverTunnelUpStreamPayload(server, control, spliceBytes(greeting, 1, 0));
        sendBytes(greeting + 1, 2);
        twfRequire(lineIsAlive(control) && methods == 1 && auths == auth && inits == 1 && commands == 1 &&
                       max_depth == 1,
                   "splice reply reentry advanced parser recursively or lost request");
        teardown();
    }
    twfSetCase("pipelined splice method/auth/CONNECT retains original application tail before nested input");
    setup(true);
    splice_input                                                       = true;
    inject_auth                                                        = true;
    uint8_t pipeline[3 + sizeof(credentials) + sizeof(request) + 8192] = {5, 1, 2};
    memoryCopy(pipeline + 3, credentials, sizeof(credentials));
    memoryCopy(pipeline + 3 + sizeof(credentials), request, sizeof(request));
    memset(pipeline + 3 + sizeof(credentials) + sizeof(request), 'A', 8192);
    sendBytes(pipeline, sizeof(pipeline));
    twfRequire(inits == 1 && methods == 1 && auths == 1 && commands == 1 && max_depth == 1 &&
                   captured_len == 8192 + sizeof(request) &&
                   memoryEqual(captured, pipeline + 3 + sizeof(credentials) + sizeof(request), 8192) &&
                   memoryEqual(captured + 8192, request, sizeof(request)),
               "pipelined splice authentication reordered or dropped input");
    teardown();
    for (unsigned split = 0; split < 2; ++split)
    {
        twfSetCase("coalesced splice CONNECT preserves large early body and nested FIFO");
        setup(false);
        method(false);
        uint8_t wire[sizeof(request) + 8192];
        memoryCopy(wire, request, sizeof(request));
        memset(wire + sizeof(request), 'A', 8192);
        splice_input = true;
        inject_init = inject_payload = true;
        if (split)
        {
            sendBytes(wire, 5);
            sendBytes(wire + 5, sizeof(wire) - 5);
        }
        else
            sendBytes(wire, sizeof(wire));
        twfRequire(captured_len == 8194 && memoryEqual(captured, wire + sizeof(request), 8192) &&
                       memoryEqual(captured + 8192, "IP", 2),
                   "splice CONNECT body was capped as handshake or nested input overtook it");
        captured_len             = 0;
        const uint8_t opaque[]   = {'R', 'E', 'A', 'D', 'Y', 0, 'U', 'P'};
        expected_upstream_buffer = spliceBytes(opaque, sizeof(opaque), 2);
        socks5serverTunnelUpStreamPayload(server, control, expected_upstream_buffer);
        twfRequire(expected_upstream_buffer == NULL && captured_len == sizeof(opaque) &&
                       memoryEqual(captured, opaque, sizeof(opaque)),
                   "ready upstream splice bytes changed");
        captured_len               = 0;
        expected_downstream_buffer = spliceBytes(opaque, sizeof(opaque), 0);
        socks5serverTunnelDownStreamPayload(server, control, expected_downstream_buffer);
        twfRequire(expected_downstream_buffer == NULL && captured_len == sizeof(opaque) &&
                       memoryEqual(captured, opaque, sizeof(opaque)),
                   "ready downstream splice bytes changed");
        teardown();
    }
    twfSetCase("paused splice request tail drains before later pipe backed input");
    setup(false);
    method(false);
    splice_input = true;
    pause_init = inject_init = true;
    uint8_t wire[sizeof(request) + 1];
    memoryCopy(wire, request, sizeof(request));
    wire[sizeof(request)] = 'A';
    sendBytes(wire, sizeof(wire));
    sendBytes("B", 1);
    twfRequire(captured_len == 0, "paused splice backlog drained");
    inject_payload = true;
    socks5serverTunnelDownStreamResume(server, control);
    twfRequire(captured_len == 4 && memoryEqual(captured, "AIBP", 4), "splice Resume/reentry lost ordering");
    teardown();
    for (unsigned auth = 0; auth < 2; ++auth)
    {
        twfSetCase("splice method/auth rejection settles unread input");
        setup(auth != 0);
        splice_input = true;
        if (auth)
        {
            method(true);
            reject_auth = true;
            inject_auth = true;
            sendBytes(credentials, sizeof(credentials));
        }
        else
        {
            inject_method = true;
            method(true);
        }
        twfRequire(! lineIsAlive(control) && inits == 0 && finishes == 1, "splice rejection reopened parser");
        teardown();
    }
    twfSetCase("splice incomplete negotiation is released on Finish");
    setup(true);
    const uint8_t partial[] = {5, 2, 2};
    socks5serverTunnelUpStreamPayload(server, control, spliceBytes(partial, sizeof(partial), 1));
    twfRequire(lineIsAlive(control) && methods == 0, "incomplete splice greeting advanced");
    teardown();
    twfSetCase("splice retained FIFO uses logical bytes at the exact existing limit");
    setup(false);
    method(false);
    pause_init = true;
    uint8_t chunk[4096];
    memset(chunk, 'Q', sizeof(chunk));
    uint8_t request_tail[sizeof(request) + sizeof(chunk)];
    memoryCopy(request_tail, request, sizeof(request));
    memoryCopy(request_tail + sizeof(request), chunk, sizeof(chunk));
    sendBytes(request_tail, sizeof(request_tail));
    splice_input = true;
    independent_sources = true;
    for (unsigned i = 1; i < kSocks5ServerMaxPendingBytes / sizeof(chunk); ++i)
        sendBytes(chunk, sizeof(chunk));
    twfRequire(lineIsAlive(control) && captured_len == 0, "exact splice pending-byte boundary refused or drained");
    sendBytes("X", 1);
    twfRequire(! lineIsAlive(control) && finishes == 1, "splice pending-byte overflow did not close once");
    independent_sources = false;
    teardown();
}
static bool providerOpen(tunnel_t *t, wid_t wid, const udplistener_dynamic_endpoint_open_request_t *req,
                         udplistener_dynamic_endpoint_open_result_t *out)
{
    discard t;
    twfRequire(wid == 0 && req->expected_source_port == 0 && linePrefersOrdinaryReadUpstream(control) &&
                   linePrefersOrdinaryReadDownstream(control),
               "UDP ASSOCIATE read preferences were not committed before provider open");
    ++provider_opens;
    *out = (udplistener_dynamic_endpoint_open_result_t) {.handle           = {.owner_wid = 0, .generation = 1},
                                                         .bound_local_port = 1080};
    out->bound_local_addr.sin.sin_family = AF_INET;
    out->bound_local_addr.sin.sin_port   = htons(1080);
    return true;
}
static bool providerActivate(tunnel_t *t, udplistener_dynamic_endpoint_handle_t handle)
{
    discard t;
    twfRequire(handle.owner_wid == 0 && handle.generation == 1, "UDP provider handle changed");
    return true;
}
static void providerClose(tunnel_t *t, udplistener_dynamic_endpoint_handle_t handle)
{
    discard t;
    twfRequire(handle.owner_wid == 0 && handle.generation == 1, "UDP close selected wrong endpoint");
    ++provider_closes;
}
static void udpControlPreferences(void)
{
    for (unsigned udp_only = 0; udp_only < 2; ++udp_only)
    {
        twfSetCase(udp_only ? "UDP-only control TCP selects ordinary reads in Init"
                            : "mixed TCP control selects ordinary reads only after UDP ASSOCIATE");
        setupMode(false, udp_only != 0);
        socks5server_tstate_t *ts = tunnelGetState(server);
        ts->allow_udp             = true;
        ts->workers_count         = 1;
        ts->worker_associations   = memoryAllocateZero(sizeof(*ts->worker_associations));
        ts->dynamic_provider      = (udplistener_dynamic_provider_t) {
                 .instance = prev, .open = providerOpen, .activate = providerActivate, .close = providerClose};
        twfRequire(ip4addr_aton("127.0.0.1", ip_2_ip4(&ts->udp_reply_ip)), "UDP reply address fixture");
        ts->udp_reply_ip.type = IPADDR_TYPE_V4;
        addresscontextSetIpAddressPort(lineGetSourceAddressContext(control), "127.0.0.1", 1234);
        addresscontextSetOnlyProtocol(lineGetSourceAddressContext(control), IP_PROTO_TCP);
        provider_opens = provider_closes = 0;
        method(false);
        twfRequire(linePrefersOrdinaryReadUpstream(control) == (udp_only != 0) &&
                       linePrefersOrdinaryReadDownstream(control) == (udp_only != 0),
                   "mixed-mode method negotiation disabled TCP splice");
        const uint8_t udp_request[] = {5, 3, 0, 1, 0, 0, 0, 0, 0, 0};
        socks5serverTunnelUpStreamPayload(server, control, spliceBytes(udp_request, sizeof(udp_request), 2));
        twfRequire(lineIsAlive(control) && commands == 1 && inits == 0 && provider_opens == 1 &&
                       linePrefersOrdinaryReadUpstream(control) && linePrefersOrdinaryReadDownstream(control) &&
                       ((socks5server_lstate_t *) lineGetState(control, server))->phase == kSocks5ServerPhaseUdpControl,
                   "UDP ASSOCIATE failed to enter ordinary control mode");
        socks5serverTunnelUpStreamFinish(server, control);
        lineDestroy(control);
        twfRequire(provider_closes == 1 && socks5server_assoc_map_t_size(ts->worker_associations) == 0,
                   "UDP control close retained its association");
        socks5server_assoc_map_t_drop(ts->worker_associations);
        memoryFree(ts->worker_associations);
        ts->worker_associations = NULL;
        teardown();
    }
}
int main(int argc, char **argv)
{
    if (argc > 1 && stringCompare(argv[1], "body") == 0)
    {
        body(0);
        return 0;
    }
    udpControlPreferences();
    spliceNegotiation();
    admittedOrdering();
    addressBoundaries();
    maximumMetadataSplits();
    retainedLimits(false);
    retainedLimits(true);
    pausedResume();
    largeReadyTail();
    malformed();
    reentry(false);
    reentry(true);
    for (unsigned i = 0; i < 3; ++i)
        body(i);
    for (size_t split = 0; split <= sizeof(request); ++split)
    {
        twfSetCase("request split points and empty input");
        setup(false);
        method(false);
        sendBytes(request, split);
        sendBytes(request + split, sizeof(request) - split);
        twfRequire(lineIsAlive(control) && inits == 1, "split request lost");
        teardown();
    }
    twfSetCase("old tail before nested Init and Payload");
    setup(false);
    method(false);
    inject_init = inject_payload = true;
    uint8_t tail[sizeof(request) + 1];
    memoryCopy(tail, request, sizeof(request));
    tail[sizeof(request)] = 'A';
    sendBytes(tail, sizeof(tail));
    twfRequire(captured_len == 3 && memoryEqual(captured, "AIP", 3), "nested input overtook original tail");
    teardown();
    twfSetCase("method failure rejects reentry");
    setup(false);
    inject_method = true;
    method(true);
    twfRequire(! lineIsAlive(control) && inits == 0 && methods == 1 && finishes == 1,
               "method rejection reopened parser");
    teardown();
    twfSetCase("auth failure rejects reentry");
    setup(true);
    method(true);
    reject_auth = inject_auth = true;
    sendBytes(credentials, sizeof(credentials));
    twfRequire(! lineIsAlive(control) && inits == 0 && auths == 1 && finishes == 1, "auth rejection reopened parser");
    teardown();
    twfSetCase("reply closes borrowed line");
    setup(false);
    close_reply = true;
    method(false);
    twfRequire(! lineIsAlive(control) && inits == 0, "reply close failed");
    teardown();
    twfSetCase("failure reply closes borrowed line");
    setup(false);
    close_reply = true;
    method(true);
    twfRequire(! lineIsAlive(control) && inits == 0, "failure reply close failed");
    teardown();
    puts("SOCKS5 control-input tests passed");
    return 0;
}
