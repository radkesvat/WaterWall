#include "AuthenticationClient/interface.h"
#include "Socks5Server/internal.h"
#include "tunnel_line_failure_harness.h"

static tunnel_t        *server, *prev, *next;
static line_t          *control;
static twf_worker_env_t env;
static twf_line_pool_t  lines;
static uint8_t          captured[2 * 1024 * 1024];
static size_t           captured_len;
static bool             long_auth, omit_est;
static unsigned         methods, auths, commands, inits, finishes, callback_depth, max_depth;
static bool             inject_method, inject_auth, inject_init, inject_payload, close_reply, reject_auth, pause_init;
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
static void sendBytes(const void *data, size_t len)
{
    socks5serverTunnelUpStreamPayload(server, control, bytes(data, len));
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
    memoryCopy(captured + captured_len, sbufGetRawPtr(b), len);
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
static void setup(bool auth)
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
    ts->allow_connect         = true;
    ts->auth_client_tunnel    = next;
    long_auth = omit_est = false;
    captured_len = methods = auths = commands = inits = finishes = callback_depth = max_depth = 0;
    inject_method = inject_auth = inject_init = inject_payload = close_reply = reject_auth = pause_init = false;
    socks5serverTunnelUpStreamInit(server, control);
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
        long_auth = true;
        sendBytes(wire, split);
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
int main(int argc, char **argv)
{
    if (argc > 1 && stringCompare(argv[1], "body") == 0)
    {
        body(0);
        return 0;
    }
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
