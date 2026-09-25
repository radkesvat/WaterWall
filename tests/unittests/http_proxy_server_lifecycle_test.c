#include "AuthenticationClient/structure.h"
#include "HttpProxyServer/structure.h"
#include "splice_buffer.h"
#include "wevent.h"

#if WW_HAVE_SPLICE
#include <unistd.h>
#endif

/* Real pool-backed lines and callbacks, with no sockets or linker wrapping. */
static tunnel_t *proxy, *prev, *next, *fallback;
static unsigned  fallback_opens, init_action, child_pauses;
static bool      in_fallback_init;
static line_t   *client, *child;
static unsigned  opens, closes, establishments, client_writes, request_writes;
static unsigned  close_on; /* 1 Init, 2 Est, 3 Payload, 4 Pause, 5 Resume */
static bool      refuse, automatic_response;
static char      received[4 * 1024 * 1024], sent[4 * 1024 * 1024];
static bool      pause_request, pause_response, delay_establishment;
static size_t    received_len;
static size_t    sent_len;
static bool      producer_paused[2];
static bool        nested_payload[2], finish_response;
static const char *nested_bytes;
/* Replay the existing HTTP/auth/lifetime cases with real pipe input as well. */
static unsigned  representation;
static uintptr_t last_wrapper[2];
static unsigned  splice_writes[2];
static bool      nested_resume, finish_request;

static void requireOrdinarySlots(void)
{
    hps_session_t *s = ((hps_lstate_t *) lineGetState(client, proxy))->session;
    if (! s)
        return;
    for (unsigned d = 0; d < 2; ++d)
    {
        const hps_direction_state_t *dir     = &s->directions[d];
        sbuf_t                      *slots[] = {dir->input, dir->output, dir->deferred, dir->incoming};
        for (unsigned i = 0; i < ARRAY_SIZE(slots); ++i)
            if (slots[i] && sbufIsSplice(slots[i]))
            {
                fprintf(stderr, "splice wrapper retained in HTTP session\n");
                exit(1);
            }
    }
}

static void sendBytes(line_t *l, bool downstream, const char *bytes);
static void childEof(void);

static void require(bool ok, const char *text)
{
    if (! ok)
    {
        fprintf(stderr, "proxy lifetime: %s\n", text);
        exit(1);
    }
}

static void clientClose(void)
{
    if (! lineIsAlive(client))
        return;
    httpproxyserverTunnelUpStreamFinish(proxy, client);
    require(lineIsAlive(client), "proxy destroyed borrowed client");
    lineDestroy(client);
}

static void previousFinish(tunnel_t *t, line_t *l)
{
    discard t;
    require(l == client, "callback used child as client");
    lineDestroy(l);
}

static void previousEst(tunnel_t *t, line_t *l)
{
    discard t;
    require(l == client, "Est identity");
    ++establishments;
    if (close_on == 2)
        clientClose();
}

static void previousPayload(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    require(l == client, "Payload identity");
    size_t n = sbufGetLength(b);
    require(n < sizeof(received) - received_len, "test output capacity");
    requireOrdinarySlots();
    last_wrapper[1] = (uintptr_t) b;
    splice_writes[1] += sbufIsSplice(b);
    sbufReadRangeToMemory(b, received + received_len, (uint32_t) n);
    received_len += n;
    received[received_len] = 0;
    ++client_writes;
    lineReuseBuffer(l, b);
    if (nested_payload[1])
    {
        nested_payload[1] = false;
        unsigned before   = client_writes;
        sendBytes(child, true, nested_bytes);
        if (nested_resume)
        {
            httpproxyserverTunnelUpStreamPause(proxy, client);
            httpproxyserverTunnelUpStreamResume(proxy, client);
            require(client_writes == before, "nested response bypassed active dispatch");
        }
        if (finish_response)
            childEof();
    }
    if (close_on == 3)
        clientClose();
    else if (pause_response)
    {
        pause_response = false;
        httpproxyserverTunnelUpStreamPause(proxy, client);
    }
}

static void childPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    require(! in_fallback_init, "Pause entered unfinished fallback Init");
    ++child_pauses;
    producer_paused[1] = true;
    if (close_on == 6)
        clientClose();
}

static void childResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    require(! in_fallback_init, "Resume entered unfinished fallback Init");
    producer_paused[1] = false;
    if (close_on == 7)
        clientClose();
}

static void previousPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    producer_paused[0] = true;
    if (close_on == 4)
        clientClose();
}

static void previousResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    producer_paused[0] = false;
    if (close_on == 5)
        clientClose();
}

static void childFinish(tunnel_t *t, line_t *l)
{
    discard t;
    require(l == child, "wrong child finished");
    require(t == (fallback_opens ? fallback : next), "wrong Finish branch");
    ++closes;
    child = NULL;
}

static void childInit(tunnel_t *t, line_t *l)
{
    discard t;
    child = l;
    ++opens;
    hps_session_t *s = ((hps_lstate_t *) lineGetState(l, proxy))->session;
    require(! linePrefersOrdinaryReadUpstream(l) && linePrefersOrdinaryReadDownstream(l) == (s->phase == kHpsExchange),
            "child read preference was not selected before Init");
    require(s->phase != kHpsExchange || linePrefersOrdinaryReadUpstream(client),
            "HTTP client read preference was not selected before child Init");
    require(lineGetRoutingContext(l)->local_listener_port == 8080, "listener metadata");
    require(lineGetRoutingContext(l)->peer_source_port == 54321, "peer metadata");
    require(lineGetSourceAddressContext(l)->proto_tcp, "source protocol");
    require(ip_addr_cmp(&lineGetSourceAddressContext(l)->ip_address, &lineGetSourceAddressContext(client)->ip_address),
            "source IP");
    if (close_on == 1)
        clientClose();
    else if (refuse)
    {
        lineRef(l);
        httpproxyserverTunnelDownStreamFinish(proxy, l);
        require(! lineIsAlive(l), "owner Finish left child alive");
        lineUnref(l);
        child = NULL;
    }
    else if (! delay_establishment)
        httpproxyserverTunnelDownStreamEst(proxy, l);
}

static sbuf_t *makeInput(line_t *l, const char *bytes, unsigned mode)
{
    const size_t n = stringLength(bytes);
#if WW_HAVE_SPLICE
    /* One page fits even the smallest Linux pipe. Large callback regressions
     * remain ordinary; their nested inputs still exercise splice admission. */
    const size_t prefix = mode == 2 ? min(n > 4096 ? n - 4096 : n / 2, (size_t) 60000) : 0;
    if (mode && n - prefix <= 4096)
    {
        sbuf_t *b = sbufCreateSplice((uint16_t) (prefix + 64));
        require(sbufSpliceInitPipe(b, 0) == 0, "real test pipe");
        const splice_buffer_metadata_t metadata = sbufSpliceMetadata(b);
        if (n != prefix)
            require(write(metadata.pipefd[1], bytes + prefix, n - prefix) == (ssize_t) (n - prefix), "fill real pipe");
        b->capacity = b->l_pad + (uint32_t) (n - prefix);
        sbufSetLength(b, (uint32_t) (n - prefix));
        sbufShiftLeft(b, (uint32_t) prefix);
        memoryCopy(sbufGetMutablePtr(b), bytes, prefix);
        return b;
    }
#else
    discard mode;
#endif
    sbuf_t *b = bufferpoolGetBestFit(lineGetBufferPool(l), (uint32_t) n, 64);
    memoryCopy(sbufGetMutablePtr(b), bytes, n);
    sbufSetLength(b, (uint32_t) n);
    return b;
}

static void sendBytes(line_t *l, bool downstream, const char *bytes)
{
    sbuf_t *b = makeInput(l, bytes, representation);
    if (downstream)
        httpproxyserverTunnelDownStreamPayload(proxy, l, b);
    else
        httpproxyserverTunnelUpStreamPayload(proxy, l, b);
    requireOrdinarySlots();
}

static void childPayload(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    require(! in_fallback_init, "Payload entered unfinished fallback Init");
    require(l == child, "request did not use owned child");
    require(t == ((hps_lstate_t *) lineGetState(l, proxy))->session->child_entry, "wrong Payload branch");
    require(sbufGetLeftCapacity(b) >= 64, "rewritten buffer lost chain padding");
    size_t n = sbufGetLength(b);
    require(n < sizeof(sent) - sent_len, "test request capacity");
    requireOrdinarySlots();
    last_wrapper[0] = (uintptr_t) b;
    splice_writes[0] += sbufIsSplice(b);
    sbufReadRangeToMemory(b, sent + sent_len, (uint32_t) n);
    sent_len += n;
    sent[sent_len] = 0;
    ++request_writes;
    lineReuseBuffer(l, b);
    if (nested_payload[0])
    {
        nested_payload[0] = false;
        unsigned before   = request_writes;
        sendBytes(client, false, nested_bytes);
        if (nested_resume)
        {
            httpproxyserverTunnelDownStreamPause(proxy, child);
            httpproxyserverTunnelDownStreamResume(proxy, child);
            require(request_writes == before, "nested request bypassed active dispatch");
        }
    }
    if (finish_request)
    {
        childEof();
        return;
    }
    if (close_on == 8)
    {
        clientClose();
        return;
    }
    if (pause_request)
    {
        pause_request = false;
        httpproxyserverTunnelDownStreamPause(proxy, l);
    }
    if (automatic_response)
        sendBytes(l, true, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
}

static void resetClient(tunnel_chain_t *chain)
{
    fallback_opens = init_action = child_pauses = 0;
    last_wrapper[0] = last_wrapper[1] = 0;
    splice_writes[0] = splice_writes[1]         = 0;
    in_fallback_init                            = false;
    nested_resume = finish_request = false;
    nested_payload[0] = nested_payload[1] = finish_response = false;
    nested_bytes                                            = "NEW";
    pause_request = pause_response = delay_establishment = false;
    opens = closes = establishments = client_writes = request_writes = 0;
    received_len                                                     = 0;
    sent_len                                                         = 0;
    sent[0]                                                          = 0;
    producer_paused[0] = producer_paused[1] = false;
    received[0]                             = 0;
    close_on                                = 0;
    refuse                                  = false;
    automatic_response                      = true;
    child                                   = NULL;
    client                                  = lineCreateForWorker(0, chain->line_pools, 0);
    lineRef(client); /* test observation reference */
    lineGetRoutingContext(client)->local_listener_port = 8080;
    lineGetRoutingContext(client)->peer_source_port    = 54321;
    require(addresscontextSetIpAddress(lineGetSourceAddressContext(client), "127.0.0.2"), "source address");
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(client), IP_PROTO_TCP);
    httpproxyserverTunnelUpStreamInit(proxy, client);
    require(! linePrefersOrdinaryReadUpstream(client) && ! linePrefersOrdinaryReadDownstream(client),
            "server chose read preferences before request selection");
}

static void childEof(void)
{
    line_t *l = child;
    child     = NULL;
    lineRef(l);
    httpproxyserverTunnelDownStreamFinish(proxy, l);
    require(! lineIsAlive(l), "EOF left owned child alive");
    lineUnref(l);
}

static void fallbackInit(tunnel_t *t, line_t *l)
{
    require(t == fallback, "wrong fallback entry");
    require(! linePrefersOrdinaryReadUpstream(client) && ! linePrefersOrdinaryReadDownstream(client),
            "authentication fallback inherited an HTTP read preference");
    ++fallback_opens;
    require(! addresscontextHasPort(lineGetDestinationAddressContext(l)), "failed authority escaped to fallback");
    require(lineGetUserAuthCount(l) == lineGetUserAuthCount(client), "rejected identity escaped to fallback");
    in_fallback_init = true;
    childInit(t, l);
    if (lineIsAlive(l))
    {
        if (init_action == 1 || init_action == 3)
            httpproxyserverTunnelUpStreamResume(proxy, client);
        if (init_action == 2 || init_action == 3)
            httpproxyserverTunnelUpStreamPause(proxy, client);
        if (init_action == 2)
            httpproxyserverTunnelUpStreamResume(proxy, client);
        if (init_action == 6)
        {
            httpproxyserverTunnelDownStreamPause(proxy, l);
            httpproxyserverTunnelUpStreamResume(proxy, client);
        }
        if (init_action == 4)
            sendBytes(client, false, "nested-input");
        if (init_action == 5)
        {
            sendBytes(l, true, "raw local reply\r\n");
            childEof();
        }
    }
    in_fallback_init = false;
}

static void fallbackStart(tunnel_chain_t *chain)
{
    resetClient(chain);
    automatic_response  = false;
    delay_establishment = true;
}

static tunnel_t *localConfig(const char *json, bool valid);

static void responseOrdering(tunnel_chain_t *chain, const char *request, bool fallback_mode, bool http)
{
    const size_t n    = kHpsDeliveryHeadroomBytes + 32768;
    char        *wire = memoryAllocate(n + 1);
    memorySet(wire, 'x', n);
    wire[n] = 0;
    for (unsigned event = 0; event < 7; ++event)
    {
        resetClient(chain);
        automatic_response  = false;
        delay_establishment = fallback_mode;
        sendBytes(client, false, request);
        if (http)
        {
            char header[128];
            stringNPrintf(header, sizeof(header), "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n", n + 3);
            sendBytes(child, true, header);
        }
        received_len      = 0;
        nested_payload[1] = true;
        finish_response   = event == 1 || event == 3;
        pause_response    = event == 2 || event == 3;
        if (event == 4)
            nested_bytes = wire; /* Active remainder and nested input share D. */
        else if (event == 5)
            close_on = 3;
        else if (event == 6)
            nested_bytes = "";
        sendBytes(child, true, wire);
        if (event == 4 || event == 5)
        {
            require(! lineIsAlive(client) && ! child && closes == 1, "active response overflow/close failed to settle");
            lineUnref(client);
            continue;
        }
        if (event == 2 || event == 3)
        {
            require(lineIsAlive(client) && received_len < n, "Pause lost active response retention");
            httpproxyserverTunnelUpStreamResume(proxy, client);
        }
        size_t extra = event == 6 ? 0 : 3;
        require(received_len == n + extra && ! memoryCompare(received, wire, n) &&
                    ! stringCompare(received + n, extra ? "NEW" : ""),
                "nested response overtook active delivery");
        if (! http && finish_response)
            require(! lineIsAlive(client) && ! child && ! closes, "raw EOF failed to drain active response");
        clientClose();
        lineUnref(client);
    }
    memoryFree(wire);
}

static void requestOrdering(tunnel_chain_t *chain, const char *request, bool fallback_mode)
{
    const size_t n    = kHpsDeliveryHeadroomBytes + 32768;
    char        *wire = memoryAllocate(n + 1);
    memorySet(wire, 'x', n);
    wire[n] = 0;
    resetClient(chain);
    automatic_response  = false;
    delay_establishment = fallback_mode;
    sendBytes(client, false, request);
    sent_len          = 0;
    nested_payload[0] = true;
    sendBytes(client, false, wire);
    require(sent_len == n + 3 && ! memoryCompare(sent, wire, n) && ! stringCompare(sent + n, "NEW"),
            "nested request overtook active delivery");
    clientClose();
    lineUnref(client);
    memoryFree(wire);
}

static void fallbackCases(tunnel_chain_t *chain)
{
    tunnel_t *saved = proxy;
    proxy           = localConfig("{\"users\":[{\"username\":\"alice\",\"password\":\"one\"}]}", true);
    proxy->chain    = chain;
    tunnelBind(prev, proxy);
    tunnelBind(proxy, next);
    hps_tstate_t *ts   = tunnelGetState(proxy);
    ts->fallback       = fallback;
    ts->max_pending    = 65536;
    const char *raw    = "POST http://untrusted.invalid:19/a HTTP/1.1\r\nhoST: unchanged\r\n"
                         "pRoXy-Authorization: Basic !!!\r\nConnection: X-Hop\r\nX-Hop:  value \t\r\n"
                         "Transfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n3;x=y\r\nabc\r\n0\r\n\r\npipeline";
    size_t      length = stringLength(raw);
    responseOrdering(chain, raw, true, false);
    responseOrdering(
        chain, "CONNECT a:443 HTTP/1.1\r\nHost: a\r\nProxy-Authorization: Basic YWxpY2U6b25l\r\n\r\n", false, false);
    responseOrdering(
        chain, "GET http://a/ HTTP/1.1\r\nHost: a\r\nProxy-Authorization: Basic YWxpY2U6b25l\r\n\r\n", false, true);
    requestOrdering(chain, raw, true);
    requestOrdering(
        chain, "CONNECT a:443 HTTP/1.1\r\nHost: a\r\nProxy-Authorization: Basic YWxpY2U6b25l\r\n\r\n", false);
    char post[256];
    stringNPrintf(post,
                  sizeof(post),
                  "POST http://a/ HTTP/1.1\r\nHost: a\r\n"
                  "Proxy-Authorization: Basic YWxpY2U6b25l\r\nContent-Length: %u\r\n\r\n",
                  kHpsDeliveryHeadroomBytes + 32768 + 3);
    requestOrdering(chain, post, false);
    for (size_t split = 0; split <= length; ++split)
    {
        fallbackStart(chain);
        char prefix[512];
        memoryCopy(prefix, raw, split);
        prefix[split] = 0;
        sendBytes(client, false, prefix);
        sendBytes(client, false, raw + split);
        require(fallback_opens == 1 && opens == 1 && ! received_len && sent_len == length &&
                    ! memoryCompare(sent, raw, length),
                "split exact replay");
        sendBytes(client, false, "GET http://a/ HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6b25l\r\n\r\n");
        require(fallback_opens == 1 && opens == 1 && strstr(sent, "http://a/"), "fallback was not permanent");
        sendBytes(child, true, "arbitrary non-HTTP response");
        require(! stringCompare(received, "arbitrary non-HTTP response") && ! establishments, "early raw reply");
        httpproxyserverTunnelUpStreamPause(proxy, client);
        httpproxyserverTunnelDownStreamEst(proxy, child);
        httpproxyserverTunnelDownStreamEst(proxy, child);
        require(establishments == 1, "paused fallback Est latch");
        clientClose();
        require(closes == 1, "fallback Finish branch");
        lineUnref(client);
    }
    const char *denials[] = {"GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n",
                             "GET http://a/ HTTP/1.1\r\nHost: a\r\nProxy-Authorization: Digest a\r\n\r\n",
                             "GET http://a/ HTTP/1.1\r\nHost: a\r\nProxy-Authorization: Basic Ym9iOnR3bw==\r\n\r\n",
                             "CONNECT a:443 HTTP/1.1\r\nHost: a\r\n\r\ncoalesced",
                             "OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n",
                             "POST http://a/ HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabcTAIL"};
    for (unsigned i = 0; i < ARRAY_SIZE(denials); ++i)
    {
        fallbackStart(chain);
        sendBytes(client, false, denials[i]);
        require(fallback_opens == 1 && ! received_len && ! stringCompare(sent, denials[i]), "auth denial replay");
        clientClose();
        lineUnref(client);
    }
    /* Current receiver permission wins, regardless of when selection/Init occurs. */
    for (unsigned action = 0; action <= 3; ++action)
        for (unsigned before = 0; before <= 2; ++before)
        {
            fallbackStart(chain);
            if (before)
                httpproxyserverTunnelUpStreamPause(proxy, client);
            if (before == 2)
                httpproxyserverTunnelUpStreamResume(proxy, client);
            init_action = action;
            sendBytes(client, false, raw);
            bool want = action == 3 || (action == 0 && before == 1);
            require(producer_paused[1] == want && child_pauses == (unsigned) want, "stale or lost Init pressure");
            sendBytes(child, true, "reply");
            require(received_len == (want ? 0 : 5), "receiver permission ignored");
            childEof();
            if (want)
            {
                require(lineIsAlive(client), "paused EOF discarded reply");
                httpproxyserverTunnelUpStreamResume(proxy, client);
            }
            require(! lineIsAlive(client) && ! stringCompare(received, "reply") && ! closes, "EOF reply settlement");
            lineUnref(client);
        }
    for (unsigned paused = 0; paused < 2; ++paused)
    {
        fallbackStart(chain);
        if (paused)
            httpproxyserverTunnelUpStreamPause(proxy, client);
        init_action = 5;
        sendBytes(client, false, raw);
        require(! sent_len && ! closes && ! establishments, "Init EOF reflected or emitted replay/Est");
        if (paused)
        {
            require(lineIsAlive(client) && ! received_len, "Init EOF lost paused output");
            httpproxyserverTunnelUpStreamResume(proxy, client);
        }
        require(! lineIsAlive(client) && ! stringCompare(received, "raw local reply\r\n"), "Init reply disappeared");
        lineUnref(client);
    }
    /* Larger than D: the outer Payload owns a suffix when parsing selects fallback. */
    fallbackStart(chain);
    init_action       = 4;
    size_t big_length = kHpsDeliveryHeadroomBytes + 32768;
    char  *big        = memoryAllocate(big_length + 1);
    memoryCopy(big, raw, length);
    memorySet(big + length, 'x', big_length - length);
    big[big_length] = 0;
    sendBytes(client, false, big);
    require(lineIsAlive(client) && sent_len == big_length + 12 && ! memoryCompare(sent, big, big_length) &&
                ! stringCompare(sent + big_length, "nested-input"),
            "outer remainder overtaken by Init reentry");
    memoryFree(big);
    clientClose();
    lineUnref(client);

    fallbackStart(chain);
    init_action = 6;
    sendBytes(client, false, raw);
    require(! sent_len && producer_paused[0], "independent request pressure was released");
    httpproxyserverTunnelDownStreamResume(proxy, child);
    require(sent_len == length && ! stringCompare(sent, raw) && ! producer_paused[0], "paused replay lost");
    clientClose();
    lineUnref(client);

    /* First handoff at the full P+D boundary remains charged, including the header. */
    fallbackStart(chain);
    init_action            = 6;
    size_t boundary_length = kHpsDeliveryHeadroomBytes + ts->max_pending;
    char  *boundary        = memoryAllocate(boundary_length + 2);
    memoryCopy(boundary, raw, length);
    memorySet(boundary + length, 'x', boundary_length - length);
    boundary[boundary_length] = 0;
    sendBytes(client, false, boundary);
    require(lineIsAlive(client) && child && ! sent_len, "P+D fallback admission failed");
    sendBytes(child, true, "raw reply while request is paused");
    require(! stringCompare(received, "raw reply while request is paused") && ! producer_paused[1],
            "full request budget blocked unpaused response");
    received_len = 0;
    httpproxyserverTunnelDownStreamResume(proxy, child);
    require(sent_len == boundary_length && ! memoryCompare(sent, boundary, boundary_length), "P+D replay bytes");
    boundary[boundary_length]     = 'x';
    boundary[boundary_length + 1] = 0;
    sendBytes(client, false, boundary);
    require(! lineIsAlive(client) && ! received_len, "raw overflow invented HTTP error");
    memoryFree(boundary);
    lineUnref(client);

    const char *valid = "GET http://a/ HTTP/1.1\r\nHost: a\r\nProxy-Authorization: Basic YWxpY2U6b25l\r\n\r\n";
    resetClient(chain);
    sendBytes(client, false, valid);
    sendBytes(client, false, denials[0]);
    require(! lineIsAlive(client) && ! fallback_opens && opens == 1 && strstr(received, "407"),
            "later failure fell back");
    lineUnref(client);
    resetClient(chain);
    ts->auth_mode = kHpsAuthNone;
    sendBytes(client, false, denials[0]);
    require(opens == 1 && ! fallback_opens && strstr(received, "200"), "no-auth fallback was active");
    clientClose();
    lineUnref(client);
    ts->auth_mode = kHpsAuthLocal;
    resetClient(chain);
    httpproxyserverTunnelUpStreamPause(proxy, client);
    sendBytes(client,
              false,
              "OPTIONS * HTTP/1.1\r\nHost: a\r\n"
              "Proxy-Authorization: Basic YWxpY2U6b25l\r\n\r\n");
    hps_session_t *options_session = ((hps_lstate_t *) lineGetState(client, proxy))->session;
    require(options_session && options_session->protected_committed && ! opens, "OPTIONS commitment");
    httpproxyserverTunnelUpStreamResume(proxy, client);
    require(! lineIsAlive(client) && ! fallback_opens && strstr(received, "200"), "OPTIONS local response");
    lineUnref(client);
    resetClient(chain);
    automatic_response = false;
    sendBytes(client,
              false,
              "CONNECT a:443 HTTP/1.1\r\nHost: a\r\n"
              "Proxy-Authorization: Basic YWxpY2U6b25l\r\n\r\n");
    sendBytes(client, false, denials[0]);
    require(opens == 1 && ! fallback_opens && ! stringCompare(sent, denials[0]), "CONNECT commitment");
    clientClose();
    lineUnref(client);
    const char *malformed[] = {
        "GET http://a/ HTTP/1.1\r\nHost: a\r\nProxy-Authorization: x\r\nProxy-Authorization: y\r\n\r\n",
        "GET http://a/ HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        "TRACE http://a/ HTTP/1.1\r\nHost: a\r\n\r\n"};
    for (unsigned i = 0; i < ARRAY_SIZE(malformed); ++i)
    {
        fallbackStart(chain);
        sendBytes(client, false, malformed[i]);
        require(! lineIsAlive(client) && ! opens && ! fallback_opens && received_len, "malformed input fell back");
        lineUnref(client);
    }
    fallbackStart(chain);
    for (unsigned i = 0; i < kLineMaxUsers; ++i)
        lineAddAuthenticatedCredentials(client, "inherited", "value");
    sendBytes(client, false, valid);
    require(! lineIsAlive(client) && ! opens && strstr(received, "503"), "post-auth local failure fell back");
    lineUnref(client);
    for (unsigned event = 1; event <= 8; ++event)
    {
        fallbackStart(chain);
        close_on = event;
        if (event == 6 || event == 7)
            httpproxyserverTunnelUpStreamPause(proxy, client);
        sendBytes(client, false, raw);
        if (event == 2)
            httpproxyserverTunnelDownStreamEst(proxy, child);
        else if (event == 3)
            sendBytes(child, true, "reply");
        else if (event == 4 || event == 5)
        {
            httpproxyserverTunnelDownStreamPause(proxy, child);
            if (event == 5)
                httpproxyserverTunnelDownStreamResume(proxy, child);
        }
        else if (event == 7)
            httpproxyserverTunnelUpStreamResume(proxy, client);
        require(! lineIsAlive(client) && ! child && closes == 1, "fallback callback close lifetime");
        lineUnref(client);
    }
    for (unsigned idle = 0; idle < 2; ++idle)
    {
        fallbackStart(chain);
        sendBytes(client, false, raw);
        hps_session_t *session = ((hps_lstate_t *) lineGetState(client, proxy))->session;
        require(! session->directions[kHpsUpstream].header_at && ! session->directions[kHpsDownstream].header_at,
                "fallback retained HTTP deadline");
        wloop_t *loop = getWorkerLoop(lineGetWID(client));
        if (idle)
        {
            httpproxyserverTunnelDownStreamEst(proxy, child);
            loop->cur_hrtime = (session->progress_at + ts->idle_timeout) * 1000;
        }
        else
            loop->cur_hrtime = (session->connect_at + ts->connect_timeout) * 1000;
        session->timer->cb((wevent_t *) session->timer);
        require(! lineIsAlive(client) && ! child && ! received_len && closes == 1, "raw timeout settlement");
        lineUnref(client);
        wloopUpdateTime(loop);
    }
    fallbackStart(chain);
    sendBytes(client, false, raw);
    httpproxyserverTunnelUpStreamPause(proxy, client);
    sendBytes(child, true, "pending");
    httpproxyserverTunnelOnWorkerStop(proxy, 0, NULL);
    require(! child && lineIsAlive(client) && ! ts->workers[0].timers, "fallback worker inventory");
    sendBytes(client, false, raw);
    require(opens == 1, "quiescent fallback reopened");
    clientClose();
    lineUnref(client);
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0, "fallback line leak");
    httpproxyserverTunnelDestroy(proxy, NULL);
    proxy = saved;
    tunnelBind(prev, proxy);
    tunnelBind(proxy, next);
}

static void pipelinePressure(tunnel_chain_t *chain, const char *get)
{
    hps_tstate_t *ts    = tunnelGetState(proxy);
    uint32_t      saved = ts->max_pending;
    ts->max_pending     = 65536;
    resetClient(chain);
    automatic_response = false;
    char pipeline[51000];
    int  prefix = stringNPrintf(pipeline,
                               sizeof(pipeline),
                               "%sPOST http://127.0.0.1:80/second HTTP/1.1\r\nHost: a\r\nContent-Length: 50000\r\n\r\n",
                               get);
    memorySet(pipeline + prefix, 'p', 50000);
    pipeline[prefix + 50000] = 0;
    sendBytes(client, false, pipeline); /* One already admitted callback may cross the high watermark. */
    require(producer_paused[0] && ! strstr(sent, "POST"), "R1 pipeline admission or sequencing");
    require(! producer_paused[1], "R1 queued request paused current response producer");
    char response[100100];
    int  header = stringNPrintf(response, sizeof(response), "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n");
    memorySet(response + header, 'r', 100000);
    response[header + 100000] = 0;
    sendBytes(child, true, response); /* Several capacity-limited slices in one permitted callback. */
    require(lineIsAlive(client) && received_len == (size_t) header + stringLength("Via: 1.1 WaterWall\r\n") + 100000,
            "R1 large response did not stream"); /* rewrite appends Via: 1.1 WaterWall */
    require(opens == 1 && strstr(sent, "POST /second HTTP/1.1") && ! producer_paused[0], "R1 pipeline did not resume");
    const char *post = strstr(sent, "POST /second");
    const char *body = strstr(post, "\r\n\r\n") + 4;
    require(stringLength(body) == 50000 && strspn(body, "p") == 50000, "R1 POST bytes changed or replayed");
    require(! producer_paused[1], "R1 response producer remained paused");
    sendBytes(child, true, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    require(strstr(received + received_len - 4, "ok") != NULL, "R1 second response missing");
    clientClose();
    lineUnref(client);

    resetClient(chain);
    automatic_response = false;
    sendBytes(client, false, get);
    httpproxyserverTunnelUpStreamPause(proxy, client);
    const size_t overflow_length = UINT64_C(2) * 1024 * 1024 + 1;
    char *overflow = memoryAllocate(overflow_length + 1);
    memorySet(overflow, 'x', overflow_length);
    overflow[overflow_length] = 0;
    sendBytes(client, false, overflow); /* True overflow of the fixed delivery allowance. */
    memoryFree(overflow);
    httpproxyserverTunnelUpStreamResume(proxy, client);
    require(! lineIsAlive(client) && child == NULL, "R1 real overflow did not settle");
    lineUnref(client);
    ts->max_pending = saved;
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0, "R1 line leak");
}

static void responseEof(tunnel_chain_t *chain, const char *get)
{
    const char *truncated[] = {"HTTP/1.1 20",
                               "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n",
                               "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na",
                               "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r",
                               "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: partial",
                               "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nx"};
    for (size_t i = 0; i < ARRAY_SIZE(truncated); ++i)
    {
        resetClient(chain);
        automatic_response = false;
        sendBytes(client, false, get);
        sendBytes(child, true, truncated[i]);
        size_t before = received_len;
        childEof();
        require(! lineIsAlive(client), "R3 truncation did not settle directly at EOF");
        require(i < 2 ? strstr(received, "502 Bad Gateway") != NULL : received_len == before,
                "R3 wrong commitment handling");
        require(closes == 0, "R3 reflected Finish toward child");
        lineUnref(client);
    }
    const char *complete[] = {"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                              "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
                              "HTTP/1.1 200 OK\r\n\r\nok"};
    for (size_t i = 0; i < ARRAY_SIZE(complete); ++i)
    {
        resetClient(chain);
        automatic_response = false;
        sendBytes(client, false, get);
        /* EOF must preserve already in-flight input retained behind a blocked consumer. */
        httpproxyserverTunnelUpStreamPause(proxy, client);
        sendBytes(child, true, complete[i]); /* already in-flight input */
        childEof();
        require(lineIsAlive(client) && received_len == 0, "R3 discarded paused complete response at EOF");
        httpproxyserverTunnelUpStreamResume(proxy, client);
        require(strstr(received, i == 1 ? "2\r\nok\r\n0\r\n\r\n" : "\r\n\r\nok") != NULL && ! strstr(received, "502"),
                "R3 valid retained response lost on Resume");
        if (i < 2)
        {
            require(lineIsAlive(client), "R3 complete persistent response killed client");
            sendBytes(client, false, get);
            require(opens == 2, "R3 complete EOF prevented replacement");
            clientClose();
        }
        else
            require(! lineIsAlive(client), "R3 close-delimited response did not close");
        lineUnref(client);
    }
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0, "R3 line leak");
}

static tunnel_t *localConfig(const char *json, bool valid)
{
    node_t node = {.type               = (char *) "HttpProxyServer",
                   .next               = (char *) "out",
                   .hash_next          = 1,
                   .node_settings_json = cJSON_Parse(json)};
    require(node.node_settings_json != NULL, "test JSON");
    tunnel_t *t = httpproxyserverTunnelCreate(&node);
    require((t != NULL) == valid, "L1 local configuration acceptance");
    cJSON_Delete(node.node_settings_json);
    if (t)
    {
        t->node          = NULL; /* No runtime callback below needs the temporary configuration node. */
        hps_tstate_t *ts = tunnelGetState(t);
        require(ts->auth_mode == kHpsAuthLocal && ! ts->controller && ! ts->auth_node && ! ts->auth,
                "L4 local configuration created tracked topology");
        httpproxyserverTunnelOnPrepair(t);
    }
    return t;
}

static void localConfiguration(void)
{
    const char *bad[] = {
        "{}",
        "{\"users\":null}",
        "{\"users\":[]}",
        "{\"users\":{}}",
        "{\"users\":true}",
        "{\"no-auth\":true,\"users\":null}",
        "{\"users\":[],\"auth-client-node-name\":null}",
        "{\"users\":[null]}",
        "{\"users\":[\"u:p\"]}",
        "{\"users\":[{}]}",
        "{\"users\":[{\"username\":\"u\"}]}",
        "{\"users\":[{\"password\":\"p\"}]}",
        "{\"users\":[{\"username\":1,\"password\":\"p\"}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":null}]}",
        "{\"users\":[{\"username\":\"\",\"password\":\"p\"}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"\"}]}",
        "{\"users\":[{\"username\":\"u:p\",\"password\":\"p\"}]}",
        "{\"users\":[{\"username\":\"u\\n\",\"password\":\"p\"}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"p\\u007f\"}]}",
        "{\"users\":[{\"username\":\"u\",\"username\":\"v\",\"password\":\"p\"}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"p\",\"password\":\"q\"}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"p\",\"limit\":0}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"p\",\"enabled\":true}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"p\",\"expire-at-ms\":0}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"p\"},{\"username\":\"u\",\"password\":\"p\"}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"p\"},{}]}"};
    for (size_t i = 0; i < ARRAY_SIZE(bad); ++i)
        localConfig(bad[i], false);
    tunnel_t     *t  = localConfig("{\"no-auth\":false,\"users\":[{\"username\":\"u\",\"password\":\"p:q\"},"
                                   "{\"username\":\"u\",\"password\":\"p\"},{\"username\":\"v\",\"password\":\"p\"}]}",
                              true);
    hps_tstate_t *ts = tunnelGetState(t);
    require(ts->user_count == 3 && ! stringCompare(ts->users[0].password, "p:q"), "L1 owned credential copy");
    httpproxyserverTunnelDestroy(t, NULL);
    char component[257], json[1024];
    memorySet(component, 'x', 255);
    component[255] = 0;
    stringNPrintf(json, sizeof(json), "{\"users\":[{\"username\":\"%s\",\"password\":\"%s\"}]}", component, component);
    t = localConfig(json, true);
    httpproxyserverTunnelDestroy(t, NULL);
    component[255] = 'x';
    component[256] = 0;
    stringNPrintf(json, sizeof(json), "{\"users\":[{\"username\":\"%s\",\"password\":\"p\"}]}", component);
    localConfig(json, false);
    stringNPrintf(json, sizeof(json), "{\"users\":[{\"username\":\"u\",\"password\":\"%s\"}]}", component);
    localConfig(json, false);
}

static void localAuthentication(tunnel_chain_t *chain)
{
    tunnel_t *saved = proxy;
    proxy           = localConfig("{\"users\":[{\"username\":\"alice\",\"password\":\"one\"},"
                                  "{\"username\":\"bob\",\"password\":\"two\"}]}",
                        true);
    proxy->chain    = chain;
    tunnelBind(prev, proxy);
    tunnelBind(proxy, next);
    const char *alice = "GET http://127.0.0.1:80/a HTTP/1.1\r\nHost: a\r\nProxy-Authorization: Basic "
                        "YWxpY2U6b25l\r\nAuthorization: Bearer origin\r\n\r\n";
    const char *bob =
        "GET http://127.0.0.1:80/b HTTP/1.1\r\nHost: a\r\nProxy-Authorization: Basic Ym9iOnR3bw==\r\n\r\n";
    resetClient(chain);
    user_handle_t inherited = {.generation = 1, .user_id = 42};
    lineAddUser(client, &inherited, "inherited", "value");
    for (unsigned i = 0; i < 8; ++i)
        sendBytes(client, false, alice);
    require(opens == 1 && lineGetUserAuthCount(child) == 2 && lineGetUserAuthCount(client) == 1,
            "L3 local reuse or marker growth");
    require(lineGetUserAuthAt(child, 0)->has_handle && ! lineGetUserAuthAt(child, 1)->has_handle &&
                lineHasAuthenticatedCredentials(child, "alice", "one") &&
                lineHasAuthenticatedCredentials(child, "inherited", "value"),
            "L4 credentials-only marker/inheritance");
    require(! strstr(sent, "Proxy-Authorization") && strstr(sent, "Authorization: Bearer origin"),
            "L2 header stripping");
    sendBytes(client, false, bob);
    require(opens == 2 && closes == 1 && lineHasAuthenticatedCredentials(child, "bob", "two"),
            "L3 pair switch metadata");
    sendBytes(client, false, "GET http://127.0.0.1:80/a HTTP/1.1\r\nHost: a\r\n\r\n");
    require(! lineIsAlive(client) && opens == 2 && strstr(received, "407"), "L3 missing reauthentication");
    lineUnref(client);
    resetClient(chain);
    for (unsigned i = 0; i < kLineMaxUsers; ++i)
        lineAddUser(client, &inherited, NULL, NULL);
    sendBytes(client, false, alice);
    require(! lineIsAlive(client) && opens == 0 && strstr(received, "503"), "L4 local marker capacity");
    lineUnref(client);
    for (unsigned event = 1; event <= 5; ++event)
    {
        resetClient(chain);
        close_on = event;
        sendBytes(client, false, alice);
        if (event >= 4)
        {
            httpproxyserverTunnelDownStreamPause(proxy, child);
            if (event == 5)
                httpproxyserverTunnelDownStreamResume(proxy, child);
        }
        require(! lineIsAlive(client) && child == NULL && closes == 1, "L5 local reentrant settlement");
        lineUnref(client);
    }
    resetClient(chain);
    sendBytes(client, false, alice);
    httpproxyserverTunnelOnWorkerQuiesce(proxy, 0, NULL);
    httpproxyserverTunnelOnWorkerStop(proxy, 0, NULL);
    require(child == NULL && lineIsAlive(client), "L5 local child drain");
    clientClose();
    lineUnref(client);
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0, "L5 local reference leak");
    httpproxyserverTunnelDestroy(proxy, NULL);
    proxy = saved;
    tunnelBind(prev, proxy);
    tunnelBind(proxy, next);
}

static void requireRetainedBounds(hps_session_t *session)
{
    buffer_pool_t *pool    = lineGetBufferPool(session->client);
    const uint64_t p       = ((hps_tstate_t *) tunnelGetState(proxy))->max_pending;
    const uint64_t d       = UINT64_C(2) * 1024 * 1024;
    uint64_t       working = 0, charge = 0, total = 0;
    uint32_t       remainder_capacity;
    require(sbufTryComputeCapacity(max((uint64_t) bufferpoolGetSmallBufferSize(pool), 2 * d),
                                   max(bufferpoolGetSmallBufferPadding(pool), bufferpoolGetLargeBufferPadding(pool)),
                                   &remainder_capacity),
            "test remainder bound geometry");
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        const hps_direction_state_t *dir       = &session->directions[direction];
        sbuf_t                      *buffers[] = {dir->input, dir->output};
        for (unsigned i = 0; i < 2; ++i)
            if (buffers[i])
            {
                working += sbufGetLength(buffers[i]);
                charge += sbufGetTotalCapacity(buffers[i]) + sizeof(sbuf_t) + kSbufAllocationAlignment;
            }
        if (dir->deferred)
        {
            require(sbufGetLength(dir->deferred) <= d, "remainder exceeded logical allowance");
            require(sbufGetTotalCapacity(dir->deferred) <= remainder_capacity,
                    "remainder exceeded allocation allowance");
            total += sbufGetLength(dir->deferred);
        }
    }
    require(working <= p && charge <= 4 * p && total + working <= p + 2 * d, "retained budgets exceeded");
}

static void largeDeliveries(tunnel_chain_t *chain, bool delayed, bool close_retained)
{
    resetClient(chain);
    automatic_response  = false;
    delay_establishment = delayed;
    pause_request       = ! delayed;
    const size_t n      = SPLICE_PAYLOAD_LIMIT;
    char        *text   = memoryAllocate(n + 6000);
    char         padding[5001];
    memorySet(padding, 'h', 5000);
    padding[5000] = 0;
    int prefix    = stringNPrintf(
        text,
        n + 6000,
        "POST http://127.0.0.1:80/large HTTP/1.1\r\nHost: a\r\nX-Large: %s\r\nContent-Length: %zu\r\n\r\n",
        padding,
        n);
    memorySet(text + prefix, 'q', n);
    text[prefix + n] = 0;
    sendBytes(client, false, text);
    hps_session_t *session = ((hps_lstate_t *) lineGetState(client, proxy))->session;
    require(lineIsAlive(client) && session && session->directions[kHpsUpstream].deferred,
            "large request lost its deferred remainder");
    requireRetainedBounds(session);
    require(producer_paused[0] && ! strstr(received, "503"), "large request did not use bounded headroom");
    if (close_retained)
    {
        clientClose();
        lineUnref(client);
        memoryFree(text);
        return;
    }
    if (delayed)
        httpproxyserverTunnelDownStreamEst(proxy, child);
    else
        httpproxyserverTunnelDownStreamResume(proxy, child);
    const char *body = strstr(sent, "\r\n\r\n");
    require(body && strlen(body + 4) == n && strspn(body + 4, "q") == n, "large request bytes changed");
    prefix = stringNPrintf(text, n + 6000, "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n", n);
    memorySet(text + prefix, 'r', n);
    text[prefix + n] = 0;
    pause_response   = true;
    sendBytes(child, true, text);
    require(session->directions[kHpsDownstream].deferred && producer_paused[1],
            "large response lost its deferred remainder");
    requireRetainedBounds(session);
    httpproxyserverTunnelUpStreamResume(proxy, client);
    body = strstr(received, "\r\n\r\n");
    require(body && strlen(body + 4) == n && strspn(body + 4, "r") == n, "large response bytes changed");
    require(! session->directions[kHpsUpstream].deferred && ! session->directions[kHpsDownstream].deferred,
            "large delivery failed to drain");
    clientClose();
    lineUnref(client);
    memoryFree(text);
}

static void cachedTimeoutClock(tunnel_chain_t *chain, const char *get)
{
    wloop_t       *loop     = getWorkerLoop(0);
    hps_tstate_t  *ts       = tunnelGetState(proxy);
    const uint64_t start_ms = UINT64_C(5000000000); /* Exercise more than 32 bits. */
    for (unsigned mode = 0; mode < 4; ++mode)
    {
        loop->cur_hrtime = start_ms * 1000 + 789;
        resetClient(chain);
        hps_session_t *s = ((hps_lstate_t *) lineGetState(client, proxy))->session;
        require(s->progress_at == start_ms, "Init sampled a fresh clock instead of the cached loop clock");
        /* Adding the session timer refreshes the real loop clock. Subsequent
         * callbacks below use a controlled cached timestamp, without sleeping. */
        loop->cur_hrtime   = start_ms * 1000 + 789;
        automatic_response = false;
        uint32_t duration  = ts->idle_timeout;
        if (mode == 0)
        {
            sendBytes(client, false, "GET http://a/ HTTP/1.1\r\nHost:");
            require(s->directions[kHpsUpstream].header_at == start_ms, "request header used a different clock");
            duration = ts->header_timeout;
        }
        else if (mode == 1)
        {
            delay_establishment = true;
            sendBytes(client, false, get);
            require(s->connect_at == start_ms, "child connection used a different clock");
            duration = ts->connect_timeout;
        }
        else if (mode == 2)
        {
            sendBytes(client, false, get);
            sendBytes(child, true, "HTTP/1.1 200");
            require(! s->connect_at && s->directions[kHpsDownstream].header_at == start_ms,
                    "response header used a different clock");
            duration = ts->header_timeout;
        }
        require(s->progress_at == start_ms, "payload or Est sampled a fresh clock");
        loop->cur_hrtime = (start_ms + duration - 1) * 1000 + 999;
        for (unsigned backwards = 0; backwards < 2; ++backwards)
        {
            loop->cur_time_ms = backwards ? start_ms - 3600000 : start_ms + 3600000;
            s->timer->cb((wevent_t *) s->timer);
            require(lineIsAlive(client), "wall-clock adjustment or rounding expired an early deadline");
        }
        loop->cur_hrtime = (start_ms + duration) * 1000;
        s->timer->cb((wevent_t *) s->timer);
        require(! lineIsAlive(client) && ! child, "cached monotonic deadline did not expire");
        require(mode == 3 ? ! received_len : strstr(received, mode == 0 ? "408" : "504") != NULL,
                "cached deadline changed HTTP timeout behavior");
        lineUnref(client);
        wloopUpdateTime(loop);
    }
}

static void httpBodyCases(tunnel_chain_t *chain)
{
    for (unsigned http10 = 0; http10 < 2; ++http10)
    {
        resetClient(chain);
        automatic_response = false;
        sendBytes(client,
                  false,
                  http10 ? "GET http://a/ HTTP/1.0\r\nHost: a\r\n\r\n"
                         : "POST http://a/ HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n"
                           "Trailer: X-End\r\n\r\n3;x=y\r\nabc\r\n0\r\nX-End: yes\r\n\r\n");
        if (! http10)
            require(strstr(sent, "3;x=y\r\nabc\r\n0\r\nX-End: yes\r\n\r\n") != NULL,
                    "materialized chunked upload/trailer");
        sendBytes(child,
                  true,
                  "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\n"
                  "Transfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n"
                  "3\r\nxyz\r\n0\r\nX-End: yes\r\n\r\n");
        require(! splice_writes[0] && ! splice_writes[1], "HTTP body escaped as splice");
        if (http10)
            require(! lineIsAlive(client) && ! strstr(received, "103") && ! strstr(received, "Transfer-Encoding") &&
                        strstr(received, "\r\n\r\nxyz") != NULL && ! strstr(received, "X-End"),
                    "HTTP/1.0 dechunking/informational/trailer policy");
        else
            require(strstr(received, "103 Early Hints") && strstr(received, "3\r\nxyz\r\n0\r\nX-End: yes\r\n\r\n"),
                    "chunked response/trailer policy");
        clientClose();
        lineUnref(client);
    }
    resetClient(chain);
    automatic_response = false;
    sendBytes(client, false, "POST http://a/ HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\nfirst");
    httpproxyserverTunnelDownStreamPause(proxy, child);
    sendBytes(client, false, "held-upload");
    sendBytes(child, true, "HTTP/1.1 413 Content Too Large\r\nContent-Length: 4\r\n\r\nstop");
    require(! lineIsAlive(client) && ! child && ! strstr(sent, "held-upload") && strstr(received, "\r\n\r\nstop"),
            "early response did not cancel materialized upload");
    lineUnref(client);
}

static void readPreferenceCases(tunnel_chain_t *chain)
{
    const unsigned saved_representation = representation;
    resetClient(chain);
    automatic_response = false;
    sendBytes(client, false, "POST http://a/ HTTP/1.1\r\nHost: a\r\nContent-Length: 9\r\n");
    require(! child && ! linePrefersOrdinaryReadUpstream(client), "partial HTTP header selected ordinary reads");
    sendBytes(client, false, "\r\n");
    require(linePrefersOrdinaryReadUpstream(client) && ! linePrefersOrdinaryReadDownstream(client),
            "HTTP preference used the wrong incoming direction");
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        representation = mode;
        sendBytes(client, false, "abc");
    }
    require(strstr(sent, "\r\n\r\nabcabcabc") != NULL, "HTTP preference rejected mixed upload representations");
    sendBytes(child, true, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n");
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        representation = mode;
        sendBytes(child, true, "xyz");
    }
    require(strstr(received, "\r\n\r\nxyzxyzxyz") != NULL, "HTTP preference rejected mixed response representations");
    sendBytes(client, false, "GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n");
    require(opens == 1 && linePrefersOrdinaryReadDownstream(child), "reused HTTP child lost its read preference");
    sendBytes(child, true, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    sendBytes(client, false, "CONNECT a:443 HTTP/1.1\r\nHost: a\r\n\r\n");
    require(opens == 2 && closes == 1 && linePrefersOrdinaryReadUpstream(client) &&
                ! linePrefersOrdinaryReadUpstream(child) && ! linePrefersOrdinaryReadDownstream(child),
            "HTTP-to-CONNECT transition reset the client preference or copied it to a new child");
    for (unsigned d = 0; d < 2; ++d)
    {
        line_t   *source   = d ? child : client;
        sbuf_t   *b        = makeInput(source, "opaque", 2);
        uintptr_t identity = (uintptr_t) b;
        if (d)
            httpproxyserverTunnelDownStreamPayload(proxy, source, b);
        else
            httpproxyserverTunnelUpStreamPayload(proxy, source, b);
        require(last_wrapper[d] == identity, "persistent preference changed CONNECT buffer forwarding");
    }
    clientClose();
    lineUnref(client);
    resetClient(chain);
    automatic_response = false;
    sendBytes(client, false, "CONNECT a:443 HTTP/1.1\r\nHost: a\r\n\r\n");
    require(! linePrefersOrdinaryReadUpstream(client) && ! linePrefersOrdinaryReadDownstream(client),
            "fresh CONNECT selected ordinary reads");
    clientClose();
    lineUnref(client);
    representation = saved_representation;
}

#if WW_HAVE_SPLICE
static void spliceRelayCases(tunnel_chain_t *chain, unsigned mode)
{
    hps_tstate_t  *ts                   = tunnelGetState(proxy);
    const unsigned saved_representation = representation;
    representation                      = mode;
    for (unsigned raw_fallback = 0; raw_fallback < 2; ++raw_fallback)
    {
        hps_local_user_t user = {.username = "alice", .password = "one"};
        ts->auth_mode         = raw_fallback ? kHpsAuthLocal : kHpsAuthNone;
        ts->users             = raw_fallback ? &user : NULL;
        ts->user_count        = raw_fallback;
        ts->fallback          = raw_fallback ? fallback : NULL;
        const char *request   = raw_fallback ? "GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\nreplay"
                                             : "CONNECT a:443 HTTP/1.1\r\nHost: a\r\n\r\nearly";
        for (unsigned d = 0; d < 2; ++d)
            for (unsigned event = 0; event < 6; ++event)
            {
                resetClient(chain);
                automatic_response  = false;
                delay_establishment = true;
                sendBytes(client, false, request);
                sendBytes(child, true, "banner");
                if (! raw_fallback)
                {
                    require(! sent_len && ! received_len, "CONNECT bytes escaped before Est");
                    httpproxyserverTunnelDownStreamEst(proxy, child);
                    require(! stringCompare(sent, "early") &&
                                ! stringCompare(received, "HTTP/1.1 200 Connection Established\r\n\r\nbanner"),
                            "CONNECT success barrier");
                }
                else
                    require(! establishments && ! stringCompare(sent, request) && ! stringCompare(received, "banner"),
                            "pre-Est fallback replay/reply");
                sent_len = received_len = 0;
                sent[0] = received[0] = 0;
                splice_writes[0] = splice_writes[1] = 0;
                if (event == 1)
                {
                    if (d)
                        httpproxyserverTunnelUpStreamPause(proxy, client);
                    else
                        httpproxyserverTunnelDownStreamPause(proxy, child);
                }
                nested_payload[d] = event == 2 || event == 3;
                nested_resume     = event == 2;
                finish_response   = d && event == 3;
                finish_request    = ! d && event == 3;
                if (event == 4)
                    close_on = d ? 3 : 8;
                pause_request      = ! d && event == 5;
                pause_response     = d && event == 5;
                line_t   *source   = d ? child : client;
                sbuf_t   *b        = makeInput(source, "prefix-body", mode);
                uintptr_t identity = (uintptr_t) b;
                if (d)
                    httpproxyserverTunnelDownStreamPayload(proxy, source, b);
                else
                    httpproxyserverTunnelUpStreamPayload(proxy, source, b);
                if (event == 1)
                {
                    require(! splice_writes[d] && ! (d ? received_len : sent_len), "paused splice escaped");
                    requireOrdinarySlots();
                    if (d)
                        httpproxyserverTunnelUpStreamResume(proxy, client);
                    else
                        httpproxyserverTunnelDownStreamResume(proxy, child);
                    require(! splice_writes[d], "retained splice did not materialize");
                }
                else
                {
                    require(splice_writes[d] == 1, "ready splice was materialized or nested splice escaped");
                    if (event != 2 && ! (d && event == 3))
                        require(last_wrapper[d] == identity, "ready relay replaced the wrapper");
                }
                const char *expected = event == 2 || (d && event == 3) ? "prefix-bodyNEW" : "prefix-body";
                require(! stringCompare(d ? received : sent, expected), "direct relay bytes/order");
                if (event == 5)
                {
                    sendBytes(d ? child : client, d != 0, "held");
                    require(splice_writes[d] == 1 && ! stringCompare(d ? received : sent, expected),
                            "Pause after direct handoff did not hold next input");
                    requireOrdinarySlots();
                    if (d)
                        httpproxyserverTunnelUpStreamResume(proxy, client);
                    else
                        httpproxyserverTunnelDownStreamResume(proxy, child);
                    require(! stringCompare(d ? received : sent, "prefix-bodyheld"), "paused suffix lost");
                }
                if (event == 3 || event == 4)
                    require(! lineIsAlive(client) && ! child, "direct callback close leaked association");
                clientClose();
                lineUnref(client);
                require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0, "direct relay reference leak");
            }
        ts->users      = NULL;
        ts->user_count = 0;
    }
    ts->auth_mode  = kHpsAuthNone;
    ts->fallback   = NULL;
    representation = saved_representation;
}
#endif

static void runSuite(uint32_t large_size, uint32_t splice_limit)
{
    GSTATE.flag_initialized = true;
    GSTATE.workers_count    = 2;
    master_pool_t *large = masterpoolCreateWithCapacity(8), *small = masterpoolCreateWithCapacity(8);
    master_pool_t *medium = masterpoolCreateWithCapacity(8);
    master_pool_t *splice = masterpoolCreateWithCapacity(8);
    master_pool_t *ios  = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool   = bufferpoolCreate(large,
                                           medium,
                                           small,
                                           splice,
                                           4,
                                           large_size,
                                           MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                           4096,
                                           splice_limit,
                                           max((uint32_t) (large_size), (uint32_t) (splice_limit)));
    bufferpoolUpdateAllocationPaddings(pool, 64, 64, 64, 64);
    threadsafe_generic_pool_t *io_pool =
        threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(ios, sizeof(wio_t), 8);
    GSTATE.shortcut_buffer_pools = &pool;
    GSTATE.shortcut_wios_pools   = &io_pool;
    wloop_t *loop                = wloopCreate(WLOOP_FLAG_AUTO_FREE, pool, 0);
    GSTATE.shortcut_loops        = &loop;
    worker_t worker = {.wid = 0, .buffer_pool = pool, .wios_pool = io_pool, .loop = loop, .has_event_loop = true};
    GSTATE.workers  = &worker;
    testWorkerBindWID(0);
    localConfiguration();
    node_t local_node = {
        .type               = (char *) "HttpProxyServer",
        .next               = (char *) "out",
        .hash_next          = 1,
        .node_settings_json = cJSON_Parse(
            "{\"users\":[{\"username\":\"alice\",\"password\":\"one\"},{\"username\":\"bob\",\"password\":\"two\"}]}")};
    tunnel_t *local_proxy = httpproxyserverTunnelCreate(&local_node);
    require(local_proxy != NULL, "L1 local users require no account service");
    httpproxyserverTunnelDestroy(local_proxy, NULL);
    cJSON_Delete(local_node.node_settings_json);
    node_t node = {.type               = (char *) "HttpProxyServer",
                   .next               = (char *) "out",
                   .hash_next          = 1,
                   .node_settings_json = cJSON_Parse("{\"no-auth\":true}")};
    proxy       = httpproxyserverTunnelCreate(&node);
    require(proxy != NULL, "create");
    prev = tunnelCreate(NULL, 0, 0);
    next = tunnelCreate(NULL, 0, 0);
    tunnelBind(prev, proxy);
    tunnelBind(proxy, next);
    prev->fnFinD                = previousFinish;
    prev->fnEstD                = previousEst;
    prev->fnPayloadD            = previousPayload;
    prev->fnPauseD              = previousPause;
    prev->fnResumeD             = previousResume;
    next->fnInitU               = childInit;
    next->fnPayloadU            = childPayload;
    next->fnFinU                = childFinish;
    next->fnPauseU              = childPause;
    next->fnResumeU             = childResume;
    tunnel_chain_t *chain       = tunnelchainCreate(1);
    chain->masterpool_line_pool = masterpoolCreateWithCapacity(8);
    uint32_t item_size;
    require(tunnelchainTryComputeLineItemSize(proxy->lstate_size, &item_size), "item size");
    chain->line_pools[0] =
        genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(chain->masterpool_line_pool, item_size, 4);
    proxy->chain         = chain;
    fallback             = tunnelCreate(NULL, 0, 0);
    fallback->fnInitU    = fallbackInit;
    fallback->fnPayloadU = childPayload;
    fallback->fnFinU     = childFinish;
    fallback->fnPauseU   = childPause;
    fallback->fnResumeU  = childResume;
#if WW_HAVE_SPLICE
    spliceRelayCases(chain, 1);
    spliceRelayCases(chain, 2);
#endif
    fallbackCases(chain);
    localAuthentication(chain);
    httpBodyCases(chain);
    readPreferenceCases(chain);

    const char *get      = "GET http://127.0.0.1:80/a HTTP/1.1\r\nHost: ignored.test\r\n\r\n";
    cachedTimeoutClock(chain, get);
    const char *fix_case = getenv("HPS_FIX_CASE");
    if (! fix_case || ! stringCompare(fix_case, "R1"))
    {
        largeDeliveries(chain, false, false);
        largeDeliveries(chain, true, false);
        largeDeliveries(chain, false, true);
    }
    pipelinePressure(chain, get);
    if (! fix_case || ! stringCompare(fix_case, "R3"))
        responseEof(chain, get);
    for (unsigned event = 1; event <= 5; ++event)
    {
        resetClient(chain);
        close_on = event;
        sendBytes(client, false, get);
        if (event >= 4)
        {
            httpproxyserverTunnelDownStreamPause(proxy, child);
            if (event == 5)
                httpproxyserverTunnelDownStreamResume(proxy, child);
        }
        require(! lineIsAlive(client) && child == NULL, "re-entrant close did not settle both lines");
        require(closes == 1, "child closed more than once");
        lineUnref(client);
        require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0, "line reference leak");
    }
    resetClient(chain);
    sendBytes(client, false, get);
    sendBytes(client, false, get);
    require(opens == 1 && establishments == 1, "same authority did not reuse child");
    sendBytes(client, false, "GET http://127.0.0.1:81/b HTTP/1.1\r\nHost: a\r\n\r\n");
    require(opens == 2 && closes == 1 && establishments == 1, "destination replacement or Est count");
    line_t *lost = child;
    lineRef(lost);
    httpproxyserverTunnelDownStreamFinish(proxy, lost);
    require(! lineIsAlive(lost) && lineIsAlive(client), "idle child loss killed client or retained child");
    lineUnref(lost);
    child = NULL;
    sendBytes(client, false, get);
    require(opens == 3 && establishments == 1, "idle child loss prevented a fresh request");
    clientClose();
    lineUnref(client);

    resetClient(chain);
    refuse = true;
    sendBytes(client, false, "CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: a\r\n\r\n");
    require(! lineIsAlive(client) && strstr(received, "502") && ! strstr(received, "200"),
            "CONNECT failure became success");
    lineUnref(client);

    for (size_t split = 1; split < stringLength(get); ++split)
    {
        resetClient(chain);
        char prefix[256];
        memoryCopy(prefix, get, split);
        prefix[split] = 0;
        sendBytes(client, false, prefix);
        require(opens == 0, "partial request header opened destination");
        sendBytes(client, false, get + split);
        require(opens == 1 && strstr(received, "\r\n\r\nok"), "fragmented header lost bytes");
        clientClose();
        lineUnref(client);
    }
    resetClient(chain);
    automatic_response = false;
    sendBytes(client, false, "POST http://127.0.0.1:80/a HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\n");
    httpproxyserverTunnelDownStreamPause(proxy, child);
    sendBytes(client, false, "abc");
    require(request_writes == 1, "upload crossed Pause");
    httpproxyserverTunnelDownStreamResume(proxy, child);
    require(request_writes == 2, "upload did not resume");
    const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    for (size_t i = 0; i < stringLength(response); ++i)
    {
        char byte[] = {response[i], 0};
        sendBytes(child, true, byte);
    }
    require(strstr(received, "\r\n\r\nok") != NULL, "fragmented response lost bytes");
    clientClose();
    lineUnref(client);
    resetClient(chain);
    automatic_response = false;
    sendBytes(client, false, get);
    sendBytes(child, true, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokUNSOLICITED");
    require(! lineIsAlive(client) && opens == 1, "unsolicited response bytes advanced exchange");
    lineUnref(client);

    resetClient(chain);
    automatic_response = false;
    httpproxyserverTunnelUpStreamPause(proxy, client);
    sendBytes(client, false, "CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: a\r\n\r\nearly");
    sendBytes(child, true, "banner");
    require(client_writes == 0 && request_writes == 0, "paused CONNECT success or early data escaped");
    httpproxyserverTunnelUpStreamResume(proxy, client);
    require(strstr(received, "200 Connection Established\r\n\r\nbanner") != NULL && request_writes == 1,
            "CONNECT success/data ordering");
    clientClose();
    lineUnref(client);
    resetClient(chain);
    refuse   = true;
    close_on = 3;
    sendBytes(client, false, "CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: a\r\n\r\n");
    require(! lineIsAlive(client) && closes == 0, "error write reflected child Finish");
    lineUnref(client);
    resetClient(chain);
    automatic_response = false;
    sendBytes(client, false, get);
    char informationals[2048] = {0};
    for (unsigned i = 0; i < 33; ++i)
        strcat(informationals, "HTTP/1.1 103 Early Hints\r\n\r\n");
    sendBytes(child, true, informationals);
    require(! lineIsAlive(client) && strstr(received, "502"), "informational limit");
    lineUnref(client);

    require(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization");
    tunnel_t                      *auth = tunnelCreate(NULL, sizeof(authenticationclient_tstate_t), 0);
    authenticationclient_tstate_t *ats  = tunnelGetState(auth);
    require(mutexTryInit(&ats->control_mutex) && rwlockTryInit(&ats->users_lock), "auth locks");
    users_t users;
    require(usersCreate(&users), "users table");
    cJSON *user_json = cJSON_Parse("{\"id\":1001,\"password\":\"user:pass\",\"enabled\":true}");
    require(usersAddUserFromJson(&users, user_json), "test account");
    cJSON_Delete(user_json);
    ats->users        = &users;
    ats->users_loaded = ats->authenticated = true;
    ats->users_generation                  = 7;
    hps_tstate_t *pts                      = tunnelGetState(proxy);
    pts->auth_mode                         = kHpsAuthTracked;
    pts->auth                              = auth;
    const char *authenticated_get          = "GET http://127.0.0.1:80/a HTTP/1.1\r\nHost: a\r\n"
                                             "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
    resetClient(chain);
    user_handle_t inherited = {.generation = 1, .user_id = 42};
    lineAddUser(client, &inherited, "inherited", "value");
    for (unsigned i = 0; i < 8; ++i)
        sendBytes(client, false, authenticated_get);
    require(opens == 1 && lineGetUserAuthCount(client) == 1 && lineGetUserAuthCount(child) == 2,
            "stable auth snapshot failed reuse or grew markers");
    require(lineHasAuthenticatedCredentials(child, "user", "pass"), "child raw credentials missing");
    require(lineHasAuthenticatedCredentials(child, "inherited", "value"), "inherited marker lost");
    ++ats->users_generation;
    sendBytes(client, false, authenticated_get);
    require(opens == 2 && closes == 1, "generation change reused old child");
    userSetEnabled(usersLookupByIdentifier(&users, 1001), false);
    sendBytes(client, false, authenticated_get);
    require(! lineIsAlive(client) && opens == 2 && strstr(received, "407"),
            "disabled account bypassed reauthentication");
    lineUnref(client);
    resetClient(chain);
    ats->authenticated = false;
    sendBytes(client, false, authenticated_get);
    require(! lineIsAlive(client) && opens == 0 && strstr(received, "503"), "unready auth opened destination");
    lineUnref(client);
    resetClient(chain);
    ats->authenticated = true;
    userSetEnabled(usersLookupByIdentifier(&users, 1001), true);
    for (unsigned i = 0; i < kLineMaxUsers; ++i)
        lineAddUser(client, &inherited, NULL, NULL);
    sendBytes(client, false, authenticated_get);
    require(! lineIsAlive(client) && opens == 0 && strstr(received, "503"), "marker capacity did not refuse locally");
    lineUnref(client);
    /* Exercise real tracked lookup outcomes without replacing AuthenticationClient. */
    pts->fallback   = fallback;
    user_t *account = usersLookupByIdentifier(&users, 1001);
    for (unsigned failure = 0; failure < 7; ++failure)
    {
        fallbackStart(chain);
        ats->authenticated = failure != 0;
        ats->users         = failure == 1 ? NULL : &users;
        userSetEnabled(account, failure != 2);
        userSetClientViewExpiry(account, 1, failure == 3);
        account->limit.traffic.total = failure == 4 ? 1 : 0;
        if (failure == 4)
            userAddTraffic(account, 2, 0);
        userSetId(account, failure == 5 ? 0 : 1001);
        const char *wire = failure == 6 ? "GET http://a/ HTTP/1.1\r\nHost: a\r\n"
                                          "Proxy-Authorization: Basic Ym9iOnR3bw==\r\n\r\n"
                                        : authenticated_get;
        sendBytes(client, false, wire);
        require(fallback_opens == 1 && opens == 1 && ! received_len && ! stringCompare(sent, wire),
                "tracked denial did not select exact fallback");
        clientClose();
        lineUnref(client);
    }
    userSetId(account, 1001);
    userSetClientViewExpiry(account, 0, false);
    account->limit.traffic.total = 0;
    pts->fallback                = NULL;
    pts->auth_mode               = kHpsAuthNone;
    pts->auth                    = NULL;
    usersDestroy(&users);
    rwlockDestroy(&ats->users_lock);
    mutexDestroy(&ats->control_mutex);
    tunnelDestroy(auth);

    resetClient(chain);
    automatic_response = false;
    sendBytes(client, false, get);
    httpproxyserverTunnelUpStreamPause(proxy, client);
    sendBytes(child, true, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    require(client_writes == 0, "payload crossed Pause");
    httpproxyserverTunnelUpStreamResume(proxy, client);
    require(strstr(received, "\r\n\r\nok") != NULL, "Resume lost response order");
    sendBytes(client, false, get);
    httpproxyserverTunnelUpStreamPause(proxy, client);
    sendBytes(child, true, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    httpproxyserverTunnelOnWorkerQuiesce(proxy, 0, NULL);
    httpproxyserverTunnelOnWorkerStop(proxy, 0, NULL);
    require(child == NULL && lineIsAlive(client), "drain borrowed/owned distinction");
    sendBytes(client, false, get);
    require(opens == 1, "late drain payload reopened a child");
    clientClose();
    lineUnref(client);
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0, "final line leak");
    httpproxyserverTunnelDestroy(proxy, NULL);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    tunnelDestroy(fallback);
    tunnelchainDestroy(chain);
    cJSON_Delete(node.node_settings_json);
    wloopDestroy(&loop);
    testWorkerUnbindWID();
    threadsafegenericpoolDestroy(io_pool);
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large);
    masterpoolMakeEmpty(small);
    masterpoolMakeEmpty(medium);
    masterpoolMakeEmpty(splice);
    masterpoolMakeEmpty(ios);
    masterpoolDestroy(large);
    masterpoolDestroy(small);
    masterpoolDestroy(medium);
    masterpoolDestroy(splice);
    masterpoolDestroy(ios);
    puts("http_proxy_server_lifecycle: passed");
}

int main(void)
{
    runSuite(32768, 32768);
    runSuite(LARGE_BUFFER_SIZE_RAM_HIGH, SPLICE_PAYLOAD_LIMIT);
    runSuite(65536, 4U * 1024U * 1024U);
#if WW_HAVE_SPLICE
    for (representation = 1; representation <= 2; ++representation)
        runSuite(32768, 32768);
#endif
    return 0;
}
