#include "HttpProxyClient/interface.h"
#include "HttpProxyClient/structure.h"
#include "wevent.h"
#if WW_HAVE_SPLICE
#include <unistd.h>
#endif

static tunnel_t       *proxy, *prev, *next, *entry;
static bool            defer_start, inject_pause_input, inject_resume_input;
static unsigned        next_inits;
static line_t         *line;
static tunnel_chain_t *chain;
static node_t          node;
static char            sent[4 * 1024 * 1024], received[4 * 1024 * 1024];
static size_t          sent_length, received_length;
static unsigned        writes, finishes, established, previous_finishes, representation;
static uintptr_t       last_up, last_down, second_up;
static bool            in_init, init_est, init_pause, init_resume, init_finish, source_in_est, rewrite_target;
static unsigned        on_write, write_action, on_receive, receive_action, close_signal;
static bool            source_paused, late_init, quiesce_in_init;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "HttpProxyClient: %s\n", message);
        exit(1);
    }
}
static sbuf_t *input(const void *bytes, size_t length)
{
#if WW_HAVE_SPLICE
    if (representation && length && length <= 4096)
    {
        sbuf_t *b = bufferpoolGetSpliceBuffer(lineGetBufferPool(line));
        require(b != NULL, "pipe allocation");
        size_t prefix = representation == 2 ? min(length, (size_t) 3) : 0;
        size_t body   = length - prefix;
        if (body)
        {
            ssize_t n = write(sbufSpliceMetadata(b).pipefd[1], (const char *) bytes + prefix, body);
            require(n == (ssize_t) body, "real pipe write");
        }
        b->capacity = b->l_pad + (uint32_t) body;
        b->len      = (uint32_t) body;
        if (prefix)
        {
            sbufShiftLeft(b, (uint32_t) prefix);
            memoryCopy(sbufGetMutablePtr(b), bytes, prefix);
        }
        return b;
    }
#endif
    sbuf_t *b = hpcBuffer(line, length);
    require(b != NULL, "ordinary allocation");
    memoryCopy(sbufGetMutablePtr(b), bytes, length);
    sbufSetLength(b, (uint32_t) length);
    return b;
}
static void sendn(bool down, const void *bytes, size_t length)
{
    require(lineIsAlive(line), "send after death in fixture");
    sbuf_t *b = input(bytes, length);
    if (down)
        proxy->fnPayloadD(proxy, line, b);
    else
        entry->fnPayloadU(entry, line, b);
}
static void sendText(bool down, const char *bytes)
{
    sendn(down, bytes, stringLength(bytes));
}
static void sourceClose(void)
{
    entry->fnFinU(entry, line);
    require(lineIsAlive(line), "client destroyed borrowed line");
    lineDestroy(line);
}
static void previousFinish(tunnel_t *t, line_t *l)
{
    discard t;
    require(l == line, "finish exact line");
    ++previous_finishes;
    lineDestroy(l);
}
static void nextFinish(tunnel_t *t, line_t *l)
{
    discard t;
    require(l == line, "next finish identity");
    ++finishes;
}
static void previousEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++established;
    if (close_signal == 1)
    {
        close_signal = 0;
        sourceClose();
        return;
    }
    if (source_in_est)
        sendText(false, "early");
}
static void previousPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    source_paused = true;
    if (inject_pause_input)
    {
        inject_pause_input = false;
        sendText(false, "pause");
    }
    if (close_signal == 2)
    {
        close_signal = 0;
        sourceClose();
    }
}
static void previousResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    source_paused = false;
    if (inject_resume_input)
    {
        inject_resume_input = false;
        sendText(false, "resume");
    }
    if (close_signal == 3)
    {
        close_signal = 0;
        sourceClose();
    }
}
static void nextSignal(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}
static void action(unsigned which)
{
    if (which == 12)
        proxy->fnResumeD(proxy, line);
    if (which == 1)
        sendText(false, "new");
    if (which == 2)
        proxy->fnPauseD(proxy, line);
    if (which == 3)
    {
        proxy->fnPauseD(proxy, line);
        proxy->fnResumeD(proxy, line);
        sendText(false, "new");
    }
    if (which == 4)
        sourceClose();
    if (which == 5)
        proxy->fnFinD(proxy, line);
    if (which == 6)
        sendText(true, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokTAIL");
    if (which == 7)
    {
        sendText(false, "new");
        proxy->fnPauseD(proxy, line);
    }
    if (which == 8)
        sendText(true, "HTTP/1.1 200 OK\r\n\r\n");
    if (which == 9)
        sendText(true, "new");
    if (which == 10)
    {
        proxy->fnPauseU(proxy, line);
        sendText(true, "new");
    }
    if (which == 11)
    {
        proxy->fnPauseD(proxy, line);
        proxy->fnResumeD(proxy, line);
        proxy->fnEstD(proxy, line);
        sendText(true, "ignored");
        proxy->fnFinD(proxy, line);
    }
}
static void nextPayload(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    require(! in_init, "header/body entered unfinished Init");
    require(l == line, "upload identity");
    size_t n = sbufGetLength(b);
    require(n < sizeof(sent) - sent_length, "capture capacity");
    last_up = (uintptr_t) b;
    sbufReadRangeToMemory(b, sent + sent_length, (uint32_t) n);
    sent_length += n;
    sent[sent_length] = 0;
    lineReuseBuffer(l, b);
    ++writes;
    if (writes == 2)
        second_up = last_up;
    if (writes == on_write)
    {
        unsigned selected = write_action;
        on_write          = 0;
        action(selected);
    }
}
static void previousPayload(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    size_t  n = sbufGetLength(b);
    require(n < sizeof(received) - received_length, "receive capacity");
    last_down = (uintptr_t) b;
    sbufReadRangeToMemory(b, received + received_length, (uint32_t) n);
    received_length += n;
    received[received_length] = 0;
    lineReuseBuffer(l, b);
    if (on_receive)
    {
        unsigned selected = receive_action;
        on_receive        = 0;
        action(selected);
    }
}
static void nextInit(tunnel_t *t, line_t *l)
{
    discard t;
    ++next_inits;
    in_init = true;
    if (rewrite_target)
    {
        require(addresscontextSetIpAddress(lineGetDestinationAddressContext(l), "127.0.0.9"), "rewrite target");
        lineGetDestinationAddressContext(l)->port = 9999;
    }
    if (init_est)
    {
        proxy->fnEstD(proxy, l);
        if (! lineIsAlive(l))
        {
            in_init = false;
            return;
        }
        proxy->fnEstD(proxy, l);
    }
    if (init_pause)
        proxy->fnPauseD(proxy, l);
    if (! lineIsAlive(l))
    {
        in_init = false;
        return;
    }
    if (init_resume)
        proxy->fnResumeD(proxy, l);
    if (init_finish)
        proxy->fnFinD(proxy, l);
    if (quiesce_in_init)
        httpproxyclientTunnelOnWorkerQuiesce(proxy, 0, NULL);
    in_init = false;
}
static tunnel_t *config(const char *settings)
{
    node_t candidate = {.name               = (char *) "client",
                        .type               = (char *) "HttpProxyClient",
                        .next               = (char *) "out",
                        .hash_next          = 1,
                        .node_settings_json = cJSON_Parse(settings)};
    require(candidate.node_settings_json != NULL, "fixture JSON");
    tunnel_t *t = httpproxyclientTunnelCreate(&candidate);
    cJSON_Delete(candidate.node_settings_json);
    return t;
}
static void openLine(const char *settings)
{
    node  = (node_t) {.name               = (char *) "client",
                      .type               = (char *) "HttpProxyClient",
                      .next               = (char *) "out",
                      .hash_next          = 1,
                      .node_settings_json = cJSON_Parse(settings)};
    proxy = httpproxyclientTunnelCreate(&node);
    require(proxy != NULL, "create valid client");
    prev             = tunnelCreate(NULL, 0, 0);
    next             = tunnelCreate(NULL, 0, 0);
    hpc_tstate_t *ts = tunnelGetState(proxy);
    entry            = ts->domain_resolver_tunnel ? ts->domain_resolver_tunnel : proxy;
    tunnelBind(prev, entry);
    if (entry != proxy)
        tunnelBind(entry, proxy);
    tunnelBind(proxy, next);
    prev->fnFinD                = previousFinish;
    prev->fnEstD                = previousEst;
    prev->fnPayloadD            = previousPayload;
    prev->fnPauseD              = previousPause;
    prev->fnResumeD             = previousResume;
    next->fnInitU               = nextInit;
    next->fnFinU                = nextFinish;
    next->fnPayloadU            = nextPayload;
    next->fnPauseU              = nextSignal;
    next->fnResumeU             = nextSignal;
    chain                       = tunnelchainCreate(1);
    chain->masterpool_line_pool = masterpoolCreateWithCapacity(8);
    uint32_t size, offset = 0;
    if (entry != proxy)
    {
        entry->onIndex(entry, 0, &offset);
        entry->chain = chain;
    }
    proxy->onIndex(proxy, entry != proxy ? 1 : 0, &offset);
    require(tunnelchainTryComputeLineItemSize(offset, &size), "line size");
    chain->line_pools[0] =
        genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(chain->masterpool_line_pool, size, 4);
    proxy->chain = chain;
    line         = lineCreateForWorker(0, chain->line_pools, 0);
    lineRef(line);
    require(addresscontextSetIpAddress(lineGetDestinationAddressContext(line), "::1"), "dynamic origin");
    lineGetDestinationAddressContext(line)->port = 443;
    sent_length = received_length = 0;
    sent[0] = received[0] = 0;
    writes = finishes = previous_finishes = established = next_inits = 0;
    last_up = last_down = second_up = 0;
    source_paused                   = false;
    if (late_init)
        httpproxyclientTunnelOnWorkerQuiesce(proxy, 0, NULL);
    if (! defer_start)
        entry->fnInitU(entry, line);
    require(! linePrefersOrdinaryReadUpstream(line) && ! linePrefersOrdinaryReadDownstream(line),
            "client selected ordinary reads instead of retaining its direct body paths");
}
static void closeLine(void)
{
    if (lineIsAlive(line))
        sourceClose();
    lineUnref(line);
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0, "line leak");
    httpproxyclientTunnelDestroy(proxy, NULL);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    tunnelchainDestroy(chain);
    cJSON_Delete(node.node_settings_json);
    init_est = init_pause = init_resume = init_finish = source_in_est = rewrite_target = false;
    late_init = quiesce_in_init = false;
    on_write = write_action = on_receive = receive_action = close_signal = 0;
}
static const char *connect_settings = "{\"target-address\":\"origin.test\",\"port\":443}";
static const char *chunk_settings   = "{\"mode\":\"http\",\"target-address\":\"origin.test\",\"port\":80}";
static const char *fixed_settings =
    "{\"mode\":\"http\",\"target-address\":\"origin.test\",\"port\":80,\"body-mode\":\"fixed\",\"content-length\":6}";
static const char *get_settings =
    "{\"mode\":\"http\",\"target-address\":\"origin.test\",\"port\":80,\"method\":\"GET\",\"body-mode\":\"none\"}";

static void configuration(void)
{
    const char *bad[] = {"{}",
                         "{\"target-address\":\"x\",\"port\":0}",
                         "{\"target-address\":\"x\",\"port\":65536}",
                         "{\"target-address\":\"x\",\"port\":80.5}",
                         "{\"target-address\":\"x\",\"port\":80,\"port\":81}",
                         "{\"target-address\":\"x\",\"port\":80,\"mode\":\"auto\"}",
                         "{\"target-address\":\"x\",\"port\":80,\"path\":\"/\"}",
                         "{\"target-address\":\"x\",\"port\":80,\"username\":\"u\"}",
                         "{\"target-address\":\"a@b\",\"port\":80}",
                         "{\"target-address\":\"x\",\"port\":80,\"headers\":{\"hOsT\":\"x\"}}",
                         "{\"target-address\":\"x\",\"port\":80,\"headers\":{\"X\":\"a\",\"x\":\"b\"}}",
                         "{\"target-address\":\"x\",\"port\":80,\"headers\":{\"X\":\"a\\r\\nb\"}}",
                         "{\"mode\":\"http\",\"target-address\":\"x\",\"port\":80,\"content-length\":1}",
                         "{\"mode\":\"http\",\"target-address\":\"x\",\"port\":80,\"body-mode\":\"fixed\"}",
                         "{\"mode\":\"http\",\"target-address\":\"x\",\"port\":80,\"body-mode\":\"fixed\",\"content-"
                         "length\":9007199254740992}",
                         "{\"mode\":\"http\",\"target-address\":\"x\",\"port\":80,\"method\":\"HEAD\"}",
                         "{\"mode\":\"http\",\"target-address\":\"x\",\"port\":80,\"path\":\"/%zz\"}",
                         "{\"mode\":\"http\",\"target-address\":\"x\",\"port\":80,\"path\":\"/#fragment\"}",
                         "{\"mode\":\"http\",\"target-address\":\"x\",\"port\":80,\"connect-response-timeout-ms\":1}",
                         "{\"target-address\":\"x\",\"port\":80,\"http-version\":\"1.1\"}"};
    for (size_t i = 0; i < ARRAY_SIZE(bad); ++i)
        require(config(bad[i]) == NULL, bad[i]);
    rewrite_target = true;
    openLine("{\"target-address\":\"dest_context->address\",\"port\":\"dest_context->port\",\"username\":\"u\","
             "\"password\":\"p:p\"}");
    require(! stringCompare(
                sent, "CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\nProxy-Authorization: Basic dTpwOnA=\r\n\r\n"),
            "immutable dynamic target/auth bytes");
    require(lineGetUserAuthCount(line) == 0, "proxy credentials became user identity");
    closeLine();
    openLine("{\"mode\":\"http\",\"target-address\":\"127.0.0.1\",\"port\":80,\"path\":\"/"
             "a%2Fb?q=%23\",\"body-mode\":\"fixed\",\"content-length\":0,\"headers\":{\"Authorization\":\"origin\"}}");
    require(strstr(sent, "POST http://127.0.0.1:80/a%2Fb?q=%23 HTTP/1.1\r\n") &&
                strstr(sent, "Content-Length: 0\r\n") && strstr(sent, "Authorization: origin\r\n"),
            "HTTP request wire");
    sendText(false, "x");
    require(! lineIsAlive(line), "fixed zero accepted payload");
    closeLine();
    node_t metadata = nodeHttpProxyClientGet();
    require(metadata.required_padding_left == 10 && (metadata.flags & kNodeFlagSupportsSplice), "capability/padding");
    memoryFree(metadata.type);
}
static void startup(void)
{
    openLine(connect_settings);
    require(writes == 1 && established == 0, "immediate header requires neither input nor Est");
    sendText(false, "early");
    require(writes == 1 && source_paused, "CONNECT early upload escaped");
    proxy->fnEstD(proxy, line);
    proxy->fnEstD(proxy, line);
    require(established == 1, "Est once");
    sendText(true, "HTTP/1.1 200 OK\r\nContent-Length: bad\r\nTransfer-Encoding: gzip\r\n\r\nreply");
    require(writes == 2 && strstr(sent, "\r\n\r\nearly") && ! stringCompare(received, "reply") && ! source_paused,
            "CONNECT transition");
    closeLine();
    init_est = source_in_est = init_pause = true;
    openLine(chunk_settings);
    require(writes == 0 && established == 1, "paused Init emitted header or delayed Est");
    proxy->fnResumeD(proxy, line);
    require(writes == 3 && strstr(sent, "\r\n\r\n5\r\nearly\r\n"), "Init reentry body/header order");
    closeLine();
    init_pause = init_resume = true;
    openLine(connect_settings);
    require(writes == 1, "nested Resume lost immediate header");
    closeLine();
    init_finish = true;
    openLine(connect_settings);
    require(! lineIsAlive(line) && writes == 0 && finishes == 0, "Init Finish reflected");
    closeLine();
    on_write     = 1;
    write_action = 6;
    openLine(get_settings);
    require(! lineIsAlive(line) && ! stringCompare(received, "ok") && finishes == 1,
            "synchronous header response close");
    closeLine();
    on_write     = 1;
    write_action = 1;
    openLine(chunk_settings);
    require(writes == 3 && strstr(sent, "\r\n\r\n3\r\nnew\r\n"), "nested header upload order");
    closeLine();
}
static void framing(void)
{
    const char *response = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: "
                           "chunked\r\n\r\n3;x=\"y\"\r\nabc\r\n2\r\nde\r\n0\r\nX-Sum: ok\r\n\r\nTAIL";
    size_t      length   = stringLength(response);
    for (size_t split = 1; split < length; ++split)
    {
        openLine(get_settings);
        sendn(true, response, split);
        if (lineIsAlive(line))
            sendn(true, response + split, length - split);
        require(! lineIsAlive(line) && ! stringCompare(received, "abcde"), "fragmented response/trailer/tail");
        closeLine();
    }
    const char *bad[] = {"HTTP/1.0 200 OK\r\n\r\n",
                         "HTTP/1.1 101 Upgrade\r\n\r\n",
                         "HTTP/1.1 407 Denied\r\n\r\nsecret",
                         "HTTP/1.1 302 Redirect\r\n\r\nsecret",
                         "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
                         "HTTP/1.1 205 Reset\r\nContent-Length: 1\r\n\r\nx",
                         "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Type: x\r\n\r\n"};
    for (size_t i = 0; i < ARRAY_SIZE(bad); ++i)
    {
        openLine(get_settings);
        sendText(true, bad[i]);
        require(! lineIsAlive(line) && ! received_length, "invalid/error response leaked");
        closeLine();
    }
    openLine(fixed_settings);
    sendText(false, "ab");
    sendText(false, "cdef");
    require(lineIsAlive(line) && strstr(sent, "\r\n\r\nabcdef"), "finite upload closed response direction");
    sendText(true, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokTAIL");
    require(! lineIsAlive(line) && ! stringCompare(received, "ok"), "fixed completion leaked tail");
    closeLine();
    openLine(fixed_settings);
    unsigned before = writes;
    sendText(false, "1234567");
    require(! lineIsAlive(line) && writes == before, "excess fixed bytes escaped");
    closeLine();
    openLine(get_settings);
    sendText(false, "x");
    require(! lineIsAlive(line), "bodyless upload accepted");
    closeLine();
    openLine(chunk_settings);
    sendText(true, "HTTP/1.1 200 OK\r\n\r\nearly");
    sendText(false, "upload");
    require(lineIsAlive(line) && strstr(sent, "6\r\nupload\r\n") && ! stringCompare(received, "early"),
            "concurrent streaming response");
    sourceClose();
    require(strstr(sent, "0\r\n\r\n") != NULL, "missing terminal chunk");
    closeLine();
    openLine(get_settings);
    sendText(true, "HTTP/1.1 204 No Content\r\n\r\nTAIL");
    require(! lineIsAlive(line) && ! received_length, "no-content response");
    closeLine();
    openLine(get_settings);
    for (unsigned i = 0; i < 33 && lineIsAlive(line); ++i)
        sendText(true, "HTTP/1.1 100 Continue\r\n\r\n");
    require(! lineIsAlive(line), "informational cap");
    closeLine();
}
static void reentry(void)
{
    for (unsigned event = 1; event <= 7; ++event)
    {
        openLine(chunk_settings);
        on_write     = 2;
        write_action = event;
        sendText(false, "old");
        if (event == 4 || event == 5 || event == 6)
            require(! lineIsAlive(line) && ! strstr(sent, "old\r\n"),
                    "active frame emitted suffix after Finish/final response");
        else if (event == 2 || event == 7)
        {
            require(strstr(sent, "3\r\nold\r\n") != NULL, "Pause split admitted chunk");
            if (event == 7)
            {
                require(! strstr(sent, "new"), "paused backlog drained");
                proxy->fnResumeD(proxy, line);
                require(strstr(sent, "old\r\n3\r\nnew\r\n") != NULL, "Resume reordered suffix");
            }
        }
        else
            require(strstr(sent, "old\r\n3\r\nnew\r\n") != NULL, "nested chunk overtook suffix");
        closeLine();
    }
    openLine(chunk_settings);
    on_write     = 2;
    write_action = 11;
    sourceClose();
    require(finishes == 0 && previous_finishes == 0 && established == 0, "terminal callback reflected Finish/Est");
    closeLine();
    openLine(chunk_settings);
    proxy->fnPauseD(proxy, line);
    unsigned before = writes;
    sourceClose();
    require(writes == before, "paused Finish emitted terminal chunk");
    closeLine();
    openLine(get_settings);
    sendText(true, "HTTP/1.1 200 OK\r\n\r\n");
    on_receive     = 1;
    receive_action = 9;
    sendText(true, "old");
    require(! stringCompare(received, "oldnew"), "response reentry FIFO");
    closeLine();
    openLine(get_settings);
    sendText(true, "HTTP/1.1 200 OK\r\n\r\n");
    on_receive     = 1;
    receive_action = 10;
    sendText(true, "old");
    require(! stringCompare(received, "old"), "paused independent response backlog");
    proxy->fnResumeU(proxy, line);
    require(! stringCompare(received, "oldnew"), "response Resume");
    closeLine();
}
static void directBuffers(void)
{
    openLine(connect_settings);
    sendText(true, "HTTP/1.1 200 OK\r\n\r\n");
    sbuf_t   *b        = input("opaque", 6);
    uintptr_t identity = (uintptr_t) b;
    entry->fnPayloadU(entry, line, b);
    require(last_up == identity, "CONNECT upload copied");
    b        = input("opaque", 6);
    identity = (uintptr_t) b;
    proxy->fnPayloadD(proxy, line, b);
    require(last_down == identity, "CONNECT download copied");
    closeLine();
    openLine(fixed_settings);
    b        = input("abcdef", 6);
    identity = (uintptr_t) b;
    entry->fnPayloadU(entry, line, b);
    require(last_up == identity, "fixed upload copied");
    closeLine();
    openLine(chunk_settings);
    b            = input("abcdef", 6);
    identity     = (uintptr_t) b;
    on_write     = 2;
    write_action = 2;
    entry->fnPayloadU(entry, line, b);
    require(second_up == identity && strstr(sent, "6\r\nabcdef\r\n") && writes == 3, "chunk body/tail bytes");
    closeLine();
    const char *headers[] = {"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n",
                             "HTTP/1.1 200 OK\r\n\r\n",
                             "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n"};
    for (size_t i = 0; i < ARRAY_SIZE(headers); ++i)
    {
        openLine(get_settings);
        sendText(true, headers[i]);
        b        = input("abc", 3);
        identity = (uintptr_t) b;
        proxy->fnPayloadD(proxy, line, b);
        require(last_down == identity, "body-only download copied");
        b        = input("def", 3);
        identity = (uintptr_t) b;
        proxy->fnPayloadD(proxy, line, b);
        require(last_down == identity, "exact body boundary copied");
        if (i == 2)
            sendText(true, "\r\n0\r\n\r\nTAIL");
        require(! stringCompare(received, "abcdef"), "direct body bytes");
        closeLine();
    }
    openLine(get_settings);
    sendText(true, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n");
    sendText(true, "ab\r\n3\r\ncde\r\n0\r\n\r\nTAIL");
    require(! lineIsAlive(line) && ! stringCompare(received, "abcde"), "mixed parsing fallback");
    closeLine();
}
static void ordinaryReadPreferences(void)
{
    openLine(connect_settings);
    linePreferOrdinaryReadBoth(line);
    linePreferOrdinaryReadBoth(line);
    sendText(true, "HTTP/1.1 200");
#if WW_HAVE_SPLICE
    // A preference cannot promise ordinary input: an already admitted delivery
    // or a Mux association can still supply a private pipe, including in headers.
    representation = 2;
#endif
    sendText(true, " OK\r\n\r\n");
    for (unsigned i = 0; i < 3; ++i)
    {
        representation     = i;
        sbuf_t   *upload   = input("abc", 3);
        uintptr_t identity = (uintptr_t) upload;
        proxy->fnPayloadU(proxy, line, upload);
        require(last_up == identity, "read preference changed opaque upload forwarding");
        sbuf_t *download = input("def", 3);
        identity         = (uintptr_t) download;
        proxy->fnPayloadD(proxy, line, download);
        require(last_down == identity, "read preference changed opaque download forwarding");
    }
    require(linePrefersOrdinaryReadUpstream(line) && linePrefersOrdinaryReadDownstream(line) &&
                ! stringCompare(received, "defdefdef"),
            "mixed representations lost preferences or response bytes");
    representation = 0;
    closeLine();
}

static void additionalBoundaries(void)
{
    late_init = true;
    openLine(connect_settings);
    require(! lineIsAlive(line) && ! writes && ! finishes, "late Init created work");
    closeLine();
    quiesce_in_init = true;
    openLine(connect_settings);
    require(lineIsAlive(line) && ! writes && ! ((hpc_lstate_t *) lineGetState(line, proxy))->timer,
            "quiescence during Init emitted header or retained timer");
    closeLine();
    init_pause = true;
    openLine(chunk_settings);
    require(! writes, "fixture header must be pending");
    sourceClose();
    require(! writes && finishes == 1, "source Finish started pending request");
    closeLine();
    init_est     = true;
    close_signal = 1;
    openLine(connect_settings);
    require(! lineIsAlive(line) && finishes == 1 && ! writes, "Est closure continued Init");
    closeLine();
    init_pause   = true;
    close_signal = 2;
    openLine(connect_settings);
    require(! lineIsAlive(line) && finishes == 1 && ! writes, "Pause closure continued Init");
    closeLine();
    openLine(connect_settings);
    close_signal = 3;
    sendText(true, "HTTP/1.1 200 OK\r\n\r\ntail");
    require(! lineIsAlive(line) && finishes == 1 && ! received_length, "Resume closure continued response");
    closeLine();
    openLine(chunk_settings);
    on_write     = 3;
    write_action = 4;
    sendText(false, "old");
    require(! lineIsAlive(line) && writes == 3 && ! strstr(sent, "0\r\n\r\n"), "tail closure emitted final chunk");
    closeLine();
    openLine(get_settings);
    on_receive     = 1;
    receive_action = 4;
    sendText(true, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc");
    require(! lineIsAlive(line) && ! stringCompare(received, "abc"), "response callback close");
    closeLine();
    openLine(chunk_settings);
    on_write     = 2;
    write_action = 7;
    sendText(false, "old");
    unsigned pending_writes = writes;
    on_receive              = 1;
    receive_action          = 12;
    sendText(true, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    require(! lineIsAlive(line) && writes == pending_writes, "final response resumed canceled upload");
    closeLine();
    /* Maximum interoperable credential pair and lossless path/query bytes. */
    char user[256], password[256], json[2048];
    memorySet(user, 'u', 255);
    user[255] = 0;
    memorySet(password, 'p', 255);
    password[255] = 0;
    stringNPrintf(json,
                  sizeof(json),
                  "{\"target-address\":\"x\",\"port\":443,\"username\":\"%s\",\"password\":\"%s\"}",
                  user,
                  password);
    openLine(json);
    char *auth = strstr(sent, "Proxy-Authorization: Basic ");
    require(auth && (size_t) (strstr(auth, "\r\n") - auth) == stringLength("Proxy-Authorization: Basic ") + 684,
            "maximum Basic encoding");
    closeLine();
    openLine("{\"mode\":\"http\",\"target-address\":\"x\",\"port\":80,\"method\":\"HEAD\",\"body-mode\":\"none\"}");
    sendText(true, "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nTAIL");
    require(! lineIsAlive(line) && ! received_length, "HEAD delivered body");
    closeLine();
    openLine(connect_settings);
    sbuf_t *b = hpcBuffer(line, kHpcDeliveryLimit - 128);
    memorySet(sbufGetMutablePtr(b), 0, kHpcDeliveryLimit - 128);
    sbufSetLength(b, kHpcDeliveryLimit - 128);
    buffer_budget_cost_t cost;
    require(bufferbudgetTryGetCost(b, &cost) && cost.charge == kHpcDeliveryLimit, "exact charge fixture");
    entry->fnPayloadU(entry, line, b);
    hpc_lstate_t *ls = lineGetState(line, proxy);
    require(lineIsAlive(line) && bufferbudgetGetUsage(&ls->budgets[0]).charge == kHpcDeliveryLimit,
            "exact budget admission");
    /* A full upload budget cannot block a response in the other direction. */
    proxy->fnPauseD(proxy, line);
    sendText(true, "HTTP/1.1 200 OK\r\n\r\nreply");
    require(! stringCompare(received, "reply"), "full upload budget blocked response");
    sendText(false, "x");
    require(! lineIsAlive(line), "charge overflow accepted");
    closeLine();
    openLine(get_settings);
    char oversized[9000];
    memorySet(oversized, 'x', sizeof(oversized));
    memoryCopy(oversized, "HTTP/1.1 200 ", 13);
    sendn(true, oversized, sizeof(oversized));
    require(! lineIsAlive(line), "status line cap");
    closeLine();
    openLine(
        "{\"mode\":\"http\",\"target-address\":\"x\",\"port\":80,\"body-mode\":\"none\",\"max-header-bytes\":1024}");
    char fields[1024];
    memorySet(fields, 'a', sizeof(fields));
    memoryCopy(fields, "HTTP/1.1 200 OK\r\nX: ", 20);
    sendn(true, fields, sizeof(fields));
    require(! lineIsAlive(line), "incomplete header cap");
    closeLine();
    openLine(get_settings);
    sendText(true, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
    char chunk[1024];
    memorySet(chunk, 'a', sizeof(chunk));
    sendn(true, chunk, sizeof(chunk));
    require(! lineIsAlive(line), "chunk line cap");
    closeLine();
    openLine(fixed_settings);
    sendText(false, "abc");
    unsigned before = writes;
    sourceClose();
    require(writes == before, "truncated fixed upload emitted completion");
    closeLine();
    openLine(connect_settings);
    proxy->fnFinD(proxy, line);
    require(! lineIsAlive(line) && ! finishes, "response truncation reflected");
    closeLine();
    openLine(get_settings);
    sendText(true, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc");
    proxy->fnFinD(proxy, line);
    require(! lineIsAlive(line) && ! finishes, "truncated body reflected");
    closeLine();
    /* Real pipe materialization must exceed the deliberately tiny pool tiers. */
#if WW_HAVE_SPLICE
    unsigned old_representation = representation;
    representation              = 1;
    openLine(get_settings);
    char mixed[4096];
    memorySet(mixed, 'b', sizeof(mixed));
    const char *head = "HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\n";
    size_t      h    = stringLength(head);
    memoryCopy(mixed, head, h);
    sendn(true, mixed, h + 4000);
    require(! lineIsAlive(line) && received_length == 4000, "large pipe parsing geometry");
    closeLine();
    representation = old_representation;
#endif
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        openLine(mode == 1 ? connect_settings : get_settings);
        wloop_t *loop        = getWorkerLoop(0);
        ls                   = lineGetState(line, proxy);
        const uint64_t start = UINT64_C(5000000000);
        loop->cur_hrtime     = start * 1000;
        ls->progress_at      = start;
        ls->connect_at       = start;
        uint32_t duration    = mode == 0 ? 15000 : mode == 1 ? 30000 : 300000;
        if (mode == 0)
            sendText(true, "HTTP/1.1 200");
        loop->cur_hrtime = (start + duration - 1) * 1000;
        ls->timer->cb((wevent_t *) ls->timer);
        require(lineIsAlive(line), "deadline early");
        proxy->fnPauseD(proxy, line);
        proxy->fnResumeD(proxy, line);
        proxy->fnEstD(proxy, line);
        loop->cur_hrtime = (start + duration) * 1000;
        ls->timer->cb((wevent_t *) ls->timer);
        require(! lineIsAlive(line), "cached deadline missed");
        closeLine();
    }
}

static void limitsAndTimers(void)
{
    openLine(connect_settings);
    hpc_lstate_t *ls       = lineGetState(line, proxy);
    unsigned      admitted = 0;
    while (lineIsAlive(line) && admitted < 2000)
    {
        sendText(false, "x");
        ++admitted;
    }
    require(! lineIsAlive(line) && admitted == 1025, "queue entry cap");
    closeLine();
    openLine(connect_settings);
    sbuf_t *b = hpcBuffer(line, kHpcDeliveryLimit + 1);
    sbufSetLength(b, kHpcDeliveryLimit + 1);
    entry->fnPayloadU(entry, line, b);
    require(! lineIsAlive(line), "delivery cap");
    closeLine();
    openLine(get_settings);
    sendText(true, "HTTP/1.1 200 OK\r\n");
    ls              = lineGetState(line, proxy);
    ls->header_at   = hpcNow(line) - 15000;
    wtimer_t *timer = ls->timer;
    timer->cb((wevent_t *) timer);
    require(! lineIsAlive(line), "header deadline");
    closeLine();
    openLine(connect_settings);
    ls             = lineGetState(line, proxy);
    ls->connect_at = hpcNow(line) - 30000;
    proxy->fnPauseD(proxy, line);
    timer = ls->timer;
    timer->cb((wevent_t *) timer);
    require(! lineIsAlive(line), "paused CONNECT deadline");
    closeLine();
    openLine(get_settings);
    ls              = lineGetState(line, proxy);
    ls->progress_at = hpcNow(line) - 300000;
    timer           = ls->timer;
    timer->cb((wevent_t *) timer);
    require(! lineIsAlive(line), "idle deadline");
    closeLine();
    openLine(connect_settings);
    httpproxyclientTunnelOnWorkerQuiesce(proxy, 0, NULL);
    ls = lineGetState(line, proxy);
    require(! ls->timer, "timer quiescence");
    unsigned before = writes;
    sendText(false, "late");
    require(writes == before, "quiescence payload");
    closeLine();
}
#ifdef HPC_DNS_TEST
#include "http_proxy_client_dns_cases.h"
#endif
int main(void)
{
    discard representation;
    GSTATE.flag_initialized = true;
    GSTATE.workers_count    = 2;
    master_pool_t *large = masterpoolCreateWithCapacity(8), *medium = masterpoolCreateWithCapacity(8),
                  *small = masterpoolCreateWithCapacity(8), *splice = masterpoolCreateWithCapacity(8),
                  *ios  = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool = bufferpoolCreate(large, medium, small, splice, 4, 1024, 512, 128, 4096, 4096);
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
    wloopUpdateTime(loop);
    configuration();
#ifdef HPC_DNS_TEST
    dnsTests();
#endif
    startup();
    framing();
    reentry();
    directBuffers();
    ordinaryReadPreferences();
    limitsAndTimers();
    additionalBoundaries();
#if WW_HAVE_SPLICE
    for (representation = 1; representation <= 2; ++representation)
    {
        startup();
        framing();
        reentry();
        directBuffers();
    }
#endif
    wloopDestroy(&loop);
    testWorkerUnbindWID();
    threadsafegenericpoolDestroy(io_pool);
    bufferpoolDestroy(pool);
    master_pool_t *pools[] = {large, medium, small, splice, ios};
    for (size_t i = 0; i < ARRAY_SIZE(pools); ++i)
    {
        masterpoolMakeEmpty(pools[i]);
        masterpoolDestroy(pools[i]);
    }
    puts("http_proxy_client_lifecycle: passed");
    return 0;
}
