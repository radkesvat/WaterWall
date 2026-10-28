/*
 * Covers: router splice; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testRouting, testMetadataRouting, testStartupReplay, testPendingPause, testPendingPauseBoundary,
 * testBorrowedFinish, testStartupOverflow, testExplicitNextTarget, testClose, testLargeCompleteHeader, testCapabilities
 * Checks: Assertion labels include: initialized the wrong route; payload reached the wrong route/direction;
 * incorrect payload representation; opaque forwarding replaced the buffer
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.router_splice_unit
 */
#include "Router/interface.h"
#include "fixtures/splice_inventory.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "Router/structure.h"
#include "SniffRouter/interface.h"
#include "SniffRouter/structure.h"

#if WW_HAVE_SPLICE
#include <unistd.h>
#endif

enum
{
    kOnwardPadding = 192
};

static _Atomic(sbuf_t *) disposal_buffer;
static atomic_uint      *disposal_counter;
static bool              check_datagram_sniff_disposal;
static unsigned          sniff_view_destroys;

void __real_sbufDestroy(sbuf_t *buf);
void __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void __wrap_sbufDestroy(sbuf_t *buf);
void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);

static void watchBufferDisposal(sbuf_t *buf, atomic_uint *counter)
{
    assert(atomic_load_explicit(&disposal_buffer, memory_order_acquire) == NULL);
    disposal_counter = counter;
    atomic_store_explicit(&disposal_buffer, buf, memory_order_release);
}

static void observeBufferDisposal(sbuf_t *buf)
{
    sbuf_t *expected = buf;
    if (atomic_compare_exchange_strong_explicit(
            &disposal_buffer, &expected, NULL, memory_order_acq_rel, memory_order_acquire))
        atomicAddExplicit(disposal_counter, 1, memory_order_release);
}

void __wrap_sbufDestroy(sbuf_t *buf)
{
    if (check_datagram_sniff_disposal && sbufGetLeftPadding(buf) == 0)
        ++sniff_view_destroys;
    observeBufferDisposal(buf);
    __real_sbufDestroy(buf);
}

void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf)
{
    // Every fixture datagram has onward padding; the detached inspection copy has none.
    require(! check_datagram_sniff_disposal || sbufGetLeftPadding(buf) != 0,
            "detached UDP sniff view was returned to the buffer pool");
    observeBufferDisposal(buf);
    __real_bufferpoolReuseBuffer(pool, buf);
}

typedef struct router_fixture_s
{
    node_t          node;
    tunnel_t       *router;
    tunnel_t       *prev;
    tunnel_t       *next;
    tunnel_t       *target;
    tunnel_chain_t *chain;
    line_t         *line;
    tunnel_t       *expected_receiver;
    sbuf_t         *expected_buffer;
    const uint8_t  *expected_bytes;
    uint32_t        expected_length;
    unsigned        inits;
    unsigned        payloads;
    unsigned        finishes;
    bool            expect_splice;
    bool            close_on_init;
    bool            close_on_payload;
    bool            close_on_pause;
    bool            borrowed_close;
    bool            reenter_init;
    bool            reenter_empty;
    bool            reenter_payload;
    bool            reenter_pause;
    bool            overflow_init;
    bool            init_running;
    bool            pause_running;
    bool            record_startup;
    bool            record_callbacks;
    const char     *init_signals;
    char            callback_trace[64];
    unsigned        callback_count;
    char            startup_bytes[256];
    uint32_t        startup_length;
    unsigned        upstream_pauses;
    unsigned        upstream_resumes;
    unsigned        downstream_pauses;
    unsigned        downstream_resumes;
    unsigned        upstream_ests;
    unsigned        downstream_ests;
    const uint8_t  *datagram_bytes[8];
    uint32_t        datagram_lengths[8];
    unsigned        datagram_count;
} router_fixture_t;

static router_fixture_t *fixture;

static sbuf_t *payload(const void *data, uint32_t length, bool splice, uint32_t prefix);

static void recordCallback(char event)
{
    if (! fixture->record_callbacks)
        return;
    require(fixture->callback_count + 1 < sizeof(fixture->callback_trace), "callback trace overflow");
    fixture->callback_trace[fixture->callback_count++] = event;
    fixture->callback_trace[fixture->callback_count]   = '\0';
}

static void sendUpstreamSignals(tunnel_t *t, line_t *l, const char *signals)
{
    for (; signals != NULL && *signals != '\0'; ++signals)
    {
        if (*signals == 'U')
            tunnelUpStreamPause(t, l);
        else
        {
            require(*signals == 'R', "invalid fixture pressure signal");
            tunnelUpStreamResume(t, l);
        }
    }
}

static void pauseSignal(tunnel_t *t, line_t *l)
{
    if (t == fixture->prev)
        ++fixture->downstream_pauses;
    else
    {
        require(t == fixture->expected_receiver, "Pause reached the wrong route");
        ++fixture->upstream_pauses;
        recordCallback('U');
        if (fixture->reenter_pause)
        {
            fixture->reenter_pause = false;
            fixture->pause_running = true;
            tunnelUpStreamPayload(fixture->router, l, payload("Q", 1, false, 0));
            fixture->pause_running = false;
        }
        if (fixture->close_on_pause)
        {
            tunnelDownStreamFin(fixture->router, l);
            return;
        }
        recordCallback('u');
    }
}

static void resumeSignal(tunnel_t *t, line_t *l)
{
    discard l;
    if (t == fixture->prev)
        ++fixture->downstream_resumes;
    else
    {
        require(t == fixture->expected_receiver, "Resume reached the wrong route");
        ++fixture->upstream_resumes;
        recordCallback('R');
    }
}

static void established(tunnel_t *t, line_t *l)
{
    discard l;
    if (t == fixture->prev)
        ++fixture->downstream_ests;
    else
        ++fixture->upstream_ests;
}

static void requireRouteState(router_fixture_t *f, bool bypassed)
{
    require(tunnelIsActiveForLine(f->router, f->line) != bypassed, "unexpected route bypass state");
    if (bypassed)
    {
        const uint8_t *state = lineGetState(f->line, f->router);
        for (uint32_t i = 0; i < f->router->lstate_size; ++i)
            require(state[i] == 0, "bypassed router retained line state");
    }
}

static void repeatSignals(router_fixture_t *f)
{
    const unsigned up_pauses   = f->upstream_pauses;
    const unsigned down_pauses = f->downstream_pauses;
    const unsigned up_resumes   = f->upstream_resumes;
    const unsigned down_resumes = f->downstream_resumes;
    const unsigned down_ests    = f->downstream_ests;
    for (unsigned i = 0; i < 2; ++i)
    {
        tunnelUpStreamPause(f->router, f->line);
        tunnelDownStreamPause(f->router, f->line);
        tunnelDownStreamEst(f->router, f->line);
    }
    for (unsigned i = 0; i < 2; ++i)
    {
        tunnelUpStreamResume(f->router, f->line);
        tunnelDownStreamResume(f->router, f->line);
    }
    require(f->upstream_pauses == up_pauses + 2 && f->downstream_pauses == down_pauses + 2,
            "repeat Pause did not reach the selected path");
    require(f->upstream_resumes == up_resumes + 2 && f->downstream_resumes == down_resumes + 2,
            "repeat Resume did not reach the selected path");
    require(f->downstream_ests == down_ests + 2, "repeat Est did not reach the previous side");
}

static void finish(tunnel_t *t, line_t *l)
{
    recordCallback('F');
    ++fixture->finishes;
    if (t == fixture->prev && ! fixture->borrowed_close)
    {
        lineDestroy(l);
        fixture->line = NULL;
    }
}

static void init(tunnel_t *t, line_t *l)
{
    require(t == fixture->expected_receiver, "initialized the wrong route");
    recordCallback('I');
    ++fixture->inits;
    fixture->init_running = true;
    sendUpstreamSignals(fixture->router, l, fixture->init_signals);
    if (fixture->overflow_init)
    {
        sbuf_t *buf = sbufCreateWithPadding(2U * 1024U * 1024U + 1U, kOnwardPadding);
        sbufSetLength(buf, 2U * 1024U * 1024U + 1U);
        tunnelUpStreamPayload(fixture->router, l, buf);
    }
    else if (fixture->reenter_init)
    {
        tunnelUpStreamPayload(fixture->router, l, payload("I", 1, false, 0));
        if (fixture->reenter_empty)
            tunnelUpStreamPayload(fixture->router, l, payload("", 0, false, 0));
    }
    fixture->init_running = false;
    recordCallback('i');
    if (fixture->close_on_init)
        tunnelDownStreamFin(fixture->router, l);
}

static void receive(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    require(t == fixture->expected_receiver, "payload reached the wrong route/direction");
    require(! fixture->init_running, "startup payload escaped before the selected Init returned");
    require(! fixture->pause_running, "startup payload escaped before pending Pause returned");
    recordCallback('P');
    if (fixture->datagram_count != 0)
    {
        require(fixture->payloads < fixture->datagram_count, "unexpected UDP replay delivery");
        const unsigned index  = fixture->payloads;
        const uint32_t length = fixture->datagram_lengths[index];
        require(sbufGetLength(buf) == length, "UDP replay changed datagram boundaries");
        require(! sbufIsSplice(buf), "UDP replay unexpectedly became splice input");
        require(sbufGetLeftCapacity(buf) >= kOnwardPadding, "UDP replay lost onward padding");
        require(length == 0 || memcmp(sbufGetRawPtr(buf), fixture->datagram_bytes[index], length) == 0,
                "UDP replay changed datagram contents or order");
        lineReuseBuffer(l, buf);
        ++fixture->payloads;
        if (fixture->reenter_payload)
        {
            fixture->reenter_payload = false;
            tunnelUpStreamPayload(fixture->router, l, payload("P", 1, false, 0));
        }
        if (fixture->close_on_payload)
            tunnelDownStreamFin(fixture->router, l);
        return;
    }
    if (fixture->record_startup)
    {
        const uint32_t length = sbufGetLength(buf);
        require(length <= sizeof(fixture->startup_bytes) - fixture->startup_length, "startup trace overflow");
        sbufReadRangeToMemory(buf, fixture->startup_bytes + fixture->startup_length, length);
        fixture->startup_length += length;
        lineReuseBuffer(l, buf);
        ++fixture->payloads;
        if (fixture->reenter_payload)
        {
            fixture->reenter_payload = false;
            tunnelDownStreamPause(fixture->router, l);
            tunnelDownStreamPause(fixture->router, l);
            tunnelUpStreamPayload(fixture->router, l, payload("P", 1, false, 0));
        }
        if (fixture->close_on_payload)
            tunnelDownStreamFin(fixture->router, l);
        return;
    }
    require(sbufIsSplice(buf) == fixture->expect_splice, "incorrect payload representation");
    require(! fixture->expected_buffer || buf == fixture->expected_buffer, "opaque forwarding replaced the buffer");
    require(sbufGetLeftCapacity(buf) >= kOnwardPadding, "materialization lost onward padding");
    require(sbufGetLength(buf) == fixture->expected_length, "replay changed payload length");
    uint8_t *bytes = memoryAllocate(fixture->expected_length);
    require(bytes != NULL, "allocate received-byte comparison");
    sbufReadRangeToMemory(buf, bytes, fixture->expected_length);
    require(memcmp(bytes, fixture->expected_bytes, fixture->expected_length) == 0, "replay changed payload bytes");
    memoryFree(bytes);
    lineReuseBuffer(l, buf);
    ++fixture->payloads;
    if (fixture->close_on_payload)
        tunnelDownStreamFin(fixture->router, l);
}

static void setupBeforeInit(router_fixture_t *f, bool sniffrouter, bool target, bool sniffing, bool resolve_domains)
{
    check_datagram_sniff_disposal = false;
    sniff_view_destroys           = 0;

    memoryZero(f, sizeof(*f));
    fixture                    = f;
    f->node                    = sniffrouter ? nodeSniffRouterGet() : nodeRouterGet();
    f->node.name               = (char *) "router-test";
    f->node.next               = (char *) "default";
    f->node.node_settings_json = resolve_domains ? cJSON_Parse("{\"resolve-domains\":true}") : NULL;
    f->router                  = f->node.createHandle(&f->node);
    require(f->router != NULL, "construct router");
    f->prev   = tunnelCreate(NULL, 0, 0);
    f->next   = tunnelCreate(NULL, 0, 0);
    f->target = tunnelCreate(NULL, 0, 0);
    require(f->prev && f->next && f->target, "construct fixture endpoints");
    f->prev->fnPayloadD = f->next->fnPayloadU = f->target->fnPayloadU = receive;
    f->prev->fnFinD = f->next->fnFinU = f->target->fnFinU = finish;
    f->next->fnInitU = f->target->fnInitU = init;
    f->prev->fnPauseD = f->next->fnPauseU = f->target->fnPauseU = pauseSignal;
    f->prev->fnResumeD = f->next->fnResumeU = f->target->fnResumeU = resumeSignal;
    f->prev->fnEstD = f->next->fnEstU = f->target->fnEstU = established;
    f->prev->chain_index                                  = 0;
    f->router->chain_index                                = 1;
    f->next->chain_index                                  = 2;
    f->target->chain_index                                = 3;
    tunnelBind(f->prev, f->router);
    tunnelBind(f->router, f->next);
    tunnelBindDown(f->router, f->target);
    f->expected_receiver = target ? f->target : f->next;

    if (sniffrouter)
    {
        sniffrouter_tstate_t *ts    = tunnelGetState(f->router);
        ts->routes                  = memoryAllocateZero(sizeof(*ts->routes));
        ts->routes_count            = 1;
        ts->routes[0].tunnel        = f->target;
        ts->routes[0].detection     = kSniffDetectionHttp1 | kSniffDetectionTlsClientHello;
        ts->routes[0].domains       = memoryAllocate(sizeof(char *));
        ts->routes[0].domains[0]    = stringDuplicate(target ? "route.test" : "other.test");
        ts->routes[0].domains_count = 1;
    }
    else
    {
        router_tstate_t *ts = tunnelGetState(f->router);
        ts->sniffing_modes  = sniffing ? kRouterSniffHttp1 | kRouterSniffTls : 0;
        if (target)
        {
            ts->rules                  = memoryAllocateZero(sizeof(*ts->rules));
            ts->rules_count            = 1;
            ts->rules[0].target_tunnel = f->target;
        }
    }

    f->chain = tunnelchainCreate(1);
    tunnelchainInsert(f->chain, f->router);
    tunnelchainFinalize(f->chain);
    f->line                                              = lineCreate(tunnelchainGetLinePools(f->chain), 0);
    lineGetDestinationAddressContext(f->line)->proto_tcp = true;
}

static void setup(router_fixture_t *f, bool sniffrouter, bool target, bool sniffing, bool resolve_domains)
{
    setupBeforeInit(f, sniffrouter, target, sniffing, resolve_domains);
    tunnelUpStreamInit(f->router, f->line);
}

static void teardown(router_fixture_t *f)
{
    if (f->line)
    {
        if (! f->borrowed_close)
            tunnelUpStreamFin(f->router, f->line);
        lineDestroy(f->line);
    }
    tunnelchainDestroy(f->chain);
    f->router->onDestroy(f->router, wwLifecycleStartupRollback());
    tunnelDestroy(f->prev);
    tunnelDestroy(f->next);
    tunnelDestroy(f->target);
    memoryFree(f->node.type);
    cJSON_Delete(f->node.node_settings_json);
    check_datagram_sniff_disposal = false;
    fixture                       = NULL;
}

static sbuf_t *payload(const void *data, uint32_t length, bool splice, uint32_t prefix)
{
    buffer_pool_t *pool = getWorkerBufferPool(0);
    if (! splice)
    {
        sbuf_t *buf = bufferpoolGetBestFit(pool, length, kOnwardPadding);
        sbufWrite(buf, data, length);
        sbufSetLength(buf, length);
        return buf;
    }
#if WW_HAVE_SPLICE
    require(prefix <= length && prefix <= kOnwardPadding, "invalid test prefix");
    sbuf_t *buf = bufferpoolGetSpliceBuffer(pool);
    require(buf != NULL, "allocate real splice buffer");
    const uint8_t *bytes = data;
    const uint32_t body  = length - prefix;
    require(write(sbufSpliceMetadata(buf).pipefd[1], bytes + prefix, body) == (ssize_t) body, "populate private pipe");
    buf->capacity = buf->l_pad + body;
    sbufSetLength(buf, body);
    sbufShiftLeft(buf, prefix);
    sbufWrite(buf, bytes, prefix);
    return buf;
#else
    discard data;
    discard length;
    discard prefix;
    require(false, "splice fixture on unsupported build");
    return NULL;
#endif
}

static void expect(router_fixture_t *f, const void *bytes, uint32_t length, bool splice, sbuf_t *identity)
{
    f->expected_bytes  = bytes;
    f->expected_length = length;
    f->expect_splice   = splice;
    f->expected_buffer = identity;
}

static uint32_t makeClientHello(uint8_t *buf, uint16_t padding)
{
    static const char sni[] = "route.test";
    uint8_t          *p     = buf;
    *p++                    = 0x16;
    *p++                    = 0x03;
    *p++                    = 0x01;
    uint8_t *record_length  = p;
    p += 2;
    *p++                  = 0x01;
    uint8_t *hello_length = p;
    p += 3;
    uint8_t *body = p;
    *p++          = 0x03;
    *p++          = 0x03;
    memorySet(p, 0x11, 32);
    p += 32;
    *p++ = 0;
    PUT_BE16(p, 2);
    p += 2;
    PUT_BE16(p, 0x1301);
    p += 2;
    *p++                       = 1;
    *p++                       = 0;
    uint8_t *extensions_length = p;
    p += 2;
    if (padding)
    {
        PUT_BE16(p, 21);
        PUT_BE16(p + 2, padding);
        p += 4;
        memoryZero(p, padding);
        p += padding;
    }
    PUT_BE16(p, 0);
    PUT_BE16(p + 2, 5 + sizeof(sni) - 1);
    PUT_BE16(p + 4, 3 + sizeof(sni) - 1);
    p += 6;
    *p++ = 0;
    PUT_BE16(p, sizeof(sni) - 1);
    p += 2;
    memoryCopy(p, sni, sizeof(sni) - 1);
    p += sizeof(sni) - 1;
    PUT_BE16(extensions_length, p - extensions_length - 2);
    PUT_BE24(hello_length, p - body);
    PUT_BE16(record_length, p - buf - 5);
    return (uint32_t) (p - buf);
}

static void testRouting(bool sniffrouter, bool target, bool splice, bool tls)
{
    router_fixture_t f;
    setup(&f, sniffrouter, target, true, false);
    static const char http[] = "GET / HTTP/1.1\r\nHost: route.test\r\n\r\ncoalesced-body";
    uint8_t           request[128];
    uint32_t          length = tls ? makeClientHello(request, 0) : sizeof(http) - 1;
    if (! tls)
        memoryCopy(request, http, length);
    const uint32_t split = tls ? 7 : 12;
    tunnelUpStreamPayload(f.router, f.line, payload(request, split, splice, splice ? 3 : 0));
    require(f.inits == 0 && f.payloads == 0, "incomplete request committed a route");
    sbuf_t *pending = sniffrouter ? ((sniffrouter_lstate_t *) lineGetState(f.line, f.router))->pending
                                  : ((router_lstate_t *) lineGetState(f.line, f.router))->pending;
    require(pending && ! sbufIsSplice(pending), "pending sniff input must be ordinary");
    require(sbufGetLength(pending) == split && memcmp(sbufGetRawPtr(pending), request, split) == 0,
            "pending input differs from actual private-pipe bytes");
    expect(&f, request, length, false, NULL);
    tunnelUpStreamPayload(f.router, f.line, payload(request + split, length - split, ! splice && WW_HAVE_SPLICE, 0));
    require(f.inits == 1 && f.payloads == 1, "request was not replayed exactly once");
    requireRouteState(&f, ! target);
    repeatSignals(&f);

    static const char opaque[] = "later opaque payload";
    sbuf_t           *buf      = payload(opaque, sizeof(opaque) - 1, splice, splice ? 4 : 0);
    expect(&f, opaque, sizeof(opaque) - 1, splice, buf);
    tunnelUpStreamPayload(f.router, f.line, buf);
    f.expected_receiver = f.prev;
    buf                 = payload(opaque, sizeof(opaque) - 1, splice, splice ? 4 : 0);
    expect(&f, opaque, sizeof(opaque) - 1, splice, buf);
    tunnelDownStreamPayload(f.router, f.line, buf);
    require(f.payloads == 3, "opaque traffic failed in one direction");
    teardown(&f);
}

static void testMetadataRouting(bool target, bool splice)
{
    router_fixture_t f;
    setup(&f, false, target, false, false);
    require(f.inits == 1, "metadata route did not commit during Init");
    requireRouteState(&f, ! target);
    repeatSignals(&f);
    static const char data[] = "metadata-route-body";
    sbuf_t           *buf    = payload(data, sizeof(data) - 1, splice, 0);
    expect(&f, data, sizeof(data) - 1, splice, buf);
    tunnelUpStreamPayload(f.router, f.line, buf);
    require(f.payloads == 1, "metadata route dropped payload");
    teardown(&f);
}

static void testStartupReplay(bool sniffrouter, bool target, bool metadata)
{
    router_fixture_t f;
    setupBeforeInit(&f, sniffrouter, target, ! metadata, false);
    f.record_startup  = true;
    f.reenter_init    = true;
    f.reenter_payload = true;
    tunnelUpStreamInit(f.router, f.line);
    static const char request[] = "GET / HTTP/1.1\r\nHost: route.test\r\n\r\n";
    if (! metadata)
        tunnelUpStreamPayload(f.router, f.line, payload(request, sizeof(request) - 1, false, 0));
    const uint32_t prefix = metadata ? 0 : sizeof(request) - 1;
    require(f.startup_length == prefix + 2, "startup replay lost nested payload");
    require(metadata || memcmp(f.startup_bytes, request, prefix) == 0, "nested input overtook sniffed input");
    require(memcmp(f.startup_bytes + prefix, "IP", 2) == 0, "nested startup payload reordered");
    require(f.downstream_pauses == 2 && f.upstream_resumes == 0, "startup replay incorrectly required Resume");
    requireRouteState(&f, ! target);
    teardown(&f);
}

static void testPendingPause(bool sniffrouter, bool target)
{
    static const struct
    {
        const char *early_signals;
        const char *init_signals;
        const char *trace;
        unsigned    pauses;
        unsigned    resumes;
        bool        nested_payload;
    } cases[] = {
        {"U", "", "IiUuP", 1, 0, false},
        {"UU", "", "IiUuP", 1, 0, false},
        {"UR", "", "IiP", 0, 0, false},
        {"URU", "", "IiUuP", 1, 0, false},
        {"R", "", "IiP", 0, 0, false},
        {"U", "R", "IRiP", 0, 1, false},
        {"U", "U", "IUuiP", 1, 0, false},
        {"U", "UU", "IUuUuiP", 2, 0, false},
        {"U", "UR", "IUuRiP", 1, 1, false},
        {"U", "RU", "IRUuiP", 1, 1, false},
        {"U", "", "IiUuPP", 1, 0, true},
    };
    static const char request[] = "GET / HTTP/1.1\r\nHost: route.test\r\n\r\n";
    const uint32_t    length    = sizeof(request) - 1;
    const uint32_t    split     = 12;

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        router_fixture_t f;
        setup(&f, sniffrouter, target, true, false);
        f.record_startup   = true;
        f.record_callbacks = true;
        f.init_signals     = cases[i].init_signals;
        f.reenter_init     = cases[i].nested_payload;
        f.reenter_pause    = cases[i].nested_payload;
        tunnelUpStreamPayload(f.router, f.line, payload(request, split, false, 0));
        sendUpstreamSignals(f.router, f.line, cases[i].early_signals);
        require(f.inits == 0 && f.callback_count == 0, "pressure reached a branch before Init");
        tunnelUpStreamPayload(f.router, f.line, payload(request + split, length - split, false, 0));

        require(strcmp(f.callback_trace, cases[i].trace) == 0, "pending Pause callback order changed");
        require(f.upstream_pauses == cases[i].pauses && f.upstream_resumes == cases[i].resumes,
                "pending Pause was lost, duplicated or replayed after Resume");
        require(f.startup_length == length + (cases[i].nested_payload ? 2U : 0U), "pending Pause lost startup payload");
        require(memcmp(f.startup_bytes, request, length) == 0, "pending Pause reordered the classified input");
        if (cases[i].nested_payload)
            require(memcmp(f.startup_bytes + length, "IQ", 2) == 0, "pending Pause reordered nested startup input");
        requireRouteState(&f, ! target);
        f.record_callbacks = false;
        repeatSignals(&f);
        teardown(&f);
    }
}

static void testPendingPauseBoundary(bool sniffrouter, bool target, bool during_init, bool borrowed_close)
{
    router_fixture_t f;
    setup(&f, sniffrouter, target, true, false);
    f.record_startup   = true;
    f.record_callbacks = true;
    f.borrowed_close   = borrowed_close;
    f.reenter_init     = true;
    f.reenter_pause    = true;
    f.close_on_init    = during_init;
    f.close_on_pause   = ! during_init;
    tunnelUpStreamPause(f.router, f.line);
    static const char request[] = "GET / HTTP/1.1\r\nHost: route.test\r\n\r\n";
    sbuf_t           *buf       = payload(request, sizeof(request) - 1, false, 0);
    atomic_uint       disposed  = 0;
    watchBufferDisposal(buf, &disposed);
    line_t *line = f.line;
    lineRef(line);
    tunnelUpStreamPayload(f.router, f.line, buf);

    require(strcmp(f.callback_trace, during_init ? "IiF" : "IiUF") == 0,
            "pending Pause continued after a terminal callback");
    require(f.inits == 1 && f.finishes == 1 && f.payloads == 0, "pending Pause leaked payload after Finish");
    require(atomic_load(&disposed) == 1, "pending Pause did not settle the classified input exactly once");
    require(atomicLoadU32Relaxed(&line->refc) == (borrowed_close ? 2U : 1U), "pending Pause leaked a line reference");
    if (borrowed_close)
    {
        require(f.line != NULL && lineIsAlive(f.line), "pending Pause destroyed a borrowed line");
        require(tunnelIsActiveForLine(f.router, f.line), "pending Pause bypassed a finished router");
    }
    else
    {
        require(f.line == NULL, "pending Pause did not reach the source owner Finish");
        require(! lineIsAlive(line), "pending Pause left the source owner line alive");
    }
    const uint8_t *state = lineGetState(line, f.router);
    for (uint32_t i = 0; i < f.router->lstate_size; ++i)
        require(state[i] == 0, "pending Pause retained state after Finish");
    lineUnref(line);
    teardown(&f);
}

static void testBorrowedFinish(bool sniffrouter, bool target, bool during_init)
{
    router_fixture_t f;
    setup(&f, sniffrouter, target, true, false);
    f.borrowed_close            = true;
    f.record_startup            = true;
    f.reenter_init              = true;
    f.close_on_init             = during_init;
    f.close_on_payload          = ! during_init;
    static const char request[] = "GET / HTTP/1.1\r\nHost: route.test\r\n\r\n";
    tunnelUpStreamPayload(f.router, f.line, payload(request, sizeof(request) - 1, false, 0));
    require(lineIsAlive(f.line), "borrowed Finish fixture destroyed the owner line");
    require(f.finishes == 1 && f.payloads == (during_init ? 0U : 1U), "startup replay continued after borrowed Finish");
    require(tunnelIsActiveForLine(f.router, f.line), "closed router was bypassed");
    const uint8_t *state = lineGetState(f.line, f.router);
    for (uint32_t i = 0; i < f.router->lstate_size; ++i)
        require(state[i] == 0, "borrowed Finish retained router state");
    teardown(&f);
}

static void testStartupOverflow(bool sniffrouter)
{
    router_fixture_t f;
    setup(&f, sniffrouter, false, true, false);
    f.overflow_init             = true;
    static const char request[] = "GET / HTTP/1.1\r\nHost: route.test\r\n\r\n";
    tunnelUpStreamPayload(f.router, f.line, payload(request, sizeof(request) - 1, false, 0));
    require(f.line == NULL && f.payloads == 0 && f.finishes == 2,
            "startup overflow did not close both initialized sides before replay");
    teardown(&f);
}

static void testExplicitNextTarget(bool sniffrouter)
{
    router_fixture_t f;
    setupBeforeInit(&f, sniffrouter, true, true, false);
    f.expected_receiver = f.next;
    if (sniffrouter)
        ((sniffrouter_tstate_t *) tunnelGetState(f.router))->routes[0].tunnel = f.next;
    else
        ((router_tstate_t *) tunnelGetState(f.router))->rules[0].target_tunnel = f.next;
    tunnelUpStreamInit(f.router, f.line);
    tunnelUpStreamPause(f.router, f.line);
    static const char request[] = "GET / HTTP/1.1\r\nHost: route.test\r\n\r\n";
    expect(&f, request, sizeof(request) - 1, false, NULL);
    tunnelUpStreamPayload(f.router, f.line, payload(request, sizeof(request) - 1, false, 0));
    require(f.upstream_pauses == 1, "explicit next target lost pending Pause");
    requireRouteState(&f, ! sniffrouter);
    repeatSignals(&f);
    if (sniffrouter)
    {
        tunnelUpStreamEst(f.router, f.line);
        tunnelUpStreamEst(f.router, f.line);
        require(f.upstream_ests == 0, "configured SniffRouter target received upstream Est");
    }
    teardown(&f);
}

static void testClose(bool sniffrouter, bool splice, unsigned mode)
{
    router_fixture_t f;
    setup(&f, sniffrouter, true, true, false);
    static const char request[] = "GET / HTTP/1.1\r\nHost: route.test\r\n\r\n";
    sbuf_t           *buf       = payload(request, mode == 0 ? 4 : sizeof(request) - 1, splice, 0);
    atomic_uint       disposed  = 0;
    watchBufferDisposal(buf, &disposed);
    line_t *line = f.line;
    lineRef(line);
    f.close_on_init    = mode == 1;
    f.close_on_payload = mode == 2;
    expect(&f, request, sizeof(request) - 1, false, NULL);
    tunnelUpStreamPayload(f.router, f.line, buf);
    if (mode == 0)
        tunnelDownStreamFin(f.router, f.line);
    require(f.line == NULL, "Finish did not reach line owner");
    require(atomic_load(&disposed) == 1, "input buffer was not disposed exactly once on close");
    require(f.payloads == (mode == 2 ? 1U : 0U), "payload escaped a closed route");
    require(! lineIsAlive(line), "closed line remains logically alive");
    require(atomicLoadU32Relaxed(&line->refc) == 1, "route close leaked a line reference");
    const uint8_t *state = lineGetState(line, f.router);
    for (uint32_t i = 0; i < f.router->lstate_size; ++i)
        require(state[i] == 0, "route close did not clear line state");
    lineUnref(line);
    teardown(&f);
}

static void testLargeCompleteHeader(bool sniffrouter, bool tls)
{
    router_fixture_t f;
    setup(&f, sniffrouter, true, true, false);
    static const char start[] = "GET / HTTP/1.1\r\nX-Padding: ";
    static const char end[]   = "\r\nHost: route.test\r\n\r\nbody";
    const uint32_t    padding = 9000;
    uint32_t          length  = sizeof(start) - 1 + padding + sizeof(end) - 1;
    uint8_t          *request = memoryAllocate(length + 128);
    require(request != NULL, "allocate large header");
    if (tls)
        length = makeClientHello(request, padding);
    else
    {
        memoryCopy(request, start, sizeof(start) - 1);
        memorySet(request + sizeof(start) - 1, 'a', padding);
        memoryCopy(request + sizeof(start) - 1 + padding, end, sizeof(end) - 1);
    }
    expect(&f, request, length, false, NULL);
    tunnelUpStreamPayload(f.router, f.line, payload(request, length, false, 0));
    require(f.inits == 1 && f.payloads == 1, "complete header exceeding sniff window changed routing");
    memoryFree(request);
    teardown(&f);
}

static void testCapabilities(void)
{
    for (unsigned sniffrouter = 0; sniffrouter < 2; ++sniffrouter)
    {
        router_fixture_t f;
        setup(&f, sniffrouter != 0, false, true, sniffrouter == 0);
        require(f.node.flags == kNodeFlagSupportsSplice, "router did not advertise splice capability");
        if (! sniffrouter)
        {
            router_tstate_t *ts = tunnelGetState(f.router);
            require(ts->domain_resolver_node.flags == kNodeFlagSupportsSplice,
                    "Router cleared internal resolver splice capability");
        }
        teardown(&f);
    }
}

static void testSniffRouterUdpReplay(bool target, bool empty_first, unsigned close_mode, bool borrowed_close)
{
    router_fixture_t f;
    setupBeforeInit(&f, true, target, true, false);
    check_datagram_sniff_disposal = true;

    f.line->routing_context.dest_ctx.proto_tcp = false;
    f.line->routing_context.dest_ctx.proto_udp = true;
    static const uint8_t request[]             = "GET / HTTP/1.1\r\nHost: route.test\r\n\r\n";
    const uint32_t       split                 = empty_first ? 0 : 12;
    f.datagram_bytes[0]                        = request;
    f.datagram_lengths[0]                      = split;
    f.datagram_bytes[1]                        = request + split;
    f.datagram_lengths[1]                      = sizeof(request) - 1U - split;
    f.datagram_bytes[2]                        = (const uint8_t *) "I";
    f.datagram_lengths[2]                      = 1;
    f.datagram_bytes[3]                        = (const uint8_t *) "";
    f.datagram_lengths[3]                      = 0;
    f.datagram_bytes[4]                        = (const uint8_t *) "P";
    f.datagram_lengths[4]                      = 1;
    f.datagram_count                           = 5;
    f.reenter_init = f.reenter_empty = f.reenter_payload = true;
    f.close_on_init                                      = close_mode == 1;
    f.close_on_payload                                   = close_mode == 2;
    f.borrowed_close                                     = borrowed_close;
    tunnelUpStreamInit(f.router, f.line);
    tunnelUpStreamPayload(f.router, f.line, payload(request, split, false, 0));
    require(f.inits == 0 && f.payloads == 0, "incomplete UDP sniff input committed early");
    tunnelUpStreamPayload(f.router, f.line, payload(request + split, sizeof(request) - 1U - split, false, 0));
    if (close_mode != 0)
    {
        require(f.finishes == 1 && f.payloads == (close_mode == 1 ? 0U : 1U),
                "SniffRouter UDP replay continued after Finish");
        if (borrowed_close)
        {
            require(f.line != NULL && lineIsAlive(f.line), "borrowed UDP Finish destroyed its owner's line");
            const uint8_t *state = lineGetState(f.line, f.router);
            for (uint32_t i = 0; i < f.router->lstate_size; ++i)
                require(state[i] == 0, "borrowed UDP Finish retained line state");
        }
        else
            require(f.line == NULL, "UDP Finish did not reach its owner");
    }
    else
    {
        require(f.payloads == f.datagram_count && f.inits == 1, "SniffRouter UDP replay lost a datagram");
        requireRouteState(&f, ! target);
    }
    require(sniff_view_destroys != 0, "SniffRouter did not destroy its detached inspection view");
    teardown(&f);
}

static void testSniffRouterUdpLimits(void)
{
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        router_fixture_t f;
        setupBeforeInit(&f, true, false, true, false);
        check_datagram_sniff_disposal = true;

        f.line->routing_context.dest_ctx.proto_tcp = false;
        f.line->routing_context.dest_ctx.proto_udp = true;
        tunnelUpStreamInit(f.router, f.line);
        line_t *line = f.line;
        lineRef(line);
        if (mode == 0)
        {
            for (unsigned i = 0; i < 1024; ++i)
                tunnelUpStreamPayload(f.router, f.line, sbufCreateWithPadding(0, kOnwardPadding));
            require(f.line != NULL && f.inits == 0, "SniffRouter empty UDP allowance was too small");
            tunnelUpStreamPayload(f.router, f.line, sbufCreateWithPadding(0, kOnwardPadding));
        }
        else if (mode == 1)
            tunnelUpStreamPayload(f.router, f.line, sbufCreateWithPadding(4U * 1024U * 1024U, kOnwardPadding));
        else
        {
            f.overflow_init             = true;
            static const char request[] = "GET / HTTP/1.1\r\nHost: route.test\r\n\r\n";
            tunnelUpStreamPayload(f.router, f.line, payload(request, sizeof(request) - 1, false, 0));
        }
        require(f.line == NULL && ! lineIsAlive(line) && f.payloads == 0,
                "SniffRouter UDP retention overflow did not close the owner");
        require(f.inits == (mode == 2 ? 1U : 0U) && f.finishes == (mode == 2 ? 2U : 1U),
                "SniffRouter UDP overflow finished an uninitialized or missing side");
        require(atomicLoadU32Relaxed(&line->refc) == 1, "SniffRouter UDP overflow leaked a line reference");
        const uint8_t *state = lineGetState(line, f.router);
        for (uint32_t i = 0; i < f.router->lstate_size; ++i)
            require(state[i] == 0, "SniffRouter UDP overflow retained line state");
        require(sniff_view_destroys == (mode == 1 ? 0U : 1U),
                "SniffRouter UDP refusal did not destroy its inspection view exactly once");
        lineUnref(line);
        teardown(&f);
    }
}

#ifdef ROUTER_ENABLE_QUIC_SNIFFING
static uint32_t readQuicDatagram(const char *name, uint8_t *bytes, size_t capacity)
{
    char path[1024];
    require(snprintf(path, sizeof(path), "%s/%s", ROUTER_QUIC_SNI_VECTOR_DIR, name) < (int) sizeof(path),
            "QUIC fixture path overflow");
    FILE *file = fopen(path, "rb");
    require(file != NULL, "open QUIC datagram fixture");
    const size_t length = fread(bytes, 1, capacity, file);
    require(! ferror(file) && feof(file), "read complete QUIC datagram fixture");
    require(fclose(file) == 0, "close QUIC datagram fixture");
    return (uint32_t) length;
}

static void testUdpReplay(bool target, bool metadata, unsigned close_mode)
{
    router_fixture_t f;
    setupBeforeInit(&f, false, target, ! metadata, false);
    check_datagram_sniff_disposal = true;

    f.line->routing_context.dest_ctx.proto_tcp = false;
    f.line->routing_context.dest_ctx.proto_udp = true;
    router_tstate_t *ts                        = tunnelGetState(f.router);
    ts->sniffing_modes                         = metadata ? 0 : kRouterSniffQuic;
    uint8_t        first[2048], second[2048];
    const uint32_t first_length  = readQuicDatagram("02_split_inside_host_part1.bin", first, sizeof(first));
    const uint32_t second_length = readQuicDatagram("02_split_inside_host_part2.bin", second, sizeof(second));
    unsigned       index         = 0;
    if (! metadata)
    {
        f.datagram_bytes[index]     = first;
        f.datagram_lengths[index++] = first_length;
        f.datagram_bytes[index]     = second;
        f.datagram_lengths[index++] = second_length;
    }
    f.datagram_bytes[index]     = (const uint8_t *) "I";
    f.datagram_lengths[index++] = 1;
    f.datagram_bytes[index]     = (const uint8_t *) "";
    f.datagram_lengths[index++] = 0;
    f.datagram_bytes[index]     = (const uint8_t *) "P";
    f.datagram_lengths[index++] = 1;
    f.datagram_count            = index;
    f.reenter_init = f.reenter_empty = f.reenter_payload = true;
    f.close_on_init                                      = close_mode == 1;
    f.close_on_payload                                   = close_mode == 2;
    tunnelUpStreamInit(f.router, f.line);
    if (! metadata)
    {
        tunnelUpStreamPayload(f.router, f.line, payload(first, first_length, false, 0));
        require(f.inits == 0 && f.payloads == 0, "partial QUIC handshake committed early");
        tunnelUpStreamPayload(f.router, f.line, payload(second, second_length, false, 0));
    }
    if (close_mode != 0)
    {
        require(f.line == NULL && f.finishes == 1, "UDP startup Finish did not close the owner");
        require(f.payloads == (close_mode == 1 ? 0U : 1U), "UDP replay continued after Finish");
    }
    else
    {
        require(f.payloads == f.datagram_count && f.inits == 1, "UDP replay lost a datagram");
        requireRouteState(&f, ! target);
    }
    require((sniff_view_destroys != 0) == ! metadata, "Router did not settle its detached inspection view");
    teardown(&f);
}

static void testUdpRetentionLimits(void)
{
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        router_fixture_t f;
        setupBeforeInit(&f, false, false, true, false);
        check_datagram_sniff_disposal = true;

        f.line->routing_context.dest_ctx.proto_tcp                     = false;
        f.line->routing_context.dest_ctx.proto_udp                     = true;
        ((router_tstate_t *) tunnelGetState(f.router))->sniffing_modes = kRouterSniffQuic;
        tunnelUpStreamInit(f.router, f.line);
        line_t *line = f.line;
        lineRef(line);
        if (mode == 0)
        {
            for (unsigned i = 0; i < 1024; ++i)
                tunnelUpStreamPayload(f.router, f.line, sbufCreateWithPadding(0, kOnwardPadding));
            require(f.line != NULL && f.inits == 0, "empty datagrams exhausted entry allowance too soon");
            tunnelUpStreamPayload(f.router, f.line, sbufCreateWithPadding(0, kOnwardPadding));
        }
        else if (mode == 1)
        {
            // Retained allocation, not just the empty logical payload, must be bounded.
            tunnelUpStreamPayload(f.router, f.line, sbufCreateWithPadding(4U * 1024U * 1024U, kOnwardPadding));
        }
        else
        {
            // Close while only the first datagram and its partial sniff view are retained.
            uint8_t        bytes[2048];
            const uint32_t length = readQuicDatagram("02_split_inside_host_part1.bin", bytes, sizeof(bytes));
            tunnelUpStreamPayload(f.router, f.line, payload(bytes, length, false, 0));
            tunnelUpStreamFin(f.router, f.line);
            lineDestroy(f.line);
            f.line = NULL;
        }
        require(f.line == NULL && ! lineIsAlive(line) && f.inits == 0 && f.payloads == 0,
                "pending UDP retention did not settle without initializing a branch");
        require(atomicLoadU32Relaxed(&line->refc) == 1, "pending UDP retention leaked a line reference");
        const uint8_t *state = lineGetState(line, f.router);
        for (uint32_t i = 0; i < f.router->lstate_size; ++i)
            require(state[i] == 0, "pending UDP retention left line state after Finish");
        require(sniff_view_destroys == (mode == 1 ? 0U : 1U),
                "Router UDP refusal or Finish did not destroy its inspection view exactly once");
        lineUnref(line);
        teardown(&f);
    }
}
#endif

int main(void)
{
    testCaseSet("router_splice_test");
    static char            off[]        = "OFF";
    ww_construction_data_t data         = {0};
    data.workers_count                  = 1;
    data.ram_profile                    = kRamProfileS1Memory;
    data.mtu_size                       = 1500;
    data.internal_logger_data.log_level = data.core_logger_data.log_level = off;
    data.network_logger_data.log_level = data.dns_logger_data.log_level = off;
    require(wwStartupSucceeded(createGlobalState(data)), "initialize runtime");
    testSpliceInventoryInitialize(kOnwardPadding + 32);
    globalstateUpdateAllocationPadding(kOnwardPadding + 32);
    for (unsigned splice = 0; splice <= WW_HAVE_SPLICE; ++splice)
    {
        for (unsigned sniffrouter = 0; sniffrouter < 2; ++sniffrouter)
        {
            for (unsigned tls = 0; tls < 2; ++tls)
            {
                testRouting(sniffrouter != 0, false, splice != 0, tls != 0);
                testRouting(sniffrouter != 0, true, splice != 0, tls != 0);
            }
            for (unsigned mode = 0; mode < 3; ++mode)
                testClose(sniffrouter != 0, splice != 0, mode);
        }
        testMetadataRouting(false, splice != 0);
        testMetadataRouting(true, splice != 0);
    }
    for (unsigned sniffrouter = 0; sniffrouter < 2; ++sniffrouter)
    {
        testLargeCompleteHeader(sniffrouter != 0, false);
        testLargeCompleteHeader(sniffrouter != 0, true);
        testExplicitNextTarget(sniffrouter != 0);
        testStartupOverflow(sniffrouter != 0);
        for (unsigned target = 0; target < 2; ++target)
        {
            testPendingPause(sniffrouter != 0, target != 0);
            for (unsigned borrowed = 0; borrowed < 2; ++borrowed)
            {
                testPendingPauseBoundary(sniffrouter != 0, target != 0, false, borrowed != 0);
                testPendingPauseBoundary(sniffrouter != 0, target != 0, true, borrowed != 0);
            }
            testStartupReplay(sniffrouter != 0, target != 0, false);
            if (! sniffrouter)
                testStartupReplay(false, target != 0, true);
            testBorrowedFinish(sniffrouter != 0, target != 0, true);
            testBorrowedFinish(sniffrouter != 0, target != 0, false);
        }
    }
    testCapabilities();
    for (unsigned target = 0; target < 2; ++target)
        for (unsigned empty_first = 0; empty_first < 2; ++empty_first)
            for (unsigned close_mode = 0; close_mode < 3; ++close_mode)
            {
                testSniffRouterUdpReplay(target != 0, empty_first != 0, close_mode, false);
                if (close_mode != 0)
                    testSniffRouterUdpReplay(target != 0, empty_first != 0, close_mode, true);
            }
    testSniffRouterUdpLimits();
#ifdef ROUTER_ENABLE_QUIC_SNIFFING
    testUdpRetentionLimits();
    for (unsigned target = 0; target < 2; ++target)
        for (unsigned metadata = 0; metadata < 2; ++metadata)
            for (unsigned close_mode = 0; close_mode < 3; ++close_mode)
                testUdpReplay(target != 0, metadata != 0, close_mode);
#endif
    worker_t                     *worker  = getWorker(0);
    const ww_lifecycle_context_t *context = wwLifecycleProcessShutdown();
    require(workerInstallApplicationQuiesceRequest(worker, context) != kWorkerQuiesceRequestUnavailable, "quiesce");
    workerPerformQuiesce(worker, context);
    require(workerRequestDrain(worker), "request drain");
    workerPerformDrain(worker, context);
    require(workerRequestTeardown(worker), "request teardown");
    workerPerformTeardown(worker);
    destroyGlobalState();
    puts("Router and SniffRouter ordinary/splice payload tests passed");
    return 0;
}
