/*
 * Covers: router splice; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testRouting, testMetadataRouting, testClose, testLargeCompleteHeader, testCapabilities
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
#include "fixtures/failure/buffer_disposal_probe.h"

#if WW_HAVE_SPLICE
#include <unistd.h>
#endif

enum
{
    kOnwardPadding = 192
};

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
} router_fixture_t;

static router_fixture_t *fixture;


static void finish(tunnel_t *t, line_t *l)
{
    ++fixture->finishes;
    if (t == fixture->prev)
    {
        lineDestroy(l);
        fixture->line = NULL;
    }
}

static void init(tunnel_t *t, line_t *l)
{
    require(t == fixture->expected_receiver, "initialized the wrong route");
    ++fixture->inits;
    if (fixture->close_on_init)
        tunnelDownStreamFin(fixture->router, l);
}

static void receive(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    require(t == fixture->expected_receiver, "payload reached the wrong route/direction");
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

static void setup(router_fixture_t *f, bool sniffrouter, bool target, bool sniffing, bool resolve_domains)
{
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
    tunnelUpStreamInit(f->router, f->line);
}

static void teardown(router_fixture_t *f)
{
    if (f->line)
    {
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
    fixture = NULL;
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
    static const char data[] = "metadata-route-body";
    sbuf_t           *buf    = payload(data, sizeof(data) - 1, splice, 0);
    expect(&f, data, sizeof(data) - 1, splice, buf);
    tunnelUpStreamPayload(f.router, f.line, buf);
    require(f.payloads == 1, "metadata route dropped payload");
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
    }
    testCapabilities();
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
