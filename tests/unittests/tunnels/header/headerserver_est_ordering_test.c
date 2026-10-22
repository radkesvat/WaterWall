/* HeaderServer Est ordering with a worker-zero loop/pool, an owning previous
 * mock and borrowing node/next mocks. Checks synchronous Est, nested ABC order,
 * close during Est, exact byte/entry reentry limits, state/buffer reclamation,
 * protocol markers, metadata preservation and (WW_HAVE_SPLICE) split headers,
 * identity and PROXY modes via private pipes.
 * Failures use _Exit(1); requires the fixture's GNU wrappers.
 * CTest: waterwall.headerserver_est_ordering_unit. */
#include "HeaderServer/structure.h"
#include "fixtures/protocols/protocol_est_ordering_fixture.h"

static unsigned header_pauses[2], header_resumes[2];

static void headerPause(tunnel_t *t, line_t *l)
{
    discard l;
    ++header_pauses[t == estContext(t)->next];
}

static void headerResume(tunnel_t *t, line_t *l)
{
    discard l;
    ++header_resumes[t == estContext(t)->next];
}

static void headerSetup(est_fixture_t *f)
{
    estFixtureSetup(f, sizeof(headerserver_tstate_t), sizeof(headerserver_lstate_t));
    f->prev->chain_index = 0;
    f->node->chain_index = 1;
    f->next->chain_index = 2;
    f->node->fnInitU     = headerserverTunnelUpStreamInit;
    f->node->fnPayloadU  = headerserverTunnelUpStreamPayload;
    f->node->fnPayloadD  = headerserverTunnelDownStreamPayload;
    f->node->fnFinU      = headerserverTunnelUpStreamFinish;
    f->node->fnFinD      = headerserverTunnelDownStreamFinish;
    f->node->fnEstD      = headerserverTunnelDownStreamEst;
    f->node->fnPauseU    = headerserverTunnelUpStreamPause;
    f->node->fnResumeU   = headerserverTunnelUpStreamResume;
    f->node->fnPauseD    = headerserverTunnelDownStreamPause;
    f->node->fnResumeD   = headerserverTunnelDownStreamResume;
    f->prev->fnPauseD = f->next->fnPauseU = headerPause;
    f->prev->fnResumeD = f->next->fnResumeU = headerResume;
    memoryZero(header_pauses, sizeof(header_pauses));
    memoryZero(header_resumes, sizeof(header_resumes));
}

static void headerSignals(est_fixture_t *f, line_t *l)
{
    for (unsigned i = 0; i < 2; ++i)
    {
        tunnelUpStreamPause(f->node, l);
        tunnelDownStreamPause(f->node, l);
    }
    for (unsigned i = 0; i < 2; ++i)
    {
        tunnelUpStreamResume(f->node, l);
        tunnelDownStreamResume(f->node, l);
    }
}

static void headerRequireBypassed(est_fixture_t *f)
{
    twfRequire(! tunnelIsActiveForLine(f->node, f->line), "HeaderServer stayed active after routing settled");
    twfRequireLineStateZeroed(f->line, f->node, "HeaderServer retained state after bypass");
}

/* Next reenters Est synchronously twice; both notifications must pass through. */
static void initEst(est_fixture_t *f, line_t *l)
{
    tunnelDownStreamEst(f->node, l);
    if (lineIsAlive(l))
        tunnelDownStreamEst(f->node, l);
}

/* Est admits B before the original A is forwarded; B must wait behind A. */
static void nestedInput(est_fixture_t *f, line_t *l)
{
    f->on_est = NULL;
    twfRequire(tunnelIsActiveForLine(f->node, l), "HeaderServer retired during initial routing");
    headerSignals(f, l);
    tunnelUpStreamPayload(f->node, l, estBytes(l, "B", 1));
}

/* Forwarding A admits C behind the already queued B. Clear the hook first. */
static void nestedAfterFirst(est_fixture_t *f, line_t *l)
{
    f->on_up = NULL;
    tunnelUpStreamPayload(f->node, l, estBytes(l, "C", 1));
}

/* The owning previous mock closes during Est; the held observation reference
 * allows postconditions without permitting later payload delivery. */
static void closeFromEst(est_fixture_t *f, line_t *l)
{
    tunnelUpStreamFin(f->node, l);
    lineDestroy(l);
}

static void testInitialOrder(bool close)
{
    est_fixture_t f;
    headerSetup(&f);
    ((headerserver_tstate_t *) tunnelGetState(f.node))->override_mode = kHeaderServerOverrideModeHeaderPort;
    f.on_init                                                         = initEst;
    f.on_est                                                          = close ? closeFromEst : nestedInput;
    f.on_up                                                           = nestedAfterFirst;
    tunnelUpStreamInit(f.node, f.line);
    const uint8_t input[] = {0x01, 0xbb, 'A'};
    tunnelUpStreamPayload(f.node, f.line, estBytes(f.line, input, sizeof(input)));
    twfRequire(f.init_count == 1 && f.est_count == (close ? 1U : 2U), "HeaderServer lost synchronous Est");
    if (close)
        twfRequire(f.up_len == 0 && f.up_finish_count == 1, "HeaderServer sent initial data after Est close");
    else
    {
        twfRequire(f.up_len == 3 && memoryCompare(f.up, "ABC", 3) == 0,
                   "HeaderServer nested Est input overtook original payload");
        headerRequireBypassed(&f);
        headerSignals(&f, f.line);
        twfRequire(header_pauses[0] == 4 && header_pauses[1] == 4 && header_resumes[0] == 4 && header_resumes[1] == 4,
                   "HeaderServer suppressed repeated advisory signals before or after bypass");
        tunnelDownStreamEst(f.node, f.line);
        twfRequire(f.est_count == 3, "bypassed HeaderServer lost Est");
        tunnelUpStreamFin(f.node, f.line);
        twfRequire(f.up_finish_count == 1, "bypassed HeaderServer lost Finish");
        lineDestroy(f.line);
    }
    twfRequireLineStateZeroed(f.line, f.node, "HeaderServer retained state after Finish");
    estFixtureDestroy(&f);
}

static void overflowReentryBytes(est_fixture_t *f, line_t *l)
{
    sbuf_t *large = bufferpoolGetBestFit(lineGetBufferPool(l), kHeaderServerMaxReentryBytes, 16);
    sbufSetLength(large, kHeaderServerMaxReentryBytes);
    tunnelUpStreamPayload(f->node, l, large);
    headerserver_lstate_t *ls = lineGetState(l, f->node);
    twfRequire(bufferqueueGetBufLen(&ls->initial_reentry) == kHeaderServerMaxReentryBytes,
               "HeaderServer rejected exact transient reentry byte limit");
    tunnelUpStreamPayload(f->node, l, estBytes(l, "X", 1));
}

static void overflowReentryEntries(est_fixture_t *f, line_t *l)
{
    for (unsigned i = 0; i < kHeaderServerMaxReentryBuffers; ++i)
        tunnelUpStreamPayload(f->node, l, estBytes(l, "", 0));
    headerserver_lstate_t *ls = lineGetState(l, f->node);
    twfRequire(bufferqueueGetBufCount(&ls->initial_reentry) == kHeaderServerMaxReentryBuffers,
               "HeaderServer rejected exact transient reentry entry limit");
    tunnelUpStreamPayload(f->node, l, estBytes(l, "", 0));
}

static void testReentryLimit(est_inject_fn inject)
{
    est_fixture_t f;
    headerSetup(&f);
    ((headerserver_tstate_t *) tunnelGetState(f.node))->override_mode = kHeaderServerOverrideModeHeaderPort;
    f.on_init                                                         = initEst;
    f.on_est                                                          = inject;
    tunnelUpStreamInit(f.node, f.line);
    const uint8_t input[] = {0x01, 0xbb, 'A'};
    tunnelUpStreamPayload(f.node, f.line, estBytes(f.line, input, sizeof(input)));
    twfRequire(! lineIsAlive(f.line) && f.up_finish_count == 1 && f.down_finish_count == 1 && f.up_len == 0,
               "HeaderServer reentry overflow did not close both directions and discard initial bytes");
    twfRequireLineStateZeroed(f.line, f.node, "HeaderServer reentry overflow retained state");
    estFixtureDestroy(&f);
}

#if WW_HAVE_SPLICE
static sbuf_t *headerPipe(line_t *l, const void *data, uint32_t length, uint32_t prefix)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf  = bufferpoolGetSpliceBuffer(pool);
    twfRequire(buf != NULL && prefix <= length && prefix <= sbufGetLeftCapacity(buf), "header pipe geometry");
    const uint8_t *bytes = data;
    uint32_t       body  = length - prefix;
    twfRequire(write(sbufSpliceMetadata(buf).pipefd[1], bytes + prefix, body) == (ssize_t) body,
               "populate header pipe");
    buf->capacity = buf->l_pad + body;
    sbufSetLength(buf, body);
    sbufShiftLeft(buf, prefix);
    memoryCopy(sbufGetMutablePtr(buf), bytes, prefix);
    return buf;
}

static sbuf_t *expected_header_identity;
static void    headerCapture(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    est_fixture_t *f        = estContext(t);
    bool           upstream = t == f->next;
    size_t        *length   = upstream ? &f->up_len : &f->down_len;
    uint8_t       *bytes    = upstream ? f->up : f->down;
    uint32_t       count    = sbufGetLength(buf);
    twfRequire(count <= sizeof(f->up) - *length, "header splice capture capacity");
    if (expected_header_identity != NULL)
        twfRequire(buf == expected_header_identity && sbufIsSplice(buf), "established HeaderServer replaced splice");
    sbufReadRangeToMemory(buf, bytes + *length, count);
    *length += count;
    lineReuseBuffer(l, buf);
    if (upstream && f->on_up != NULL)
        f->on_up(f, l);
}

static void headerNestedInit(est_fixture_t *f, line_t *l)
{
    tunnelUpStreamPayload(f->node, l, headerPipe(l, "B", 1, 0));
}

static void headerNestedPayload(est_fixture_t *f, line_t *l)
{
    f->on_up = NULL;
    tunnelUpStreamPayload(f->node, l, headerPipe(l, "C", 1, 0));
}

static void headerConstantInit(est_fixture_t *f, line_t *l)
{
    headerRequireBypassed(f);
    twfRequire(lineGetDestinationAddressContext(l)->port == 443, "constant bypass lost routing metadata");
    initEst(f, l);
}

static void testHeaderSplice(void)
{
    est_fixture_t f;
    headerSetup(&f);
    ((headerserver_tstate_t *) tunnelGetState(f.node))->override_mode = kHeaderServerOverrideModeHeaderPort;
    f.next->fnPayloadU = f.prev->fnPayloadD = headerCapture;
    f.on_init                               = headerNestedInit;
    f.on_up                                 = headerNestedPayload;
    tunnelUpStreamInit(f.node, f.line);
    const uint8_t input[] = {0x01, 0xbb, 'A'};
    tunnelUpStreamPayload(f.node, f.line, headerPipe(f.line, input, 1, 0));
    twfRequire(f.init_count == 0, "split port header initialized next too early");
    tunnelUpStreamPayload(f.node, f.line, headerPipe(f.line, input + 1, 2, 1));
    twfRequire(f.init_count == 1 && f.up_len == 3 && memoryCompare(f.up, "ABC", 3) == 0,
               "HeaderServer splice header or reentry FIFO changed bytes");
    headerRequireBypassed(&f);
    expected_header_identity = headerPipe(f.line, "U", 1, 0);
    tunnelUpStreamPayload(f.node, f.line, expected_header_identity);
    expected_header_identity = headerPipe(f.line, "D", 1, 0);
    tunnelDownStreamPayload(f.node, f.line, expected_header_identity);
    expected_header_identity = NULL;
    twfRequire(f.up_len == 4 && f.up[3] == 'U' && f.down_len == 1 && f.down[0] == 'D',
               "HeaderServer changed established splice bytes");
    tunnelUpStreamFin(f.node, f.line);
    lineDestroy(f.line);
    estFixtureDestroy(&f);

    for (unsigned version = 1; version <= 2; ++version)
    {
        headerSetup(&f);
        ((headerserver_tstate_t *) tunnelGetState(f.node))->override_mode =
            kHeaderServerOverrideModeProxyProtocolSourceFields;
        tunnelUpStreamInit(f.node, f.line);
        uint8_t  proxy[400] = {0};
        uint32_t length;
        if (version == 1)
        {
            const char header[] = "PROXY TCP4 192.0.2.1 198.51.100.1 1234 443\r\n";
            length              = sizeof(header) - 1;
            memoryCopy(proxy, header, length);
        }
        else
        {
            const uint8_t header[] = {13, 10, 13,  10, 0, 13, 10,  'Q', 'U', 'I', 'T', 10,   0x21, 0x11,
                                      0,  12, 192, 0,  2, 1,  198, 51,  100, 1,   4,   0xd2, 1,    0xbb};
            length                 = sizeof(header);
            memoryCopy(proxy, header, length);
        }
        memorySet(proxy + length, 'X', 300);
        tunnelUpStreamPayload(f.node, f.line, headerPipe(f.line, proxy, 5, 2));
        tunnelUpStreamPayload(f.node, f.line, headerPipe(f.line, proxy + 5, length + 300 - 5, 0));
        twfRequire(f.init_count == 1 && f.up_len == 300 && f.up[0] == 'X' && f.up[299] == 'X',
                   "PROXY splice header consumed coalesced payload");
        headerRequireBypassed(&f);
        tunnelUpStreamFin(f.node, f.line);
        lineDestroy(f.line);
        estFixtureDestroy(&f);
    }

    headerSetup(&f);
    headerserver_tstate_t *ts = tunnelGetState(f.node);
    ts->override_mode         = kHeaderServerOverrideModeConstant;
    ts->constant_port         = 443;
    f.next->fnPayloadU = f.prev->fnPayloadD = headerCapture;
    f.on_init                               = headerConstantInit;
    tunnelUpStreamInit(f.node, f.line);
    headerRequireBypassed(&f);
    expected_header_identity = headerPipe(f.line, "K", 1, 0);
    tunnelUpStreamPayload(f.node, f.line, expected_header_identity);
    expected_header_identity = NULL;
    twfRequire(f.init_count == 1 && f.up_len == 1 && f.up[0] == 'K', "constant mode inspected splice input");
    tunnelUpStreamFin(f.node, f.line);
    lineDestroy(f.line);
    estFixtureDestroy(&f);

    headerSetup(&f);
    ((headerserver_tstate_t *) tunnelGetState(f.node))->override_mode = kHeaderServerOverrideModeHeaderPort;
    tunnelUpStreamInit(f.node, f.line);
    const uint8_t invalid[] = {0, 0, 'X'};
    tunnelUpStreamPayload(f.node, f.line, headerPipe(f.line, invalid, sizeof(invalid), 1));
    twfRequire(! lineIsAlive(f.line) && f.init_count == 0 && f.down_finish_count == 1,
               "invalid splice header did not close through its owner");
    estFixtureDestroy(&f);
}
#endif

static address_context_t protocol_source, protocol_destination;

static void headerRequireContext(const address_context_t *actual, const address_context_t *expected)
{
    twfRequire(ipAddrEqualsExact(&actual->ip_address, &expected->ip_address) && actual->port == expected->port &&
                   actual->domain == expected->domain && actual->domain_len == expected->domain_len &&
                   actual->domain_strategy == expected->domain_strategy && actual->type_ip == expected->type_ip &&
                   actual->domain_constant == expected->domain_constant &&
                   actual->domain_resolved == expected->domain_resolved && actual->proto_tcp == expected->proto_tcp &&
                   actual->proto_udp == expected->proto_udp && actual->proto_icmp == expected->proto_icmp &&
                   actual->proto_packet == expected->proto_packet &&
                   actual->optional_flags.detected_protocols == expected->optional_flags.detected_protocols,
               "protocol override changed unrelated address metadata");
}

static void headerProtocolContexts(line_t *l, uint8_t protocol)
{
    address_context_t *src  = lineGetSourceAddressContext(l);
    address_context_t *dest = lineGetDestinationAddressContext(l);
    twfRequire(addresscontextSetIpAddress(src, "2001:db8::1") && addresscontextSetIpAddress(dest, "198.51.100.2"),
               "protocol fixture endpoint setup");
    twfRequire(addresscontextSetObservedDomain(src, (const uint8_t *) "source.example", 14) &&
                   addresscontextSetObservedDomain(dest, (const uint8_t *) "destination.example", 19),
               "protocol fixture domain setup");
    src->port                               = 1234;
    dest->port                              = 443;
    src->domain_strategy                    = kDsOnlyIpV6;
    dest->domain_strategy                   = kDsPreferIpV4;
    src->optional_flags.detected_protocols  = kAddressContextProtocolTls;
    dest->optional_flags.detected_protocols = kAddressContextProtocolHttp1 | kAddressContextRouteFlagPinnedDestination;
    addresscontextSetOnlyProtocol(src, IP_PROTO_UDP);
    dest->proto_tcp = dest->proto_udp = dest->proto_icmp = dest->proto_packet = true;

    protocol_source      = *src;
    protocol_destination = *dest;
    addresscontextSetOnlyProtocol(&protocol_destination, protocol);
}

static void headerProtocolNextInit(est_fixture_t *f, line_t *l)
{
    headerRequireContext(lineGetSourceAddressContext(l), &protocol_source);
    headerRequireContext(lineGetDestinationAddressContext(l), &protocol_destination);
    initEst(f, l);
}

static sbuf_t *headerProtocolBytes(line_t *l, const void *data, uint32_t length, bool splice)
{
#if WW_HAVE_SPLICE
    if (splice)
        return headerPipe(l, data, length, 0);
#else
    discard splice;
#endif
    return estBytes(l, data, length);
}

static void testHeaderProtocol(void)
{
    const char   *settings[]  = {"{\"override\":\"dest_context->protocol\"}",
                                 "{\"override\":\"line->dest_ctx->protocol\"}"};
    const uint8_t protocols[] = {6, 17};
    for (unsigned splice = 0; splice <= WW_HAVE_SPLICE; ++splice)
    {
        for (unsigned mode = 0; mode < 2; ++mode)
        {
            /* Header alone, coalesced data with reentrant ABC, and close in Init. */
            for (unsigned scenario = 0; scenario < 3; ++scenario)
            {
                est_fixture_t f;
                headerSetup(&f);
                cJSON *json = cJSON_Parse(settings[mode]);
                twfRequire(headerserverLoadSettings(tunnelGetState(f.node), json), "protocol override settings");
                cJSON_Delete(json);
                headerProtocolContexts(f.line, protocols[mode]);
                f.on_init = headerProtocolNextInit;
                f.on_est  = scenario == 1 ? nestedInput : scenario == 2 ? closeFromEst : NULL;
                f.on_up   = scenario == 1 ? nestedAfterFirst : NULL;
#if WW_HAVE_SPLICE
                if (splice)
                    f.next->fnPayloadU = f.prev->fnPayloadD = headerCapture;
#endif
                tunnelUpStreamInit(f.node, f.line);
                twfRequire(f.init_count == 0, "protocol HeaderServer initialized next before its marker");
                tunnelUpStreamPayload(f.node, f.line, headerProtocolBytes(f.line, "", 0, splice));
                twfRequire(f.init_count == 0, "empty payload completed a protocol marker");
                const uint8_t input[] = {protocols[mode], 'A'};
                tunnelUpStreamPayload(
                    f.node, f.line, headerProtocolBytes(f.line, input, scenario == 0 ? 1 : 2, splice));
                twfRequire(f.init_count == 1 && f.est_count == (scenario == 2 ? 1U : 2U),
                           "protocol marker changed synchronous Init/Est delivery");
                if (scenario == 2)
                    twfRequire(! lineIsAlive(f.line) && f.up_len == 0 && f.up_finish_count == 1,
                               "protocol HeaderServer sent data after close during Init");
                else
                {
                    twfRequire(f.up_len == (scenario == 0 ? 0U : 3U) &&
                                   (scenario == 0 || memoryCompare(f.up, "ABC", 3) == 0),
                               "protocol marker leaked or nested input overtook initial data");
                    headerRequireBypassed(&f);
                    tunnelUpStreamPayload(f.node, f.line, headerProtocolBytes(f.line, "U", 1, splice));
                    tunnelDownStreamPayload(f.node, f.line, headerProtocolBytes(f.line, "D", 1, splice));
                    twfRequire(f.up[f.up_len - 1] == 'U' && f.down_len == 1 && f.down[0] == 'D',
                               "protocol bypass changed established payload");
                    tunnelUpStreamFin(f.node, f.line);
                    twfRequire(f.up_finish_count == 1 && f.down_finish_count == 0,
                               "protocol bypass changed Finish direction");
                    lineDestroy(f.line);
                }
                twfRequireLineStateZeroed(f.line, f.node, "protocol HeaderServer retained state after Finish");
                estFixtureDestroy(&f);
            }
        }

        const uint8_t invalid[] = {0, 1, 7, 16, 18, 255};
        for (unsigned i = 0; i < sizeof(invalid); ++i)
        {
            est_fixture_t f;
            headerSetup(&f);
            ((headerserver_tstate_t *) tunnelGetState(f.node))->override_mode = kHeaderServerOverrideModeHeaderProtocol;
            tunnelUpStreamInit(f.node, f.line);
            const uint8_t input[] = {invalid[i], 'X'};
            tunnelUpStreamPayload(f.node, f.line, headerProtocolBytes(f.line, input, sizeof(input), splice));
            twfRequire(! lineIsAlive(f.line) && f.init_count == 0 && f.up_finish_count == 0 &&
                           f.down_finish_count == 1 && f.up_len == 0,
                       "invalid protocol marker did not close only its initialized owner");
            twfRequireLineStateZeroed(f.line, f.node, "invalid protocol marker retained state");
            estFixtureDestroy(&f);
        }
    }

    for (unsigned downstream = 0; downstream < 2; ++downstream)
    {
        est_fixture_t f;
        headerSetup(&f);
        ((headerserver_tstate_t *) tunnelGetState(f.node))->override_mode = kHeaderServerOverrideModeHeaderProtocol;
        tunnelUpStreamInit(f.node, f.line);
        tunnelUpStreamPayload(f.node, f.line, estBytes(f.line, "", 0));
        if (downstream)
            tunnelDownStreamFin(f.node, f.line);
        else
        {
            tunnelUpStreamFin(f.node, f.line);
            lineDestroy(f.line);
        }
        twfRequire(f.init_count == 0 && f.up_finish_count == 0 && f.down_finish_count == downstream,
                   "pending protocol Finish crossed an uninitialized direction");
        twfRequireLineStateZeroed(f.line, f.node, "pending protocol Finish retained state");
        estFixtureDestroy(&f);
    }
}

int main(void)
{
    TEST_RUN_CASE(testHeaderProtocol);
    twfSetCase("reentry byte limit");
    testReentryLimit(overflowReentryBytes);
    twfSetCase("reentry entry limit");
    testReentryLimit(overflowReentryEntries);
    twfSetCase("initial Est with nested input");
    testInitialOrder(false);
    twfSetCase("owner closes during Est");
    testInitialOrder(true);
#if WW_HAVE_SPLICE
    TEST_RUN_CASE(testHeaderSplice);
#endif
    return 0;
}
