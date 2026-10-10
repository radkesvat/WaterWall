/* Real private-pipe framing, UDP boundaries, immediate initialization,
 * reentrant input/close and allocation refusal. Oracle reads are excluded from
 * the measured parser/encoder reads. No kernel UDP-send or throughput claims.
 * CTest: waterwall.udpovertcp{client,server}_{splice,no_splice}_unit
 */
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/protocols/splice_source.h"

#ifdef TEST_UOT_SERVER
#include "UdpOverTcpServer/interface.h"
#include "UdpOverTcpServer/structure.h"
#define nodeGet         nodeUdpOverTcpServerGet
#define nodeCreate      udpovertcpserverTunnelCreate
#define encode(t, l, b) udpovertcpserverTunnelDownStreamPayload(t, l, b)
#define decode(t, l, b) udpovertcpserverTunnelUpStreamPayload(t, l, b)
#else
#include "UdpOverTcpClient/interface.h"
#include "UdpOverTcpClient/structure.h"
#define nodeGet         nodeUdpOverTcpClientGet
#define nodeCreate      udpovertcpclientTunnelCreate
#define encode(t, l, b) udpovertcpclientTunnelUpStreamPayload(t, l, b)
#define decode(t, l, b) udpovertcpclientTunnelDownStreamPayload(t, l, b)
#endif

#include <unistd.h>

static twf_worker_env_t env;
static twf_line_pool_t  lines;
static node_t           metadata;
static tunnel_t        *node, *prev, *next;
static tunnel_chain_t   chain;
static line_t          *line;
static uint8_t          wire[256 * 1024], plain[256 * 1024];
static size_t           wire_length, plain_length, measured_reads;
static uint32_t         datagrams[256];
static unsigned         wire_calls, plain_calls, inits, finishes, pauses, resumes;
static bool             measuring, require_splice, close_output, inject_encode, inject_decode;
static bool             pause_output, startup_payload, startup_pause, close_init, fail_stream, fail_queue;
static unsigned         decode_overflow;
static sbuf_t          *expected_identity;

ssize_t __real_read(int fd, void *destination, size_t bytes);
ssize_t __wrap_read(int fd, void *destination, size_t bytes);
ssize_t __wrap_read(int fd, void *destination, size_t bytes)
{
    ssize_t result = __real_read(fd, destination, bytes);
    if (measuring && result > 0)
        measured_reads += (size_t) result;
    return result;
}

splice_stream_t *__real_splicestreamCreate(buffer_pool_t *pool, uint32_t header_size);
splice_stream_t *__wrap_splicestreamCreate(buffer_pool_t *pool, uint32_t header_size);
splice_stream_t *__wrap_splicestreamCreate(buffer_pool_t *pool, uint32_t header_size)
{
    return fail_stream ? NULL : __real_splicestreamCreate(pool, header_size);
}

bool __real_bufferqueueReserveExtra(buffer_queue_t *queue, size_t extra);
bool __wrap_bufferqueueReserveExtra(buffer_queue_t *queue, size_t extra);
bool __wrap_bufferqueueReserveExtra(buffer_queue_t *queue, size_t extra)
{
    return ! fail_queue && __real_bufferqueueReserveExtra(queue, extra);
}

static sbuf_t *ordinary(const void *data, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetBestFit(env.pool, length, 128);
    sbufSetLength(buf, length);
    if (length != 0)
        memoryCopy(sbufGetMutablePtr(buf), data, length);
    return buf;
}

#if WW_HAVE_SPLICE
static sbuf_t *pipeBytes(const void *data, uint32_t length, uint32_t prefix)
{
    sbuf_t *buf;
    if (prefix <= 128)
        buf = bufferpoolGetSpliceBuffer(env.pool);
    else
    {
        buf = twfTrackAcquired(sbufCreateSplice((uint16_t) (prefix + 128)));
        twfRequire(testSpliceSourceInitPipe(buf) == 0, "create resident-prefix pipe");
        buf->flags |= kSbufFlagSplice;
    }
    twfRequire(buf != NULL && prefix <= length, "create splice input");
    const uint32_t body = length - prefix;
    twfRequire(write(sbufSpliceMetadata(buf).pipefd[1], (const uint8_t *) data + prefix, body) == (ssize_t) body,
               "populate exclusive pipe");
    buf->capacity = buf->l_pad + body;
    sbufSetLength(buf, body);
    sbufShiftLeft(buf, prefix);
    memoryCopy(sbufGetMutablePtr(buf), data, prefix);
    return buf;
}
#endif

static sbuf_t *input(const void *data, uint32_t length, bool splice, uint32_t prefix)
{
#if WW_HAVE_SPLICE
    if (splice)
        return pipeBytes(data, length, prefix);
#else
    discard splice;
    discard prefix;
#endif
    return ordinary(data, length);
}

static void finish(tunnel_t *t, line_t *l)
{
    ++finishes;
    if (t == prev)
        lineDestroy(l);
}

static void closeFrom(tunnel_t *t, line_t *l)
{
    if (t == prev)
    {
        node->fnFinU(node, l);
        lineDestroy(l);
    }
    else
        node->fnFinD(node, l);
}

static void recordPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++pauses;
}

static void resume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++resumes;
}

static void est(tunnel_t *t, line_t *l)
{
    discard t;
    if (startup_payload)
        encode(node, l, ordinary("early", 5));
}

static void init(tunnel_t *t, line_t *l)
{
    ++inits;
#ifdef TEST_UOT_SERVER
    const address_context_t *destination = lineGetDestinationAddressContext(l);
    twfRequire(destination->proto_udp && ! destination->proto_tcp && ! destination->proto_icmp &&
                   ! destination->proto_packet,
               "backend Init did not receive UDP destination protocol");
#endif
    if (close_init)
    {
        closeFrom(t, l);
        return;
    }
    if (startup_pause)
        node->fnPauseD(node, l);
    node->fnEstD(node, l);
}

static void captureWire(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    const uint32_t length = sbufGetLength(buf);
    ++wire_calls;
    if (expected_identity != NULL)
        twfRequire(buf == expected_identity, "encoder replaced a complete opaque datagram");
    if (require_splice)
        twfRequire(sbufIsSplice(buf), "encoder materialized a feasible body");
    twfRequire(length <= sizeof(wire) - wire_length, "encoded capture overflow");
    const bool saved = measuring;
    measuring        = false;
    sbufReadRangeToMemory(buf, wire + wire_length, length);
    measuring = saved;
    wire_length += length;
    lineReuseBuffer(l, buf);
    if (pause_output)
    {
#ifdef TEST_UOT_SERVER
        node->fnPauseU(node, l);
#else
        node->fnPauseD(node, l);
#endif
    }
    if (inject_encode)
    {
        inject_encode = false;
        encode(node, l, ordinary("nested", 6));
    }
    if (close_output)
        closeFrom(t, l);
}

static void capturePlain(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if (require_splice)
        twfRequire(sbufIsSplice(buf), "decoder materialized a feasible body");
    const uint32_t length = sbufGetLength(buf);
    twfRequire(length <= sizeof(plain) - plain_length && plain_calls < 256, "decoded capture overflow");
    datagrams[plain_calls++] = length;
    const bool saved         = measuring;
    measuring                = false;
    sbufReadRangeToMemory(buf, plain + plain_length, length);
    measuring = saved;
    plain_length += length;
    lineReuseBuffer(l, buf);
    if (pause_output)
    {
#ifdef TEST_UOT_SERVER
        node->fnPauseD(node, l);
#else
        node->fnPauseU(node, l);
#endif
    }
    if (inject_decode)
    {
        inject_decode          = false;
        const uint8_t nested[] = {0, 1, 'N'};
        decode(node, l, ordinary(nested, sizeof(nested)));
    }
    if (decode_overflow != 0)
    {
        decode_overflow = 0;
        sbuf_t *nested  = bufferpoolGetBestFit(env.pool, 2U * 1024U * 1024U + 1, 128);
        sbufSetLength(nested, 2U * 1024U * 1024U + 1);
        decode(node, l, nested);
    }
    if (close_output)
        closeFrom(t, l);
}

static void setup(uint8_t source_protocol)
{
    wire_length = plain_length = measured_reads = 0;
    wire_calls = plain_calls = inits = finishes = pauses = resumes = 0;
    measuring = require_splice = close_output = inject_encode = inject_decode = pause_output = false;
    expected_identity                                                                        = NULL;
    twfWorkerEnvSetupWithBufferSizes(&env, 8192, 1024, 128, 65536, 65536);
    decode_overflow = 0;
    metadata        = nodeGet();
    twfRequire(metadata.flags == kNodeFlagSupportsSplice && metadata.required_padding_left == 2,
               "incorrect UdpOverTcp capability or padding");
    node = nodeCreate(&metadata);
    prev = tunnelCreate(NULL, 0, 0);
    next = tunnelCreate(NULL, 0, 0);
    twfRequire(node != NULL && prev != NULL && next != NULL, "construct UdpOverTcp fixture");
    tunnelBind(prev, node);
    tunnelBind(node, next);
    memoryZero(&chain, sizeof(chain));
    chain.supports_splice = WW_HAVE_SPLICE;
    node->chain           = &chain;
    prev->fnFinD = next->fnFinU = finish;
    next->fnInitU               = init;
    prev->fnEstD                = est;
    prev->fnPauseD = next->fnPauseU = recordPause;
    prev->fnResumeD = next->fnResumeU = resume;
#ifdef TEST_UOT_SERVER
    prev->fnPayloadD = captureWire;
    next->fnPayloadU = capturePlain;
#else
    prev->fnPayloadD = capturePlain;
    next->fnPayloadU = captureWire;
#endif
    twfLinePoolSetup(&lines, node->lstate_size, 4);
    line = twfLinePoolCreateLine(&lines);
    lineRef(line);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(line), source_protocol);
    node->fnInitU(node, line);
}

static void checkInitialized(void)
{
    twfRequire(inits == 1, "next Init was deferred until payload arrival");
    twfRequire(wire_calls == 0 && wire_length == 0, "Init emitted protocol bytes");
    twfRequire(! linePrefersOrdinaryReadUpstream(line) && ! linePrefersOrdinaryReadDownstream(line),
               "UdpOverTcp disabled carrier splice");
}

static void teardown(void)
{
    fail_stream = fail_queue = false;
    startup_payload = startup_pause = close_init = false;
    if (lineIsAlive(line))
    {
        node->fnFinU(node, line);
        lineDestroy(line);
    }
    twfRequireLineStateZeroed(line, node, "UdpOverTcp retained line state");
    twfRequireEqualU32(twfLineRefCount(line), 1, "UdpOverTcp leaked a line reference");
    lineUnref(line);
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&lines);
    tunnelDestroy(node);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    memoryFree(metadata.type);
    twfWorkerEnvTeardown(&env);
}

static void expectEncoded(const uint8_t *expected, uint32_t length)
{
    uint32_t position = 0, consumed = 0;
    while (position < wire_length)
    {
        twfRequire(wire_length - position >= 2, "incomplete encoded header");
        const uint32_t bytes = ((uint32_t) wire[position] << 8) | wire[position + 1];
        position += 2;
        twfRequire(bytes > 0 && bytes <= 65505 && bytes <= wire_length - position && bytes <= length - consumed,
                   "invalid encoded length");
        twfRequire(memcmp(wire + position, expected + consumed, bytes) == 0, "encoder changed byte order");
        consumed += bytes;
        position += bytes;
    }
    twfRequire(consumed == length, "encoder lost payload bytes");
}

static void testOpaqueEncode(uint8_t source_protocol, bool splice, uint32_t prefix)
{
    twfSetCase("opaque datagram encoder ignores source metadata and preserves body and prefix");
    setup(source_protocol);
    checkInitialized();
    const uint8_t data[] = "one intact payload";
    sbuf_t       *buf    = input(data, sizeof(data), splice, prefix);
    expected_identity    = buf;
    require_splice       = splice && WW_HAVE_SPLICE;
    measuring            = true;
    encode(node, line, buf);
    twfRequire(measured_reads == 0 && wire_calls == 1, "opaque encoder consumed body or split datagram");
    expectEncoded(data, sizeof(data));
    teardown();
}

static void testDecode(uint8_t source_protocol, bool splice, uint32_t prefix, bool fragmented)
{
    twfSetCase("mixed framed input retains datagram boundaries across fragmented headers");
    setup(source_protocol);
    checkInitialized();
    const uint8_t data[] = {0, 3, 'a', 'b', 'c', 0, 4, 'd', 'e', 'f', 'g'};
    require_splice       = splice && WW_HAVE_SPLICE;
    measuring            = true;
    if (fragmented)
    {
        decode(node, line, ordinary(data, 1));
        decode(node, line, input(data + 1, 4, splice, 0));
        decode(node, line, input(data + 5, sizeof(data) - 5, splice, 0));
    }
    else
        decode(node, line, input(data, sizeof(data), splice, prefix));
    twfRequire(plain_calls == 2 && datagrams[0] == 3 && datagrams[1] == 4 && plain_length == 7 &&
                   memcmp(plain, "abcdefg", 7) == 0,
               "decoder combined, split or changed datagrams");
    const size_t expected_reads = splice && WW_HAVE_SPLICE ? (fragmented ? 3 : 4 - prefix) : 0;
    twfRequire(measured_reads == expected_reads, "decoder read more than framing headers");
    teardown();
}

static void testReentrantDecode(void)
{
    twfSetCase("coalesced input completes after Pause and precedes nested input");
    setup(IP_PROTO_UDP);
    checkInitialized();
    const uint8_t data[] = {0, 1, 'A', 0, 1, 'B'};
    inject_decode = pause_output = true;
    decode(node, line, ordinary(data, sizeof(data)));
    twfRequire(plain_calls == 3 && plain_length == 3 && memcmp(plain, "ABN", 3) == 0 && pauses == 3,
               "Pause stopped admitted frames or nested input overtook their suffix");
    teardown();
}

static void testLargeDecode(void)
{
    twfSetCase("drain complete coalesced frames before checking incomplete storage");
    setup(IP_PROTO_UDP);
    checkInitialized();
    uint8_t data[3 * (60000 + 2)];
    for (unsigned i = 0; i < 3; ++i)
    {
        data[i * 60002]     = 60000 >> 8;
        data[i * 60002 + 1] = 60000 & 255;
        memset(data + i * 60002 + 2, (int) ('A' + i), 60000);
    }
    decode(node, line, ordinary(data, sizeof(data)));
    twfRequire(lineIsAlive(line) && plain_calls == 3 && plain_length == 180000, "valid coalesced input was rejected");
    for (unsigned i = 0; i < 3; ++i)
        twfRequire(datagrams[i] == 60000 && plain[i * 60000] == 'A' + i && plain[(i + 1) * 60000 - 1] == 'A' + i,
                   "large coalesced datagram boundary changed");
    teardown();
}

static void testMalformed(void)
{
    twfSetCase("zero data length closes both initialized sides");
    setup(IP_PROTO_UDP);
    checkInitialized();
    const uint8_t data[] = {0, 0};
    decode(node, line, ordinary(data, sizeof(data)));
    twfRequire(! lineIsAlive(line) && finishes == 2 && plain_calls == 0, "malformed stream was silently discarded");
    teardown();
    twfSetCase("a zero-length prefix is rejected without protocol negotiation");
    setup(IP_PROTO_TCP);
    checkInitialized();
    const uint8_t invalid[] = {0, 0, IP_PROTO_TCP};
    decode(node, line, input(invalid, sizeof(invalid), WW_HAVE_SPLICE, 0));
    twfRequire(! lineIsAlive(line) && finishes == 2 && inits == 1 && plain_calls == 0,
               "zero-length prefix changed protocol or retained carrier");
    teardown();
}

static void testAdmission(void)
{
    twfSetCase("decoder reentry byte overflow closes without delivering newer bytes");
    setup(IP_PROTO_TCP);
    checkInitialized();
    decode_overflow      = 1;
    const uint8_t data[] = {0, 1, 'A', 0, 1, 'B'};
    decode(node, line, ordinary(data, sizeof(data)));
    twfRequire(! lineIsAlive(line) && finishes == 2 && plain_calls == 1, "unbounded decoder reentry survived");
    teardown();
    twfSetCase("compact oversized retained allocation while waiting for a full 16-bit frame");
    setup(IP_PROTO_UDP);
    checkInitialized();
    sbuf_t       *oversized = bufferpoolGetBestFit(env.pool, 4U * 1024U * 1024U + 1, 128);
    const uint8_t partial[] = {255, 255, 'A'};
    memoryCopy(sbufGetMutablePtr(oversized), partial, sizeof(partial));
    sbufSetLength(oversized, sizeof(partial));
    decode(node, line, oversized);
    twfRequire(lineIsAlive(line) && plain_calls == 0, "beneficial compaction rejected partial frame");
    uint8_t suffix[65534];
    memset(suffix, 'B', sizeof(suffix));
    decode(node, line, ordinary(suffix, sizeof(suffix)));
    twfRequire(plain_calls == 1 && datagrams[0] == 65535 && plain[0] == 'A' && plain[65534] == 'B',
               "compaction or 16-bit receive boundary changed body");
    teardown();
}

static void testFailures(void)
{
    twfSetCase("stream allocation refusal closes only the owner before backend Init");
    fail_stream = true;
    setup(IP_PROTO_UDP);
    twfRequire(! lineIsAlive(line) && finishes == 1 && inits == 0, "stream refusal leaked live carrier");
    teardown();
    twfSetCase("receive queue refusal settles transferred input and both initialized sides");
    setup(IP_PROTO_UDP);
    checkInitialized();
    fail_queue           = true;
    const uint8_t data[] = {0, 1, 'A'};
    decode(node, line, ordinary(data, sizeof(data)));
    twfRequire(! lineIsAlive(line) && finishes == 2, "stream admission refusal did not close carrier");
    teardown();
    twfSetCase("reentrant Init close does not resume parsing or emit payload");
    close_init = true;
    setup(IP_PROTO_TCP);
    twfRequire(! lineIsAlive(line) && wire_calls == 0, "closed Init emitted payload");
    teardown();
    for (unsigned encoder = 0; encoder < 2; ++encoder)
    {
        twfSetCase("reentrant Finish stops dispatch and releases retained private bodies");
        setup(IP_PROTO_UDP);
        checkInitialized();
        close_output = true;
        if (encoder)
            encode(node, line, input("payload", 7, WW_HAVE_SPLICE, 0));
        else
        {
            const uint8_t framed[] = {0, 1, 'A', 0, 1, 'B'};
            decode(node, line, input(framed, sizeof(framed), WW_HAVE_SPLICE, 0));
        }
        twfRequire(! lineIsAlive(line) && wire_calls + plain_calls == 1, "closed output continued dispatch");
        teardown();
    }
}

static void testStartup(void)
{
    twfSetCase("Init Est reentry frames early datagrams without control output");
    startup_payload = true;
    setup(IP_PROTO_TCP);
    twfRequire(inits == 1 && wire_calls == 1 && wire_length == 7 && wire[0] == 0 && wire[1] == 5 &&
                   memcmp(wire + 2, "early", 5) == 0,
               "startup lost or prefixed early datagram with control bytes");
    teardown();
    twfSetCase("Pause and Resume relay immediately after Init without control output");
    startup_pause = true;
    setup(IP_PROTO_TCP);
    checkInitialized();
    twfRequire(pauses == 1, "Init-time Pause did not reach previous node");
    node->fnResumeD(node, line);
    node->fnPauseU(node, line);
    node->fnResumeU(node, line);
    twfRequire(pauses == 2 && resumes == 2 && wire_calls == 0, "Pause/Resume lost forwarding or emitted bytes");
    teardown();
    twfSetCase("encoder reentry follows the complete older datagram");
    setup(IP_PROTO_UDP);
    checkInitialized();
    inject_encode = true;
    encode(node, line, input("A", 1, WW_HAVE_SPLICE, 0));
    twfRequire(wire_calls == 2, "encoder lost reentrant datagram");
    expectEncoded((const uint8_t *) "Anested", 7);
    teardown();
}

#if WW_HAVE_SPLICE
static void testOversizedPipe(void)
{
    twfSetCase("oversized private-pipe datagram is dropped intact and recycled");
    setup(IP_PROTO_TCP);
    checkInitialized();
    uint8_t data[65376 + 4096];
    memset(data, 'A', sizeof(data));
    sbuf_t *buf = pipeBytes(data, sizeof(data), 65376);
    encode(node, line, buf);
    twfRequire(lineIsAlive(line) && wire_calls == 0, "oversized datagram was split or closed the line");
    teardown();
}

static void testDecodeFallback(void)
{
    twfSetCase("pipe inventory exhaustion materializes complete frame with correct boundaries");
    setup(IP_PROTO_UDP);
    checkInitialized();
    const uint8_t                data[] = {0, 3, 'a', 'b', 'c', 0, 1, 'd'};
    sbuf_t                      *buf    = pipeBytes(data, sizeof(data), 0);
    test_splice_inventory_hold_t held   = testSpliceInventoryHoldAvailable(getCurrentEventWorkerBufferPool());
    decode(node, line, buf);
    testSpliceInventoryReleaseHeld(&held);
    twfRequire(plain_calls == 2 && datagrams[0] == 3 && datagrams[1] == 1 && plain_length == 4 &&
                   memcmp(plain, "abcd", 4) == 0,
               "fallback changed datagram boundaries or bytes");
    teardown();
}
#endif

int main(void)
{
    const uint8_t source_protocols[] = {IP_PROTO_UDP, IP_PROTO_TCP, 0};
    for (unsigned i = 0; i < sizeof(source_protocols); ++i)
    {
        testOpaqueEncode(source_protocols[i], false, 0);
        testOpaqueEncode(source_protocols[i], WW_HAVE_SPLICE, 3);
        testDecode(source_protocols[i], false, 0, false);
        testDecode(source_protocols[i], WW_HAVE_SPLICE, 0, false);
        testDecode(source_protocols[i], WW_HAVE_SPLICE, 2, false);
        testDecode(source_protocols[i], WW_HAVE_SPLICE, 0, true);
    }
    testReentrantDecode();
    testLargeDecode();
    testMalformed();
    testAdmission();
    testFailures();
    testStartup();
#if WW_HAVE_SPLICE
    testOversizedPipe();
    testDecodeFallback();
#endif
    return 0;
}
