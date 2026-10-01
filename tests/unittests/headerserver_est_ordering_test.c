#include "HeaderServer/structure.h"
#include "protocol_est_ordering_fixture.h"

static void initEst(est_fixture_t *f, line_t *l)
{
    headerserverTunnelDownStreamEst(f->node, l);
    if (lineIsAlive(l))
        headerserverTunnelDownStreamEst(f->node, l);
}

static void nestedInput(est_fixture_t *f, line_t *l)
{
    headerserverTunnelUpStreamPayload(f->node, l, estBytes(l, "B", 1));
    headerserverTunnelDownStreamPause(f->node, l);
}

static void nestedAfterFirst(est_fixture_t *f, line_t *l)
{
    f->on_up = NULL;
    headerserverTunnelUpStreamPayload(f->node, l, estBytes(l, "C", 1));
}

static void closeFromEst(est_fixture_t *f, line_t *l)
{
    headerserverTunnelUpStreamFinish(f->node, l);
    lineDestroy(l);
}

static void testInitialOrder(bool close)
{
    est_fixture_t f;
    estFixtureSetup(&f, sizeof(headerserver_tstate_t), sizeof(headerserver_lstate_t));
    ((headerserver_tstate_t *) tunnelGetState(f.node))->override_mode = kHeaderServerOverrideModeHeaderPort;
    f.on_init                                                         = initEst;
    f.on_est                                                          = close ? closeFromEst : nestedInput;
    f.on_up                                                           = nestedAfterFirst;
    headerserverTunnelUpStreamInit(f.node, f.line);
    const uint8_t input[] = {0x01, 0xbb, 'A'};
    headerserverTunnelUpStreamPayload(f.node, f.line, estBytes(f.line, input, sizeof(input)));
    twfRequire(f.init_count == 1 && f.est_count == 1, "HeaderServer lost or duplicated synchronous Est");
    if (close)
        twfRequire(f.up_len == 0 && f.up_finish_count == 1, "HeaderServer sent initial data after Est close");
    else
    {
        twfRequire(f.up_len == 3 && memoryCompare(f.up, "ABC", 3) == 0,
                   "HeaderServer nested Est input overtook original payload");
        headerserverTunnelUpStreamFinish(f.node, f.line);
        lineDestroy(f.line);
    }
    twfRequireLineStateZeroed(f.line, f.node, "HeaderServer retained state after Finish");
    estFixtureDestroy(&f);
}

static void overflowReentryBytes(est_fixture_t *f, line_t *l)
{
    sbuf_t *large = bufferpoolGetBestFit(lineGetBufferPool(l), kHeaderServerMaxReentryBytes, 16);
    sbufSetLength(large, kHeaderServerMaxReentryBytes);
    headerserverTunnelUpStreamPayload(f->node, l, large);
    headerserver_lstate_t *ls = lineGetState(l, f->node);
    twfRequire(bufferqueueGetBufLen(&ls->initial_reentry) == kHeaderServerMaxReentryBytes,
               "HeaderServer rejected exact transient reentry byte limit");
    headerserverTunnelUpStreamPayload(f->node, l, estBytes(l, "X", 1));
}

static void overflowReentryEntries(est_fixture_t *f, line_t *l)
{
    for (unsigned i = 0; i < kHeaderServerMaxReentryBuffers; ++i)
        headerserverTunnelUpStreamPayload(f->node, l, estBytes(l, "", 0));
    headerserver_lstate_t *ls = lineGetState(l, f->node);
    twfRequire(bufferqueueGetBufCount(&ls->initial_reentry) == kHeaderServerMaxReentryBuffers,
               "HeaderServer rejected exact transient reentry entry limit");
    headerserverTunnelUpStreamPayload(f->node, l, estBytes(l, "", 0));
}

static void testReentryLimit(est_inject_fn inject)
{
    est_fixture_t f;
    estFixtureSetup(&f, sizeof(headerserver_tstate_t), sizeof(headerserver_lstate_t));
    ((headerserver_tstate_t *) tunnelGetState(f.node))->override_mode = kHeaderServerOverrideModeHeaderPort;
    f.on_init                                                         = initEst;
    f.on_est                                                          = inject;
    headerserverTunnelUpStreamInit(f.node, f.line);
    const uint8_t input[] = {0x01, 0xbb, 'A'};
    headerserverTunnelUpStreamPayload(f.node, f.line, estBytes(f.line, input, sizeof(input)));
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
    headerserverTunnelUpStreamPayload(f->node, l, headerPipe(l, "B", 1, 0));
}

static void headerNestedPayload(est_fixture_t *f, line_t *l)
{
    f->on_up = NULL;
    headerserverTunnelUpStreamPayload(f->node, l, headerPipe(l, "C", 1, 0));
}

static void testHeaderSplice(void)
{
    est_fixture_t f;
    estFixtureSetup(&f, sizeof(headerserver_tstate_t), sizeof(headerserver_lstate_t));
    ((headerserver_tstate_t *) tunnelGetState(f.node))->override_mode = kHeaderServerOverrideModeHeaderPort;
    f.next->fnPayloadU = f.prev->fnPayloadD = headerCapture;
    f.on_init                               = headerNestedInit;
    f.on_up                                 = headerNestedPayload;
    headerserverTunnelUpStreamInit(f.node, f.line);
    const uint8_t input[] = {0x01, 0xbb, 'A'};
    headerserverTunnelUpStreamPayload(f.node, f.line, headerPipe(f.line, input, 1, 0));
    twfRequire(f.init_count == 0, "split port header initialized next too early");
    headerserverTunnelUpStreamPayload(f.node, f.line, headerPipe(f.line, input + 1, 2, 1));
    twfRequire(f.init_count == 1 && f.up_len == 3 && memoryCompare(f.up, "ABC", 3) == 0,
               "HeaderServer splice header or reentry FIFO changed bytes");
    expected_header_identity = headerPipe(f.line, "U", 1, 0);
    headerserverTunnelUpStreamPayload(f.node, f.line, expected_header_identity);
    expected_header_identity = headerPipe(f.line, "D", 1, 0);
    headerserverTunnelDownStreamPayload(f.node, f.line, expected_header_identity);
    expected_header_identity = NULL;
    twfRequire(f.up_len == 4 && f.up[3] == 'U' && f.down_len == 1 && f.down[0] == 'D',
               "HeaderServer changed established splice bytes");
    headerserverTunnelUpStreamFinish(f.node, f.line);
    lineDestroy(f.line);
    estFixtureDestroy(&f);

    for (unsigned version = 1; version <= 2; ++version)
    {
        estFixtureSetup(&f, sizeof(headerserver_tstate_t), sizeof(headerserver_lstate_t));
        ((headerserver_tstate_t *) tunnelGetState(f.node))->override_mode =
            kHeaderServerOverrideModeProxyProtocolSourceFields;
        headerserverTunnelUpStreamInit(f.node, f.line);
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
        headerserverTunnelUpStreamPayload(f.node, f.line, headerPipe(f.line, proxy, 5, 2));
        headerserverTunnelUpStreamPayload(f.node, f.line, headerPipe(f.line, proxy + 5, length + 300 - 5, 0));
        twfRequire(f.init_count == 1 && f.up_len == 300 && f.up[0] == 'X' && f.up[299] == 'X',
                   "PROXY splice header consumed coalesced payload");
        headerserverTunnelUpStreamFinish(f.node, f.line);
        lineDestroy(f.line);
        estFixtureDestroy(&f);
    }

    estFixtureSetup(&f, sizeof(headerserver_tstate_t), sizeof(headerserver_lstate_t));
    headerserver_tstate_t *ts = tunnelGetState(f.node);
    ts->override_mode         = kHeaderServerOverrideModeConstant;
    ts->constant_port         = 443;
    f.next->fnPayloadU = f.prev->fnPayloadD = headerCapture;
    headerserverTunnelUpStreamInit(f.node, f.line);
    expected_header_identity = headerPipe(f.line, "K", 1, 0);
    headerserverTunnelUpStreamPayload(f.node, f.line, expected_header_identity);
    expected_header_identity = NULL;
    twfRequire(f.init_count == 1 && f.up_len == 1 && f.up[0] == 'K', "constant mode inspected splice input");
    headerserverTunnelUpStreamFinish(f.node, f.line);
    lineDestroy(f.line);
    estFixtureDestroy(&f);

    estFixtureSetup(&f, sizeof(headerserver_tstate_t), sizeof(headerserver_lstate_t));
    ((headerserver_tstate_t *) tunnelGetState(f.node))->override_mode = kHeaderServerOverrideModeHeaderPort;
    headerserverTunnelUpStreamInit(f.node, f.line);
    const uint8_t invalid[] = {0, 0, 'X'};
    headerserverTunnelUpStreamPayload(f.node, f.line, headerPipe(f.line, invalid, sizeof(invalid), 1));
    twfRequire(! lineIsAlive(f.line) && f.init_count == 0 && f.down_finish_count == 1,
               "invalid splice header did not close through its owner");
    estFixtureDestroy(&f);
}
#endif

int main(void)
{
    testReentryLimit(overflowReentryBytes);
    testReentryLimit(overflowReentryEntries);
    testInitialOrder(false);
    testInitialOrder(true);
#if WW_HAVE_SPLICE
    testHeaderSplice();
#endif
    return 0;
}
