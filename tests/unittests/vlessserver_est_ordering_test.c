#include "VlessServer/structure.h"
#include "protocol_est_ordering_fixture.h"

static line_t *backendLine(est_fixture_t *f)
{
    vlessserver_lstate_t *ls = lineGetState(f->line, f->node);
    return ls->udp_remote_line != NULL ? ls->udp_remote_line : f->line;
}

static void applicationInput(est_fixture_t *f, char byte)
{
    vlessserver_lstate_t *ls       = lineGetState(f->line, f->node);
    uint8_t               framed[] = {0, 1, (uint8_t) byte};
    bool udp = ls->phase == kVlessServerPhaseUdpWaitPacket || ls->phase == kVlessServerPhaseUdpConnecting ||
               ls->phase == kVlessServerPhaseUdpEstablished;
    vlessserverTunnelUpStreamPayload(f->node, f->line, estBytes(f->line, udp ? framed : framed + 2, udp ? 3 : 1));
}

static void nestedFromEst(est_fixture_t *f, line_t *l)
{
    vlessserverTunnelDownStreamEst(f->node, backendLine(f));
    vlessserverTunnelDownStreamPayload(f->node, backendLine(f), estBytes(l, "Y", 1));
    vlessserverTunnelUpStreamPause(f->node, l);
    applicationInput(f, 'B');
}

static void nestedFromInput(est_fixture_t *f, line_t *l)
{
    f->on_up = NULL;
    applicationInput(f, 'C');
    vlessserverTunnelDownStreamPayload(f->node, l, estBytes(l, "Z", 1));
}

static void initReplyThenEst(est_fixture_t *f, line_t *l)
{
    vlessserverTunnelDownStreamPayload(f->node, l, estBytes(l, "X", 1));
    twfRequire(f->est_count == 0, "VlessServer synthesized Est from pre-Est reply");
    vlessserverTunnelDownStreamEst(f->node, l);
    if (lineIsAlive(l))
        vlessserverTunnelDownStreamEst(f->node, l);
}

static void initEst(est_fixture_t *f, line_t *l)
{
    vlessserverTunnelDownStreamEst(f->node, l);
}

static void setupVless(est_fixture_t *f, vlessserver_user_t *user)
{
    estFixtureSetup(f, sizeof(vlessserver_tstate_t), sizeof(vlessserver_lstate_t));
    vlessserver_tstate_t *ts = tunnelGetState(f->node);
    memoryZero(user, sizeof(*user));
    memorySet(user->uuid, 0x42, sizeof(user->uuid));
    ts->users         = user;
    ts->user_count    = 1;
    ts->allow_connect = true;
    ts->allow_udp     = true;
    vlessserverTunnelUpStreamInit(f->node, f->line);
}

static void sendRequest(est_fixture_t *f, const vlessserver_user_t *user, bool udp)
{
    uint8_t request[29] = {0};
    memoryCopy(request + 1, user->uuid, sizeof(user->uuid));
    request[18] = udp ? 2 : 1;
    request[19] = 0x01;
    request[20] = 0xbb;
    request[21] = 1;
    request[22] = 127;
    request[25] = 1;
    request[26] = udp ? 0 : 'A';
    request[27] = 1;
    request[28] = 'A';
    vlessserverTunnelUpStreamPayload(f->node, f->line, estBytes(f->line, request, udp ? 29 : 27));
}

static void closeFixture(est_fixture_t *f)
{
    vlessserverTunnelUpStreamFinish(f->node, f->line);
    lineDestroy(f->line);
    twfRequireLineStateZeroed(f->line, f->node, "VlessServer state survives owner Finish");
    estFixtureDestroy(f);
}

static void testEarlyReplyAndEstOrdering(bool udp, bool early_reply)
{
    est_fixture_t      f;
    vlessserver_user_t user;
    setupVless(&f, &user);
    f.on_init = early_reply ? initReplyThenEst : initEst;
    f.on_est  = nestedFromEst;
    f.on_up   = nestedFromInput;
    sendRequest(&f, &user, udp);
    twfRequire(f.est_count == 1 && f.init_count == 1, "VlessServer lost or duplicated transport Est");
    twfRequire(f.up_len == 3 && memoryCompare(f.up, "ABC", 3) == 0,
               "VlessServer nested Init/Est input overtook original input");
    size_t first_reply = udp ? 5 : 3;
    twfRequire(f.down_len == (early_reply ? first_reply : 0),
               "VlessServer independently drained response backlog through Pause");
    vlessserverTunnelUpStreamResume(f.node, f.line);
    const uint8_t  tcp_expected[] = {0, 0, 'X', 'Y', 'Z'};
    const uint8_t  udp_expected[] = {0, 0, 0, 1, 'X', 0, 1, 'Y', 0, 1, 'Z'};
    const uint8_t *expected       = udp ? udp_expected : tcp_expected;
    size_t         length         = udp ? sizeof(udp_expected) : sizeof(tcp_expected);
    uint8_t        without_early[sizeof(udp_expected)];
    if (! early_reply)
    {
        without_early[0] = 0;
        without_early[1] = 0;
        memoryCopy(without_early + 2, expected + first_reply, length - first_reply);
        length -= first_reply - 2;
        expected = without_early;
    }
    twfRequire(f.down_len == length && memoryCompare(f.down, expected, length) == 0,
               "VlessServer response header/reply FIFO changed under reentrant Est");
    closeFixture(&f);
}

static void closeFromEst(est_fixture_t *f, line_t *l)
{
    vlessserverTunnelUpStreamFinish(f->node, l);
    lineDestroy(l);
}

static void testCloseDuringEst(void)
{
    est_fixture_t      f;
    vlessserver_user_t user;
    setupVless(&f, &user);
    f.on_init = initEst;
    f.on_est  = closeFromEst;
    sendRequest(&f, &user, false);
    twfRequire(! lineIsAlive(f.line) && f.est_count == 1 && f.up_len == 0 && f.down_len == 0,
               "VlessServer emitted header/body after Est callback close");
    twfRequireLineStateZeroed(f.line, f.node, "VlessServer Est callback close retained state");
    estFixtureDestroy(&f);
}

static void finishBackendFromEst(est_fixture_t *f, line_t *l)
{
    discard l;
    vlessserverTunnelDownStreamFinish(f->node, backendLine(f));
}

static void testBackendFinishDuringEst(void)
{
    est_fixture_t      f;
    vlessserver_user_t user;
    setupVless(&f, &user);
    sendRequest(&f, &user, true);
    line_t *backend = backendLine(&f);
    lineRef(backend);
    f.on_est = finishBackendFromEst;
    vlessserverTunnelDownStreamEst(f.node, backend);
    twfRequire(! lineIsAlive(backend) && lineIsAlive(f.line) && f.est_count == 1,
               "VlessServer backend Finish during Est did not preserve the client association");
    lineUnref(backend);
    vlessserver_lstate_t *ls = lineGetState(f.line, f.node);
    twfRequire(! ls->response_dispatching, "VlessServer backend Finish stranded the client's response dispatch guard");
    f.on_init = initEst;
    applicationInput(&f, 'B');
    vlessserverTunnelDownStreamPayload(f.node, backendLine(&f), estBytes(f.line, "X", 1));
    const uint8_t expected[] = {0, 0, 0, 1, 'X'};
    twfRequire(f.est_count == 1 && f.init_count == 2 && f.up_len == 2 && memoryCompare(f.up, "AB", 2) == 0 &&
                   f.down_len == sizeof(expected) && memoryCompare(f.down, expected, sizeof(expected)) == 0 &&
                   bufferqueueGetBufCount(&ls->pending_down) == 0,
               "VlessServer replacement backend could not deliver replies after Est callback Finish");
    closeFixture(&f);
}

static void overflowResponseBytes(est_fixture_t *f, line_t *l)
{
    vlessserverTunnelUpStreamPause(f->node, l);
    sbuf_t *large = bufferpoolGetBestFit(lineGetBufferPool(l), kVlessServerMaxPendingBytes, 16);
    sbufSetLength(large, kVlessServerMaxPendingBytes);
    vlessserverTunnelDownStreamPayload(f->node, l, large);
    vlessserver_lstate_t *ls = lineGetState(l, f->node);
    twfRequire(bufferqueueGetBufLen(&ls->pending_down) == kVlessServerMaxPendingBytes,
               "VlessServer refused exact response FIFO byte limit");
    vlessserverTunnelDownStreamPayload(f->node, l, estBytes(l, "X", 1));
}

static void overflowResponseEntries(est_fixture_t *f, line_t *l)
{
    vlessserverTunnelUpStreamPause(f->node, l);
    for (unsigned i = 0; i < kVlessServerMaxPendingBuffers; ++i)
        vlessserverTunnelDownStreamPayload(f->node, l, estBytes(l, "", 0));
    vlessserver_lstate_t *ls = lineGetState(l, f->node);
    twfRequire(bufferqueueGetBufCount(&ls->pending_down) == kVlessServerMaxPendingBuffers,
               "VlessServer refused exact response FIFO entry limit");
    vlessserverTunnelDownStreamPayload(f->node, l, estBytes(l, "", 0));
}

static void testResponseLimit(est_inject_fn inject)
{
    est_fixture_t      f;
    vlessserver_user_t user;
    setupVless(&f, &user);
    f.on_init = initEst;
    f.on_est  = inject;
    sendRequest(&f, &user, false);
    twfRequire(! lineIsAlive(f.line) && f.est_count == 1 && f.up_finish_count == 1 && f.down_finish_count == 1 &&
                   f.up_len == 0 && f.down_len == 0,
               "VlessServer response overflow did not close and discard initial payload");
    twfRequireLineStateZeroed(f.line, f.node, "VlessServer response overflow retained state");
    estFixtureDestroy(&f);
}

static void closeOnReplayedPause(tunnel_t *t, line_t *l)
{
    est_fixture_t *f = estContext(t);
    ++f->pause_count;
    vlessserverTunnelDownStreamFinish(f->node, l);
}

static void testPauseBeforeBranchInit(bool udp, bool close)
{
    est_fixture_t      f;
    vlessserver_user_t user;
    setupVless(&f, &user);
    f.on_init = initEst;
    if (close)
        f.next->fnPauseU = closeOnReplayedPause;
    vlessserverTunnelUpStreamPause(f.node, f.line);
    twfRequire(f.pause_count == 0, "VlessServer sent Pause before backend Init");
    sendRequest(&f, &user, udp);
    twfRequire(f.pause_count == 1 && f.est_count == 1,
               "VlessServer did not replay stored receiver Pause after exact backend Init");
    if (close)
    {
        twfRequire(! lineIsAlive(f.line) && f.up_len == 0 && f.down_len == 0,
                   "VlessServer continued initial input after replayed Pause closed the backend");
        twfRequireLineStateZeroed(f.line, f.node, "VlessServer retained state after Pause replay close");
        estFixtureDestroy(&f);
    }
    else
    {
        twfRequire(f.up_len == 1 && f.up[0] == 'A' && f.down_len == 0,
                   "VlessServer stored receiver Pause stopped admitted input or emitted an idle response");
        if (udp)
        {
            line_t *first_backend = backendLine(&f);
            lineRef(first_backend);
            vlessserverTunnelDownStreamFinish(f.node, first_backend);
            twfRequire(! lineIsAlive(first_backend) && lineIsAlive(f.line),
                       "VlessServer backend Finish killed the client or retained its owned line");
            lineUnref(first_backend);
            applicationInput(&f, 'B');
            twfRequire(f.pause_count == 2 && f.init_count == 2 && f.est_count == 1 && f.up_len == 2 &&
                           memoryCompare(f.up, "AB", 2) == 0,
                       "VlessServer recreated backend lost Pause, input, or client Est identity");
        }
        vlessserverTunnelUpStreamResume(f.node, f.line);
        twfRequire(f.down_len == 2 && f.down[0] == 0 && f.down[1] == 0,
                   "VlessServer Resume lost the pending response header");
        closeFixture(&f);
    }
}

static void testUdpSplitLengthPrefix(bool malformed)
{
    est_fixture_t      f;
    vlessserver_user_t user;
    setupVless(&f, &user);
    f.on_init = initEst;
    sendRequest(&f, &user, true);
    const uint8_t prefix[] = {0};
    vlessserverTunnelUpStreamPayload(f.node, f.line, estBytes(f.line, prefix, sizeof(prefix)));
    vlessserver_lstate_t *ls = lineGetState(f.line, f.node);
    twfRequire(lineIsAlive(f.line) && f.up_len == 1 && bufferstreamGetBufLen(&ls->in_stream) == 1,
               "VlessServer did not retain an incomplete UDP length prefix");
    if (malformed)
    {
        vlessserverTunnelUpStreamPayload(f.node, f.line, estBytes(f.line, prefix, sizeof(prefix)));
        twfRequire(! lineIsAlive(f.line) && f.down_finish_count == 1 && f.up_len == 1,
                   "VlessServer accepted a split zero-length UDP frame");
        twfRequireLineStateZeroed(f.line, f.node, "VlessServer malformed split UDP frame retained state");
        estFixtureDestroy(&f);
        return;
    }
    const uint8_t partial_body[] = {2, 'B'};
    vlessserverTunnelUpStreamPayload(f.node, f.line, estBytes(f.line, partial_body, sizeof(partial_body)));
    twfRequire(f.up_len == 1 && bufferstreamGetBufLen(&ls->in_stream) == 3,
               "VlessServer released a split UDP frame before its body completed");
    const uint8_t completed_batch[] = {'C', 0, 1, 'D', 0};
    vlessserverTunnelUpStreamPayload(f.node, f.line, estBytes(f.line, completed_batch, sizeof(completed_batch)));
    twfRequire(lineIsAlive(f.line) && f.up_len == 4 && memoryCompare(f.up, "ABCD", 4) == 0 &&
                   bufferstreamGetBufLen(&ls->in_stream) == 1,
               "VlessServer lost complete UDP records or their incomplete suffix");
    const uint8_t final_frame[] = {1, 'E'};
    vlessserverTunnelUpStreamPayload(f.node, f.line, estBytes(f.line, final_frame, sizeof(final_frame)));
    twfRequire(f.up_len == 5 && memoryCompare(f.up, "ABCDE", 5) == 0 && bufferstreamIsEmpty(&ls->in_stream),
               "VlessServer failed to resume the retained UDP prefix");
    closeFixture(&f);
}

int main(void)
{
    testBackendFinishDuringEst();
    testUdpSplitLengthPrefix(false);
    testUdpSplitLengthPrefix(true);
    testPauseBeforeBranchInit(false, false);
    testPauseBeforeBranchInit(true, false);
    testPauseBeforeBranchInit(false, true);
    testPauseBeforeBranchInit(true, true);
    testResponseLimit(overflowResponseBytes);
    testResponseLimit(overflowResponseEntries);
    testEarlyReplyAndEstOrdering(false, false);
    testEarlyReplyAndEstOrdering(false, true);
    testEarlyReplyAndEstOrdering(true, false);
    testEarlyReplyAndEstOrdering(true, true);
    testCloseDuringEst();
    return 0;
}
