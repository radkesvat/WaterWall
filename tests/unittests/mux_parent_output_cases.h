/* Shared behavioral cases, included by the two existing Mux framing fixtures. */
#ifdef MUX_OUTPUT_CLIENT
#define pq_fixture_t         muxclient_fixture_t
#define pq_state_t           muxclient_lstate_t
#define pq_tstate_t          muxclient_tstate_t
#define pqQueue              muxclientQueueChildPayload
#define pqSend               muxclientTunnelUpStreamPayload
#define pqReceive            muxclientTunnelDownStreamPayload
#define pqChildDeliveries(f) ((f)->trace.prev_payload)
#define pqPause              muxclientTunnelDownStreamPause
#define pqResume             muxclientTunnelDownStreamResume
#define pqControl            muxclientSendControlFrame
#define pqLoss               muxclientHandleParentLoss
#define pqFinish             muxclientTunnelUpStreamFinish
#define pqPeerPause          muxclientPauseChildSource
#define pqPeerResume         muxclientResumeChildSource
#define pqCreate             muxclientTunnelCreate
#define pqDestroy            muxclientTunnelDestroy
#define pqSibling            createPausedClientChild
#define pqDestroySibling     destroySurvivingClientChild
#define pqParentSink(f)      ((f)->next)
#define pqSource(f)          ((f)->prev)
#define pqPayloadSlot        fnPayloadU
#define pqPauseSlot          fnPauseD
#define pqResumeSlot         fnResumeD
#define pqCapture            twfNextPayload
#define pqStop               muxclientTunnelOnWorkerStop
#else
#define pq_fixture_t         muxserver_fixture_t
#define pq_state_t           muxserver_lstate_t
#define pq_tstate_t          muxserver_tstate_t
#define pqQueue              muxserverQueueChildPayload
#define pqSend               muxserverTunnelDownStreamPayload
#define pqReceive            muxserverTunnelUpStreamPayload
#define pqChildDeliveries(f) ((f)->trace.next_payload)
#define pqPause              muxserverTunnelUpStreamPause
#define pqResume             muxserverTunnelUpStreamResume
#define pqControl            muxserverSendControlFrame
#define pqLoss               muxserverHandleParentLoss
#define pqFinish             muxserverTunnelDownStreamFinish
#define pqPeerPause          muxserverPauseChildSource
#define pqPeerResume         muxserverResumeChildSource
#define pqCreate             muxserverTunnelCreate
#define pqDestroy            muxserverTunnelDestroy
#define pqSibling            createServerSibling
#define pqDestroySibling     destroyServerSibling
#define pqParentSink(f)      ((f)->prev)
#define pqSource(f)          ((f)->next)
#define pqPayloadSlot        fnPayloadD
#define pqPauseSlot          fnPauseU
#define pqResumeSlot         fnResumeU
#define pqCapture            twfPrevPayload
#define pqStop               muxserverTunnelOnWorkerStop
#endif

static pq_fixture_t *pqFixture;
static unsigned      pqPauses, pqResumes, pqDeliveries;
static bool          pqTransportPaused;
static unsigned      pqPauseAt, pqNestedAt, pqToggleAt;
static bool          pqReblockOnResume, pqResumeInPause;
static line_t       *pqRemoveOnPause;
static bool          pqCloseSelfOnPause;
static line_t       *pqPeerResumeUnvisited;

static void pqParentPause(pq_fixture_t *f)
{
    pqTransportPaused = true;
    pqPause(f->mux, f->parent_l);
}

static void pqParentResume(pq_fixture_t *f)
{
    pqTransportPaused = false;
    pqResume(f->mux, f->parent_l);
}

static void pqSink(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    twfRequire(! pqTransportPaused, "strict parent received output while paused");
    ++pqDeliveries;
    pqCapture(t, l, buf);
    if (pqDeliveries == pqNestedAt)
        pqSend(pqFixture->mux, pqFixture->child_l, makePatternPayload(pqFixture, 4));
    if (pqDeliveries == pqPauseAt)
        pqParentPause(pqFixture);
    if (pqDeliveries == pqToggleAt)
    {
        pqParentPause(pqFixture);
        pqParentResume(pqFixture);
    }
}

static void pqSourcePause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++pqPauses;
    if (pqPeerResumeUnvisited != NULL)
    {
        line_t *target        = pqPeerResumeUnvisited;
        pqPeerResumeUnvisited = NULL;
        pq_state_t *child     = lineGetState(target, pqFixture->mux);
        discard     pqPeerResume(pqFixture->mux, pqFixture->parent_l, child, true, false);
    }
    if (pqCloseSelfOnPause && l == pqFixture->child_l)
    {
        pqFinish(pqFixture->mux, l);
#ifdef MUX_OUTPUT_CLIENT
        lineDestroy(l);
#endif
        return;
    }
    if (pqResumeInPause)
    {
        pqResumeInPause = false;
        pqParentResume(pqFixture);
    }
    if (pqRemoveOnPause)
    {
        line_t *victim  = pqRemoveOnPause;
        pqRemoveOnPause = NULL;
        pqFinish(pqFixture->mux, victim);
#ifdef MUX_OUTPUT_CLIENT
        lineDestroy(victim); // the fake source owns the borrowed client child
#endif
    }
}

static void pqSourceResume(tunnel_t *t, line_t *l)
{
    discard t;
    ++pqResumes;
    if (pqReblockOnResume)
    {
        pqReblockOnResume = false;
        pqParentPause(pqFixture);
        pqSend(pqFixture->mux, l, makePatternPayload(pqFixture, 1));
    }
}

static void pqSetup(pq_fixture_t *f)
{
    fixtureSetup(f, 4096);
    pqFixture = f;
    pqPauses = pqResumes = pqDeliveries = 0;
    pqPauseAt = pqNestedAt = pqToggleAt = 0;
    pqTransportPaused = pqReblockOnResume = pqResumeInPause = false;
    pqRemoveOnPause                                         = NULL;
    pqCloseSelfOnPause                                      = false;
    pqPeerResumeUnvisited                                   = NULL;
    pqParentSink(f)->pqPayloadSlot                          = pqSink;
    pqSource(f)->pqPauseSlot                                = pqSourcePause;
    pqSource(f)->pqResumeSlot                               = pqSourceResume;
}

static mux_parent_output_t *pqOutput(pq_fixture_t *f)
{
    pq_state_t *parent = lineGetState(f->parent_l, f->mux);
    return &parent->parent_state->output;
}

static void caseParentPumpReentrancy(void)
{
    twfSetCase("parent FIFO handles repeated signals, nested output and synchronous Pause+Resume");
    pq_fixture_t f;
    pqSetup(&f);
    tunnel_t *middle = tunnelCreate(NULL, 0, 0);
    twfRequire(middle != NULL, "failed to create intermediate parent consumer");
#ifdef MUX_OUTPUT_CLIENT
    tunnelBind(f.mux, middle);
    tunnelBind(middle, f.next);
#else
    tunnelBind(f.prev, middle);
    tunnelBind(middle, f.mux);
#endif
    pqPauseAt = 1;
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 2));
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 3));
    pq_state_t *parent = lineGetState(f.parent_l, f.mux);
    twfRequire(pqControl(f.mux, f.parent_l, parent, f.child_l, kTestChildCid, kMuxFlagFlowPause),
               "queued FlowPause failed");
    twfRequire(pqControl(f.mux, f.parent_l, parent, f.child_l, kTestChildCid, kMuxFlagFlowResume),
               "queued FlowResume failed");
    pqParentPause(&f);
    twfRequire(pqPauses == 0 && pqResumes == 0 && pqDeliveries == 1, "short stall walked child producers");
    const size_t charge = pqOutput(&f)->charge;
    pqPauseAt           = 2;
    pqParentResume(&f);
    twfRequire(pqDeliveries == 2 && pqOutput(&f)->charge < charge && pqOutput(&f)->charge > 0,
               "Pause during drain lost residual accounting");
    pqNestedAt = 3;
    pqToggleAt = 3;
    pqParentResume(&f);
    pqParentResume(&f);
    twfRequire(pqDeliveries == 6 && pqOutput(&f)->charge == 0 && pqPauses == 0 && pqResumes == 0,
               "nested output was stranded, duplicated, or caused unnecessary fanout");
    frame_view_t frames[8];
    unsigned     n = parseFrames(f.capture, f.trace.capture_len, frames, 8);
#ifdef MUX_OUTPUT_CLIENT
    twfRequire(frames[0].flags == kMuxFlagOpen, "first Data lost Open");
    unsigned start = 1;
#else
    unsigned start = 0;
#endif
    twfRequire(n == start + 6 && frames[start].length == 1 && frames[start + 1].length == 2 &&
                   frames[start + 2].length == 3 && frames[start + 3].flags == kMuxFlagFlowPause &&
                   frames[start + 4].flags == kMuxFlagFlowResume && frames[start + 5].length == 4,
               "nested Data overtook previously submitted output");
    tunnelBind(f.prev, f.mux);
    tunnelBind(f.mux, f.next);
    tunnelDestroy(middle);
    fixtureTeardown(&f);
}

static void caseParentGate(unsigned children, bool resume_in_pause)
{
    twfSetCase("parent high water fans out once and releases only empty+writable");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts                  = tunnelGetState(f.mux);
    const size_t charge              = pooledBufferCharge(f.env.pool, false);
    ts->parent_write_pause_threshold = (uint32_t) (2 * charge);
    ts->parent_write_limit           = (uint32_t) (4 * charge);
    pq_state_t *parent               = lineGetState(f.parent_l, f.mux);
    line_t    **siblings             = memoryAllocate(children * sizeof(*siblings));
    for (unsigned i = 1; i < children; ++i)
        siblings[i] = pqSibling(&f, parent, 100 + i);
    pqParentPause(&f);
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    twfRequire(pqPauses == 0 && pqOutput(&f)->charge == charge, "below high water paused sources");
    pqResumeInPause = resume_in_pause;
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    twfRequire(pqPauses == children, "exact high water missed or duplicated fanout");
    if (! resume_in_pause)
    {
        pqParentPause(&f);
        pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
        twfRequire(pqPauses == children, "additional retained output repeated fanout");
        pqPauseAt = 3;
        pqParentResume(&f);
        twfRequire(pqOutput(&f)->charge == 0 && pqOutput(&f)->sources_throttled && pqResumes == 0,
                   "empty but paused transport released sources");
        pqParentResume(&f);
    }
    twfRequire(pqResumes == children && ! pqOutput(&f)->sources_throttled && pqOutput(&f)->charge == 0,
               "gate failed to settle after nested Resume");
    for (unsigned i = 1; i < children; ++i)
        pqDestroySibling(&f, siblings[i]);
    memoryFree(siblings);
    fixtureTeardown(&f);
}

static void caseParentGateMutation(void)
{
    twfSetCase("gate traversal survives sibling deletion and a fresh gate during Resume");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts                  = tunnelGetState(f.mux);
    const size_t charge              = pooledBufferCharge(f.env.pool, false);
    ts->parent_write_pause_threshold = (uint32_t) charge;
    ts->parent_write_limit           = (uint32_t) (4 * charge);
    pq_state_t *parent               = lineGetState(f.parent_l, f.mux);
    line_t     *victim               = pqSibling(&f, parent, 100);
    line_t     *survivor             = pqSibling(&f, parent, 101);
    pqRemoveOnPause                  = victim;
    pqPeerResumeUnvisited            = f.child_l;
    pqParentPause(&f);
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    twfRequire(pqPauses == 2 && parent->children_count == 2, "fanout visited a destroyed sibling");
    pqReblockOnResume = true;
    pqParentResume(&f);
    twfRequire(pqResumes == 1 && pqOutput(&f)->sources_throttled, "obsolete Resume pass released another source");
    pqParentResume(&f);
    twfRequire(! pqOutput(&f)->sources_throttled && pqResumes == 3, "new gate did not release exactly once");
    pq_state_t *child = lineGetState(f.child_l, f.mux);
    discard     pqPeerPause(f.mux, f.parent_l, child, true, false);
    pqParentPause(&f);
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    discard pqPeerResume(f.mux, f.parent_l, child, true, false);
    twfRequire(child->parent_write_paused, "peer Resume bypassed local gate");
    discard pqPeerPause(f.mux, f.parent_l, child, true, false);
    pqParentResume(&f);
    twfRequire(child->peer_flow_paused && ! child->parent_write_paused, "local release erased peer pressure");
    discard pqPeerResume(f.mux, f.parent_l, child, true, false);
    pqDestroySibling(&f, survivor);
    fixtureTeardown(&f);
}

static sbuf_t *pqChargedBuffer(size_t charge)
{
    const size_t overhead = sizeof(sbuf_t) + kSbufAllocationAlignment + 64;
    sbuf_t      *buf      = twfTrackAcquired(sbufCreateWithPadding((uint32_t) (charge - overhead), 64));
    twfRequire(sbufGetAllocationCharge(buf) == charge, "test charge geometry is not exact");
    sbufSetLength(buf, 1);
    sbufWriteUI8(buf, 17);
    return buf;
}

static void caseParentHardLimit(bool defaults, bool reservation_failure, bool shutdown)
{
    twfSetCase("parent output enforces inclusive allocation limit and releases backlog on local failure/Stop");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts = tunnelGetState(f.mux);
    if (! defaults)
    {
        ts->parent_write_pause_threshold = 8192;
        ts->parent_write_limit           = 16384;
    }
    const size_t threshold = ts->parent_write_pause_threshold;
    const size_t limit     = ts->parent_write_limit;
    pqParentPause(&f);
    pqSend(f.mux, f.child_l, pqChargedBuffer(threshold - 256));
    twfRequire(pqPauses == 0, "just below threshold paused sources");
    pqSend(f.mux, f.child_l, pqChargedBuffer(256));
    twfRequire(pqPauses == 1 && pqOutput(&f)->charge == threshold, "exact threshold missed fanout");
    pqSend(f.mux, f.child_l, pqChargedBuffer(limit - threshold));
    twfRequire(pqPauses == 1 && pqOutput(&f)->charge == limit, "exact hard limit was rejected");
    lineRef(f.parent_l);
    lineRef(f.child_l);
    if (shutdown)
    {
#ifdef MUX_OUTPUT_CLIENT
        pqStop(f.mux, 0, wwLifecycleProcessShutdown());
#else
        pqStop(f.mux, 0, wwLifecycleProcessShutdown());
        pqLoss(f.mux, f.parent_l, false); // actual borrowed-parent owner drives its Finish
#endif
    }
    else if (reservation_failure)
    {
        pqParentResume(&f);
        bufferqueueDestroy(&pqOutput(&f)->pending);
        bufferqueueInitEmpty(&pqOutput(&f)->pending);
        pqParentPause(&f);
        g_reject_next_queue_reallocation = true;
        pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
        twfRequire(! g_reject_next_queue_reallocation, "insertion refusal seam was not exercised");
    }
    else
        pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    twfRequireLineStateZeroed(f.parent_l, f.mux, "terminal output retained parent state");
    twfRequireLineStateZeroed(f.child_l, f.mux, "terminal output retained child state");
#ifdef MUX_OUTPUT_CLIENT
    twfRequire(! lineIsAlive(f.parent_l), "overflow left owned parent alive");
    lineUnref(f.parent_l);
    f.parent_l = NULL;
    lineUnref(f.child_l);
#else
    twfRequire(! lineIsAlive(f.child_l), "overflow left owned child alive");
    lineUnref(f.child_l);
    f.child_l = NULL;
    lineUnref(f.parent_l);
#endif
    twfRequireNoLeakedBuffers();
    fixtureTeardown(&f);
}

static cJSON *pqSettings(void)
{
#ifdef MUX_OUTPUT_CLIENT
    return cJSON_Parse("{\"mode\":\"counter\",\"connection-capacity\":100}");
#else
    return cJSON_Parse("{}");
#endif
}

static void caseParentWriteConfiguration(void)
{
    twfSetCase("both parent write settings are checked independently and used by their node instance");
    pq_fixture_t f;
    pqSetup(&f);
    GSTATE.ram_profile = kRamProfileL2Memory;
    const char *keys[] = {"parent-write-buffer-pause-threshold", "parent-write-buffer-limit"};
    const char *bad[]  = {"0", "-1", "1.5", "2147483648", "true", "null", "\"123\"", "[]", "{}"};
    for (unsigned key = 0; key < 2; ++key)
    {
        for (unsigned i = 0; i < ARRAY_SIZE(bad); ++i)
        {
            cJSON *settings = pqSettings();
            cJSON_AddItemToObject(settings, keys[key], cJSON_Parse(bad[i]));
            node_t node = {.node_settings_json = settings};
            twfRequire(pqCreate(&node) == NULL, "malformed parent write setting accepted");
            cJSON_Delete(settings);
        }
    }
    const uint32_t pairs[][2] = {
        {0, 0}, {4096, 0}, {0, 33554432}, {8192, 16384}, {16384, 16384}, {32768, 16384}, {0, 16384}};
    for (unsigned i = 0; i < ARRAY_SIZE(pairs); ++i)
    {
        cJSON *settings = pqSettings();
        for (unsigned key = 0; key < 2; ++key)
            if (pairs[i][key])
                cJSON_AddNumberToObject(settings, keys[key], pairs[i][key]);
        node_t    node = {.node_settings_json = settings};
        tunnel_t *mux  = pqCreate(&node);
        if (i >= 4)
            twfRequire(mux == NULL, "invalid effective threshold/limit pair accepted");
        else
        {
            twfRequire(mux != NULL, "valid parent write settings rejected");
            pq_tstate_t *ts = tunnelGetState(mux);
            twfRequire(ts->parent_write_pause_threshold == (pairs[i][0] ? pairs[i][0] : 8388608) &&
                           ts->parent_write_limit == (pairs[i][1] ? pairs[i][1] : 16777216),
                       "parent write independent defaults drifted");
            if (i == 3)
            {
                /* Run the existing real line fixture against the parsed instance. */
                tunnel_t    *original    = f.mux;
                pq_tstate_t *original_ts = tunnelGetState(original);
#ifdef MUX_OUTPUT_CLIENT
                ts->worker_states[0].owned_parents          = original_ts->worker_states[0].owned_parents;
                original_ts->worker_states[0].owned_parents = NULL;
#endif
                f.mux = mux;
                tunnelBind(f.prev, mux);
                tunnelBind(mux, f.next);
                pqParentPause(&f);
                pqSend(mux, f.child_l, pqChargedBuffer(8192));
                twfRequire(pqPauses == 1 && pqOutput(&f)->charge == 8192, "runtime ignored parsed threshold");
                pqSend(mux, f.child_l, pqChargedBuffer(8192));
                twfRequire(pqOutput(&f)->charge == 16384, "runtime rejected parsed hard-limit equality");
                lineRef(f.parent_l);
                lineRef(f.child_l);
                pqSend(mux, f.child_l, makePatternPayload(&f, 1));
                twfRequireLineStateZeroed(f.parent_l, mux, "runtime ignored parsed hard limit");
                twfRequireLineStateZeroed(f.child_l, mux, "parsed hard-limit cleanup retained child");
#ifdef MUX_OUTPUT_CLIENT
                twfRequire(! lineIsAlive(f.parent_l), "parsed limit did not close owned parent");
                lineUnref(f.parent_l);
                f.parent_l = NULL;
                lineUnref(f.child_l);
#else
                twfRequire(! lineIsAlive(f.child_l), "parsed limit did not close owned child");
                lineUnref(f.child_l);
                f.child_l = NULL;
                lineUnref(f.parent_l);
#endif
                twfRequire(original_ts->parent_write_pause_threshold == 8388608 &&
                               original_ts->parent_write_limit == 16777216,
                           "node instances shared settings");
                f.mux = original;
                tunnelBind(f.prev, original);
                tunnelBind(original, f.next);
            }
            pqDestroy(mux, wwLifecycleProcessShutdown());
        }
        cJSON_Delete(settings);
    }
    fixtureTeardown(&f);
}

static unsigned pqLifetimeRefs;
static void     pqLifetimeRetain(sbuf_lifetime_t *lifetime)
{
    discard lifetime;
    ++pqLifetimeRefs;
}
static void pqLifetimeRelease(sbuf_lifetime_t *lifetime)
{
    discard lifetime;
    twfRequire(pqLifetimeRefs != 0, "output released lifetime twice");
    --pqLifetimeRefs;
}

static void caseParentQueuedChildClose(bool with_data)
{
    twfSetCase("encoded output and lifetime survive local child Finish");
    pq_fixture_t f;
    pqSetup(&f);
    pqParentPause(&f);
    sbuf_lifetime_t lifetime = {.retain = pqLifetimeRetain, .release = pqLifetimeRelease};
    pqLifetimeRefs           = 0;
    if (with_data)
    {
        sbuf_t *buf    = makePatternPayload(&f, 1);
        pqLifetimeRefs = 1;
        sbufAttachLifetime(buf, &lifetime);
        pqSend(f.mux, f.child_l, buf);
    }
    lineRef(f.child_l);
    pqFinish(f.mux, f.child_l);
    twfRequire(pqDeliveries == 0, "child Close bypassed Pause");
    twfRequireLineStateZeroed(f.child_l, f.mux, "local Finish retained child state");
    twfRequire(pqLifetimeRefs == (unsigned) with_data, "child teardown released queued output lifetime");
#ifndef MUX_OUTPUT_CLIENT
    twfRequire(! lineIsAlive(f.child_l), "local Finish left owned child alive");
    lineUnref(f.child_l);
    f.child_l = NULL;
#else
    lineUnref(f.child_l);
#endif
    pqParentResume(&f);
    twfRequire(pqLifetimeRefs == 0 && pqOutput(&f)->charge == 0, "drain leaked output lifetime");
    frame_view_t frames[4];
    unsigned     count = parseFrames(f.capture, f.trace.capture_len, frames, 4);
#ifdef MUX_OUTPUT_CLIENT
    twfRequire(count == (with_data ? 3U : 2U) && frames[0].flags == kMuxFlagOpen,
               "queued close lost or duplicated Open");
#else
    twfRequire(count == (with_data ? 2U : 1U), "queued close duplicated a frame");
#endif
    twfRequire(frames[count - 1].flags == kMuxFlagClose, "Close did not follow prior output");
    fixtureTeardown(&f);
}

static void caseParentAdmissionArithmeticAndDirect(void)
{
    twfSetCase("retention arithmetic rejects overflow while writable direct output has no retention bound");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts                  = tunnelGetState(f.mux);
    ts->parent_write_pause_threshold = 1;
    ts->parent_write_limit           = 2;
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    twfRequire(pqDeliveries == 1 && pqOutput(&f)->pending.q.cbuf == NULL,
               "direct path allocated a queue or applied the retention limit");
    mux_parent_output_t output = {0};
    bufferqueueInitEmpty(&output.pending);
    output.charge    = SIZE_MAX - 4;
    sbuf_t *buf      = makePatternPayload(&f, 0);
    sbuf_t *original = buf;
    twfRequire(! muxParentOutputEnqueue(&output, &buf, SIZE_MAX) && original == buf &&
                   bufferqueueGetBufCount(&output.pending) == 0,
               "overflowing admission changed ownership");
    lineReuseBuffer(f.parent_l, buf);
    bufferqueueDestroy(&output.pending);
    fixtureTeardown(&f);
}

static void caseQueueLimitCloseCannotReenterChild(void)
{
    twfSetCase("incoming queue-limit Close cannot notify or close its destroyed child twice");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts                  = tunnelGetState(f.mux);
    ts->parent_write_pause_threshold = 1;
    ts->child_buffer_limit           = 1;
    pq_state_t *parent               = lineGetState(f.parent_l, f.mux);
    pq_state_t *child                = lineGetState(f.child_l, f.mux);
#ifdef MUX_OUTPUT_CLIENT
    child->open_frame_submitted = true;
#endif
    child->paused      = true;
    line_t *sibling    = pqSibling(&f, parent, 100);
    pqCloseSelfOnPause = true;
    pqParentPause(&f);
    lineRef(f.child_l);
    discard pqQueue(f.mux, f.parent_l, ts, parent, child, makePatternPayload(&f, 1));
    twfRequireLineStateZeroed(f.child_l, f.mux, "queue-limit victim state survived Close");
    twfRequire(pqPauses == 1, "queue-limit Close notified its own terminal child");
#ifndef MUX_OUTPUT_CLIENT
    lineUnref(f.child_l);
    f.child_l = NULL;
#else
    lineUnref(f.child_l);
#endif
    pqParentResume(&f);
    frame_view_t   frames[2];
    const unsigned count = parseFrames(f.capture, f.trace.capture_len, frames, 2);
    twfRequire(count == 1 && frames[0].flags == kMuxFlagClose && frames[0].cid == kTestChildCid,
               "reentrant pressure duplicated Close");
    pqDestroySibling(&f, sibling);
    fixtureTeardown(&f);
}

static void caseChildCloseKeepsParentParsing(void)
{
    twfSetCase("queued FlowPause may close one child without stranding a sibling frame");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts                  = tunnelGetState(f.mux);
    ts->child_buffer_pause_tolerance = 0;
    ts->parent_write_pause_threshold = 1;
    pq_state_t *parent               = lineGetState(f.parent_l, f.mux);
    pq_state_t *child                = lineGetState(f.child_l, f.mux);
    child->paused                    = true;
#ifdef MUX_OUTPUT_CLIENT
    child->open_frame_submitted = true;
#endif
    line_t *sibling                                       = pqSibling(&f, parent, 100);
    ((pq_state_t *) lineGetState(sibling, f.mux))->paused = false;
    pqCloseSelfOnPause                                    = true;
    pqParentPause(&f);
    lineRef(f.child_l);

    const uint32_t frame_size = kMuxFrameLength + 1;
    sbuf_t        *batch      = makePatternPayload(&f, 2 * frame_size);
    uint8_t       *data       = sbufGetMutablePtr(batch);
    writeFrameHeader(data, 1, kMuxFlagData, kTestChildCid);
    data[kMuxFrameLength] = 17;
    writeFrameHeader(data + frame_size, 1, kMuxFlagData, 100);
    data[frame_size + kMuxFrameLength] = 34;
    pqReceive(f.mux, f.parent_l, batch);

    twfRequire(lineIsAlive(f.parent_l) && ! lineIsAlive(f.child_l), "Pause did not close only its child");
    twfRequire(bufferstreamGetBufLen(&parent->read_stream) == 0, "complete sibling frame remained stranded");
    twfRequire(pqChildDeliveries(&f) == 1 && f.trace.capture_len == 1 && f.capture[0] == 34,
               "sibling payload was not delivered immediately and intact");
    twfRequire(parent->pending_child_queue_charge == 0, "closed child's incoming queue charge was retained");

    lineUnref(f.child_l);
    f.child_l          = sibling;
    pqCloseSelfOnPause = false;
    fixtureTeardown(&f);
}

static void runParentOutputCases(void)
{
    caseChildCloseKeepsParentParsing();
    caseQueueLimitCloseCannotReenterChild();
    caseParentQueuedChildClose(false);
    caseParentQueuedChildClose(true);
    caseParentAdmissionArithmeticAndDirect();
    caseParentPumpReentrancy();
    caseParentGate(1000, false);
    caseParentGate(3, true);
    caseParentGateMutation();
    caseParentHardLimit(true, false, false);
    caseParentHardLimit(false, false, false);
    caseParentHardLimit(true, true, false);
    caseParentHardLimit(false, false, true);
    caseParentWriteConfiguration();
}
