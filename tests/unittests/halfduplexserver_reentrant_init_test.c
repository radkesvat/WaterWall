/*
 * HalfDuplexServer reconstructs one owned main line from borrowed upload and
 * download transports. The next tunnel may reject the main line synchronously
 * from Init, which closes the download transport before the pairing callback
 * resumes. Both transports must remain allocated across that callback, and the
 * pending upload buffer must be returned through a buffer pool captured before
 * re-entry.
 */
#include "HalfDuplexServer/structure.h"

#include "tunnel_line_failure_harness.h"
#include "wthread.h"

enum
{
    kTestLargeBufferSize = 4096
};

typedef struct halfduplexserver_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_chain_t  *chain;
    tunnel_t        *prev;
    tunnel_t        *halfduplex;
    tunnel_t        *next;
    line_t          *upload_line;
    line_t          *download_line;
    line_t          *replacement_line;
    buffer_pool_t   *unavailable_pool_shortcut[1];
    uint32_t         scheduled_closes;
    bool             buffer_shortcut_hidden;
    bool             refuse_scheduled_closes;
    bool             closed_upload_ref_held;
    bool             scheduled_upload_ref_held;
} halfduplexserver_fixture_t;

static halfduplexserver_fixture_t *g_fixture = NULL;
static bool                        g_protocol_schedule_mode;

typedef struct pending_rendezvous_probe_s
{
    atomic_uint miss_count;
    atomic_bool first_miss_entered;
    atomic_bool release_first_miss;
    atomic_bool second_before_lock;
} pending_rendezvous_probe_t;

typedef struct pending_claim_thread_s
{
    halfduplexserver_tstate_t          *ts;
    halfduplexserver_lstate_t          *ls;
    halfduplex_pair_id_t                pair_id;
    bool                                is_upload;
    halfduplexserver_pending_decision_t decision;
} pending_claim_thread_t;

static pending_rendezvous_probe_t *g_pending_rendezvous_probe;

static void waitForPendingRendezvousFlag(const atomic_bool *flag, const char *message)
{
    const uint64_t deadline_us = getHRTimeUs() + UINT64_C(2000000);
    while (! atomicLoadExplicit((atomic_bool *) flag, memory_order_acquire))
    {
        twfRequire(getHRTimeUs() < deadline_us, message);
        YIELD_THREAD();
    }
}

void halfduplexserverPendingBeforeLockTestSeam(bool is_upload)
{
    pending_rendezvous_probe_t *probe = g_pending_rendezvous_probe;
    if (probe != NULL && ! is_upload)
    {
        atomicStoreExplicit(&probe->second_before_lock, true, memory_order_release);
    }
}

void halfduplexserverPendingMissTestSeam(bool is_upload)
{
    discard                     is_upload;
    pending_rendezvous_probe_t *probe = g_pending_rendezvous_probe;
    if (probe == NULL)
    {
        return;
    }

    const unsigned int previous = atomic_fetch_add_explicit(&probe->miss_count, 1U, memory_order_acq_rel);
    if (previous == 0U)
    {
        atomicStoreExplicit(&probe->first_miss_entered, true, memory_order_release);
        while (! atomicLoadExplicit(&probe->release_first_miss, memory_order_acquire))
        {
            YIELD_THREAD();
        }
    }
}

static WTHREAD_ROUTINE(pendingClaimThreadMain)
{
    pending_claim_thread_t *claim = userdata;
    claim->decision = halfduplexserverTestPendingClaim(claim->ts, claim->ls, claim->pair_id, claim->is_upload, NULL);
    return 0;
}

line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel);
sbuf_t                   *__real_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict b1, sbuf_t *restrict b2);
sbuf_t                   *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict b1, sbuf_t *restrict b2);

sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict b1, sbuf_t *restrict b2)
{
    sbuf_t *merged = __real_sbufAppendMerge(pool, b1, b2);

    /* The merge recycles b2 inside ww's LTO unit, beyond the ordinary
     * bufferpoolReuseBuffer linker wrapper. Mirror that ownership settlement
     * in this test-only ledger. */
    twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, b2);
    twfLedgerRemember(g_twf_buffers.recycled, &g_twf_buffers.recycled_count, b2, "too many merged buffers to track");
    if (merged != b1)
    {
        twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, b1);
        twfLedgerRemember(
            g_twf_buffers.live, &g_twf_buffers.live_count, merged, "too many grown merged buffers to track");
    }
    return merged;
}

line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel)
{
    discard task;
    discard t;

    if (g_fixture == NULL)
    {
        twfRequire(g_protocol_schedule_mode, "HalfDuplexServer scheduled a close outside an active fixture");
        twfRequire(line != NULL, "HalfDuplexServer scheduled a NULL transport close");
        twfRequire(on_cancel == NULL, "HalfDuplexServer unexpectedly requested cancellation notification");
        return kLineTaskSubmitRejectedSettled;
    }

    halfduplexserver_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL, "HalfDuplexServer scheduled a close outside the active fixture");
    twfRequire(line == fixture->upload_line, "HalfDuplexServer scheduled the wrong transport for closure");
    twfRequireEqualU32(
        twfLineRefCount(line), 3, "the upload transport was not retained across the re-entrant main Init");
    twfRequire(on_cancel == NULL, "HalfDuplexServer unexpectedly requested cancellation notification");
    ++fixture->scheduled_closes;
    lineRef(line);
    if (fixture->refuse_scheduled_closes)
    {
        lineUnref(line);
        return kLineTaskSubmitRejectedSettled;
    }
    fixture->scheduled_upload_ref_held = true;
    return kLineTaskSubmitAcceptedAsync;
}

static void transportOwnerDownstreamFinish(tunnel_t *prev, line_t *line)
{
    halfduplexserver_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL, "the transport owner ran outside the active fixture");
    twfRequire(prev == fixture->prev, "the wrong previous tunnel received the transport Finish");
    twfRequire(line == fixture->download_line || line == fixture->upload_line,
               "HalfDuplexServer finished an untracked transport synchronously");

    ++fixture->trace.prev_finish;
    twfRecord(&fixture->trace, 'f');

    if (line == fixture->upload_line)
    {
        twfRequire(fixture->refuse_scheduled_closes,
                   "HalfDuplexServer closed the upload transport after successful task admission");
        lineRef(line);
        fixture->closed_upload_ref_held = true;
        lineDestroy(line);
        return;
    }

    twfRequireEqualU32(
        twfLineRefCount(line), 3, "the download transport was not retained across the re-entrant main Init");
    lineDestroy(line);
    twfRequire(! lineIsAlive(line), "the synthetic transport owner did not destroy the download line");

    fixture->replacement_line = lineCreate(tunnelchainGetLinePools(fixture->chain), 0);
    twfRequire(fixture->replacement_line != line,
               "the download allocation was released and reused while main Init was still active");

    /*
     * Any cleanup that resolves the pool through either transport after Init
     * returns will now fail. The pending buffer can only be recycled through
     * the pool pointer captured before the nested callback.
     */
    GSTATE.shortcut_buffer_pools    = fixture->unavailable_pool_shortcut;
    fixture->buffer_shortcut_hidden = true;
}

static void rejectMainLineInit(tunnel_t *next, line_t *main_line)
{
    halfduplexserver_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL, "the rejecting tunnel ran outside the active fixture");
    twfRequire(next == fixture->next, "the wrong next tunnel received main Init");

    ++fixture->trace.next_init;
    twfRecord(&fixture->trace, 'I');

    halfduplexserver_lstate_t *main_ls = lineGetState(main_line, fixture->halfduplex);
    twfRequire(main_ls->upload_line == fixture->upload_line, "main Init referenced the wrong upload transport");
    twfRequire(main_ls->download_line == fixture->download_line, "main Init referenced the wrong download transport");
    twfRequireEqualU32(
        twfLineRefCount(fixture->upload_line), 2, "the upload transport reference was not held before main Init");
    twfRequireEqualU32(
        twfLineRefCount(fixture->download_line), 2, "the download transport reference was not held before main Init");

    halfduplexserverTunnelDownStreamFinish(fixture->halfduplex, main_line);
    twfRequire(! lineIsAlive(main_line), "rejected main Init did not destroy the owned main line");
}

static void fixtureSetup(halfduplexserver_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev       = twfCreatePrevTunnel(&fixture->trace);
    fixture->halfduplex = tunnelCreate(NULL, sizeof(halfduplexserver_tstate_t), sizeof(halfduplexserver_lstate_t));
    fixture->next       = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->halfduplex != NULL, "failed to create the HalfDuplexServer tunnel");

    halfduplexserver_tstate_t *ts = tunnelGetState(fixture->halfduplex);
    mutexInit(&ts->pending_line_maps_mutex);
    ts->pending_line_maps_mutex_initialized = true;
    ts->upload_line_map                     = hmap_cons_t_with_capacity(kHmapCap);
    ts->download_line_map                   = hmap_cons_t_with_capacity(kHmapCap);

    tunnelBind(fixture->prev, fixture->halfduplex);
    tunnelBind(fixture->halfduplex, fixture->next);
    fixture->prev->fnFinD  = transportOwnerDownstreamFinish;
    fixture->next->fnInitU = rejectMainLineInit;

    fixture->chain                      = tunnelchainCreate(1);
    fixture->chain->sum_line_state_size = fixture->halfduplex->lstate_size;
    tunnelchainFinalize(fixture->chain);
    fixture->halfduplex->chain = fixture->chain;

    g_fixture = fixture;
}

static line_t *createTransportLine(halfduplexserver_fixture_t *fixture)
{
    line_t *line = lineCreate(tunnelchainGetLinePools(fixture->chain), 0);
    halfduplexserverTunnelUpStreamInit(fixture->halfduplex, line);
    return line;
}

static sbuf_t *createIntroBuffer(halfduplexserver_fixture_t *fixture, bool upload)
{
    uint8_t intro[kHLFDIntroSize]                 = {0};
    intro[kHLFDCommandOffset]                     = upload ? kHLFDCmdUpload : kHLFDCmdDownload;
    static const uint8_t pair_id[kHLFDPairIdSize] = {
        0x25,
        0x11,
        0x42,
        0x73,
        0x19,
        0xA4,
        0xC8,
        0x5E,
        0x91,
        0x6B,
        0xD4,
        0x08,
        0x32,
        0xE7,
        0x5A,
        0xCC,
    };
    memoryCopy(intro + kHLFDPairIdOffset, pair_id, sizeof(pair_id));

    sbuf_t *buf = bufferpoolGetLargeBuffer(fixture->env.pool);
    sbufSetLength(buf, sizeof(intro));
    sbufWrite(buf, intro, sizeof(intro));
    return buf;
}

static void sendIntro(halfduplexserver_fixture_t *fixture, line_t *line, bool upload)
{
    halfduplexserverTunnelUpStreamPayload(fixture->halfduplex, line, createIntroBuffer(fixture, upload));
}

static void fixtureTeardown(halfduplexserver_fixture_t *fixture)
{
    if (fixture->buffer_shortcut_hidden)
    {
        GSTATE.shortcut_buffer_pools    = fixture->env.pool_shortcut;
        fixture->buffer_shortcut_hidden = false;
    }

    /* Model quiescence cancellation of the accepted close before owner drain. */
    if (fixture->scheduled_upload_ref_held)
    {
        lineUnref(fixture->upload_line);
        fixture->scheduled_upload_ref_held = false;
    }
    if (fixture->upload_line != NULL && lineIsAlive(fixture->upload_line))
    {
        halfduplexserverTunnelUpStreamFinish(fixture->halfduplex, fixture->upload_line);
        lineDestroy(fixture->upload_line);
    }
    if (fixture->closed_upload_ref_held)
    {
        lineUnref(fixture->upload_line);
        fixture->closed_upload_ref_held = false;
    }
    if (fixture->replacement_line != NULL && lineIsAlive(fixture->replacement_line))
    {
        lineDestroy(fixture->replacement_line);
    }

    twfRequireNoLeakedBuffers();
    tunnelchainDestroy(fixture->chain);
    tunnelDestroy(fixture->next);
    halfduplexserverTunnelDestroy(fixture->halfduplex, wwLifecycleStartupRollback());
    tunnelDestroy(fixture->prev);
    g_fixture = NULL;
}

static void runRejectedPairingCase(bool upload_first, bool refuse_scheduled_close)
{
    twfSetCase(refuse_scheduled_close
                   ? (upload_first ? "HalfDuplexServer upload-first rejected main Init and close task"
                                   : "HalfDuplexServer download-first rejected main Init and close task")
                   : (upload_first ? "HalfDuplexServer upload-first rejected main Init"
                                   : "HalfDuplexServer download-first rejected main Init"));

    halfduplexserver_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.refuse_scheduled_closes = refuse_scheduled_close;

    if (upload_first)
    {
        fixture.upload_line = createTransportLine(&fixture);
        sendIntro(&fixture, fixture.upload_line, true);
        fixture.download_line = createTransportLine(&fixture);
        sendIntro(&fixture, fixture.download_line, false);
    }
    else
    {
        fixture.download_line = createTransportLine(&fixture);
        sendIntro(&fixture, fixture.download_line, false);
        fixture.upload_line = createTransportLine(&fixture);
        sendIntro(&fixture, fixture.upload_line, true);
    }

    twfRequire(fixture.buffer_shortcut_hidden, "the synchronous transport owner did not run");
    GSTATE.shortcut_buffer_pools   = fixture.env.pool_shortcut;
    fixture.buffer_shortcut_hidden = false;

    twfRequireEqualText(fixture.trace.seq,
                        refuse_scheduled_close ? "eeIff" : "eeIf",
                        "unexpected callback order during rejected main Init");
    twfRequireEqualU32(fixture.trace.next_init, 1, "the reconstructed main line was not initialized exactly once");
    twfRequireEqualU32(fixture.trace.prev_finish,
                       refuse_scheduled_close ? 2 : 1,
                       "the required transports were not synchronously finished exactly once");
    twfRequireEqualU32(fixture.scheduled_closes, 1, "the upload transport close was not scheduled exactly once");
    twfRequireEqualU32(twfRecycleCount(), 2, "the two intro buffers were not recycled exactly once");
    twfRequire(lineIsAlive(fixture.upload_line) != refuse_scheduled_close,
               "the upload transport had the wrong logical-life result after task admission");
    twfRequireEqualU32(twfLineRefCount(fixture.upload_line),
                       refuse_scheduled_close ? 1 : 2,
                       "HalfDuplexServer leaked its upload transport reference");

    fixtureTeardown(&fixture);
}

typedef struct halfduplexserver_protocol_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_chain_t  *chain;
    tunnel_t        *prev;
    tunnel_t        *halfduplex;
    tunnel_t        *next;
    line_t          *transport_lines[4];
    line_t          *main_line;
    uint8_t          forwarded_payload[64];
    uint32_t         forwarded_length;
    uint32_t         transport_finish_count;
    uint32_t         main_init_count;
} halfduplexserver_protocol_fixture_t;

static halfduplexserver_protocol_fixture_t *g_protocol_fixture;

static void protocolTransportFinish(tunnel_t *prev, line_t *line)
{
    halfduplexserver_protocol_fixture_t *fixture = g_protocol_fixture;
    twfRequire(fixture != NULL && prev == fixture->prev, "protocol fixture finished through the wrong owner");

    bool found = false;
    for (size_t index = 0; index < ARRAY_SIZE(fixture->transport_lines); ++index)
    {
        if (fixture->transport_lines[index] == line)
        {
            fixture->transport_lines[index] = NULL;
            found                           = true;
            break;
        }
    }
    twfRequire(found, "protocol fixture finished an unknown transport line");
    ++fixture->transport_finish_count;
    lineDestroy(line);
}

static void protocolMainInit(tunnel_t *next, line_t *line)
{
    halfduplexserver_protocol_fixture_t *fixture = g_protocol_fixture;
    twfRequire(fixture != NULL && next == fixture->next, "protocol fixture initialized through the wrong target");
    twfRequire(fixture->main_line == NULL, "protocol fixture created more than one main line");
    fixture->main_line = line;
    ++fixture->main_init_count;
}

static void protocolMainPayload(tunnel_t *next, line_t *line, sbuf_t *buf)
{
    halfduplexserver_protocol_fixture_t *fixture = g_protocol_fixture;
    twfRequire(fixture != NULL && next == fixture->next && line == fixture->main_line,
               "protocol fixture forwarded payload on the wrong main line");
    twfRequire(sbufGetLength(buf) <= sizeof(fixture->forwarded_payload),
               "protocol fixture payload exceeded the capture buffer");

    fixture->forwarded_length = sbufGetLength(buf);
    memoryCopy(fixture->forwarded_payload, sbufGetRawPtr(buf), fixture->forwarded_length);
    lineReuseBuffer(line, buf);
}

static void protocolFixtureSetup(halfduplexserver_protocol_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev       = twfCreatePrevTunnel(&fixture->trace);
    fixture->halfduplex = tunnelCreate(NULL, kTunnelStateSize, kLineStateSize);
    fixture->next       = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->halfduplex != NULL, "failed to create the HalfDuplexServer protocol fixture");

    halfduplexserver_tstate_t *ts = tunnelGetState(fixture->halfduplex);
    mutexInit(&ts->pending_line_maps_mutex);
    ts->pending_line_maps_mutex_initialized = true;
    ts->upload_line_map                     = hmap_cons_t_with_capacity(kHmapCap);
    ts->download_line_map                   = hmap_cons_t_with_capacity(kHmapCap);

    tunnelBind(fixture->prev, fixture->halfduplex);
    tunnelBind(fixture->halfduplex, fixture->next);
    fixture->prev->fnFinD     = protocolTransportFinish;
    fixture->next->fnInitU    = protocolMainInit;
    fixture->next->fnPayloadU = protocolMainPayload;

    fixture->chain                      = tunnelchainCreate(1);
    fixture->chain->sum_line_state_size = fixture->halfduplex->lstate_size;
    tunnelchainFinalize(fixture->chain);
    fixture->halfduplex->chain = fixture->chain;

    g_protocol_fixture       = fixture;
    g_protocol_schedule_mode = true;
}

static line_t *protocolCreateTransport(halfduplexserver_protocol_fixture_t *fixture)
{
    for (size_t index = 0; index < ARRAY_SIZE(fixture->transport_lines); ++index)
    {
        if (fixture->transport_lines[index] == NULL)
        {
            line_t *line                    = lineCreate(tunnelchainGetLinePools(fixture->chain), 0);
            fixture->transport_lines[index] = line;
            halfduplexserverTunnelUpStreamInit(fixture->halfduplex, line);
            return line;
        }
    }
    twfRequire(false, "protocol fixture exhausted its transport slots");
    return NULL;
}

static void protocolSendBytes(halfduplexserver_protocol_fixture_t *fixture, line_t *line, const uint8_t *bytes,
                              uint32_t length)
{
    sbuf_t *buf = bufferpoolGetLargeBuffer(fixture->env.pool);
    sbufSetLength(buf, length);
    sbufWrite(buf, bytes, length);
    halfduplexserverTunnelUpStreamPayload(fixture->halfduplex, line, buf);
}

static void protocolBuildIntro(uint8_t intro[kHLFDIntroSize], uint8_t command, const uint8_t pair_id[kHLFDPairIdSize])
{
    intro[kHLFDCommandOffset] = command;
    memoryCopy(intro + kHLFDPairIdOffset, pair_id, kHLFDPairIdSize);
}

static void protocolCloseMain(halfduplexserver_protocol_fixture_t *fixture)
{
    if (fixture->main_line != NULL)
    {
        line_t *main_line  = fixture->main_line;
        fixture->main_line = NULL;
        halfduplexserverTunnelDownStreamFinish(fixture->halfduplex, main_line);
    }
}

static void protocolFixtureTeardown(halfduplexserver_protocol_fixture_t *fixture)
{
    protocolCloseMain(fixture);
    for (size_t index = 0; index < ARRAY_SIZE(fixture->transport_lines); ++index)
    {
        line_t *line = fixture->transport_lines[index];
        if (line != NULL)
        {
            fixture->transport_lines[index] = NULL;
            halfduplexserverTunnelUpStreamFinish(fixture->halfduplex, line);
            lineDestroy(line);
        }
    }

    twfRequireNoLeakedBuffers();
    tunnelchainDestroy(fixture->chain);
    tunnelDestroy(fixture->next);
    halfduplexserverTunnelDestroy(fixture->halfduplex, wwLifecycleStartupRollback());
    tunnelDestroy(fixture->prev);
    g_protocol_fixture       = NULL;
    g_protocol_schedule_mode = false;
    twfWorkerEnvTeardown(&fixture->env);
}

static void caseFragmentedIntroPairsAndStripsCompletePrefix(void)
{
    twfSetCase("HalfDuplexServer fragmented 17-byte intro pairs and strips the upload prefix");
    halfduplexserver_protocol_fixture_t fixture;
    protocolFixtureSetup(&fixture);

    static const uint8_t pair_id[kHLFDPairIdSize] = {
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x80,
        0x81,
        0x82,
        0x83,
        0x84,
        0x85,
        0x86,
        0x87,
    };
    static const uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t              upload_intro[kHLFDIntroSize];
    uint8_t              download_intro[kHLFDIntroSize];
    protocolBuildIntro(upload_intro, kHLFDCmdUpload, pair_id);
    protocolBuildIntro(download_intro, kHLFDCmdDownload, pair_id);

    line_t *upload_line = protocolCreateTransport(&fixture);
    protocolSendBytes(&fixture, upload_line, upload_intro, 1);
    protocolSendBytes(&fixture, upload_line, upload_intro + 1, kHLFDIntroSize - 1);
    protocolSendBytes(&fixture, upload_line, payload, sizeof(payload));

    line_t *download_line = protocolCreateTransport(&fixture);
    protocolSendBytes(&fixture, download_line, download_intro, kHLFDIntroSize - 1);
    twfRequireEqualU32(fixture.main_init_count, 0, "16-byte download fragment completed the intro too early");
    protocolSendBytes(&fixture, download_line, download_intro + kHLFDIntroSize - 1, 1);

    halfduplexserver_tstate_t *ts = tunnelGetState(fixture.halfduplex);
    twfRequireEqualU32(fixture.main_init_count, 1, "matching full IDs did not create exactly one main line");
    twfRequireEqualU32(fixture.forwarded_length, sizeof(payload), "upload intro bytes leaked into user payload");
    twfRequire(memoryEqual(fixture.forwarded_payload, payload, sizeof(payload)),
               "the forwarded first upload payload changed after intro removal");
    twfRequireEqualU32(
        (uint32_t) hmap_cons_t_size(&ts->upload_line_map), 0, "paired upload remained in the waiting map");
    twfRequireEqualU32(
        (uint32_t) hmap_cons_t_size(&ts->download_line_map), 0, "paired download remained in the waiting map");

    protocolFixtureTeardown(&fixture);
}

static void caseSecondHalfOfPairIdParticipatesInMatching(void)
{
    twfSetCase("HalfDuplexServer compares all 128 pair-ID bits");
    halfduplexserver_protocol_fixture_t fixture;
    protocolFixtureSetup(&fixture);

    uint8_t pair_id_a[kHLFDPairIdSize] = {
        0x20,
        0x21,
        0x22,
        0x23,
        0x24,
        0x25,
        0x26,
        0x27,
        0x30,
        0x31,
        0x32,
        0x33,
        0x34,
        0x35,
        0x36,
        0x37,
    };
    uint8_t pair_id_b[kHLFDPairIdSize];
    memoryCopy(pair_id_b, pair_id_a, sizeof(pair_id_b));
    pair_id_b[kHLFDPairIdSize - 1] ^= 0x01;

    uint8_t upload_intro[kHLFDIntroSize];
    uint8_t download_intro[kHLFDIntroSize];
    protocolBuildIntro(upload_intro, kHLFDCmdUpload, pair_id_a);
    protocolBuildIntro(download_intro, kHLFDCmdDownload, pair_id_b);
    protocolSendBytes(&fixture, protocolCreateTransport(&fixture), upload_intro, sizeof(upload_intro));
    protocolSendBytes(&fixture, protocolCreateTransport(&fixture), download_intro, sizeof(download_intro));

    halfduplexserver_tstate_t *ts = tunnelGetState(fixture.halfduplex);
    twfRequireEqualU32(fixture.main_init_count, 0, "IDs differing only in the second 64-bit half cross-paired");
    twfRequireEqualU32(
        (uint32_t) hmap_cons_t_size(&ts->upload_line_map), 1, "unmatched upload was not retained independently");
    twfRequireEqualU32(
        (uint32_t) hmap_cons_t_size(&ts->download_line_map), 1, "unmatched download was not retained independently");

    protocolFixtureTeardown(&fixture);
}

static void caseInvalidAndDuplicateRolesCloseLocally(void)
{
    twfSetCase("HalfDuplexServer rejects invalid and duplicate exact roles");
    halfduplexserver_protocol_fixture_t fixture;
    protocolFixtureSetup(&fixture);

    static const uint8_t pair_id[kHLFDPairIdSize] = {
        0x40,
        0x41,
        0x42,
        0x43,
        0x44,
        0x45,
        0x46,
        0x47,
        0x50,
        0x51,
        0x52,
        0x53,
        0x54,
        0x55,
        0x56,
        0x57,
    };
    uint8_t intro[kHLFDIntroSize];

    protocolBuildIntro(intro, 0x7E, pair_id);
    protocolSendBytes(&fixture, protocolCreateTransport(&fixture), intro, sizeof(intro));

    halfduplexserver_tstate_t *ts = tunnelGetState(fixture.halfduplex);
    twfRequireEqualU32(fixture.transport_finish_count, 1, "invalid role did not close its transport exactly once");
    twfRequireEqualU32((uint32_t) hmap_cons_t_size(&ts->upload_line_map), 0, "invalid role entered the upload map");
    twfRequireEqualU32((uint32_t) hmap_cons_t_size(&ts->download_line_map), 0, "invalid role entered the download map");

    protocolBuildIntro(intro, kHLFDCmdUpload, pair_id);
    protocolSendBytes(&fixture, protocolCreateTransport(&fixture), intro, sizeof(intro));
    protocolSendBytes(&fixture, protocolCreateTransport(&fixture), intro, sizeof(intro));
    twfRequireEqualU32(
        fixture.transport_finish_count, 2, "duplicate same-role intro did not close only the duplicate transport");
    twfRequireEqualU32((uint32_t) hmap_cons_t_size(&ts->upload_line_map),
                       1,
                       "duplicate same-role handling changed the original waiting entry");
    twfRequireEqualU32(
        (uint32_t) hmap_cons_t_size(&ts->download_line_map), 0, "duplicate upload entered the download map");

    protocolFixtureTeardown(&fixture);
}

static void caseSimultaneousOppositeRolesCannotBothMiss(void)
{
    twfSetCase("HalfDuplexServer lock-linearizes simultaneous opposite-role rendezvous");

    halfduplexserver_tstate_t ts;
    memoryZero(&ts, sizeof(ts));
    mutexInit(&ts.pending_line_maps_mutex);
    ts.pending_line_maps_mutex_initialized = true;
    ts.upload_line_map                     = hmap_cons_t_with_capacity(kHmapCap);
    ts.download_line_map                   = hmap_cons_t_with_capacity(kHmapCap);

    line_t                    upload_line   = {.wid = 0};
    line_t                    download_line = {.wid = 1};
    halfduplexserver_lstate_t upload_ls;
    halfduplexserver_lstate_t download_ls;
    memoryZero(&upload_ls, sizeof(upload_ls));
    memoryZero(&download_ls, sizeof(download_ls));
    upload_ls.upload_line     = &upload_line;
    download_ls.download_line = &download_line;

    const halfduplex_pair_id_t pair_id = {.bytes = {
                                              0x61,
                                              0x62,
                                              0x63,
                                              0x64,
                                              0x65,
                                              0x66,
                                              0x67,
                                              0x68,
                                              0x71,
                                              0x72,
                                              0x73,
                                              0x74,
                                              0x75,
                                              0x76,
                                              0x77,
                                              0x78,
                                          }};

    pending_rendezvous_probe_t probe;
    memoryZero(&probe, sizeof(probe));
    atomic_init(&probe.miss_count, 0);
    atomic_init(&probe.first_miss_entered, false);
    atomic_init(&probe.release_first_miss, false);
    atomic_init(&probe.second_before_lock, false);
    g_pending_rendezvous_probe = &probe;

    pending_claim_thread_t upload_claim   = {.ts = &ts, .ls = &upload_ls, .pair_id = pair_id, .is_upload = true};
    pending_claim_thread_t download_claim = {.ts = &ts, .ls = &download_ls, .pair_id = pair_id, .is_upload = false};
    wthread_t              upload_thread;
    wthread_t              download_thread;

    twfRequire(threadCreate(&upload_thread, pendingClaimThreadMain, &upload_claim) == kWThreadErrorNone,
               "failed to start the upload rendezvous thread");
    waitForPendingRendezvousFlag(&probe.first_miss_entered,
                                 "the upload rendezvous did not pause after its opposite-role miss");

    twfRequire(! mutexTryLock(&ts.pending_line_maps_mutex),
               "the opposite-role miss seam did not retain the pending-map transaction lock");

    twfRequire(threadCreate(&download_thread, pendingClaimThreadMain, &download_claim) == kWThreadErrorNone,
               "failed to start the download rendezvous thread");
    waitForPendingRendezvousFlag(&probe.second_before_lock,
                                 "the download rendezvous did not reach the shared transaction lock");

    atomicStoreExplicit(&probe.release_first_miss, true, memory_order_release);
    twfRequire(threadJoin(upload_thread) == 0, "failed to join the upload rendezvous thread");
    twfRequire(threadJoin(download_thread) == 0, "failed to join the download rendezvous thread");
    g_pending_rendezvous_probe = NULL;

    twfRequireEqualU32((uint32_t) atomicLoadExplicit(&probe.miss_count, memory_order_acquire),
                       1,
                       "simultaneous opposite roles both observed a missing peer");
    twfRequire(upload_claim.decision.result == kHalfDuplexServerPendingInserted,
               "the first opposite-role arrival was not published while holding the transaction lock");
    twfRequire(download_claim.decision.result == kHalfDuplexServerPendingMatchedRemote &&
                   download_claim.decision.target_wid == 0,
               "the concurrent opposite-role arrival did not select the pending peer's worker");
    twfRequire(download_claim.decision.peer == NULL,
               "the cross-WID decision exposed a borrowed peer line-state pointer");
    twfRequireEqualU32((uint32_t) hmap_cons_t_size(&ts.upload_line_map),
                       1,
                       "the cross-WID decision removed its peer before piping completed");
    twfRequireEqualU32(
        (uint32_t) hmap_cons_t_size(&ts.download_line_map), 0, "the paired download entered the pending map");

    hmap_cons_t_iter remote_pending = hmap_cons_t_find(&ts.upload_line_map, pair_id);
    twfRequire(remote_pending.ref != hmap_cons_t_end(&ts.upload_line_map).ref,
               "the cross-WID pending peer disappeared before test cleanup");
    hmap_cons_t_erase_at(&ts.upload_line_map, remote_pending);

    hmap_cons_t_drop(&ts.download_line_map);
    hmap_cons_t_drop(&ts.upload_line_map);
    mutexDestroy(&ts.pending_line_maps_mutex);
}

int main(void)
{
    caseSimultaneousOppositeRolesCannotBothMiss();
    runRejectedPairingCase(true, false);
    runRejectedPairingCase(false, false);
    runRejectedPairingCase(true, true);
    runRejectedPairingCase(false, true);
    caseFragmentedIntroPairsAndStripsCompletePrefix();
    caseSecondHalfOfPairIdParticipatesInMatching();
    caseInvalidAndDuplicateRolesCloseLocally();

    printf("halfduplexserver_reentrant_init_test: all cases passed\n");
    return 0;
}
