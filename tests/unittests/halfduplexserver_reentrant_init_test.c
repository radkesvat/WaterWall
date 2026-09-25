/*
 * HalfDuplexServer reconstructs one owned main line from borrowed upload and
 * download transports. The next tunnel may reject the main line synchronously
 * from Init, which closes the download transport before the pairing callback
 * resumes. Both transports must remain allocated across that callback, and the
 * pending upload buffer must be returned through a buffer pool captured before
 * re-entry.
 */
#include "HalfDuplexServer/structure.h"

#define __wrap_bufferpoolTryGetBestFit trackedTryGetBestFit
#include "halfduplex_splice_fixture.h"
#undef __wrap_bufferpoolTryGetBestFit

static bool fail_queue;
bool        __real_bufferqueueTryPushBack(buffer_queue_t *queue, sbuf_t **buf);
bool        __wrap_bufferqueueTryPushBack(buffer_queue_t *queue, sbuf_t **buf);
bool        __wrap_bufferqueueTryPushBack(buffer_queue_t *queue, sbuf_t **buf)
{
    if (fail_queue)
    {
        fail_queue = false;
        return false;
    }
    return __real_bufferqueueTryPushBack(queue, buf);
}

static bool fail_allocation;
sbuf_t     *__wrap_bufferpoolTryGetBestFit(buffer_pool_t *pool, uint64_t size, uint16_t padding);
sbuf_t     *__wrap_bufferpoolTryGetBestFit(buffer_pool_t *pool, uint64_t size, uint16_t padding)
{
    if (fail_allocation)
    {
        fail_allocation = false;
        return NULL;
    }
    return trackedTryGetBestFit(pool, size, padding);
}

static bool splice_inputs;
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

    return halfduplexTestBytes(fixture->env.pool, intro, sizeof(intro), splice_inputs, 3);
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
    twfRequireEqualU32(twfRecycleCount(),
                       splice_inputs && WW_HAVE_SPLICE ? 4 : 2,
                       "intro buffers and materialized outputs were not recycled exactly once");
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
static uint32_t                             g_protocol_pool_size = kTestLargeBufferSize;

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

    buf = halfduplexTestMaterialize(fixture->env.pool, buf);
    twfRequire(sbufGetLeftCapacity(buf) >= 64, "server output lost onward padding");
    fixture->forwarded_length = sbufGetLength(buf);
    memoryCopy(fixture->forwarded_payload, sbufGetRawPtr(buf), fixture->forwarded_length);
    lineReuseBuffer(line, buf);
}

static void protocolFixtureSetup(halfduplexserver_protocol_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetupWithBufferSizes(&fixture->env,
                                     min(g_protocol_pool_size, (uint32_t) LARGE_BUFFER_SIZE_RAM_HIGH),
                                     min(g_protocol_pool_size, (uint32_t) LARGE_BUFFER_SIZE_RAM_HIGH),
                                     64,
                                     SPLICE_PAYLOAD_LIMIT,
                                     g_protocol_pool_size);

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
    sbuf_t *buf = halfduplexTestBytes(fixture->env.pool,
                                      bytes,
                                      length,
                                      splice_inputs && length <= 64000,
                                      (uint16_t) (length > 4096 ? length - 1000 : length / 2));
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

static uint32_t waiting_expected;
static void     waitingPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    twfRequire(! sbufIsSplice(buf) && sbufGetLeftCapacity(buf) >= 64, "waiting replay representation/padding changed");
    twfRequire(sbufGetLength(buf) == waiting_expected, "waiting HalfDuplex body length changed");
    for (uint32_t i = 0; i < waiting_expected; ++i)
        twfRequire(sbufGetMutablePtr(buf)[i] == 0x71, "waiting HalfDuplex body bytes changed");
    g_protocol_fixture->forwarded_length = waiting_expected;
    lineReuseBuffer(l, buf);
}
static void caseWaitingBoundary(uint32_t large, uint32_t total, bool append, bool available)
{
    g_protocol_pool_size = large;
    halfduplexserver_protocol_fixture_t fixture;
    protocolFixtureSetup(&fixture);
    fixture.next->fnPayloadU = waitingPayload;
    line_t        *upload    = protocolCreateTransport(&fixture);
    const uint64_t limit     = halfduplexserverWaitingLimit(upload);
    uint8_t       *data      = memoryAllocate(total);
    memorySet(data, 0x71, total);
    uint8_t id[kHLFDPairIdSize] = {7};
    protocolBuildIntro(data, kHLFDCmdUpload, id);
    waiting_expected = total - kHLFDIntroSize;
    if (available)
    {
        uint8_t intro[kHLFDIntroSize];
        protocolBuildIntro(intro, kHLFDCmdDownload, id);
        protocolSendBytes(&fixture, protocolCreateTransport(&fixture), intro, sizeof(intro));
    }
    if (append)
    {
        protocolSendBytes(&fixture, upload, data, kHLFDIntroSize);
        protocolSendBytes(&fixture, upload, data + kHLFDIntroSize, total - kHLFDIntroSize);
    }
    else
        protocolSendBytes(&fixture, upload, data, total);
    if (available)
        twfRequire(fixture.forwarded_length == waiting_expected, "available peer was limited as waiting input");
    else if (total >= limit)
        twfRequire(fixture.transport_finish_count == 1, "HalfDuplex waiting overflow survived");
    else
    {
        twfRequire(fixture.transport_finish_count == 0, "HalfDuplex valid waiting data closed");
        waiting_expected = total - kHLFDIntroSize;
        uint8_t intro[kHLFDIntroSize];
        protocolBuildIntro(intro, kHLFDCmdDownload, id);
        protocolSendBytes(&fixture, protocolCreateTransport(&fixture), intro, sizeof(intro));
        twfRequire(fixture.forwarded_length == waiting_expected, "HalfDuplex waiting data did not pair");
    }
    memoryFree(data);
    protocolFixtureTeardown(&fixture);
    g_protocol_pool_size = kTestLargeBufferSize;
}

static sbuf_t *expected_direct;
static void    protocolDirect(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    twfRequire(buf == expected_direct && sbufIsSplice(buf), "server direct path replaced splice wrapper");
    buf = halfduplexTestMaterialize(lineGetBufferPool(line), buf);
    twfRequire(sbufGetLength(buf) == 5 && memoryEqual(sbufGetRawPtr(buf), "later", 5), "direct body changed");
    lineReuseBuffer(line, buf);
}

static void caseSpliceFragments(void)
{
    for (unsigned split = 0; split <= kHLFDIntroSize; ++split)
        for (unsigned download_first = 0; download_first < 2; ++download_first)
        {
            halfduplexserver_protocol_fixture_t fixture;
            protocolFixtureSetup(&fixture);
            uint8_t id[16] = {4}, upload[21], download[17];
            protocolBuildIntro(upload, kHLFDCmdUpload, id);
            memoryCopy(upload + 17, "body", 4);
            protocolBuildIntro(download, kHLFDCmdDownload, id);
            line_t *up   = protocolCreateTransport(&fixture);
            line_t *down = protocolCreateTransport(&fixture);
            if (download_first)
                protocolSendBytes(&fixture, down, download, 17);
            halfduplexserverTunnelUpStreamPayload(
                fixture.halfduplex,
                up,
                halfduplexTestBytes(fixture.env.pool, upload, split, split % 2 == 0, split / 2));
            halfduplexserver_lstate_t *ls = lineGetState(up, fixture.halfduplex);
            twfRequire(ls->buffering == NULL || ! sbufIsSplice(ls->buffering), "partial intro retained splice");
            protocolSendBytes(&fixture, up, upload + split, sizeof(upload) - split);
            if (! download_first)
            {
                twfRequire(ls->buffering && ! sbufIsSplice(ls->buffering), "waiting upload retained splice");
                protocolSendBytes(&fixture, up, (const uint8_t *) "tail", 4);
                protocolSendBytes(&fixture, down, download, 17);
            }
            twfRequire(fixture.forwarded_length == (download_first ? 4 : 8) &&
                           memoryEqual(fixture.forwarded_payload,
                                       download_first ? "body" : "bodytail",
                                       fixture.forwarded_length),
                       "fragmented splice replay changed");
#if WW_HAVE_SPLICE
            fixture.next->fnPayloadU = protocolDirect;
            fixture.prev->fnPayloadD = protocolDirect;
            expected_direct          = halfduplexTestBytes(fixture.env.pool, "later", 5, true, 2);
            halfduplexserverTunnelUpStreamPayload(fixture.halfduplex, up, expected_direct);
            expected_direct = halfduplexTestBytes(fixture.env.pool, "later", 5, true, 2);
            halfduplexserverTunnelDownStreamPayload(fixture.halfduplex, fixture.main_line, expected_direct);
            halfduplexserverTunnelUpStreamPayload(
                fixture.halfduplex, down, halfduplexTestBytes(fixture.env.pool, "ignored", 7, true, 0));
#endif
            protocolFixtureTeardown(&fixture);
        }
}

static void caseSetupClosureAndRefusal(void)
{
    for (unsigned waiting = 0; waiting < 2; ++waiting)
        for (unsigned failure = 0; failure < 3; ++failure)
        {
            halfduplexserver_protocol_fixture_t fixture;
            protocolFixtureSetup(&fixture);
            line_t *up = protocolCreateTransport(&fixture);
            uint8_t data[64000];
            memorySet(data, 0x71, sizeof(data));
            uint8_t id[16] = {7};
            protocolBuildIntro(data, kHLFDCmdUpload, id);
            protocolSendBytes(&fixture, up, data, waiting ? 17 : 3);
            if (failure != 0)
            {
                sbuf_t *buf = halfduplexTestBytes(fixture.env.pool, data, sizeof(data), true, 63000);
                if (failure == 1)
                    fail_allocation = true;
                else
                {
                    buf      = halfduplexTestMaterialize(fixture.env.pool, buf);
                    buf->len = UINT32_MAX;
                }
                halfduplexserverTunnelUpStreamPayload(fixture.halfduplex, up, buf);
                twfRequire(fixture.transport_finish_count == 1, "setup refusal did not close borrowed input");
                halfduplexserver_tstate_t *ts = tunnelGetState(fixture.halfduplex);
                twfRequire(hmap_cons_t_size(&ts->upload_line_map) == 0, "setup refusal left waiting entry");
            }
            protocolFixtureTeardown(&fixture);
        }
}

typedef struct startup_order_test_s
{
    line_t  *upload, *download;
    bool     in_init, replayed, tail_seen, empty, fragmented;
    unsigned mode, callbacks, pauses, resumes, next_finishes;
    unsigned close_stage, close_side;
    sbuf_t  *direct;
} startup_order_test_t;
static startup_order_test_t order;

static void orderClose(unsigned side)
{
    halfduplexserver_protocol_fixture_t *f = g_protocol_fixture;
    if (side == 0)
        protocolCloseMain(f);
    else
    {
        line_t *half = side == 1 ? order.upload : order.download;
        halfduplexserverTunnelUpStreamFinish(f->halfduplex, half);
        // A received Finish must not have been reflected to its sender.
        twfRequire(lineIsAlive(half), "received Finish reflected toward half owner");
        protocolTransportFinish(f->prev, half);
    }
}
static void orderNextFinish(tunnel_t *t, line_t *line)
{
    discard t;
    twfRequire(g_protocol_fixture->main_line == line, "next Finish used wrong main");
    g_protocol_fixture->main_line = NULL;
    ++order.next_finishes;
}
static void orderSend(const char *data)
{
    protocolSendBytes(g_protocol_fixture, order.upload, (const uint8_t *) data, (uint32_t) strlen(data));
}
static void orderPause(tunnel_t *t, line_t *line)
{
    discard t;
    twfRequire(line == order.upload, "source Pause targeted wrong half");
    ++order.pauses;
    if (order.close_stage == 4)
        orderClose(order.close_side);
}
static void orderResume(tunnel_t *t, line_t *line)
{
    discard t;
    twfRequire(line == order.upload && ! order.in_init, "source Resume escaped Init barrier");
    halfduplexserver_protocol_fixture_t *f = g_protocol_fixture;
    twfRequire(! ((halfduplexserver_lstate_t *) lineGetState(f->main_line, f->halfduplex))->startup_active,
               "source Resume escaped before older startup bytes");
    ++order.resumes;
    if (order.close_stage == 3)
        orderClose(order.close_side);
    else
    {
        order.direct = halfduplexTestBytes(f->env.pool, order.resumes == 2 ? "F" : "E", 1, true, 0);
        halfduplexserverTunnelUpStreamPayload(f->halfduplex, order.upload, order.direct);
        if (order.mode == 6 && order.resumes == 1)
        {
            halfduplexserverTunnelDownStreamPause(f->halfduplex, f->main_line);
            halfduplexserverTunnelDownStreamResume(f->halfduplex, f->main_line);
        }
    }
}
static void orderPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    twfRequire(! order.in_init, "upload Payload entered next before Init returned");
    halfduplexserver_protocol_fixture_t *f = g_protocol_fixture;
    if (order.direct)
    {
        twfRequire(buf == order.direct && sbufIsSplice(buf) == (bool) WW_HAVE_SPLICE,
                   "ready input lost identity/representation");
        order.direct = NULL;
    }
    else
        twfRequire(! sbufIsSplice(buf), "startup retention was not ordinary");
    ++order.callbacks;
    uint32_t length = sbufGetLength(buf);
    buf             = halfduplexTestMaterialize(f->env.pool, buf);
    twfRequire(f->forwarded_length + length <= sizeof(f->forwarded_payload), "order capture overflow");
    memoryCopy(f->forwarded_payload + f->forwarded_length, sbufGetRawPtr(buf), length);
    f->forwarded_length += length;
    lineReuseBuffer(line, buf);
    if (order.close_stage == 2)
    {
        orderClose(order.close_side);
        return;
    }
    if (order.mode != 0 && ! order.empty && ! order.replayed)
    {
        order.replayed = true;
        orderSend("D");
        if (order.mode == 3)
            halfduplexserverTunnelDownStreamPause(f->halfduplex, line);
        if (order.mode == 5)
            fail_allocation = true; // Final combined tail allocation.
    }
    else if (order.mode == 1 && ! order.tail_seen)
    {
        order.tail_seen = true;
        order.direct    = halfduplexTestBytes(f->env.pool, "E", 1, true, 0);
        halfduplexserverTunnelUpStreamPayload(f->halfduplex, order.upload, order.direct);
    }
}
static void orderInit(tunnel_t *t, line_t *line)
{
    protocolMainInit(t, line);
    order.in_init = true;
    if (order.mode != 7)
        orderSend(order.mode == 0 ? "NEW" : "B");
    if (order.mode != 0 && order.mode != 7)
        orderSend("C");
    if (order.close_stage == 1)
        orderClose(order.close_side);
    else if (order.mode == 2 || order.mode == 4 || order.mode == 6 || order.close_stage == 4)
    {
        halfduplexserverTunnelDownStreamPause(g_protocol_fixture->halfduplex, line);
        if (order.close_stage != 4)
            halfduplexserverTunnelDownStreamResume(g_protocol_fixture->halfduplex, line);
        if (order.mode == 2)
            halfduplexserverTunnelDownStreamPause(g_protocol_fixture->halfduplex, line);
    }
    order.in_init = false;
}
static void orderSetup(halfduplexserver_protocol_fixture_t *f, unsigned mode, unsigned stage, unsigned side)
{
    protocolFixtureSetup(f);
    order               = (startup_order_test_t) {.mode = mode, .close_stage = stage, .close_side = side};
    f->next->fnInitU    = orderInit;
    f->next->fnPayloadU = orderPayload;
    f->next->fnFinU     = orderNextFinish;
    f->prev->fnPauseD   = orderPause;
    f->prev->fnResumeD  = orderResume;
    order.upload        = protocolCreateTransport(f);
    order.download      = protocolCreateTransport(f);
}
static void orderPair(halfduplexserver_protocol_fixture_t *f, bool download_first, bool empty, bool fragmented)
{
    order.empty    = empty;
    uint8_t id[16] = {9}, up[20], down[17];
    protocolBuildIntro(up, kHLFDCmdUpload, id);
    memoryCopy(up + 17, order.mode == 0 ? "OLD" : "A", order.mode == 0 ? 3 : 1);
    protocolBuildIntro(down, kHLFDCmdDownload, id);
    if (download_first)
        protocolSendBytes(f, order.download, down, sizeof(down));
    unsigned length = 17 + (empty ? 0 : order.mode == 0 ? 3 : 1);
    if (fragmented)
    {
        // Mix an ordinary partial intro with a potentially splice-backed tail.
        halfduplexserverTunnelUpStreamPayload(
            f->halfduplex, order.upload, halfduplexTestBytes(f->env.pool, up, 7, false, 0));
        protocolSendBytes(f, order.upload, up + 7, length - 7);
    }
    else
        protocolSendBytes(f, order.upload, up, length);
    if (! download_first)
        protocolSendBytes(f, order.download, down, sizeof(down));
}
static void casePairingOrder(void)
{
    twfSetCase("HalfDuplexServer startup FIFO and permission reentry");
    for (unsigned first = 0; first < 2; ++first)
        for (unsigned mode = 0; mode < 8; ++mode)
            for (unsigned empty = 0; empty < 2; ++empty)
            {
                if ((mode == 5 && empty) || (mode == 7 && ! empty))
                    continue;
                halfduplexserver_protocol_fixture_t f;
                orderSetup(&f, mode, 0, 0);
                orderPair(&f, first, empty, true);
                if (mode == 5)
                {
                    twfRequire(f.main_line == NULL && f.transport_finish_count == 2 && order.next_finishes == 1,
                               "tail allocation refusal did not close all initialized sides");
                }
                else
                {
                    if (mode == 2 || (mode == 3 && ! empty))
                    {
                        twfRequire(order.resumes == 0, "source resumed with older startup obligation");
                        twfRequire(f.forwarded_length == (mode == 2 ? 0 : 1), "Pause did not hold startup backlog");
                        halfduplexserverTunnelDownStreamResume(f.halfduplex, f.main_line);
                    }
                    const char *expected = mode == 7            ? ""
                                           : mode == 6          ? (empty ? "BCEF" : "ABCDEF")
                                           : mode == 0          ? (empty ? "NEW" : "OLDNEW")
                                           : mode == 1          ? (empty ? "BCE" : "ABCDE")
                                           : mode == 3 && empty ? "BC"
                                           : empty              ? "BCE"
                                                                : "ABCDE";
                    twfRequire(f.forwarded_length == strlen(expected) &&
                                   memoryEqual(f.forwarded_payload, expected, strlen(expected)),
                               "startup FIFO violated");
                    if (mode == 7)
                        twfRequire(order.callbacks == 0, "empty startup synthesized Payload");
                    if (mode == 6)
                        twfRequire(order.resumes == 2, "nested source permission was stranded");
                    if (mode == 2 || mode == 4 || (mode == 3 && ! empty))
                        twfRequire(order.resumes == 1, "source Resume duplicated or missing");
                    order.direct = halfduplexTestBytes(f.env.pool, "Z", 1, true, 0);
                    halfduplexserverTunnelUpStreamPayload(f.halfduplex, order.upload, order.direct);
                }
                protocolFixtureTeardown(&f);
            }
    for (unsigned stage = 1; stage <= 4; ++stage)
        for (unsigned side = 0; side < 3; ++side)
        {
            halfduplexserver_protocol_fixture_t f;
            orderSetup(&f, 4, stage, side);
            orderPair(&f, false, false, false);
            twfRequire(f.main_line == NULL && f.transport_finish_count == 2,
                       "close during startup callback leaked association");
            twfRequire(order.next_finishes == (side == 0 ? 0 : 1), "Finish reflected toward next or missed next");
            protocolFixtureTeardown(&f);
        }
}

static unsigned budget_dimension;
static bool     budget_overflow;
static size_t   budget_delivered;
static void     budgetPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    twfRequire(! order.in_init && ! sbufIsSplice(buf), "budget replay bypassed Init or materialization");
    budget_delivered += sbufGetLength(buf);
    lineReuseBuffer(line, buf);
}
static void budgetInit(tunnel_t *t, line_t *line)
{
    protocolMainInit(t, line);
    order.in_init                               = true;
    halfduplexserver_protocol_fixture_t *f      = g_protocol_fixture;
    halfduplexserver_lstate_t           *ls     = lineGetState(line, f->halfduplex);
    buffer_budget_cost_t                 limits = bufferbudgetGetLimits(&ls->startup_budget);
    twfRequire(limits.bytes == 2 * 1024 * 1024 && limits.charge == 2 * 1024 * 1024 && limits.entries == 1024,
               "startup policy limits changed");
    if (budget_dimension == 0)
    {
        // Isolate the configured byte limit before any admission. In production
        // an ordinary 2 MiB body necessarily hits charge first (case 3).
        limits.charge = SIZE_MAX;
        bufferbudgetInit(&ls->startup_budget, limits);
    }
    unsigned count = budget_dimension == 2 ? 1024 : 1;
    for (unsigned i = 0; i < count; ++i)
    {
        uint32_t size = budget_dimension == 0 || budget_dimension == 3 ? 2 * 1024 * 1024
                        : budget_dimension == 1                        ? 2 * 1024 * 1024 - 128
                                                                       : 0;
        sbuf_t  *buf  = twfTrackAcquired(sbufCreateWithPadding(size, 64));
        sbufSetLength(buf, size);
        memorySet(sbufGetMutablePtr(buf), 0x71, size);
        if (budget_dimension == 1)
            twfRequire(sbufGetQueueCharge(buf) == 2 * 1024 * 1024, "charge equality fixture geometry changed");
        halfduplexserverTunnelUpStreamPayload(f->halfduplex, order.upload, buf);
    }
    if (budget_dimension != 3)
    {
        twfRequire(f->main_line != NULL && f->forwarded_length == 0, "equality refused or replayed during Init");
        buffer_budget_cost_t used = bufferbudgetGetUsage(&ls->startup_budget);
        twfRequire((budget_dimension != 0 || used.bytes == limits.bytes) &&
                       (budget_dimension != 1 || used.charge == limits.charge) &&
                       (budget_dimension != 2 || used.entries == limits.entries),
                   "equality accounting mismatch");
        if (budget_overflow)
        {
            sbuf_t *buf = twfTrackAcquired(sbufCreateWithPadding(budget_dimension == 0 ? 1 : 0, 64));
            sbufSetLength(buf, budget_dimension == 0 ? 1 : 0);
            halfduplexserverTunnelUpStreamPayload(f->halfduplex, order.upload, buf);
        }
    }
    order.in_init = false;
}
static void refusalInit(tunnel_t *t, line_t *line)
{
    protocolMainInit(t, line);
    halfduplexserver_protocol_fixture_t *f = g_protocol_fixture;
    orderSend("B");
    sbuf_t *buf = halfduplexTestBytes(f->env.pool, "failure", 7, true, 3);
    if (budget_dimension == 0 && WW_HAVE_SPLICE)
        fail_allocation = true;
    else
        fail_queue = true;
    halfduplexserverTunnelUpStreamPayload(f->halfduplex, order.upload, buf);
}
static void caseStartupBudget(void)
{
    twfSetCase("HalfDuplexServer independent startup byte/charge/entry admission and refusal");
    for (budget_dimension = 0; budget_dimension < 4; ++budget_dimension)
        for (unsigned overflow = 0; overflow < 2; ++overflow)
        {
            halfduplexserver_protocol_fixture_t f;
            orderSetup(&f, 0, 0, 0);
            f.next->fnInitU    = budgetInit;
            f.next->fnPayloadU = budgetPayload;
            budget_overflow    = overflow != 0;
            budget_delivered   = 0;
            orderPair(&f, overflow != 0, false, false);
            bool refused = overflow || budget_dimension == 3;
            twfRequire((f.main_line == NULL) == refused, "startup budget acceptance/overflow changed");
            if (refused)
                twfRequire(f.transport_finish_count == 2 && order.next_finishes == 1 && budget_delivered == 0,
                           "budget refusal failed to settle initialized association");
            else
                twfRequire(budget_delivered == 3 + (budget_dimension == 0   ? 2 * 1024 * 1024
                                                    : budget_dimension == 1 ? 2 * 1024 * 1024 - 128
                                                                            : 0),
                           "budget replay truncated bytes");
            protocolFixtureTeardown(&f);
        }
    for (budget_dimension = 0; budget_dimension < 2; ++budget_dimension)
    {
        halfduplexserver_protocol_fixture_t f;
        orderSetup(&f, 0, 0, 0);
        f.next->fnInitU = refusalInit;
        orderPair(&f, false, false, false);
        twfRequire(f.main_line == NULL && f.transport_finish_count == 2 && order.next_finishes == 1,
                   "startup storage refusal leaked association");
        protocolFixtureTeardown(&f);
    }
}

int main(void)
{
    casePairingOrder();
    caseStartupBudget();
    const uint32_t sizes[] = {32768, 64 * 1024, SPLICE_PAYLOAD_LIMIT};
    for (unsigned i = 0; i < ARRAY_SIZE(sizes); ++i)
        for (unsigned append = 0; append < 2; ++append)
        {
            uint32_t limit = 131070 * (sizes[i] / 32768);
            caseWaitingBoundary(sizes[i], limit - 1, append, false);
            caseWaitingBoundary(sizes[i], limit, append, false);
            caseWaitingBoundary(sizes[i], limit + 1, append, false);
        }
    caseWaitingBoundary(SPLICE_PAYLOAD_LIMIT, SPLICE_PAYLOAD_LIMIT + kHLFDIntroSize, false, false);
    caseSimultaneousOppositeRolesCannotBothMiss();
    runRejectedPairingCase(true, false);
    runRejectedPairingCase(false, false);
    runRejectedPairingCase(true, true);
    runRejectedPairingCase(false, true);
    caseFragmentedIntroPairsAndStripsCompletePrefix();
    caseSecondHalfOfPairIdParticipatesInMatching();
    caseInvalidAndDuplicateRolesCloseLocally();

    splice_inputs = true;
    casePairingOrder();
    caseStartupBudget();
    runRejectedPairingCase(true, false);
    runRejectedPairingCase(false, false);
    runRejectedPairingCase(true, true);
    runRejectedPairingCase(false, true);
    caseSpliceFragments();
    caseSetupClosureAndRefusal();
    caseWaitingBoundary(4096, 64000, false, false);
    caseWaitingBoundary(4096, 64000, true, false);
    caseWaitingBoundary(65536, 262141, false, true);
    caseWaitingBoundary(SPLICE_PAYLOAD_LIMIT, kHalfDuplexServerStartupBytes + 18, false, true);
    caseFragmentedIntroPairsAndStripsCompletePrefix();
    caseSecondHalfOfPairIdParticipatesInMatching();
    caseInvalidAndDuplicateRolesCloseLocally();
    printf("halfduplexserver_reentrant_init_test: all cases passed\n");
    return 0;
}
