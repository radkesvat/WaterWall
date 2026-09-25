/* Included by worker_context_helpers_test after its worker/message fixtures. */
#ifdef WW_TEST_HALFDUPLEX_WORKERS
#include "HalfDuplexServer/structure.h"

typedef struct half_worker_fixture_s
{
    tunnel_t       *wrapper, *server, *prev, *next;
    tunnel_chain_t *chain;
    line_t         *halves[2], *main;
    sbuf_t         *expected;
    atomic_uint     finishes, payloads;
    bool            download_first;
    bool            in_init;
} half_worker_fixture_t;
static half_worker_fixture_t hw;

static sbuf_t *halfWorkerBytes(const void *data, uint32_t length)
{
#if WW_HAVE_SPLICE
    sbuf_t *buf = sbufCreateSplice(64);
    require(sbufSpliceInitPipe(buf, 0) == 0, "HalfDuplex private pipe failed");
    require(write(sbufSpliceMetadata(buf).pipefd[1], data, length) == length, "HalfDuplex pipe write failed");
    buf->capacity += length;
    sbufSetLength(buf, length);
    return buf;
#else
    sbuf_t *buf = sbufCreate(length);
    sbufSetLength(buf, length);
    memoryCopy(sbufGetMutablePtr(buf), data, length);
    return buf;
#endif
}
static void halfWorkerFinish(tunnel_t *t, line_t *line)
{
    discard t;
    require(lineIsOnCurrentEventWorker(line), "HalfDuplex transport finish on wrong worker");
    lineDestroy(line);
    atomicAddExplicit(&hw.finishes, 1, memory_order_release);
}
static void halfWorkerEst(tunnel_t *t, line_t *line)
{
    discard t;
    require(lineIsOnCurrentEventWorker(line), "HalfDuplex Est on wrong worker");
}
static void halfWorkerInit(tunnel_t *t, line_t *line)
{
    discard t;
    require(lineGetWID(line) == 0 && lineIsOnCurrentEventWorker(line), "pair did not move to first half worker");
    hw.main                       = line;
    hw.in_init                    = true;
    halfduplexserver_lstate_t *ls = lineGetState(line, hw.server);
    // The matched upload may be a PipeTunnel companion. Reenter its actual
    // server callback on the pairing worker while next Init is still active.
    halfduplexserverTunnelUpStreamPayload(hw.server, ls->upload_line, halfWorkerBytes("next", 4));
    hw.in_init = false;
}
static void halfWorkerPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    require(lineIsOnCurrentEventWorker(line), "HalfDuplex payload on wrong worker");
    unsigned count = atomicLoadExplicit(&hw.payloads, memory_order_acquire);
    require(! hw.in_init, "remote upload bypassed next Init barrier");
    if (count < 2)
        require(! sbufIsSplice(buf), "remote setup replay was not ordinary");
    else
        require(buf == hw.expected && sbufIsSplice(buf) == (bool) WW_HAVE_SPLICE,
                "remote direct payload lost wrapper identity");
    sbuf_t *ordinary = buf;
    if (sbufIsSplice(buf))
    {
        ordinary = sbufCreate(4);
        sbufSpliceReadToBuffer(buf, ordinary, 4);
        sbufDestroy(buf);
    }
    require(sbufGetLength(ordinary) == 4 && memoryEqual(sbufGetRawPtr(ordinary), count == 1 ? "next" : "body", 4),
            "HalfDuplex worker replay changed bytes");
    sbufDestroy(ordinary);
    atomicAddExplicit(&hw.payloads, 1, memory_order_release);
}
static void halfWorkerCreate(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard        arg2;
    discard        arg3;
    const unsigned index = worker->wid;
    line_t        *line  = lineCreate(tunnelchainGetLinePools(hw.chain), worker->wid);
    hw.halves[index]     = line;
    tunnelUpStreamInit(hw.wrapper, line);
    bool    download  = (index == 0) == hw.download_first;
    uint8_t intro[21] = {0};
    intro[0]          = download ? kHLFDCmdDownload : kHLFDCmdUpload;
    intro[16]         = 73;
    memoryCopy(intro + 17, "body", 4);
    tunnelUpStreamPayload(hw.wrapper, line, halfWorkerBytes(intro, download ? 17 : 21));
    atomicStoreExplicit((atomic_bool *) arg1, true, memory_order_release);
}
static void halfWorkerSend(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard  worker;
    discard  arg2;
    discard  arg3;
    unsigned upload_index = hw.download_first ? 1 : 0;
    hw.expected           = halfWorkerBytes("body", 4);
    tunnelUpStreamPayload(hw.wrapper, hw.halves[upload_index], hw.expected);
    atomicStoreExplicit((atomic_bool *) arg1, true, memory_order_release);
}
static void halfWorkerWait(atomic_uint *value, unsigned target)
{
    for (unsigned i = 0; i < 5000 && atomicLoadExplicit(value, memory_order_acquire) != target; ++i)
    {
        discard wloopProcessEvents(getWorkerLoop(0), 0);
        wwSleepMS(1);
    }
    require(atomicLoadExplicit(value, memory_order_acquire) == target, "HalfDuplex cross-worker callback missing");
}
static void testHalfDuplexWorkers(void)
{
    for (unsigned order = 0; order < 2; ++order)
    {
        memoryZero(&hw, sizeof(hw));
        atomic_init(&hw.finishes, 0);
        atomic_init(&hw.payloads, 0);
        hw.download_first = order != 0;
        hw.wrapper        = halfduplexserverTunnelCreate(NULL);
        require(hw.wrapper != NULL, "HalfDuplex wrapper creation failed");
        hw.server = *(tunnel_t **) tunnelGetState(hw.wrapper);
        hw.prev   = tunnelCreate(NULL, 0, 0);
        hw.next   = tunnelCreate(NULL, 0, 0);
        tunnelBind(hw.prev, hw.wrapper);
        tunnelBind(hw.wrapper, hw.server);
        tunnelBind(hw.server, hw.next);
        hw.wrapper->lstate_offset     = 0;
        hw.server->lstate_offset      = hw.wrapper->lstate_size;
        hw.prev->fnEstD               = halfWorkerEst;
        hw.prev->fnFinD               = halfWorkerFinish;
        hw.prev->fnPayloadD           = halfWorkerPayload;
        hw.next->fnInitU              = halfWorkerInit;
        hw.next->fnPayloadU           = halfWorkerPayload;
        hw.chain                      = tunnelchainCreate(getWorkersCount());
        hw.chain->sum_line_state_size = hw.wrapper->lstate_size + hw.server->lstate_size;
        hw.wrapper->chain = hw.server->chain = hw.chain;
        tunnelchainFinalize(hw.chain);
        hw.wrapper->onStart(hw.wrapper);
        atomic_bool done;
        atomic_init(&done, false);
        halfWorkerCreate(getWorker(0), &done, NULL, NULL);
        atomicStoreExplicit(&done, false, memory_order_release);
        require(sendWorkerMessageForceQueueWithCleanup(
                    1, (WorkerMessageCallback) halfWorkerCreate, NULL, &done, NULL, NULL),
                "second-half submission failed");
        waitForAtomicBool(&done, "second half not created");
        halfWorkerWait(&hw.payloads, 2);
        atomicStoreExplicit(&done, false, memory_order_release);
        if (hw.download_first)
        {
            require(sendWorkerMessageForceQueueWithCleanup(
                        1, (WorkerMessageCallback) halfWorkerSend, NULL, &done, NULL, NULL),
                    "upload submission failed");
            waitForAtomicBool(&done, "upload not submitted");
        }
        else
            halfWorkerSend(getWorker(0), &done, NULL, NULL);
        halfWorkerWait(&hw.payloads, 3);
        hw.expected = halfWorkerBytes("body", 4);
        halfduplexserverTunnelDownStreamPayload(hw.server, hw.main, hw.expected);
        halfWorkerWait(&hw.payloads, 4);
        halfduplexserverTunnelDownStreamFinish(hw.server, hw.main);
        halfWorkerWait(&hw.finishes, 2);
        atomicStoreExplicit(&done, false, memory_order_release);
        require(sendWorkerMessageForceQueueWithCleanup(
                    1, (WorkerMessageCallback) pipeQueueBarrier, NULL, &done, NULL, NULL),
                "cleanup barrier failed");
        waitForAtomicBool(&done, "cleanup barrier missing");
        discard wloopProcessEvents(getWorkerLoop(0), 0);
        require(masterpoolGetCheckedOut(hw.chain->masterpool_line_pool) == 0, "HalfDuplex worker lines leaked");
        tunnelchainDestroy(hw.chain);
        pipetunnelDestroy(hw.wrapper, testShutdownContext());
        tunnelDestroy(hw.prev);
        tunnelDestroy(hw.next);
    }
}
#endif
