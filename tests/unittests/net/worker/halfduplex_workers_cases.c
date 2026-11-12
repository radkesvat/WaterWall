/* Both cross-worker pairing orders, setup replay barriers, opaque direct payload identity and transport-owner Finish.
 * Invoked explicitly before workers close admission, when enabled. CTest: waterwall.worker_context_helpers_unit; see
 * the driver for ordering and CLI. */
#include "fixtures/protocols/splice_source.h"
#include "worker_fixture.h"

#ifdef WW_TEST_HALFDUPLEX_WORKERS
#include "HalfDuplexServer/structure.h"

typedef struct half_worker_fixture_s
{
    tunnel_t       *wrapper, *server, *prev, *next;
    tunnel_t       *peer_wrapper, *peer, *peer_prev;
    tunnel_t       *transport_wrapper[2], *transport_prev[2];
    tunnel_chain_t *chain;
    line_t         *halves[2], *main;
    sbuf_t         *expected;
    atomic_uint     finishes, payloads, pauses, resumes;
    bool            download_first;
    bool            in_init;
} half_worker_fixture_t;
static half_worker_fixture_t hw;

static sbuf_t *halfWorkerBytes(const void *data, uint32_t length)
{
#if WW_HAVE_SPLICE
    sbuf_t *buf = sbufCreateSplice(64);
    require(testSpliceSourceInitPipe(buf) == 0, "HalfDuplex private pipe failed");
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
    require(t == hw.transport_prev[lineGetWID(line)], "HalfDuplex Finish used wrong ingress");
    require(lineIsOnCurrentWorker(line), "HalfDuplex transport finish on wrong worker");
    lineDestroy(line);
    atomicAddExplicit(&hw.finishes, 1, memory_order_release);
}
static void halfWorkerEst(tunnel_t *t, line_t *line)
{
    require(t == hw.transport_prev[lineGetWID(line)], "HalfDuplex Est used wrong ingress");
    require(lineIsOnCurrentWorker(line), "HalfDuplex Est on wrong worker");
}
static void halfWorkerInit(tunnel_t *t, line_t *line)
{
    discard t;
    require(lineGetWID(line) == 0 && lineIsOnCurrentWorker(line), "pair did not move to first half worker");
    hw.main                       = line;
    hw.in_init                    = true;
    halfduplexserver_lstate_t *ls = lineGetState(line, hw.server);
    // The matched upload may be a PipeTunnel companion. Reenter its actual
    // server callback on the pairing worker while next Init is still active.
    halfduplexserverTunnelUpStreamPayload(ls->upload_tunnel, ls->upload_line, halfWorkerBytes("next", 4));
    hw.in_init = false;
}
static void halfWorkerPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    require(t == (line == hw.main ? hw.next : hw.transport_prev[lineGetWID(line)]),
            "HalfDuplex payload used wrong ingress or application path");
    require(lineIsOnCurrentWorker(line), "HalfDuplex payload on wrong worker");
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
static void halfWorkerPause(tunnel_t *t, line_t *line)
{
    require(t == hw.next && line == hw.main && ! hw.in_init && lineIsOnCurrentWorker(line),
            "HalfDuplex download pressure used wrong application or Init ordering");
    atomicAddExplicit(&hw.pauses, 1, memory_order_release);
}
static void halfWorkerResume(tunnel_t *t, line_t *line)
{
    require(t == hw.next && line == hw.main && lineIsOnCurrentWorker(line),
            "HalfDuplex download resume used wrong application");
    atomicAddExplicit(&hw.resumes, 1, memory_order_release);
}
static void halfWorkerReleasePressure(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;
    tunnelUpStreamResume(hw.transport_wrapper[worker->wid], hw.halves[worker->wid]);
    atomicStoreExplicit((atomic_bool *) arg1, true, memory_order_release);
}
static void halfWorkerCreate(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard        arg2;
    discard        arg3;
    const unsigned index = worker->wid;
    line_t        *line  = lineCreate(tunnelchainGetLinePools(hw.chain), worker->wid);
    hw.halves[index]     = line;
    tunnelUpStreamInit(hw.transport_wrapper[index], line);
    bool    download  = (index == 0) == hw.download_first;
    if (download)
        tunnelUpStreamPause(hw.transport_wrapper[index], line);
    uint8_t intro[21] = {0};
    intro[0]          = download ? kHLFDCmdDownload : kHLFDCmdUpload;
    intro[16]         = 73;
    memoryCopy(intro + 17, "body", 4);
    tunnelUpStreamPayload(hw.transport_wrapper[index], line, halfWorkerBytes(intro, download ? 17 : 21));
    atomicStoreExplicit((atomic_bool *) arg1, true, memory_order_release);
}
static void halfWorkerSend(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard  worker;
    discard  arg2;
    discard  arg3;
    unsigned upload_index = hw.download_first ? 1 : 0;
    hw.expected           = halfWorkerBytes("body", 4);
    tunnelUpStreamPayload(hw.transport_wrapper[upload_index], hw.halves[upload_index], hw.expected);
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
void testHalfDuplexWorkers(void)
{
    for (unsigned mode = 0; mode < 3; ++mode)
        for (unsigned order = 0; order < 2; ++order)
        {
            memoryZero(&hw, sizeof(hw));
            atomic_init(&hw.finishes, 0);
            atomic_init(&hw.payloads, 0);
            atomic_init(&hw.pauses, 0);
            atomic_init(&hw.resumes, 0);
            hw.download_first  = order != 0;
            node_t server_node = {.next = (char *) "application"};
            hw.wrapper         = halfduplexserverTunnelCreate(&server_node);
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
            hw.next->fnPauseU             = halfWorkerPause;
            hw.next->fnResumeU            = halfWorkerResume;
            hw.next->fnPayloadU           = halfWorkerPayload;
            hw.chain                      = tunnelchainCreate(getWorkersCount());
            hw.chain->sum_line_state_size = hw.wrapper->lstate_size + hw.server->lstate_size;
            hw.wrapper->chain = hw.server->chain = hw.chain;
            hw.transport_wrapper[0] = hw.transport_wrapper[1] = hw.wrapper;
            hw.transport_prev[0] = hw.transport_prev[1] = hw.prev;
            if (mode != 0)
            {
                hw.peer_wrapper = halfduplexserverTunnelCreate(&server_node);
                require(hw.peer_wrapper != NULL, "HalfDuplex peer wrapper creation failed");
                hw.peer = *(tunnel_t **) tunnelGetState(hw.peer_wrapper);
                ((halfduplexserver_tstate_t *) tunnelGetState(hw.peer))->owner = hw.server;
                hw.peer_prev                                                   = tunnelCreate(NULL, 0, 0);
                hw.peer_prev->fnEstD                                           = halfWorkerEst;
                hw.peer_prev->fnFinD                                           = halfWorkerFinish;
                hw.peer_prev->fnPayloadD                                       = halfWorkerPayload;
                tunnelBind(hw.peer_prev, hw.peer_wrapper);
                tunnelBind(hw.peer_wrapper, hw.peer);
                hw.peer_wrapper->lstate_offset = hw.chain->sum_line_state_size;
                hw.peer->lstate_offset         = hw.peer_wrapper->lstate_offset + hw.peer_wrapper->lstate_size;
                hw.chain->sum_line_state_size += hw.peer_wrapper->lstate_size + hw.peer->lstate_size;
                hw.peer_wrapper->chain = hw.peer->chain = hw.chain;
                hw.transport_wrapper[mode - 1]          = hw.peer_wrapper;
                hw.transport_prev[mode - 1]             = hw.peer_prev;
                hw.peer_wrapper->onStart(hw.peer_wrapper);
            }
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
            halfWorkerWait(&hw.pauses, 1);
            atomicStoreExplicit(&done, false, memory_order_release);
            if (hw.download_first)
                halfWorkerReleasePressure(getWorker(0), &done, NULL, NULL);
            else
            {
                require(sendWorkerMessageForceQueueWithCleanup(
                            1, (WorkerMessageCallback) halfWorkerReleasePressure, NULL, &done, NULL, NULL),
                        "download Resume submission failed");
                waitForAtomicBool(&done, "download Resume not submitted");
            }
            halfWorkerWait(&hw.resumes, 1);
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
            if (hw.peer_wrapper != NULL)
            {
                pipetunnelDestroy(hw.peer_wrapper, testShutdownContext());
                tunnelDestroy(hw.peer_prev);
            }
            tunnelDestroy(hw.prev);
            tunnelDestroy(hw.next);
        }
}
#endif
