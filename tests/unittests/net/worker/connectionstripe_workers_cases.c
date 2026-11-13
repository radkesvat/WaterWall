/* Real-worker ConnectionStripe lane-zero migration preserves its observed source at application Init.
 * Both migration directions, both JOIN submission orders and IPv4/IPv6 source addresses are exercised.
 * The fixture owns the transport lines; PipeTunnel owns each migrated companion and Stripe owns
 * its application line. CTest: waterwall.worker_context_helpers_unit. */
#include "worker_fixture.h"

#ifdef WW_TEST_CONNECTIONSTRIPE_WORKERS
#include "ConnectionStripeCommon/stripe.h"
#include "ConnectionStripeServer/interface.h"
#include "fixtures/protocols/splice_source.h"

static const uint64_t     stripe_worker_seed = UINT64_C(0xd45701a59960ab23);
static _Thread_local bool force_stripe_worker_seed;

uint64_t __real_fastRand64(void);
uint64_t __wrap_fastRand64(void);
uint64_t __wrap_fastRand64(void)
{
    return force_stripe_worker_seed ? stripe_worker_seed : __real_fastRand64();
}

typedef struct stripe_worker_fixture_s
{
    tunnel_t         *wrapper, *server, *transport, *backend;
    tunnel_chain_t   *chain;
    line_t           *lanes[2], *application;
    address_context_t expected_source;
    uint8_t           id[16];
    wid_t             target;
    atomic_uint       inits, ready, finishes, application_finishes, delivered;
    unsigned          representation;
    bool              trailing;
} stripe_worker_fixture_t;

static stripe_worker_fixture_t sw;

static void stripeWorkerEst(tunnel_t *t, line_t *line)
{
    require(t == sw.transport && lineIsOnCurrentWorker(line), "Stripe transport Est used the wrong owner");
}

static void stripeWorkerTransportPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    require(t == sw.transport && line == sw.lanes[0] && lineIsOnCurrentWorker(line),
            "Stripe READY used the wrong lane or worker");
    require(! sbufIsSplice(buf) && sbufGetLength(buf) == kStripeHeaderSize,
            "Stripe worker fixture received an unexpected control representation");
    const uint8_t type = sbufGetRawPtr(buf)[0];
    require(type == kStripeReady || type == kStripeWindow, "Stripe worker fixture received an unexpected control");
    lineReuseBuffer(line, buf);
    if (type == kStripeReady)
        atomicAddExplicit(&sw.ready, 1, memory_order_release);
}

static void stripeWorkerTransportFinish(tunnel_t *t, line_t *line)
{
    require(t == sw.transport && lineIsOnCurrentWorker(line), "Stripe transport Finish used the wrong owner");
    lineDestroy(line);
    atomicAddExplicit(&sw.finishes, 1, memory_order_release);
}

static void stripeWorkerApplicationInit(tunnel_t *t, line_t *line)
{
    require(t == sw.backend && lineGetWID(line) == sw.target && lineIsOnCurrentWorker(line),
            "Stripe application Init did not run on the deterministic session worker");
    require(lineGetWID(line) != (wid_t) (1 - sw.target), "Stripe lane zero did not migrate");
    address_context_t *source = lineGetSourceAddressContext(line);
    require(addresscontextIsIp(source) && ipAddrCmp(&source->ip_address, &sw.expected_source.ip_address),
            "Stripe lane-zero migration lost the source IP before application Init");
    require(source->port == sw.expected_source.port && source->proto_tcp == sw.expected_source.proto_tcp,
            "Stripe lane-zero migration lost the source port or protocol");
    sw.application = line;
    atomicAddExplicit(&sw.inits, 1, memory_order_release);
}

static void stripeWorkerApplicationFinish(tunnel_t *t, line_t *line)
{
    require(t == sw.backend && line == sw.application && lineIsOnCurrentWorker(line),
            "Stripe application Finish used the wrong line or worker");
    atomicAddExplicit(&sw.application_finishes, 1, memory_order_release);
}

static void stripeWorkerApplicationPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    require(t == sw.backend && line == sw.application && lineIsOnCurrentWorker(line) && lineGetWID(line) == sw.target,
            "Stripe migrated DATA used the wrong application or worker");
    uint8_t bytes[5];
    require(sbufGetLength(buf) == sizeof(bytes), "Stripe JOIN replay lost its trailing DATA length");
    sbufReadRangeToMemory(buf, bytes, sizeof(bytes));
    require(memoryEqual(bytes, "hello", sizeof(bytes)), "Stripe JOIN replay corrupted its trailing DATA");
    lineReuseBuffer(line, buf);
    atomicAddExplicit(&sw.delivered, 1, memory_order_release);
}

static sbuf_t *stripeWorkerInput(worker_t *worker, const uint8_t *bytes, size_t length)
{
#if WW_HAVE_SPLICE
    if (sw.representation != 0)
    {
        const size_t prefix = sw.representation == 2 ? min(length, (size_t) 7) : 0;
        sbuf_t      *buf    = testSpliceSourceBuffer(32, (uint32_t) (length - prefix));
        require(write(sbufSpliceMetadata(buf).pipefd[1], bytes + prefix, length - prefix) ==
                    (ssize_t) (length - prefix),
                "Stripe worker source pipe population failed");
        buf->capacity = buf->initial_headroom + length - prefix;
        sbufSetLength(buf, length - prefix);
        sbufShiftLeft(buf, prefix);
        memoryCopy(sbufGetMutablePtr(buf), bytes, prefix);
        return buf;
    }
#endif
    sbuf_t *buf = bufferpoolGetBestFit(worker->buffer_pool, length, 0);
    sbufSetLength(buf, length);
    memoryCopy(sbufGetMutablePtr(buf), bytes, length);
    return buf;
}

static void stripeWorkerCreateLane(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard  arg3;
    unsigned index = (unsigned) (uintptr_t) arg2;
    require(worker->wid == (index == 0 ? 1 - sw.target : sw.target), "Stripe lane created on the wrong worker");
    line_t *line    = lineCreate(tunnelchainGetLinePools(sw.chain), worker->wid);
    sw.lanes[index] = line;
    if (index == 0)
        addresscontextCopy(lineGetSourceAddressContext(line), &sw.expected_source);
    else
        require(addresscontextSetIpAddressPortProtocol(
                    lineGetSourceAddressContext(line), "198.51.100.22", 32000, IPPROTO_TCP),
                "Stripe alternate source address setup failed");
    tunnelUpStreamInit(sw.wrapper, line);
    uint8_t intro[kStripeJoinSize + kStripeHeaderSize + 5] = {0};
    intro[0]                                               = kStripeJoin;
    intro[7]                                               = 24;
    memoryCopy(intro + kStripeHeaderSize, sw.id, sizeof(sw.id));
    intro[41]           = (uint8_t) index;
    intro[43]           = 2;
    intro[46]           = 64; /* 16384-byte receive window, big endian. */
    const bool trailing = index == 0 && sw.trailing;
    if (trailing)
    {
        intro[kStripeJoinSize]     = kStripeData;
        intro[kStripeJoinSize + 7] = 5;
        memoryCopy(intro + kStripeJoinSize + kStripeHeaderSize, "hello", 5);
    }
    const size_t length = trailing ? sizeof(intro) : kStripeJoinSize;
    const size_t split  = sw.representation == 0 ? 0 : 19;
    if (split)
        tunnelUpStreamPayload(sw.wrapper, line, stripeWorkerInput(worker, intro, split));
    tunnelUpStreamPayload(sw.wrapper, line, stripeWorkerInput(worker, intro + split, length - split));
    atomicStoreExplicit((atomic_bool *) arg1, true, memory_order_release);
}

static void stripeWorkerCloseLane(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;
    line_t *line = sw.lanes[0];
    require(worker->wid == lineGetWID(line), "Stripe lane close ran on the wrong owner");
    tunnelUpStreamFin(sw.wrapper, line);
    lineDestroy(line);
    atomicAddExplicit(&sw.finishes, 1, memory_order_release);
    atomicStoreExplicit((atomic_bool *) arg1, true, memory_order_release);
}

static void stripeWorkerDrain(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;
    sw.server->onWorkerQuiesce(sw.server, worker->wid, testShutdownContext());
    sw.server->onWorkerStop(sw.server, worker->wid, testShutdownContext());
    sw.wrapper->onWorkerStop(sw.wrapper, worker->wid, testShutdownContext());
    atomicStoreExplicit((atomic_bool *) arg1, true, memory_order_release);
}

static void stripeWorkerCall(wid_t wid, WorkerMessageCallback callback, void *arg)
{
    atomic_bool done;
    atomic_init(&done, false);
    if (wid == 0)
        callback(getWorker(0), &done, arg, NULL);
    else
        require(sendWorkerMessageForceQueueWithCleanup(wid, callback, NULL, &done, arg, NULL),
                "Stripe worker callback submission failed");
    waitForAtomicBool(&done, "Stripe worker callback did not complete");
}

static void stripeWorkerWait(atomic_uint *value, unsigned target)
{
    for (unsigned i = 0; i < 5000 && atomicLoadExplicit(value, memory_order_acquire) != target; ++i)
    {
        discard wloopProcessEvents(getWorkerLoop(0), 0);
        wwSleepMS(1);
    }
    require(atomicLoadExplicit(value, memory_order_acquire) == target, "Stripe cross-worker callback missing");
}

void testConnectionStripeWorkers(void)
{
    for (unsigned representation = 0; representation < (WW_HAVE_SPLICE ? 3U : 1U); ++representation)
        for (unsigned ipv6 = 0; ipv6 < 2; ++ipv6)
            for (wid_t target = 0; target < 2; ++target)
                for (unsigned order = 0; order < 2; ++order)
                {
                    memoryZero(&sw, sizeof(sw));
                    atomic_init(&sw.inits, 0);
                    atomic_init(&sw.ready, 0);
                    atomic_init(&sw.finishes, 0);
                    atomic_init(&sw.application_finishes, 0);
                    atomic_init(&sw.delivered, 0);
                    sw.target         = target;
                    sw.representation = representation;
                    sw.trailing       = order == 1;
                    require(addresscontextSetIpAddressPortProtocol(
                                &sw.expected_source, ipv6 ? "2001:db8::45" : "127.0.0.1", 23456, IPPROTO_TCP),
                            "Stripe expected source address setup failed");
                    bool found = false;
                    for (unsigned id = 0; id < 65536 && ! found; ++id)
                    {
                        sw.id[0] = (uint8_t) id;
                        sw.id[1] = (uint8_t) (id >> 8);
                        found =
                            calcHashBytesSeed(sw.id, sizeof(sw.id), stripe_worker_seed) % getWorkersCount() == target;
                    }
                    require(found, "Stripe fixture could not select its session worker");
                    node_t server_node       = {.next = (char *) "backend"};
                    force_stripe_worker_seed = true;
                    sw.wrapper               = connectionstripeserverTunnelCreate(&server_node);
                    force_stripe_worker_seed = false;
                    require(sw.wrapper != NULL, "Stripe worker server creation failed");
                    sw.server    = *(tunnel_t **) tunnelGetState(sw.wrapper);
                    sw.transport = tunnelCreate(NULL, 0, 0);
                    sw.backend   = tunnelCreate(NULL, 0, 0);
                    tunnelBind(sw.transport, sw.wrapper);
                    tunnelBind(sw.wrapper, sw.server);
                    tunnelBind(sw.server, sw.backend);
                    sw.wrapper->lstate_offset     = 0;
                    sw.server->lstate_offset      = sw.wrapper->lstate_size;
                    sw.transport->fnEstD          = stripeWorkerEst;
                    sw.transport->fnPayloadD      = stripeWorkerTransportPayload;
                    sw.transport->fnFinD          = stripeWorkerTransportFinish;
                    sw.backend->fnInitU           = stripeWorkerApplicationInit;
                    sw.backend->fnFinU            = stripeWorkerApplicationFinish;
                    sw.backend->fnPayloadU        = stripeWorkerApplicationPayload;
                    sw.chain                      = tunnelchainCreate(getWorkersCount());
                    sw.chain->sum_line_state_size = sw.wrapper->lstate_size + sw.server->lstate_size;
                    sw.wrapper->chain = sw.server->chain = sw.chain;
                    tunnelchainFinalize(sw.chain);
                    sw.wrapper->onStart(sw.wrapper);
                    for (unsigned arrived = 0; arrived < 2; ++arrived)
                    {
                        unsigned index = arrived ^ order;
                        stripeWorkerCall(index == 0 ? 1 - target : target,
                                         (WorkerMessageCallback) stripeWorkerCreateLane,
                                         (void *) (uintptr_t) index);
                    }
                    stripeWorkerWait(&sw.inits, 1);
                    stripeWorkerWait(&sw.ready, 1);
                    stripeWorkerWait(&sw.delivered, sw.trailing ? 1 : 0);
                    stripeWorkerCall(1 - target, (WorkerMessageCallback) stripeWorkerCloseLane, NULL);
                    stripeWorkerWait(&sw.finishes, 2);
                    stripeWorkerWait(&sw.application_finishes, 1);
                    stripeWorkerCall(1, (WorkerMessageCallback) stripeWorkerDrain, NULL);
                    stripeWorkerCall(0, (WorkerMessageCallback) stripeWorkerDrain, NULL);
                    stripeWorkerCall(1, (WorkerMessageCallback) pipeQueueBarrier, NULL);
                    discard wloopProcessEvents(getWorkerLoop(0), 0);
                    require(masterpoolGetCheckedOut(sw.chain->masterpool_line_pool) == 0, "Stripe worker lines leaked");
                    tunnelchainDestroy(sw.chain);
                    pipetunnelDestroy(sw.wrapper, testShutdownContext());
                    tunnelDestroy(sw.transport);
                    tunnelDestroy(sw.backend);
                }
}
#endif
