/*
 * Covers: lwip shutdown; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Checks: Assertion labels include: retained pbuf freed on foreign worker; retained pbuf released before
 * detached-message teardown; owner engine unavailable; UDP setup failed
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.lwip_shutdown_unit
 */
#include "engine_runtime.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "lwip/memp.h"
#include "lwip/priv/tcp_priv.h"
#include "worker_messages.h"
#include "wwapi.h"

typedef struct retained_pbuf_s
{
    struct pbuf_custom custom;
    uint8_t            payload[64];
    wid_t              owner;
    unsigned           freed;
} retained_pbuf_t;
static retained_pbuf_t retained[2];
static atomic_uint     ready;
static atomic_uint     settled;

static void freeRetainedPbuf(struct pbuf *p)
{
    retained_pbuf_t *r = (retained_pbuf_t *) p;
    require(currentThreadIsEventWorkerWID(r->owner), "retained pbuf freed on foreign worker");
    require(getWorker(r->owner)->loop == NULL, "retained pbuf released before detached-message teardown");
    ++r->freed;
}
static void pending(void *worker, void *a, void *b, void *c)
{
    (void) worker;
    (void) a;
    (void) b;
    (void) c;
    atomic_fetch_add_explicit(&settled, 1, memory_order_relaxed);
}
static void cancelled(void *a, void *b, void *c, worker_message_cancel_reason_e reason)
{
    (void) a;
    (void) b;
    (void) c;
    (void) reason;
    atomic_fetch_add_explicit(&settled, 1, memory_order_relaxed);
}
static void install(void *worker_ptr, void *arg, void *b, void *c)
{
    (void) b;
    (void) c;
    worker_t        *worker  = worker_ptr;
    retained_pbuf_t *r       = arg;
    r->owner                 = worker->wid;
    ww_lwip_engine_t *engine = wwLwipRuntimeGet(worker->wid), *previous;
    require(engine != NULL && wwLwipEngineEnter(engine, &previous), "owner engine unavailable");
    struct tcp_pcb *pcb = tcp_new();
    require(pcb != NULL, "TCP PCB allocation failed");
    pcb->state = ESTABLISHED;
    TCP_REG_ACTIVE(pcb);
    struct tcp_seg *segment = memp_malloc(MEMP_TCP_SEG);
    require(segment != NULL, "segment allocation failed");
    memset(segment, 0, sizeof(*segment));
    r->custom.custom_free_function = freeRetainedPbuf;
    segment->p =
        pbuf_alloced_custom(PBUF_RAW, sizeof(r->payload), PBUF_REF, &r->custom, r->payload, sizeof(r->payload));
    require(segment->p != NULL, "custom pbuf allocation failed");
    pcb->ooseq          = segment;
    struct udp_pcb *udp = udp_new();
    require(udp != NULL && udp_bind(udp, NULL, 0) == ERR_OK, "UDP setup failed");
    wwLwipEngineLeave(engine, previous);
    require(sendWorkerMessageForceQueueWithCleanup(worker->wid, pending, cancelled, NULL, NULL, NULL) ==
                kWorkerMessageSubmitAccepted,
            "pending message refused");
    if (atomic_fetch_add_explicit(&ready, 1, memory_order_acq_rel) == 1)
        require(requestProgramShutdown(0), "shutdown request refused");
}
int main(void)
{
    testCaseSet("lwip_shutdown_test");
    static char            off[]        = "OFF";
    ww_construction_data_t data         = {0};
    data.workers_count                  = 3;
    data.ram_profile                    = 4;
    data.mtu_size                       = 1500;
    data.internal_logger_data.log_level = off;
    data.core_logger_data.log_level     = off;
    data.network_logger_data.log_level  = off;
    data.dns_logger_data.log_level      = off;
    require(wwStartupSucceeded(createGlobalState(data)), "global startup failed");
    require(getWorkersCount() == 3 && getTotalWorkersCount() == 3, "runtime allocated an extra stack worker");
    initTcpIpStack();
    initTcpIpStack();
    require(GSTATE.flag_lwip_initialized && wwLwipTestTcpIsnSecretIsInitialized(), "shared bootstrap unavailable");
    for (wid_t i = 0; i < 2; ++i)
        require(sendWorkerMessageForceQueueWithCleanup(i, install, NULL, &retained[i], NULL, NULL) ==
                    kWorkerMessageSubmitAccepted,
                "setup publication refused");
    require(applicationShutdownCommitRuntime(), "runtime commit failed");
    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);
    require(wloopRun(getWorkerLoop(0)) == kWLoopRunQuiesced, "main loop did not quiesce");
    globalstateRunShutdownSequence();
    require(retained[0].freed == 1 && retained[1].freed == 1, "retained pbuf not released exactly once");
    require(atomicLoadExplicit(&settled, memory_order_relaxed) == 2, "pending messages not settled exactly once");
    require(! GSTATE.flag_lwip_initialized && ! wwLwipTestTcpIsnSecretIsInitialized(),
            "shared finalization left ISN secret live");
    require(wwLwipShutdown(), "repeated finalization failed");
    destroyGlobalState();
    puts("production owner-engine shutdown, detached pbufs, pending settlement and final ISN erasure passed");
    return 0;
}
