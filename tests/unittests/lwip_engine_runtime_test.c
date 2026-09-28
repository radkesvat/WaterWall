#include "engine_runtime.h"
#include "lwip/memp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/stats.h"
#include "lwip/timeouts.h"
#include "port_registry.h"
#include "wloop_internal.h"
#include "worker_messages.h"
#include "wwapi.h"

#define CHECK(x)                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! (x))                                                                                                     \
        {                                                                                                              \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                                    \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)

typedef struct probe_s
{
    ww_lwip_engine_t *engine;
    struct netif      netif;
    uint8_t           owner;
    uint16_t          retransmit_port, timewait_port;
    unsigned          fired, immediate, due, retransmitted, polled;
    bool              write_refused, write_completed, earlier_checked;
} probe_t;
static probe_t                 probes[2];
static pthread_barrier_t       poll_pressure;
static uint32_t                clock_offset;
static atomic_bool             finished[2];
static bool                    teardown_detached[3];
static _Thread_local bool      fail_next_calloc;
static _Thread_local unsigned  timer_adds;
static _Thread_local wtimer_t *last_timer;

wtimer_t *__real_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t delay, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t delay, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t delay, uint32_t repeat)
{
    ++timer_adds;
    last_timer = __real_wtimerAdd(loop, cb, delay, repeat);
    return last_timer;
}
u32_t __real_sys_now(void);
u32_t __wrap_sys_now(void);
void *__real_calloc(size_t count, size_t size);
void *__wrap_calloc(size_t count, size_t size);
void  __real_nodemanagerQuiesceWorker(wid_t owner, const ww_lifecycle_context_t *context);
void  __wrap_nodemanagerQuiesceWorker(wid_t owner, const ww_lifecycle_context_t *context);
void  __real_workerMessagesDestroyDetached(worker_message_queue_t *queue);
void  __wrap_workerMessagesDestroyDetached(worker_message_queue_t *queue);

u32_t __wrap_sys_now(void)
{
    return __real_sys_now() + clock_offset;
}
void *__wrap_calloc(size_t count, size_t size)
{
    if (fail_next_calloc)
    {
        fail_next_calloc = false;
        return NULL;
    }
    return __real_calloc(count, size);
}
void __wrap_nodemanagerQuiesceWorker(wid_t owner, const ww_lifecycle_context_t *context)
{
    __real_nodemanagerQuiesceWorker(owner, context);
}
void __wrap_workerMessagesDestroyDetached(worker_message_queue_t *queue)
{
    __real_workerMessagesDestroyDetached(queue);
    /* Construction rollback also settles never-started workers on main. */
    if (! GSTATE.flag_lwip_initialized)
        return;
    const wid_t owner = getCurrentEventWorkerWID();
    CHECK(getWorker(owner)->loop == NULL);
    teardown_detached[owner] = true;
}
static void put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t) (value >> 8);
    p[1] = (uint8_t) value;
}
static void put32(uint8_t *p, uint32_t value)
{
    put16(p, (uint16_t) (value >> 16));
    put16(p + 2, (uint16_t) value);
}
static uint16_t get16(const uint8_t *p)
{
    return (uint16_t) (((unsigned) p[0] << 8) | p[1]);
}
static err_t output(struct netif *netif, struct pbuf *p, const ip4_addr_t *destination)
{
    (void) destination;
    probe_t *probe = netif->state;
    CHECK(currentThreadIsEventWorkerWID(probe->owner));
    uint8_t bytes[40];
    if (pbuf_copy_partial(p, bytes, sizeof(bytes), 0) == sizeof(bytes) && bytes[9] == 6 && (bytes[33] & TCP_SYN) != 0 &&
        get16(bytes + 20) == probe->retransmit_port)
        ++probe->retransmitted;
    return ERR_OK;
}
static err_t init_netif(struct netif *netif)
{
    netif->name[0] = 'r';
    netif->name[1] = 't';
    netif->mtu     = 1500;
    netif->output  = output;
    return ERR_OK;
}
static void inject(probe_t *probe, uint16_t port, uint8_t flags, uint32_t sequence, uint32_t ack)
{
    uint8_t bytes[40] = {0x45};
    put16(bytes + 2, sizeof(bytes));
    bytes[8]  = 64;
    bytes[9]  = 6;
    bytes[12] = 10;
    bytes[15] = 2;
    bytes[16] = 10;
    bytes[19] = 1;
    put16(bytes + 20, 80);
    put16(bytes + 22, port);
    put32(bytes + 24, sequence);
    put32(bytes + 28, ack);
    bytes[32] = 0x50;
    bytes[33] = flags;
    put16(bytes + 34, 16384);
    uint8_t pseudo[32] = {0};
    memcpy(pseudo, bytes + 12, 8);
    pseudo[9]  = 6;
    pseudo[11] = 20;
    memcpy(pseudo + 12, bytes + 20, 20);
    uint16_t sum = (uint16_t) ~wwLwipChecksum(pseudo, sizeof(pseudo));
    memcpy(bytes + 36, &sum, 2);
    sum = (uint16_t) ~wwLwipChecksum(bytes, 20);
    memcpy(bytes + 10, &sum, 2);
    struct pbuf *p = pbuf_alloc(PBUF_RAW, sizeof(bytes), PBUF_POOL);
    CHECK(p != NULL);
    CHECK(pbuf_take(p, bytes, sizeof(bytes)) == ERR_OK);
    CHECK(wwLwipEngineInput(probe->engine, p, &probe->netif) == ERR_OK);
}
static struct tcp_pcb *connectPcb(probe_t *probe, bool established)
{
    struct tcp_pcb *pcb = tcp_new();
    CHECK(pcb != NULL);
    CHECK(tcp_bind_netif(pcb, &probe->netif) == ERR_OK);
    ip_addr_t peer;
    IP_ADDR4(&peer, 10, 0, 0, 2);
    CHECK(tcp_connect(pcb, &peer, 80, NULL) == ERR_OK);
    if (established)
    {
        inject(probe, pcb->local_port, TCP_SYN | TCP_ACK, 9000, pcb->snd_nxt);
        CHECK(pcb->state == ESTABLISHED);
    }
    return pcb;
}
static err_t onPoll(void *argument, struct tcp_pcb *pcb)
{
    probe_t *probe = argument;
    CHECK(currentThreadIsEventWorkerWID(probe->owner));
    ++probe->polled;
    if (! probe->write_refused)
    {
        void    *held[MEMP_NUM_TCP_SEG];
        unsigned count = 0;
        while (count < MEMP_NUM_TCP_SEG && (held[count] = memp_malloc(MEMP_TCP_SEG)) != NULL)
            ++count;
        int result = pthread_barrier_wait(&poll_pressure);
        CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
        CHECK(tcp_write(pcb, "x", 1, TCP_WRITE_FLAG_COPY) == ERR_MEM);
        result = pthread_barrier_wait(&poll_pressure);
        CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
        for (unsigned i = 0; i < count; ++i)
            memp_free(MEMP_TCP_SEG, held[i]);
        probe->write_refused = true;
    }
    else if (! probe->write_completed)
    {
        err_t result = tcp_write(pcb, "x", 1, TCP_WRITE_FLAG_COPY);
        if (result == ERR_OK)
        {
            probe->write_completed = true;
            CHECK(tcp_output(pcb) == ERR_OK);
        }
        else
            CHECK(result == ERR_MEM);
    }
    return ERR_OK;
}
static void timeout(void *argument)
{
    probe_t *probe = argument;
    CHECK(wwLwipEngineCurrent() == probe->engine && currentThreadIsEventWorkerWID(probe->owner));
    ++probe->fired;
}
static void dueTimeout(void *argument)
{
    ++((probe_t *) argument)->due;
}
static void immediateTimeout(void *argument)
{
    probe_t *probe = argument;
    ++probe->immediate;
    sys_timeout(0, immediateTimeout, argument);
}
static void earlier(wtimer_t *timer)
{
    probe_t *probe = weventGetUserdata(timer);
    CHECK(probe->fired == 1);
    probe->earlier_checked = true;
}
static void finish(wtimer_t *timer)
{
    probe_t *probe = weventGetUserdata(timer);
    CHECK(probe->fired == 1 && probe->due == 1 && probe->earlier_checked);
    CHECK(probe->retransmitted > 0 && probe->polled >= 2 && probe->write_refused && probe->write_completed);
    CHECK(wwLwipTestPortOccupancy(kWwLwipTcp, probe->timewait_port) == 0);
    atomicStoreExplicit(&finished[probe->owner], true, memory_order_release);
    if (probe->owner == 0 && ! atomicLoadExplicit(&finished[1], memory_order_acquire))
    {
        CHECK(wtimerReset(timer, 10));
        return;
    }
    worker_t                       *worker = getWorker(probe->owner);
    worker_quiesce_request_result_e result =
        probe->owner == 0 ? workerInstallApplicationQuiesceRequest(worker, wwLifecycleProcessShutdown())
                          : workerRequestQuiesceResult(worker);
    CHECK(result != kWorkerQuiesceRequestUnavailable);
    CHECK(wwLwipRuntimeGet(probe->owner) == NULL);
}
static void setup(void *worker_ptr, void *argument, void *unused1, void *unused2)
{
    (void) unused1;
    (void) unused2;
    worker_t *worker = worker_ptr;
    probe_t  *probe  = argument;
    CHECK(worker->wid == probe->owner);
    unsigned timers  = worker->loop->ntimers;
    fail_next_calloc = true;
    CHECK(wwLwipRuntimeGet(worker->wid) == NULL);
    CHECK(worker->loop->ntimers == timers);
    probe->engine = wwLwipRuntimeGet(worker->wid);
    CHECK(probe->engine != NULL);
    CHECK(wwLwipRuntimeGet(worker->wid) == probe->engine);
    CHECK(wwLwipRuntimeGet((uint8_t) (1 - worker->wid)) == NULL);
    ww_lwip_engine_t *previous;
    CHECK(wwLwipEngineEnter(probe->engine, &previous));
    ip4_addr_t address, mask, gateway;
    IP4_ADDR(&address, 10, 0, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gateway);
    CHECK(netif_add(&probe->netif, &address, &mask, &gateway, probe, init_netif, ip_input) != NULL);
    netif_set_up(&probe->netif);
    netif_set_link_up(&probe->netif);
    struct tcp_pcb *retry  = connectPcb(probe, false);
    probe->retransmit_port = retry->local_port;
    retry->rto             = 1;
    struct tcp_pcb *poll   = connectPcb(probe, true);
    tcp_arg(poll, probe);
    tcp_poll(poll, onPoll, 1);
    struct tcp_pcb *tw   = connectPcb(probe, true);
    probe->timewait_port = tw->local_port;
    CHECK(tcp_close(tw) == ERR_OK);
    inject(probe, probe->timewait_port, TCP_FIN | TCP_ACK, 9001, tw->snd_nxt);
    CHECK(tw->state == TIME_WAIT);
    tw->tmr = tcp_ticks - (2 * TCP_MSL / TCP_SLOW_INTERVAL);
    sys_timeout(0, immediateTimeout, probe);
    wwLwipEngineCheckTimeouts(probe->engine);
    CHECK(probe->immediate > 0 && probe->immediate <= MEMP_NUM_SYS_TIMEOUT);
    sys_untimeout(immediateTimeout, probe);
    sys_timeout(40, timeout, probe);
    sys_timeout(0, dueTimeout, probe);
    wwLwipEngineLeave(probe->engine, previous);
    /* Repeated stack work must not slide an already-due wakeup into the
     * future. Hold this callback briefly so the owner timer cannot dispatch,
     * then verify both its identity and absolute deadline stay intact. */
    const unsigned armed = timer_adds;
    wtimer_t      *wake  = last_timer;
    CHECK(wake != NULL);
    const uint64_t deadline = wake->next_timeout;
    for (unsigned i = 0; i < 8; ++i)
    {
        const struct timespec pause = {.tv_nsec = 2000000};
        CHECK(nanosleep(&pause, NULL) == 0);
        CHECK(wwLwipEngineEnter(probe->engine, &previous));
        wwLwipEngineLeave(probe->engine, previous);
        CHECK(timer_adds == armed && last_timer == wake && wake->next_timeout == deadline);
    }
    wtimer_t *timer = wtimerAdd(worker->loop, earlier, 80, 1);
    CHECK(timer != NULL);
    weventSetUserData(timer, probe);
    timer = wtimerAdd(worker->loop, finish, 1600, 1);
    CHECK(timer != NULL);
    weventSetUserData(timer, probe);
}
int main(void)
{
    static char            log_off[]    = "OFF";
    ww_construction_data_t data         = {0};
    data.workers_count                  = 3;
    data.ram_profile                    = 4;
    data.mtu_size                       = 1500;
    data.internal_logger_data.log_level = log_off;
    data.core_logger_data.log_level     = log_off;
    data.network_logger_data.log_level  = log_off;
    data.dns_logger_data.log_level      = log_off;
    wwLwipRuntimeTestFailSlots(true);
    CHECK(! wwStartupSucceeded(createGlobalState(data)));
    CHECK(GSTATE.workers == NULL && GSTATE.workers_count == 0 && ! GSTATE.flag_lwip_initialized);
    wwLwipRuntimeTestFailSlots(false);
    CHECK(wwStartupSucceeded(createGlobalState(data)));
    CHECK(pthread_barrier_init(&poll_pressure, NULL, 2) == 0);
    clock_offset = UINT32_MAX - __real_sys_now() - 20;
    initTcpIpStack();
    CHECK(GSTATE.flag_lwip_initialized);
    CHECK(wwLwipRuntimeGet(kInvalidWID) == NULL);
    for (unsigned i = 0; i < 2; ++i)
    {
        probes[i].owner = (uint8_t) i;
        CHECK(sendWorkerMessageForceQueueWithCleanup((wid_t) i, setup, NULL, &probes[i], NULL, NULL) ==
              kWorkerMessageSubmitAccepted);
    }
    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);
    CHECK(wloopRun(getWorkerLoop(0)) == kWLoopRunQuiesced);
    workerPerformQuiesce(getWorker(0), wwLifecycleProcessShutdown());
    /* Owner cleanup may leave admitted loopback storage behind the closed
     * timer gate. Removing the netif must release it without dispatching it. */
    ww_lwip_engine_t *previous;
    CHECK(wwLwipEngineEnter(probes[0].engine, &previous));
    struct pbuf *queued = pbuf_alloc(PBUF_RAW, 40, PBUF_RAM);
    CHECK(queued != NULL);
    memset(queued->payload, 0, queued->len);
    CHECK(netif_loop_output(&probes[0].netif, queued) == ERR_OK);
    pbuf_free(queued);
    CHECK(probes[0].netif.loop_first != NULL);
    wwLwipEngineLeave(probes[0].engine, previous);
    CHECK(wwLwipEngineNextTimeout(probes[0].engine) == SYS_TIMEOUTS_SLEEPTIME_INFINITE);
    CHECK(workerRequestQuiesce(getWorker(2)));
    for (wid_t i = 0; i < 3; ++i)
        CHECK(workerWaitForPhase(getWorker(i), kWorkerLifecycleQuiesced, 5000));
    CHECK(probes[0].engine != probes[1].engine);
    for (wid_t i = 0; i < 3; ++i)
        CHECK(workerRequestDrain(getWorker(i)));
    workerPerformDrain(getWorker(0), wwLifecycleProcessShutdown());
    for (wid_t i = 0; i < 3; ++i)
        CHECK(workerWaitForPhase(getWorker(i), kWorkerLifecycleDrained, 5000));
    for (wid_t i = 0; i < 3; ++i)
        CHECK(workerRequestTeardown(getWorker(i)));
    workerPerformTeardown(getWorker(0));
    for (wid_t i = 1; i < 3; ++i)
    {
        CHECK(workerWaitForPhase(getWorker(i), kWorkerLifecycleExited, 5000));
        CHECK(workerJoin(getWorker(i)));
    }
    CHECK(teardown_detached[0] && teardown_detached[1] && teardown_detached[2]);
    CHECK(pthread_barrier_destroy(&poll_pressure) == 0);
    CHECK(wwLwipShutdown());
    GSTATE.flag_lwip_initialized = 0;
    destroyGlobalState();
    puts("real workers: lazy failure, earlier deadlines, clock wrap, retransmit, poll retry, TIME_WAIT, quiescence and "
         "detached-loop teardown passed");
    return 0;
}
