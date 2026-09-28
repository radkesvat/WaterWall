#include "ConnectionToPackets/structure.h"
#include "PacketsToConnection/interface.h"
#include "devices/device_flow_affinity.h"
#include "port_registry.h"
#include "worker_messages.h"

#define CHECK(x)                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! (x))                                                                                                     \
        {                                                                                                              \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                                    \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)
static tunnel_t         *ctp, *ptc, *resolver, *source, *wire, *echo;
static tunnel_chain_t   *chain;
static node_t            ctp_node, ptc_node;
static pthread_barrier_t barrier;
static line_t           *clients[2][2];
static unsigned          received[2][2], established[2], routed_other[2];
static atomic_bool       finished[2];
static uint16_t          local_ports[2][2];
static uint16_t          ports[2], expected_local[2];
static bool              reserve_bytes[2];
static unsigned          reserved_count[2];

void __real_nodemanagerQuiesceWorker(wid_t, const ww_lifecycle_context_t *);
void __wrap_nodemanagerQuiesceWorker(wid_t, const ww_lifecycle_context_t *);
void __real_nodemanagerStopWorkerResources(wid_t, const ww_lifecycle_context_t *);
void __wrap_nodemanagerStopWorkerResources(wid_t, const ww_lifecycle_context_t *);
void __real_workerMessagesDestroyDetached(worker_message_queue_t *);
void __wrap_workerMessagesDestroyDetached(worker_message_queue_t *);
void __wrap_nodemanagerQuiesceWorker(wid_t wid, const ww_lifecycle_context_t *ctx)
{
    __real_nodemanagerQuiesceWorker(wid, ctx);
}
static void closeClient(wid_t wid, unsigned protocol)
{
    line_t *line = clients[wid][protocol];
    CHECK(line != NULL && lineIsAlive(line));
    lineRef(line);
    tunnelNextUpStreamFinish(source, line);
    CHECK(lineIsAlive(line));
    lineDestroy(line);
    lineUnref(line);
    clients[wid][protocol] = NULL;
}
void __wrap_nodemanagerStopWorkerResources(wid_t wid, const ww_lifecycle_context_t *ctx)
{
    /* Exercise both legal node/source orders on the same live bridge. */
    if (wid == 0)
        ctp->onWorkerStop(ctp, wid, ctx);
    if (clients[wid][1])
        closeClient(wid, 1);
    if (wid == 1)
        ctp->onWorkerStop(ctp, wid, ctx);
    ptc->onWorkerStop(ptc, wid, ctx);
    __real_nodemanagerStopWorkerResources(wid, ctx);
}
void __wrap_workerMessagesDestroyDetached(worker_message_queue_t *queue)
{
    __real_workerMessagesDestroyDetached(queue);
}
static void rendezvous(void)
{
    int r = pthread_barrier_wait(&barrier);
    CHECK(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
}
static sbuf_t *bytes(line_t *line, const char *text)
{
    unsigned n = (unsigned) strlen(text);
    sbuf_t  *b = bufferpoolGetBestFit(lineGetBufferPool(line), n, 0);
    CHECK(b);
    sbufSetLength(b, n);
    memcpy(sbufGetMutablePtr(b), text, n);
    return b;
}
static unsigned protocolOf(line_t *l)
{
    return lineGetDestinationAddressContext(l)->proto_tcp ? 0 : 1;
}
static void queueStaleUdpReply(line_t *line)
{
    ctp_lstate_t *ls          = lineGetState(line, ctp);
    line_t       *packet_line = tunnelchainGetWorkerPacketLine(chain, lineGetWID(line));
    sbuf_t       *buf         = bufferpoolGetBestFit(lineGetBufferPool(packet_line), 36, 0);
    CHECK(buf != NULL);
    sbufSetLength(buf, 36);
    uint8_t *p = sbufGetMutablePtr(buf);
    memset(p, 0, 36);
    p[0] = 0x45;
    p[8] = 64;
    p[9] = 17;
    PUT_BE16(p + 2, 36);
    memcpy(p + 12, &ls->flow_key.remote_addr_network, 4);
    memcpy(p + 16, &ls->flow_key.local_addr_network, 4);
    PUT_BE16(p + 20, ls->flow_key.remote_port);
    PUT_BE16(p + 22, ls->flow_key.local_port);
    PUT_BE16(p + 24, 16);
    memcpy(p + 28, "stale001", 8);
    CHECK(calcFullPacketChecksum(p, 36));
    ctpTunnelDownStreamPayload(ctp, packet_line, buf);
    const uint64_t    old_generation = ls->generation;
    ww_lwip_engine_t *previous;
    CHECK(wwLwipEngineEnter(ls->engine, &previous));
    ctpFlowUnregister(ctp, ls);
    udp_remove(ls->udp_pcb);
    ls->udp_pcb = udp_new_ip_type(IPADDR_TYPE_V4);
    CHECK(ls->udp_pcb != NULL);
    ip_addr_t local, remote;
    IP_SET_TYPE_VAL(local, IPADDR_TYPE_V4);
    local.u_addr.ip4.addr = ls->flow_key.local_addr_network;
    IP_SET_TYPE_VAL(remote, IPADDR_TYPE_V4);
    remote.u_addr.ip4.addr = ls->flow_key.remote_addr_network;
    CHECK(udp_bind_netif(ls->udp_pcb, &ls->netif_ctx->netif) == ERR_OK);
    CHECK(udp_bind(ls->udp_pcb, &local, ls->flow_key.local_port) == ERR_OK);
    CHECK(udp_connect(ls->udp_pcb, &remote, ls->flow_key.remote_port) == ERR_OK);
    CHECK(ctpFlowRegister(ctp, ls, ls->udp_pcb, IP_PROTO_UDP));
    CHECK(ls->generation != old_generation);
    udp_recv(ls->udp_pcb, ctpUdpRecvCallback, ls);
    wwLwipEngineLeave(ls->engine, previous);
}

static void sourceEst(tunnel_t *t, line_t *l)
{
    CHECK(t == source && wwLwipEngineCurrent() == NULL && currentThreadIsEventWorkerWID(lineGetWID(l)));
    if (protocolOf(l) == 1)
        queueStaleUdpReply(l);
    ++established[lineGetWID(l)];
    tunnelNextUpStreamPayload(t, l, bytes(l, protocolOf(l) == 0 ? "tcp-echo" : "udp-echo"));
}
static void sourcePayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    CHECK(t == source && wwLwipEngineCurrent() == NULL && currentThreadIsEventWorkerWID(lineGetWID(l)));
    unsigned proto = protocolOf(l);
    CHECK(sbufGetLength(buf) == 8);
    CHECK(memcmp(sbufGetRawPtr(buf), proto == 0 ? "tcp-echo" : "udp-echo", 8) == 0);
    ++received[lineGetWID(l)][proto];
    lineReuseBuffer(l, buf);
    if (proto == 0)
        closeClient(lineGetWID(l), proto);
}
static void sourceFinish(tunnel_t *t, line_t *l)
{
    CHECK(t == source);
    clients[lineGetWID(l)][protocolOf(l)] = NULL;
    lineDestroy(l);
}
static void echoInit(tunnel_t *t, line_t *l)
{
    CHECK(wwLwipEngineCurrent() == NULL);
    tunnelPrevDownStreamEst(t, l);
}
static void echoPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    CHECK(wwLwipEngineCurrent() == NULL);
    tunnelPrevDownStreamPayload(t, l, buf);
}
static void absorb(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
}
static void wireUp(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    CHECK(wwLwipEngineCurrent() == NULL);
    const uint8_t *p   = sbufGetRawPtr(buf);
    ctp_flow_key_t key = {0};
    memcpy(&key.local_addr_network, p + 12, 4);
    memcpy(&key.remote_addr_network, p + 16, 4);
    unsigned h      = (p[0] & 15) * 4;
    key.local_port  = GET_BE16(p + h);
    key.remote_port = GET_BE16(p + h + 2);
    key.protocol    = p[9];
    wid_t    owner;
    uint64_t generation;
    CHECK(ctpFlowLookup(ctp, &key, &owner, &generation));
    wid_t hashed;
    CHECK(deviceFlowAffineWID(p, sbufGetLength(buf), &hashed));
    CHECK(hashed == lineGetWID(l));
    if (owner == 0 && hashed != owner)
        ++routed_other[key.protocol == 6 ? 0 : 1];
    tunnelNextUpStreamPayload(t, l, buf);
}
static void wireDown(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    CHECK(wwLwipEngineCurrent() == NULL);
    tunnelPrevDownStreamPayload(t, l, buf);
}
static uint16_t chooseRemotePort(unsigned proto, uint16_t local)
{
    uint8_t p[40] = {0x45};
    PUT_BE16(p + 2, sizeof(p));
    p[9]  = proto == 0 ? 6 : 17;
    p[12] = 10;
    p[13] = 90;
    p[15] = 1;
    p[16] = 10;
    p[17] = 90;
    p[19] = 2;
    PUT_BE16(p + 20, local);
    for (uint32_t port = 10000; port < 60000; ++port)
    {
        PUT_BE16(p + 22, port);
        wid_t wid;
        CHECK(deviceFlowAffineWID(p, sizeof(p), &wid));
        if (wid == 1)
            return (uint16_t) port;
    }
    CHECK(false);
    return 0;
}
static void finishTimer(wtimer_t *timer)
{
    wid_t wid = getLoopEventWorkerWID(weventGetLoop(timer));
    CHECK(established[wid] == 2 && received[wid][0] == 1 && received[wid][1] == 1);
    atomicStoreExplicit(&finished[wid], true, memory_order_release);
    if (wid == 0 && ! atomicLoadExplicit(&finished[1], memory_order_acquire))
    {
        CHECK(wtimerReset(timer, 10));
        return;
    }
    CHECK((wid == 0 ? workerInstallApplicationQuiesceRequest(getWorker(wid), wwLifecycleProcessShutdown())
                    : workerRequestQuiesceResult(getWorker(wid))) != kWorkerQuiesceRequestUnavailable);
}
static void openClients(wid_t wid)
{
    ip_addr_t remote;
    IP_ADDR4(&remote, 10, 90, 0, 2);
    for (unsigned proto = 0; proto < 2; ++proto)
    {
        line_t *l           = lineCreate(tunnelchainGetLinePools(chain), wid);
        clients[wid][proto] = l;
        addresscontextSetIpPortProtocol(
            lineGetDestinationAddressContext(l), &remote, ports[proto], proto == 0 ? 6 : 17);
        tunnelNextUpStreamInit(source, l);
        CHECK(lineIsAlive(l));
        ctp_lstate_t *ls = lineGetState(l, ctp);
        CHECK(ls->flow_registered && ls->engine == wwLwipRuntimeGet(wid));
        local_ports[wid][proto] = ls->flow_key.local_port;
        if (wid == 0)
            CHECK(ls->flow_key.local_port == expected_local[proto]);
    }
}
static void setup(void *worker_ptr, void *a, void *b, void *c)
{
    (void) a;
    (void) b;
    (void) c;
    wid_t         wid  = ((worker_t *) worker_ptr)->wid;
    ctp_tstate_t *ts   = tunnelGetState(ctp);
    reserve_bytes[wid] = ctpDrainBudgetReserve(ts, kCtpMaxDrainBytesTotal / 2 + 1);
    rendezvous();
    CHECK(reserve_bytes[0] != reserve_bytes[1]);
    rendezvous();
    if (reserve_bytes[wid])
        ctpDrainBudgetRelease(ts, kCtpMaxDrainBytesTotal / 2 + 1);
    rendezvous();
    while (ctpDrainBudgetReserve(ts, 0))
        ++reserved_count[wid];
    rendezvous();
    CHECK(reserved_count[0] + reserved_count[1] == kCtpMaxDrains);
    rendezvous();
    for (unsigned i = 0; i < reserved_count[wid]; ++i)
        ctpDrainBudgetRelease(ts, 0);
    rendezvous();
    CHECK(wwLwipRuntimeGet(wid));
    rendezvous();
    if (wid == 0)
        openClients(wid);
    rendezvous();
    if (wid == 1)
        openClients(wid);
    rendezvous();
    CHECK(wtimerAdd(getWorkerLoop(wid), finishTimer, 1200, 1));
}
int main(void)
{
    static char            off[]        = "OFF";
    ww_construction_data_t data         = {0};
    data.workers_count                  = 2;
    data.ram_profile                    = 4;
    data.mtu_size                       = 1500;
    data.internal_logger_data.log_level = off;
    data.core_logger_data.log_level     = off;
    data.network_logger_data.log_level  = off;
    data.dns_logger_data.log_level      = off;
    CHECK(wwStartupSucceeded(createGlobalState(data)));
    initTcpIpStack();
    CHECK(GSTATE.flag_lwip_initialized);
    CHECK(pthread_barrier_init(&barrier, NULL, 2) == 0);
    for (unsigned proto = 0; proto < 2; ++proto)
    {
        uint16_t p = wwLwipPortAllocate((ww_lwip_transport_t) proto, 49152, 49159);
        CHECK(p);
        expected_local[proto] = p == 49159 ? 49152 : p + 1;
        wwLwipPortRelease((ww_lwip_transport_t) proto, &p);
        ports[proto] = chooseRemotePort(proto, expected_local[proto]);
    }
    static char ctp_name[] = "ctp", ptc_name[] = "ptc", ctp_type[] = "ConnectionToPackets";
    ctp_node = (node_t) {
        .name = ctp_name, .type = ctp_type, .node_settings_json = cJSON_Parse("{\"source-ipv4\":\"10.90.0.1\"}")};
    ctp = ctpTunnelCreate(&ctp_node);
    CHECK(ctp);
    cJSON_Delete(ctp_node.node_settings_json);
    ctp_node.node_settings_json = NULL;
    ptc_node                    = nodePacketsToConnectionGet();
    ptc_node.name               = ptc_name;
    ptc                         = ptc_node.createHandle(&ptc_node);
    CHECK(ptc);
    resolver = ((ctp_tstate_t *) tunnelGetState(ctp))->domain_resolver_tunnel;
    CHECK(resolver);
    source = tunnelCreate(NULL, 0, 0);
    wire   = tunnelCreate(NULL, 0, 0);
    echo   = tunnelCreate(NULL, 0, 0);
    CHECK(source && wire && echo);
    source->fnEstD     = sourceEst;
    source->fnPayloadD = sourcePayload;
    source->fnFinD     = sourceFinish;
    source->fnPauseD   = absorb;
    source->fnResumeD  = absorb;
    wire->fnInitU      = absorb;
    wire->fnPayloadU   = wireUp;
    wire->fnPayloadD   = wireDown;
    echo->fnInitU      = echoInit;
    echo->fnPayloadU   = echoPayload;
    echo->fnFinU       = absorb;
    tunnelBind(source, resolver);
    tunnelBind(resolver, ctp);
    tunnelBind(ctp, wire);
    tunnelBind(wire, ptc);
    tunnelBind(ptc, echo);
    chain = tunnelchainCreate(2);
    CHECK(chain);
    chain->contains_packet_node = true;
    tunnel_t *nodes[]           = {source, resolver, ctp, wire, ptc, echo};
    for (unsigned i = 0; i < 6; ++i)
    {
        nodes[i]->chain         = chain;
        nodes[i]->lstate_offset = chain->sum_line_state_size;
        chain->sum_line_state_size += nodes[i]->lstate_size;
    }
    tunnelchainFinalize(chain);
    CHECK(chain->finalized);
    ptc->onStart(ptc);
    ctp->onStart(ctp);
    for (wid_t i = 0; i < 2; ++i)
        CHECK(sendWorkerMessageForceQueueWithCleanup(i, setup, NULL, NULL, NULL, NULL) == kWorkerMessageSubmitAccepted);
    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);
    CHECK(wloopRun(getWorkerLoop(0)) == kWLoopRunQuiesced);
    ctp->onQuiesceRequest(ctp, wwLifecycleProcessShutdown());
    ptc->onQuiesceRequest(ptc, wwLifecycleProcessShutdown());
    workerPerformQuiesce(getWorker(0), wwLifecycleProcessShutdown());
    CHECK(workerWaitForPhase(getWorker(1), kWorkerLifecycleQuiesced, 5000));
    CHECK(routed_other[0] > 0 && routed_other[1] > 0);
    CHECK(local_ports[0][0] != local_ports[1][0] && local_ports[0][1] != local_ports[1][1]);
    ctp->onQuiesceWait(ctp, wwLifecycleProcessShutdown());
    ptc->onQuiesceWait(ptc, wwLifecycleProcessShutdown());
    for (wid_t i = 0; i < 2; ++i)
        CHECK(workerRequestDrain(getWorker(i)));
    workerPerformDrain(getWorker(0), wwLifecycleProcessShutdown());
    CHECK(workerWaitForPhase(getWorker(1), kWorkerLifecycleDrained, 5000));
    ctp->onStop(ctp, wwLifecycleProcessShutdown());
    ptc->onStop(ptc, wwLifecycleProcessShutdown());
    for (wid_t i = 0; i < 2; ++i)
        CHECK(workerRequestTeardown(getWorker(i)));
    workerPerformTeardown(getWorker(0));
    CHECK(workerWaitForPhase(getWorker(1), kWorkerLifecycleExited, 5000));
    CHECK(workerJoin(getWorker(1)));
    CHECK(wwLwipShutdown());
    GSTATE.flag_lwip_initialized = 0;
    tunnelchainDestroy(chain);
    ctp->onDestroy(ctp, wwLifecycleProcessShutdown());
    ptc->onDestroy(ptc, wwLifecycleProcessShutdown());
    tunnelDestroy(source);
    tunnelDestroy(wire);
    tunnelDestroy(echo);
    memoryFree(ptc_node.type);
    CHECK(pthread_barrier_destroy(&barrier) == 0);
    destroyGlobalState();
    puts("CTP/PTC raw multiworker TCP/UDP roundtrip, owner/hash mismatch, shared drains and both stop orders passed");
    return 0;
}
