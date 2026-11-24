/* Real server/helpers, AuthenticationClient cache and client proof on stepped
 * owner loops. The scenario controls when each real worker queue progresses.
 * This fixture has no sockets and introduces no production lifecycle hooks. */
#pragma once

#include "fixtures/failure/tunnel_orderly_shutdown_harness.h"
#include "fixtures/user_runtime.h"
#define kTunnelStateSize kAuthStateSize
#define kLineStateSize   kAuthLineSize
#include "AuthenticationClient/structure.h"
#undef kTunnelStateSize
#undef kLineStateSize
#include "PacketsToConnection/structure.h"
#include "WireGuardServer/interface.h"
#include "WireGuardServer/structure.h"
#include "loggers/network_logger.h"
#include "lwip/engine_runtime.h"
#include "managers/node_manager.c" /* Actual central lifecycle traversal. */

enum
{
    kWgFixtureQueue   = 64,
    kWgFixtureTunnels = 6,
    kWgFixtureStages  = 8
};
typedef struct wg_server_fixture_s
{
    tos_worker_env_t               env;
    node_manager_t                *manager;
    node_manager_config_t          config;
    config_file_t                  file;
    node_t                         auth_node, server_node, adapter_node, sink_node;
    users_t                        users;
    tunnel_t                      *auth, *server, *adapter, *sink;
    authenticationclient_tstate_t *as;
    server_t                      *state;
    tunnel_chain_t                *chain;
    line_t                        *ingress[kTosMaxWorkers];
    wireguard_device_t             client;
    sbuf_t                        *to_server[kWgFixtureQueue], *to_client[kWgFixtureQueue];
    unsigned                       server_count, client_count, opened, finished, delivered, ingress_finished;
    tunnel_t                      *observed[kWgFixtureTunnels];
    TunnelLifecycleCb              saved_request[kWgFixtureTunnels], saved_wait[kWgFixtureTunnels];
    TunnelLifecycleCb              saved_stop[kWgFixtureTunnels], saved_destroy[kWgFixtureTunnels];
    TunnelWorkerLifecycleCb        saved_quiesce[kWgFixtureTunnels], saved_drain[kWgFixtureTunnels];
    TunnelStatusCb                 saved_prepare[kWgFixtureTunnels], saved_start[kWgFixtureTunnels];
    unsigned                       stages[kWgFixtureTunnels][kWgFixtureStages];
    bool                           started, start_succeeded, client_initialized, quiesced;
} wg_server_fixture_t;

static wg_server_fixture_t *wg_fixture;
static unsigned             wg_destroyed_server, wg_destroyed_ptc, wg_destroyed_binder, wg_destroyed_controller;
void                        __real_tunnelOwnedChildDestroy(tunnel_t *t);
void                        __wrap_tunnelOwnedChildDestroy(tunnel_t *t);
void                        __wrap_tunnelOwnedChildDestroy(tunnel_t *t)
{
    if (strcmp(tunnelGetNode(t)->type, "WireGuardUserBinding") == 0)
        ++wg_destroyed_binder;
    __real_tunnelOwnedChildDestroy(t);
}
void __real_tunnelDestroy(tunnel_t *t);
void __wrap_tunnelDestroy(tunnel_t *t);
void __wrap_tunnelDestroy(tunnel_t *t)
{
    const node_t *node = tunnelGetNode(t);
    if (node != NULL && node->type != NULL)
    {
        if (strcmp(node->type, "WireGuardServer") == 0)
            ++wg_destroyed_server;
        else if (strcmp(node->type, "PacketsToConnection") == 0)
            ++wg_destroyed_ptc;
        else if (strcmp(node->type, "UserController") == 0)
            ++wg_destroyed_controller;
    }
    __real_tunnelDestroy(t);
}
static bool (*wg_submit_hook)(wid_t, WorkerMessageCallback, WorkerMessageCleanupCallback, void *, void *, void *);
worker_message_submit_result_e __real_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    if (wg_submit_hook != NULL && wg_submit_hook(wid, callback, cleanup, arg1, arg2, arg3))
        return kWorkerMessageSubmitAccepted;
    return __real_sendWorkerMessageForceQueueWithCleanup(wid, callback, cleanup, arg1, arg2, arg3);
}

static unsigned wgObservedIndex(tunnel_t *t)
{
    for (unsigned i = 0; i < kWgFixtureTunnels; ++i)
        if (wg_fixture->observed[i] == t)
            return i;
    twfRequire(false, "unrecognized lifecycle participant");
    return 0;
}
static void wgObserveRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    const unsigned i = wgObservedIndex(t);
    ++wg_fixture->stages[i][0];
    wg_fixture->saved_request[i](t, context);
}
static void wgObserveQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    const unsigned i = wgObservedIndex(t);
    ++wg_fixture->stages[i][1];
    wg_fixture->saved_quiesce[i](t, wid, context);
}
static void wgObserveWait(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    const unsigned i = wgObservedIndex(t);
    ++wg_fixture->stages[i][2];
    wg_fixture->saved_wait[i](t, context);
}
static void wgObserveDrain(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    const unsigned i = wgObservedIndex(t);
    ++wg_fixture->stages[i][3];
    wg_fixture->saved_drain[i](t, wid, context);
}
static void wgObserveStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    const unsigned i = wgObservedIndex(t);
    ++wg_fixture->stages[i][4];
    wg_fixture->saved_stop[i](t, context);
}
static void wgObserveDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    const unsigned i = wgObservedIndex(t);
    ++wg_fixture->stages[i][5];
    wg_fixture->saved_destroy[i](t, context);
}
static void wgObservePrepare(tunnel_t *t)
{
    const unsigned i = wgObservedIndex(t);
    ++wg_fixture->stages[i][6];
    wg_fixture->saved_prepare[i](t);
}
static void wgObserveStart(tunnel_t *t)
{
    const unsigned i = wgObservedIndex(t);
    ++wg_fixture->stages[i][7];
    wg_fixture->saved_start[i](t);
}
static void wgObserve(wg_server_fixture_t *f)
{
    tunnel_t *tunnels[] = {f->adapter, f->server, f->state->ptc, f->state->binder, f->state->controller, f->sink};
    for (unsigned i = 0; i < kWgFixtureTunnels; ++i)
    {
        tunnel_t *t         = tunnels[i];
        f->observed[i]      = t;
        f->saved_request[i] = t->onQuiesceRequest;
        f->saved_quiesce[i] = t->onWorkerQuiesce;
        f->saved_wait[i]    = t->onQuiesceWait;
        f->saved_drain[i]   = t->onWorkerStop;
        f->saved_stop[i]    = t->onStop;
        f->saved_destroy[i] = t->onDestroy;
        f->saved_prepare[i] = t->onPrepare;
        f->saved_start[i]   = t->onStart;
        t->onQuiesceRequest = wgObserveRequest;
        t->onWorkerQuiesce  = wgObserveQuiesce;
        t->onQuiesceWait    = wgObserveWait;
        t->onWorkerStop     = wgObserveDrain;
        t->onStop           = wgObserveStop;
        t->onDestroy        = wgObserveDestroy;
        t->onPrepare        = wgObservePrepare;
        t->onStart          = wgObserveStart;
    }
}
static bool wgClientOutput(void *context, sbuf_t *packet, wireguard_peer_t *peer, const ip_addr_t *ip, uint16_t port)
{
    discard              peer;
    discard              ip;
    discard              port;
    wg_server_fixture_t *f = context;
    twfRequire(f->server_count < kWgFixtureQueue, "client output queue overflow");
    f->to_server[f->server_count++] = packet;
    return true;
}
static void wgClientInner(void *context, sbuf_t *packet, wireguard_peer_t *peer)
{
    discard peer;
    ++((wg_server_fixture_t *) context)->delivered;
    reuseBuffer(packet);
}
static void wgAdapterPayload(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    discard              t;
    discard              line;
    wg_server_fixture_t *f = wg_fixture;
    twfRequire(f->client_count < kWgFixtureQueue, "server output queue overflow");
    f->to_client[f->client_count++] = packet;
}
static void wgAdapterFinish(tunnel_t *t, line_t *line)
{
    discard              t;
    wg_server_fixture_t *f   = wg_fixture;
    const wid_t          wid = lineGetWID(line);
    twfRequire(f->ingress[wid] == line, "ingress ownership inventory changed");
    f->ingress[wid] = NULL;
    ++f->ingress_finished;
    lineDestroy(line); /* The actual ingress creator owns this normal line. */
}
static void wgAdapterEst(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
}
static void wgSinkInit(tunnel_t *t, line_t *line)
{
    discard t;
    twfRequire(lineGetCurrentUser(line) != NULL, "anonymous PTC flow reached the sink");
    ++wg_fixture->opened;
}
static void wgSinkPayload(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    discard t;
    lineReuseBuffer(line, packet);
}
static void wgSinkFinish(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
    ++wg_fixture->finished;
}
static void wgNameNode(node_t *node, const char *name, node_manager_config_t *config)
{
    node->name                = stringDuplicate(name);
    node->hash_name           = calcHashBytes(name, strlen(name));
    node->node_manager_config = config;
    twfRequire(map_node_t_insert(&config->node_map, node->hash_name, node).inserted, "fixture node publication failed");
}
static void wgServerFixtureBase(wg_server_fixture_t *f, wid_t workers)
{
    memoryZero(f, sizeof(*f));
    wg_fixture          = f;
    wg_destroyed_server = wg_destroyed_ptc = wg_destroyed_binder = wg_destroyed_controller = 0;
    wg_submit_hook                                                                         = NULL;
    tosResetProcessApi(true);
    twfRequire(userTestRuntimeInitialize(), "crypto runtime initialization failed");
    twfRequire(createNetworkLogger(NULL, true) != NULL, "network logger creation failed");
    tosWorkerEnvSetup(&f->env, workers, 8192, 2048);
    GSTATE.main_thread_id = getTID();
    GSTATE.ram_profile    = kRamProfileS1Memory;
    GSTATE.mtu_size       = 1500;
    f->manager            = nodemanagerCreate();
    f->file.name          = stringDuplicate("wireguard-server-fixture");
    f->config.config_file = &f->file;
    f->config.node_map    = map_node_t_init();
    f->config.chains      = vec_chains_t_init();
    twfRequire(vec_configs_t_push(&f->manager->configs, &f->config) != NULL, "fixture config publication failed");
    twfRequire(usersCreate(&f->users), "users initialization failed");
    user_t user;
    twfRequire(userCreate(&user, "wireguard-lifecycle-account"), "account creation failed");
    userSetId(&user, 42);
    user.limit.ips      = 1;
    user.limit.cons_out = 8;
    twfRequire(userSetWireGuardAllowedIps(&user, "10.50.0.4/30") && usersAddUser(&f->users, &user),
               "account insertion failed");
    userDestroy(&user);
    user_t *stored = usersLookupByIdentifier(&f->users, 42);
    twfRequire(usersSetUserName(&f->users, stored, "account-a"), "account naming failed");
    stored->runtime.identity_generation_floor  = 1;
    stored->runtime.wireguard_generation_floor = 1;
    f->auth_node                               = nodeAuthenticationClientGet();
    wgNameNode(&f->auth_node, "accounts", &f->config);
    f->auth               = tunnelCreate(&f->auth_node, sizeof(authenticationclient_tstate_t), 0);
    f->auth_node.instance = f->auth;
    f->as                 = tunnelGetState(f->auth);
    mutexInit(&f->as->control_mutex);
    rwlockinit(&f->as->users_lock);
    f->as->users              = &f->users;
    f->as->traffic_multiplier = kUserTrafficMultiplierScale;
    f->as->started = f->as->users_loaded = f->as->clock_loaded = true;
    atomic_init(&f->as->users_generation, 1);
}
static tunnel_t *wgServerFixtureConstruct(wg_server_fixture_t *f, const char *extra_settings)
{
    f->server_node = nodeWireGuardServerGet();
    wgNameNode(&f->server_node, "server", &f->config);
    f->server_node.next      = stringDuplicate("sink");
    f->server_node.hash_next = calcHashBytes("sink", 4);
    char settings[1024];
    snprintf(settings,
             sizeof(settings),
             "{\"mode\":\"connection\",\"privatekey\":\"EBJOHctLU2w8uteyTE+WU0hruB09Ub0vwVS+Gt9wAls=\",\"auth-client-"
             "node-name\":\"accounts\"%s}",
             extra_settings);
    f->server_node.node_settings_json = cJSON_Parse(settings);
    ww_startup_context_t startup      = {0};
    wwStartupContextBegin(&startup);
    f->server = f->server_node.createHandle(&f->server_node);
    discard wwStartupContextEnd(&startup);
    f->server_node.instance = f->server;
    if (f->server != NULL)
        f->state = tunnelGetState(f->server);
    return f->server;
}
static void wgServerFixtureSetup(wg_server_fixture_t *f, wid_t workers, const char *extra_settings)
{
    wgServerFixtureBase(f, workers);
    twfRequire(wgServerFixtureConstruct(f, extra_settings) != NULL, "server construction failed");
    f->adapter_node.type = stringDuplicate("FixtureUdpIngress");
    wgNameNode(&f->adapter_node, "adapter", &f->config);
    f->sink_node.type = stringDuplicate("FixtureSink");
    wgNameNode(&f->sink_node, "sink", &f->config);
    f->adapter                   = tunnelCreate(&f->adapter_node, 0, 0);
    f->sink                      = tunnelCreate(&f->sink_node, 0, 0);
    f->adapter_node.instance     = f->adapter;
    f->sink_node.instance        = f->sink;
    f->adapter->fnPayloadD       = wgAdapterPayload;
    f->adapter->fnFinD           = wgAdapterFinish;
    f->adapter->fnEstD           = wgAdapterEst;
    f->sink->fnInitU             = wgSinkInit;
    f->sink->fnPayloadU          = wgSinkPayload;
    f->sink->fnFinU              = wgSinkFinish;
    f->chain                     = tunnelchainCreate(workers);
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    tunnelchainInsert(f->chain, f->adapter);
    f->server->onChain(f->server, f->chain);
    tunnelBind(f->adapter, f->server);
    uint32_t offset = 0;
    for (unsigned i = 0; i < f->chain->tunnels.len; ++i)
        f->chain->tunnels.tuns[i]->onIndex(f->chain->tunnels.tuns[i], (uint16_t) i, &offset);
    f->chain->contains_packet_node = true;
    tunnelchainFinalize(f->chain);
    twfRequire(wwStartupSucceeded(wwStartupContextEnd(&startup)), "chain construction failed");
    twfRequire(vec_chains_t_push(&f->config.chains, f->chain) != NULL, "chain publication failed");
    wgObserve(f);
    char    private_key[45] = {0};
    user_t *account         = usersLookupByIdentifier(&f->users, 42);
    twfRequire(wwBase64Encode(account->sha256_pass.bytes, 32, private_key) == 44, "client key encoding failed");
    twfRequire(
        wireguardCommonInit(
            &f->client, private_key, f, (wireguard_callbacks_t) {.output = wgClientOutput, .inner = wgClientInner}),
        "client engine creation failed");
    wCryptoZero(private_key, sizeof(private_key));
    cJSON *peer =
        cJSON_Parse("{\"publickey\":\"GnRcOavdc180YrXak138cZxWlMoEUZL0Mg/ZyWhLBgo=\",\"allowedips\":\"0.0.0.0/0\"}");
    size_t index;
    twfRequire(wireguardCommonAddConfiguredPeer(&f->client, peer, &index), "client peer creation failed");
    cJSON_Delete(peer);
    f->client_initialized = true;
}
static ww_startup_result_t wgServerFixtureStart(wg_server_fixture_t *f)
{
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    prepareTunnels(&f->config);
    if (! startupFailurePending())
        startTunnels(&f->config);
    f->started         = true;
    f->start_succeeded = ! startupFailurePending();
    return wwStartupContextEnd(&startup);
}
static void wgServerFixturePump(wg_server_fixture_t *f)
{
    for (wid_t wid = 0; wid < f->env.count; ++wid)
        tosPumpWorker(&f->env, wid);
}
static line_t *wgServerFixtureIngress(wg_server_fixture_t *f, wid_t wid)
{
    const wid_t previous = tosSetCurrentWorker(wid);
    line_t     *line     = lineCreateForWorker(0, f->chain->line_pools, wid);
    twfRequire(line != NULL, "ingress creation failed");
    f->ingress[wid] = line;
    addresscontextSetIpAddressPortProtocol(lineGetSourceAddressContext(line), "192.0.2.1", 51820, 17);
    addresscontextSetTransportOffer(lineGetDestinationAddressContext(line), kAddressContextTransportUdp);
    line->routing_context.peer_source_port = 42000;
    tunnelNextUpStreamInit(f->adapter, line);
    twfRequire(lineIsAlive(line), "ingress Init unexpectedly refused");
    discard tosSetCurrentWorker(previous);
    return line;
}
static void wgServerFixtureExchangeClientOnWorker(wg_server_fixture_t *f, wireguard_device_t *client, wid_t wid,
                                                  unsigned held_dispatches)
{
    if (f->ingress[wid] == NULL)
        wgServerFixtureIngress(f, wid);
    for (unsigned iteration = 0; iteration < 32; ++iteration)
    {
        discard        tosSetCurrentWorker(wid);
        const unsigned count = f->server_count;
        f->server_count      = 0;
        for (unsigned i = 0; i < count; ++i)
            tunnelNextUpStreamPayload(f->adapter, f->ingress[wid], f->to_server[i]);
        wgServerFixturePump(f);
        discard   tosSetCurrentWorker(0);
        ip_addr_t source;
        twfRequire(ipaddr_aton("192.0.2.2", &source), "server source parse failed");
        const unsigned responses = f->client_count;
        f->client_count          = 0;
        for (unsigned i = 0; i < responses; ++i)
            wireguardCommonReceive(client, f->to_client[i], &source, 51820);
        if (f->server_count == 0 && f->client_count == 0 && atomic_load(&f->state->dispatch.count) == held_dispatches)
            return;
    }
    twfRequire(false, "server proof exchange did not settle");
}
static void wgServerFixtureExchangeClient(wg_server_fixture_t *f, wireguard_device_t *client, unsigned held_dispatches)
{
    wgServerFixtureExchangeClientOnWorker(f, client, f->env.count - 1, held_dispatches);
}
static void wgServerFixtureExchangePending(wg_server_fixture_t *f, unsigned held_dispatches)
{
    wgServerFixtureExchangeClient(f, &f->client, held_dispatches);
}
static void wgServerFixtureExchange(wg_server_fixture_t *f)
{
    wgServerFixtureExchangePending(f, 0);
}
static void wgServerFixtureProof(wg_server_fixture_t *f)
{
    discard tosSetCurrentWorker(0);
    twfRequire(wireguardifStartHandshake(&f->client, f->client.first_peer, true) == ERR_OK, "client initiation failed");
    wgServerFixtureExchange(f);
    twfRequire(f->state->binding_head->usable && f->state->binding_head->peer->curr_keypair.valid &&
                   f->client.first_peer->curr_keypair.valid,
               "real authenticated proof did not establish binding and keys");
}
static sbuf_t *wgServerFixtureUdpPacket(wg_server_fixture_t *f, uint16_t source_port)
{
    sbuf_t *packet = bufferpoolGetSmallBuffer(f->env.pools[0]);
    sbufSetLength(packet, 29);
    sbufWriteZeros(packet, 29);
    uint8_t *bytes = sbufGetMutablePtr(packet);
    bytes[0]       = 0x45;
    PUT_BE16(bytes + 2, 29);
    bytes[8]  = 64;
    bytes[9]  = 17;
    bytes[12] = 10;
    bytes[13] = 50;
    bytes[15] = 5;
    bytes[16] = 203;
    bytes[18] = 113;
    bytes[19] = 1;
    PUT_BE16(bytes + 20, source_port);
    PUT_BE16(bytes + 22, 8000);
    PUT_BE16(bytes + 24, 9);
    bytes[28] = 0x5a;
    twfRequire(calcFullPacketChecksum(bytes, 29), "UDP packet checksum creation failed");
    return packet;
}
static void wgServerFixtureOpenUdp(wg_server_fixture_t *f)
{
    discard tosSetCurrentWorker(0);
    wireguardCommonSendInner(&f->client, wgServerFixtureUdpPacket(f, 40001));
    wgServerFixtureExchange(f);
    twfRequire(f->opened == 1, "real PTC/UserController did not open an authenticated UDP flow");
    user_t *account = usersLookupByIdentifier(&f->users, 42);
    twfRequire(account->runtime.active_cons_out == 1 && account->runtime.ip_usage_count == 1,
               "real inner flow did not reserve its user and IP");
}
static void wgServerFixtureQuiesce(wg_server_fixture_t *f, const ww_lifecycle_context_t *context)
{
    if (f->quiesced)
        return;
    f->quiesced = true;
    nodemanagerQuiesceRequest(context);
    nodemanagerQuiesceRequest(context); /* Main passes are once-only. */
    for (wid_t wid = 0; wid < f->env.count; ++wid)
    {
        discard tosSetCurrentWorker(wid);
        discard wloopCloseNormalAdmission(f->env.loops[wid]);
        workerMessagesCloseAdmission(&f->env.workers[wid]);
        wwLwipRuntimeQuiesceWorker(wid);
        nodemanagerQuiesceWorker(wid, context);
        workerMessagesCleanupPending(&f->env.workers[wid]);
        wloopQuiesceNormalWork(f->env.loops[wid]);
        twfRequire(f->env.loops[wid]->ntimers == 0, "quiescence retained or rearmed a timer root");
    }
    nodemanagerQuiesceWait(context);
    nodemanagerQuiesceWait(context);
    discard tosSetCurrentWorker(0);
}
static void wgServerFixtureClose(wg_server_fixture_t *f, const ww_lifecycle_context_t *context)
{
    if (f->server != NULL)
    {
        wgServerFixtureQuiesce(f, context);
        for (wid_t wid = 0; wid < f->env.count; ++wid)
        {
            discard tosSetCurrentWorker(wid);
            nodemanagerStopWorkerResources(wid, context);
            twfRequire(lineIsAlive(tunnelchainGetWorkerPacketLine(f->chain, wid)),
                       "worker Stop destroyed a chain packet line");
            twfRequire(f->ingress[wid] == NULL, "ingress owner retained a normal line");
            wwLwipRuntimeDestroyWorker(wid);
        }
        discard tosSetCurrentWorker(0);
        nodemanagerStop(context);
        nodemanagerStop(context);
        twfRequire(f->state->timer == NULL && atomic_load(&f->state->dispatch.count) == 0 &&
                       atomic_load(&f->state->dispatch.bytes) == 0 && atomic_load(&f->state->ingress_count) == 0,
                   "server destruction retained a timer, dispatch or ingress owner");
        for (size_t i = 0; i < usersCount(&f->users); ++i)
        {
            const user_t *account = usersGetAtConst(&f->users, i);
            twfRequire(account->runtime.active_cons_out == 0 && account->runtime.ip_usage_count == 0,
                       "shutdown leaked account/IP reservations");
        }
        twfRequire(masterpoolGetCheckedOut(f->chain->masterpool_line_pool) == f->env.count,
                   "normal-line references survived owner drain");
        f->server->onDestroy(f->server, context);
        f->adapter->onDestroy(f->adapter, context);
        f->sink->onDestroy(f->sink, context);
        for (unsigned i = 0; i < kWgFixtureTunnels; ++i)
        {
            twfRequire(f->stages[i][0] == 1 && f->stages[i][1] == f->env.count && f->stages[i][2] == 1 &&
                           f->stages[i][3] == f->env.count && f->stages[i][4] == 1 && f->stages[i][5] == 1,
                       "central lifecycle skipped or duplicated an inserted helper stage");
            twfRequire(f->stages[i][6] == 1 && f->stages[i][7] <= 1 && (! f->start_succeeded || f->stages[i][7] == 1),
                       "central startup skipped or duplicated an inserted helper stage");
        }
        tunnelchainDestroy(f->chain);
    }
    if (GSTATE.flag_lwip_initialized)
    {
        twfRequire(wwLwipShutdown(), "lwIP shared teardown failed");
        GSTATE.flag_lwip_initialized = false;
    }
    for (unsigned i = 0; i < f->server_count; ++i)
        sbufDestroy(f->to_server[i]);
    for (unsigned i = 0; i < f->client_count; ++i)
        sbufDestroy(f->to_client[i]);
    if (f->client_initialized)
        wireguardDeviceDestroy(&f->client);
    usersDestroy(&f->users);
    mutexDestroy(&f->as->control_mutex);
    rwlockDestroy(&f->as->users_lock);
    tunnelDestroy(f->auth);
    node_t *nodes[] = {&f->auth_node, &f->server_node, &f->adapter_node, &f->sink_node};
    for (unsigned i = 0; i < 4; ++i)
    {
        memoryFree(nodes[i]->name);
        memoryFree(nodes[i]->type);
        memoryFree(nodes[i]->next);
        cJSON_Delete(nodes[i]->node_settings_json);
    }
    map_node_t_drop(&f->config.node_map);
    memoryFree(f->file.name);
    vec_chains_t_drop(&f->config.chains);
    vec_configs_t_drop(&f->manager->configs);
    memoryFree(f->manager);
    nodemanager_gstate = NULL;
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();
    tosWorkerEnvTeardown(&f->env);
    for (wid_t wid = 0; wid < f->env.count; ++wid)
    {
        threadsafegenericpoolDestroy(f->env.wios_pools[wid]);
        master_pool_t *masters[] = {f->env.large_masters[wid],
                                    f->env.small_masters[wid],
                                    f->env.medium_masters[wid],
                                    f->env.splice_masters[wid]};
        for (unsigned i = 0; i < 4; ++i)
        {
            masterpoolMakeEmpty(masters[i]);
            masterpoolDestroy(masters[i]);
        }
    }
    twfRequire(masterpoolGetCheckedOut(f->env.message_master) == 0, "worker message records survived teardown");
    masterpoolMakeEmpty(f->env.message_master);
    masterpoolDestroy(f->env.message_master);
    masterpoolMakeEmpty(f->env.wios_master);
    masterpoolDestroy(f->env.wios_master);
    GSTATE.masterpool_messages = NULL;
    networkloggerDestroy();
    userTestRuntimeCleanup();
    wg_fixture = NULL;
}
