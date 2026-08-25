#include "UdpListener/interface.h"
#include "UdpListener/structure.h"
#include "tunnel_orderly_shutdown_harness.h"

#if defined(OS_LINUX)
#include <dirent.h>
#endif
#if defined(OS_UNIX)
#include <sys/mman.h>
#include <unistd.h>
#endif

enum
{
    kTestLargeBuffer = 8192,
    kTestLinePoolCap = 8,
};

static udplistener_dynamic_endpoint_test_fault_t g_dynamic_endpoint_fault;

bool udplistenerDynamicEndpointTestShouldFail(udplistener_dynamic_endpoint_test_fault_t fault)
{
    if (g_dynamic_endpoint_fault != fault)
    {
        return false;
    }

    g_dynamic_endpoint_fault = kUdpListenerDynamicEndpointTestFaultNone;
    return true;
}

#if defined(OS_LINUX)
static bool     g_fail_wio_read;
static uint32_t g_wio_read_calls;

int __real_wioRead(wio_t *io);
int __wrap_wioRead(wio_t *io);

int __wrap_wioRead(wio_t *io)
{
    ++g_wio_read_calls;
    if (g_fail_wio_read)
    {
        g_fail_wio_read = false;
        wioClose(io);
        return -1;
    }

    return __real_wioRead(io);
}
#endif

typedef struct udplistener_test_fixture_s
{
    twf_worker_env_t                      env;
    twf_line_pool_t                       lines;
    tunnel_t                             *listener;
    tunnel_t                             *next;
    tunnel_chain_t                       *chain;
    udplistener_dynamic_provider_t        provider;
    udplistener_dynamic_endpoint_handle_t reentrant_close_handle;
    uint32_t                              reentrant_init_calls;
    uint32_t                              accepted_init_calls;
    uint32_t                              accepted_payload_calls;
    uint32_t                              accepted_finish_calls;
    wid_t                                 accepted_init_wid;
    wid_t                                 accepted_payload_wid;
    wid_t                                 accepted_finish_wid;
    line_t                               *accepted_line;
} udplistener_test_fixture_t;

static void closeEndpointDuringInit(tunnel_t *t, line_t *l)
{
    udplistener_test_fixture_t *fixture = *(udplistener_test_fixture_t **) tunnelGetState(t);
    (void) l;
    ++fixture->reentrant_init_calls;
    udplistenerDynamicEndpointClose(fixture->listener, fixture->reentrant_close_handle);
}

static void acceptEndpointFinish(tunnel_t *t, line_t *l)
{
    udplistener_test_fixture_t *fixture = *(udplistener_test_fixture_t **) tunnelGetState(t);
    ++fixture->accepted_finish_calls;
    fixture->accepted_finish_wid = getWID();
    if (fixture->accepted_line != NULL)
    {
        twfRequire(l == fixture->accepted_line, "UdpListener finished an unexpected dynamic endpoint line");
    }
}

static void recordEndpointInit(tunnel_t *t, line_t *l)
{
    udplistener_test_fixture_t *fixture = *(udplistener_test_fixture_t **) tunnelGetState(t);
    ++fixture->accepted_init_calls;
    fixture->accepted_init_wid = getWID();
    fixture->accepted_line     = l;
}

static void recordEndpointPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udplistener_test_fixture_t *fixture = *(udplistener_test_fixture_t **) tunnelGetState(t);
    twfRequire(l == fixture->accepted_line, "UdpListener delivered payload on an unexpected dynamic endpoint line");
    ++fixture->accepted_payload_calls;
    fixture->accepted_payload_wid = getWID();
    lineReuseBuffer(l, buf);
}

static void illegalEndpointFinishDestroysProviderLine(tunnel_t *t, line_t *l)
{
    (void) t;
    lineDestroy(l);
}

static void setupFixture(udplistener_test_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBuffer, 0);

    fixture->listener = tunnelCreate(NULL, sizeof(udplistener_tstate_t), sizeof(udplistener_lstate_t));
    twfRequire(fixture->listener != NULL, "failed to create UdpListener tunnel");

    udplistener_tstate_t *lts   = tunnelGetState(fixture->listener);
    lts->workers_count          = 1;
    lts->fwmark                 = -1;
    lts->dynamic_admission_open = true;
    lts->worker_registries      = memoryAllocateZero(sizeof(udplistener_worker_registry_t) * lts->workers_count);
    twfRequire(lts->worker_registries != NULL, "failed to allocate worker registries");
    for (wid_t wid = 0; wid < lts->workers_count; ++wid)
    {
        lts->worker_registries[wid].endpoints       = udplistener_endpoint_map_t_init();
        lts->worker_registries[wid].next_generation = 1;
    }

    twfLinePoolSetup(&fixture->lines, fixture->listener->lstate_size, kTestLinePoolCap);
    fixture->provider = udplistenerGetDynamicProvider(fixture->listener);
    twfRequire(fixture->provider.instance != NULL, "provider instance is null");
    twfRequire(fixture->provider.open != NULL, "provider.open is null");
    twfRequire(fixture->provider.activate != NULL, "provider.activate is null");
    twfRequire(fixture->provider.close != NULL, "provider.close is null");
    twfRequire(fixture->provider.get_line_info != NULL, "provider.get_line_info is null");
}

static void attachRecordingNext(udplistener_test_fixture_t *fixture)
{
    fixture->next = tunnelCreate(NULL, sizeof(udplistener_test_fixture_t *), 0);
    twfRequire(fixture->next != NULL, "failed to create dynamic endpoint recording tunnel");
    *(udplistener_test_fixture_t **) tunnelGetState(fixture->next) = fixture;
    fixture->next->fnInitU                                         = recordEndpointInit;
    fixture->next->fnPayloadU                                      = recordEndpointPayload;
    fixture->next->fnFinU                                          = acceptEndpointFinish;
    tunnelBind(fixture->listener, fixture->next);

    fixture->chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    twfRequire(fixture->chain != NULL, "failed to allocate dynamic endpoint recording chain");
    fixture->chain->workers_count = 1;
    fixture->chain->line_pools[0] = fixture->lines.pools[0];
    fixture->listener->chain      = fixture->chain;
}

static void teardownFixture(udplistener_test_fixture_t *fixture)
{
    udplistener_tstate_t *lts = tunnelGetState(fixture->listener);
    if (lts->worker_registries != NULL)
    {
        for (wid_t wid = 0; wid < lts->workers_count; ++wid)
        {
            udplistener_endpoint_map_t_drop(&lts->worker_registries[wid].endpoints);
        }
        memoryFree(lts->worker_registries);
        lts->worker_registries = NULL;
    }

    if (fixture->chain != NULL)
    {
        fixture->listener->chain = NULL;
        memoryFree(fixture->chain);
        fixture->chain = NULL;
    }
    if (fixture->next != NULL)
    {
        tunnelDestroy(fixture->next);
        fixture->next = NULL;
    }

    twfLinePoolTeardown(&fixture->lines);
    tunnelDestroy(fixture->listener);
    twfWorkerEnvTeardown(&fixture->env);
}

static void testDynamicEndpointOpenActivateClose(void)
{
    twfSetCase("udplistener dynamic endpoint open, activate, line info query, and close");
    udplistener_test_fixture_t fixture;
    setupFixture(&fixture);

    ip_addr_t peer_ip = {.type = IPADDR_TYPE_V4};
    twfRequire(ip4AddrAddressToNetwork("127.0.0.1", &peer_ip.u_addr.ip4) != 0, "failed to parse 127.0.0.1");

    udplistener_dynamic_endpoint_open_request_t req = {
        .expected_peer_ip     = peer_ip,
        .expected_source_port = 12345,
    };
    udplistener_dynamic_endpoint_open_result_t res = {0};

    bool ok = fixture.provider.open(fixture.provider.instance, 0, &req, &res);
    twfRequire(ok, "provider.open failed");
    twfRequireEqualU32(res.handle.owner_wid, 0, "owner_wid mismatch");
    twfRequire(res.handle.generation > 0, "generation must be > 0");
    twfRequire(res.bound_local_port > 0, "bound_local_port must be allocated");
    twfRequireEqualU32(
        sockaddrPort(&res.bound_local_addr), res.bound_local_port, "bound endpoint address and result port must agree");

    udplistener_dynamic_endpoint_open_result_t second_res = {0};
    twfRequire(fixture.provider.open(fixture.provider.instance, 0, &req, &second_res),
               "second simultaneous provider.open failed");
    twfRequire(second_res.bound_local_port > 0 && second_res.bound_local_port != res.bound_local_port,
               "simultaneous port-zero opens must return distinct live ports");

    ok = fixture.provider.activate(fixture.provider.instance, res.handle);
    twfRequire(ok, "provider.activate failed");

    line_t                         *normal_line = twfLinePoolCreateLine(&fixture.lines);
    udplistener_dynamic_line_info_t info        = {0};
    bool is_dyn = fixture.provider.get_line_info(fixture.provider.instance, normal_line, &info);
    twfRequire(! is_dyn, "normal line must not report as dynamic endpoint line");
    lineDestroy(normal_line);

    fixture.provider.close(fixture.provider.instance, res.handle);
    // Double close must be safe idempotent no-op
    fixture.provider.close(fixture.provider.instance, res.handle);
    fixture.provider.close(fixture.provider.instance, second_res.handle);

    teardownFixture(&fixture);
}

typedef struct udplistener_nonzero_worker_fixture_s
{
    tunnel_t                             *listener;
    tunnel_t                             *next;
    tunnel_chain_t                       *chain;
    master_pool_t                        *line_master;
    generic_pool_t                       *line_pools[2];
    udplistener_dynamic_endpoint_handle_t handle;
    uint16_t                              port;
    line_t                               *line;
    uint32_t                              init_calls;
    uint32_t                              payload_calls;
    uint32_t                              finish_calls;
    wid_t                                 init_wid;
    wid_t                                 payload_wid;
    wid_t                                 finish_wid;
} udplistener_nonzero_worker_fixture_t;

static void recordNonzeroWorkerEndpointInit(tunnel_t *t, line_t *l)
{
    udplistener_nonzero_worker_fixture_t *fixture = *(udplistener_nonzero_worker_fixture_t **) tunnelGetState(t);
    ++fixture->init_calls;
    fixture->init_wid = getWID();
    fixture->line     = l;

    udplistener_dynamic_line_info_t info = {0};
    twfRequire(udplistenerGetLineInfo(fixture->listener, l, &info),
               "nonzero-worker endpoint line did not expose dynamic provider metadata");
    twfRequire(udplistenerDynamicEndpointHandleEquals(info.handle, fixture->handle) && info.expected_wid == 1 &&
                   info.generation == fixture->handle.generation && info.bound_local_port == fixture->port,
               "nonzero-worker endpoint line metadata lost its exact handle, WID, generation, or port");
}

static void recordNonzeroWorkerEndpointPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udplistener_nonzero_worker_fixture_t *fixture = *(udplistener_nonzero_worker_fixture_t **) tunnelGetState(t);
    twfRequire(l == fixture->line, "nonzero-worker payload arrived on the wrong endpoint line");
    ++fixture->payload_calls;
    fixture->payload_wid = getWID();
    lineReuseBuffer(l, buf);
}

static void recordNonzeroWorkerEndpointFinish(tunnel_t *t, line_t *l)
{
    udplistener_nonzero_worker_fixture_t *fixture = *(udplistener_nonzero_worker_fixture_t **) tunnelGetState(t);
    twfRequire(l == fixture->line, "nonzero-worker Finish arrived on the wrong endpoint line");
    ++fixture->finish_calls;
    fixture->finish_wid = getWID();
}

static void testDynamicEndpointNonzeroOwnerWorker(void)
{
    twfSetCase("udplistener dynamic endpoint creates and drains a live line on a nonzero owner worker");
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, 2, kTestLargeBuffer, kTwfDefaultSmallBufferSize);

    udplistener_nonzero_worker_fixture_t fixture = {0};
    fixture.listener = tunnelCreate(NULL, sizeof(udplistener_tstate_t), sizeof(udplistener_lstate_t));
    fixture.next     = tunnelCreate(NULL, sizeof(udplistener_nonzero_worker_fixture_t *), 0);
    twfRequire(fixture.listener != NULL && fixture.next != NULL, "failed to create nonzero-worker UdpListener chain");
    *(udplistener_nonzero_worker_fixture_t **) tunnelGetState(fixture.next) = &fixture;
    fixture.next->fnInitU                                                   = recordNonzeroWorkerEndpointInit;
    fixture.next->fnPayloadU                                                = recordNonzeroWorkerEndpointPayload;
    fixture.next->fnFinU                                                    = recordNonzeroWorkerEndpointFinish;
    tunnelBind(fixture.listener, fixture.next);

    fixture.line_master = masterpoolCreateWithCapacity(4 * kTestLinePoolCap);
    twfRequire(fixture.line_master != NULL, "failed to create nonzero-worker line master pool");
    for (wid_t wid = 0; wid < ARRAY_SIZE(fixture.line_pools); ++wid)
    {
        fixture.line_pools[wid] = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
            fixture.line_master, sizeof(line_t) + fixture.listener->lstate_size, kTestLinePoolCap);
        twfRequire(fixture.line_pools[wid] != NULL, "failed to create nonzero-worker line pool");
    }
    fixture.chain =
        memoryAllocateZero(sizeof(*fixture.chain) + ARRAY_SIZE(fixture.line_pools) * sizeof(generic_pool_t *));
    twfRequire(fixture.chain != NULL, "failed to allocate nonzero-worker endpoint chain");
    fixture.chain->workers_count = ARRAY_SIZE(fixture.line_pools);
    for (wid_t wid = 0; wid < fixture.chain->workers_count; ++wid)
    {
        fixture.chain->line_pools[wid] = fixture.line_pools[wid];
    }
    fixture.listener->chain = fixture.chain;

    udplistener_tstate_t *lts = tunnelGetState(fixture.listener);
    lts->workers_count        = 2;
    lts->fwmark               = -1;
    atomic_init(&lts->dynamic_admission_open, true);
    lts->worker_registries = memoryAllocateZero(sizeof(udplistener_worker_registry_t) * lts->workers_count);
    twfRequire(lts->worker_registries != NULL, "failed to allocate nonzero-worker endpoint registries");
    for (wid_t wid = 0; wid < lts->workers_count; ++wid)
    {
        lts->worker_registries[wid].endpoints       = udplistener_endpoint_map_t_init();
        lts->worker_registries[wid].next_generation = 1;
    }

    ip_addr_t peer_ip = {.type = IPADDR_TYPE_V4};
    twfRequire(ip4AddrAddressToNetwork("127.0.0.1", &peer_ip.u_addr.ip4) != 0, "failed to parse owner peer IP");
    const udplistener_dynamic_endpoint_open_request_t req = {
        .expected_peer_ip     = peer_ip,
        .expected_source_port = 33000,
    };

    testWorkerBindWID(1);
    udplistener_dynamic_endpoint_open_result_t res = {0};
    twfRequire(udplistenerDynamicEndpointOpen(fixture.listener, 1, &req, &res),
               "nonzero-worker dynamic endpoint open failed");
    fixture.handle = res.handle;
    fixture.port   = res.bound_local_port;
    twfRequireEqualU32(res.handle.owner_wid, 1, "nonzero-worker endpoint reported the wrong owner WID");
    twfRequire(udplistenerDynamicEndpointActivate(fixture.listener, res.handle),
               "nonzero-worker dynamic endpoint activation failed");

    udplistener_dynamic_endpoint_t *ep = udplistenerFindDynamicEndpoint(fixture.listener, res.handle);
    twfRequire(ep != NULL && ep->wio != NULL, "nonzero-worker endpoint was not published locally");

    sockaddr_u foreign_peer = {0};
    twfRequire(sockaddrSetIpAddressPort(&foreign_peer, "127.0.0.2", 33000) == 0,
               "failed to build nonzero-worker foreign peer");
    wioSetPeerAddr(ep->wio, &foreign_peer.sa, (int) sockaddrLen(&foreign_peer));
    sbuf_t *payload = bufferpoolGetSmallBuffer(env.pools[1]);
    sbufSetLength(payload, 1);
    udplistenerOnDynamicEndpointRead(ep->wio, payload);
    twfRequire(ep->line == NULL, "nonzero-worker foreign ingress created a client line");

    sockaddr_u peer = {0};
    twfRequire(sockaddrSetIpAddressPort(&peer, "127.0.0.1", 33000) == 0, "failed to build nonzero-worker valid peer");
    wioSetPeerAddr(ep->wio, &peer.sa, (int) sockaddrLen(&peer));
    payload = bufferpoolGetSmallBuffer(env.pools[1]);
    sbufSetLength(payload, 1);
    udplistenerOnDynamicEndpointRead(ep->wio, payload);
    twfRequire(ep->line != NULL && ep->line == fixture.line, "nonzero-worker valid ingress did not create one line");
    twfRequireEqualU32(lineGetWID(fixture.line), 1, "nonzero-worker endpoint line lost WID 1");
    twfRequireEqualU32(fixture.init_calls, 1, "nonzero-worker Init did not reach the next tunnel once");
    twfRequireEqualU32(fixture.payload_calls, 1, "nonzero-worker Payload did not reach the next tunnel once");
    twfRequireEqualU32(fixture.init_wid, 1, "nonzero-worker Init ran on the wrong worker");
    twfRequireEqualU32(fixture.payload_wid, 1, "nonzero-worker Payload ran on the wrong worker");

    wio_t                       *endpoint_wio = ep->wio;
    const ww_lifecycle_context_t context      = {0};
    udplistenerTunnelOnQuiesceRequest(fixture.listener, &context);
    udplistenerTunnelOnWorkerQuiesce(fixture.listener, 1, &context);
    ep = udplistenerFindDynamicEndpoint(fixture.listener, res.handle);
    twfRequire(ep != NULL && ep->state == kDynamicEndpointClosing && ep->wio == NULL,
               "worker quiesce did not retain a detached closing endpoint for drain");
    twfRequire(ep->line == fixture.line && lineIsAlive(fixture.line),
               "worker quiesce destroyed the provider-owned line before worker stop");
    twfRequire(endpoint_wio != NULL && wioIsClosed(endpoint_wio) && wioGetEvents(endpoint_wio) == 0 &&
                   weventGetUserdata(endpoint_wio) == NULL && wioGetCallBackRead(endpoint_wio) == NULL,
               "worker quiesce left the dynamic endpoint WIO able to dispatch callbacks");
    twfRequireEqualU32(fixture.payload_calls, 1, "worker quiesce allowed a new endpoint payload callback");

    udplistenerTunnelOnWorkerStop(fixture.listener, 1, &context);
    twfRequire(udplistenerFindDynamicEndpoint(fixture.listener, res.handle) == NULL,
               "nonzero-worker stop left a registry entry behind");
    twfRequireEqualU32(fixture.finish_calls, 1, "nonzero-worker provider close did not emit one upstream Finish");
    twfRequireEqualU32(fixture.finish_wid, 1, "nonzero-worker Finish ran on another worker");
    twfRequireEqualU32(
        masterpoolGetCheckedOut(fixture.line_master), 0, "nonzero-worker stop retained a provider-owned line");

    testWorkerBindWID(0);
    for (wid_t wid = 0; wid < lts->workers_count; ++wid)
    {
        udplistener_endpoint_map_t_drop(&lts->worker_registries[wid].endpoints);
    }
    memoryFree(lts->worker_registries);
    lts->worker_registries  = NULL;
    fixture.listener->chain = NULL;
    memoryFree(fixture.chain);
    for (wid_t wid = 0; wid < ARRAY_SIZE(fixture.line_pools); ++wid)
    {
        genericpoolDestroy(fixture.line_pools[wid]);
    }
    masterpoolDestroy(fixture.line_master);
    tunnelDestroy(fixture.next);
    tunnelDestroy(fixture.listener);
    tosWorkerEnvTeardown(&env);
}

static void testDynamicEndpointAdmissionShutdown(void)
{
    twfSetCase("udplistener dynamic endpoint admission close on quiesce request");
    udplistener_test_fixture_t fixture;
    setupFixture(&fixture);

    ip_addr_t peer_ip = {.type = IPADDR_TYPE_V4};
    twfRequire(ip4AddrAddressToNetwork("127.0.0.1", &peer_ip.u_addr.ip4) != 0, "failed to parse 127.0.0.1");

    udplistener_dynamic_endpoint_open_request_t req = {
        .expected_peer_ip     = peer_ip,
        .expected_source_port = 12345,
    };
    udplistener_dynamic_endpoint_open_result_t res = {0};

    bool ok = fixture.provider.open(fixture.provider.instance, 0, &req, &res);
    twfRequire(ok, "provider.open failed");

    ww_lifecycle_context_t ctx = {0};
    udplistenerTunnelOnQuiesceRequest(fixture.listener, &ctx);

    udplistener_dynamic_endpoint_open_result_t res2 = {0};
    bool                                       ok2  = fixture.provider.open(fixture.provider.instance, 0, &req, &res2);
    twfRequire(! ok2, "provider.open must fail when dynamic admission is closed");
    twfRequire(! fixture.provider.activate(fixture.provider.instance, res.handle),
               "provider.activate must fail when dynamic admission is closed");

    udplistenerTunnelOnWorkerStop(fixture.listener, 0, &ctx);
    teardownFixture(&fixture);
}

static void testDynamicEndpointFailedActivationReclaimsPreparedEndpoint(void)
{
    twfSetCase("udplistener failed activation removes a prepared endpoint from its registry");
    udplistener_test_fixture_t fixture;
    setupFixture(&fixture);

    ip_addr_t peer_ip = {.type = IPADDR_TYPE_V4};
    twfRequire(ip4AddrAddressToNetwork("127.0.0.1", &peer_ip.u_addr.ip4) != 0, "failed to parse activation peer IP");
    const udplistener_dynamic_endpoint_open_request_t req = {
        .expected_peer_ip     = peer_ip,
        .expected_source_port = 12345,
    };
    udplistener_dynamic_endpoint_open_result_t res = {0};
    twfRequire(fixture.provider.open(fixture.provider.instance, 0, &req, &res),
               "provider.open failed before activation-failure test");

    udplistener_dynamic_endpoint_t *ep = udplistenerFindDynamicEndpoint(fixture.listener, res.handle);
    twfRequire(ep != NULL && ep->wio != NULL, "prepared endpoint was not published before activation failure");
    wioClose(ep->wio);
    twfRequire(! fixture.provider.activate(fixture.provider.instance, res.handle),
               "activation unexpectedly succeeded for a closed prepared WIO");
    twfRequire(udplistenerFindDynamicEndpoint(fixture.listener, res.handle) == NULL,
               "failed activation left a prepared endpoint registry entry behind");

    teardownFixture(&fixture);
}

#if defined(OS_LINUX)
static uint32_t countOpenFileDescriptors(void)
{
    DIR *dir = opendir("/proc/self/fd");
    twfRequire(dir != NULL, "failed to inspect /proc/self/fd during dynamic endpoint rollback test");

    uint32_t count = 0;
    for (struct dirent *entry = readdir(dir); entry != NULL; entry = readdir(dir))
    {
        if (entry->d_name[0] != '.')
        {
            ++count;
        }
    }
    closedir(dir);
    return count;
}

static void requireDynamicOpenFailureLeavesNoResources(udplistener_test_fixture_t           *fixture,
                                                       udplistener_dynamic_endpoint_handle_t expected_handle,
                                                       const udplistener_dynamic_endpoint_open_result_t *result,
                                                       uint32_t fd_count_before)
{
    udplistener_tstate_t *lts = tunnelGetState(fixture->listener);
    twfRequire(! udplistenerDynamicEndpointHandleIsValid(result->handle) && result->bound_local_port == 0 &&
                   sockaddrPort((sockaddr_u *) &result->bound_local_addr) == 0,
               "failed dynamic endpoint open returned published metadata");
    twfRequire(udplistenerFindDynamicEndpoint(fixture->listener, expected_handle) == NULL,
               "failed dynamic endpoint open left a visible map handle");
    twfRequireEqualU32((uint32_t) udplistener_endpoint_map_t_size(&lts->worker_registries[0].endpoints),
                       0,
                       "failed dynamic endpoint open retained a registry entry");
    twfRequireEqualU32(
        countOpenFileDescriptors(), fd_count_before, "failed dynamic endpoint open retained a socket FD");
    twfRequireEqualU32(masterpoolGetCheckedOut(fixture->lines.master),
                       0,
                       "failed dynamic endpoint open created a provider-owned line");

    udplistenerDynamicEndpointClose(fixture->listener, expected_handle);
    udplistenerDynamicEndpointClose(fixture->listener, expected_handle);
}

static void testDynamicEndpointOpenRollbackFailures(void)
{
    twfSetCase("udplistener dynamic endpoint open and read-arm rollback release every resource");
    udplistener_test_fixture_t fixture;
    setupFixture(&fixture);

    ip_addr_t peer_ip = {.type = IPADDR_TYPE_V4};
    twfRequire(ip4AddrAddressToNetwork("127.0.0.1", &peer_ip.u_addr.ip4) != 0, "failed to parse rollback peer IP");
    const udplistener_dynamic_endpoint_open_request_t req = {
        .expected_peer_ip     = peer_ip,
        .expected_source_port = 12345,
    };

    const udplistener_dynamic_endpoint_test_fault_t faults[] = {
        kUdpListenerDynamicEndpointTestFaultAllocateEndpoint,
        kUdpListenerDynamicEndpointTestFaultPublishEndpoint,
    };
    for (size_t index = 0; index < ARRAY_SIZE(faults); ++index)
    {
        udplistener_tstate_t                       *lts             = tunnelGetState(fixture.listener);
        const udplistener_dynamic_endpoint_handle_t expected_handle = {
            .owner_wid  = 0,
            .generation = lts->worker_registries[0].next_generation,
        };
        const uint32_t                             fd_count_before = countOpenFileDescriptors();
        udplistener_dynamic_endpoint_open_result_t result          = {
                     .handle           = {.owner_wid = 7, .generation = 7},
                     .bound_local_port = 7,
        };

        g_dynamic_endpoint_fault = faults[index];
        twfRequire(! fixture.provider.open(fixture.provider.instance, 0, &req, &result),
                   "injected dynamic endpoint open failure unexpectedly succeeded");
        requireDynamicOpenFailureLeavesNoResources(&fixture, expected_handle, &result, fd_count_before);
    }

    const uint32_t                             fd_count_before = countOpenFileDescriptors();
    udplistener_dynamic_endpoint_open_result_t result          = {0};
    twfRequire(fixture.provider.open(fixture.provider.instance, 0, &req, &result),
               "dynamic endpoint open failed before read-arm rollback test");
    g_fail_wio_read  = true;
    g_wio_read_calls = 0;
    twfRequire(! fixture.provider.activate(fixture.provider.instance, result.handle),
               "injected wioRead failure unexpectedly activated an endpoint");
    twfRequireEqualU32(g_wio_read_calls, 1, "read-arm rollback did not execute the real wioRead call site");
    requireDynamicOpenFailureLeavesNoResources(
        &fixture, result.handle, &(udplistener_dynamic_endpoint_open_result_t) {0}, fd_count_before);

    teardownFixture(&fixture);
}
#endif

static void testDynamicEndpointInitCanCloseItselfReentrantly(void)
{
    twfSetCase("udplistener dynamic endpoint Init can close its endpoint re-entrantly");
    udplistener_test_fixture_t fixture;
    setupFixture(&fixture);

    fixture.next = tunnelCreate(NULL, sizeof(udplistener_test_fixture_t *), 0);
    twfRequire(fixture.next != NULL, "failed to create dynamic endpoint next tunnel");
    *(udplistener_test_fixture_t **) tunnelGetState(fixture.next) = &fixture;
    fixture.next->fnInitU                                         = closeEndpointDuringInit;
    fixture.next->fnFinU                                          = acceptEndpointFinish;
    tunnelBind(fixture.listener, fixture.next);

    fixture.chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    twfRequire(fixture.chain != NULL, "failed to allocate dynamic endpoint test chain");
    fixture.chain->workers_count = 1;
    fixture.chain->line_pools[0] = fixture.lines.pools[0];
    fixture.listener->chain      = fixture.chain;

    ip_addr_t peer_ip = {.type = IPADDR_TYPE_V4};
    twfRequire(ip4AddrAddressToNetwork("127.0.0.1", &peer_ip.u_addr.ip4) != 0, "failed to parse 127.0.0.1");
    const udplistener_dynamic_endpoint_open_request_t req = {
        .expected_peer_ip     = peer_ip,
        .expected_source_port = 12345,
    };
    udplistener_dynamic_endpoint_open_result_t res = {0};
    twfRequire(fixture.provider.open(fixture.provider.instance, 0, &req, &res), "provider.open failed");
    fixture.reentrant_close_handle = res.handle;
    twfRequire(fixture.provider.activate(fixture.provider.instance, res.handle), "provider.activate failed");

    udplistener_dynamic_endpoint_t *ep = udplistenerFindDynamicEndpoint(fixture.listener, res.handle);
    twfRequire(ep != NULL, "opened endpoint is absent from the provider registry");

    sockaddr_u peer = {0};
    twfRequire(sockaddrSetIpAddressPort(&peer, "127.0.0.1", 12345) == 0, "failed to build peer address");
    wioSetPeerAddr(ep->wio, &peer.sa, (int) sockaddrLen(&peer));

    sbuf_t *payload = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(payload, 1);
    sbufGetMutablePtr(payload)[0] = 0xA5;
    udplistenerOnDynamicEndpointRead(ep->wio, payload);

    twfRequireEqualU32(fixture.reentrant_init_calls, 1, "dynamic endpoint Init did not run once");
    twfRequire(udplistenerFindDynamicEndpoint(fixture.listener, res.handle) == NULL,
               "re-entrant endpoint close left a registry entry behind");
    twfRequireEqualU32(masterpoolGetCheckedOut(fixture.lines.master),
                       0,
                       "re-entrant endpoint close left its provider-owned line alive");

    teardownFixture(&fixture);
}

static void testDynamicEndpointIngressPinningPauseAndFinish(void)
{
    twfSetCase("udplistener dynamic endpoint enforces source pinning, pause, and provider ownership");
    udplistener_test_fixture_t fixture;
    setupFixture(&fixture);
    attachRecordingNext(&fixture);

    ip_addr_t peer_ip = {.type = IPADDR_TYPE_V4};
    twfRequire(ip4AddrAddressToNetwork("127.0.0.1", &peer_ip.u_addr.ip4) != 0, "failed to parse 127.0.0.1");
    const udplistener_dynamic_endpoint_open_request_t req = {
        .expected_peer_ip     = peer_ip,
        .expected_source_port = 0,
    };
    udplistener_dynamic_endpoint_open_result_t res = {0};
    twfRequire(fixture.provider.open(fixture.provider.instance, 0, &req, &res), "provider.open failed");
    twfRequire(fixture.provider.activate(fixture.provider.instance, res.handle), "provider.activate failed");

    udplistener_dynamic_endpoint_t *ep = udplistenerFindDynamicEndpoint(fixture.listener, res.handle);
    twfRequire(ep != NULL, "opened endpoint is absent from registry");

    sockaddr_u peer = {0};
    twfRequire(sockaddrSetIpAddressPort(&peer, "127.0.0.2", 32000) == 0, "failed to build foreign peer");
    wioSetPeerAddr(ep->wio, &peer.sa, (int) sockaddrLen(&peer));
    sbuf_t *payload = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(payload, 1);
    udplistenerOnDynamicEndpointRead(ep->wio, payload);
    twfRequire(ep->line == NULL, "wrong source IP created a dynamic UDP client line");
    twfRequireEqualU32(fixture.accepted_init_calls, 0, "wrong source IP reached next Init");

    twfRequire(sockaddrSetIpAddressPort(&peer, "127.0.0.1", 32001) == 0, "failed to build legitimate peer");
    wioSetPeerAddr(ep->wio, &peer.sa, (int) sockaddrLen(&peer));
    payload = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(payload, 1);
    sbufGetMutablePtr(payload)[0] = 0xA1;
    udplistenerOnDynamicEndpointRead(ep->wio, payload);
    twfRequire(ep->line != NULL, "legitimate source did not create a dynamic UDP client line");
    twfRequire(ep->source_port_pinned && ep->expected_source_port == 32001,
               "zero source-port request did not pin the first legitimate sender");
    twfRequireEqualU32(fixture.accepted_init_calls, 1, "legitimate source did not initialize next exactly once");
    twfRequireEqualU32(fixture.accepted_payload_calls, 1, "legitimate source payload did not reach next");

    line_t                         *line = ep->line;
    udplistener_dynamic_line_info_t info = {0};
    twfRequire(fixture.provider.get_line_info(fixture.provider.instance, line, &info),
               "dynamic client line did not report provider metadata");
    twfRequire(udplistenerDynamicEndpointHandleEquals(info.handle, res.handle) && info.expected_wid == 0 &&
                   info.generation == res.handle.generation && info.bound_local_port == res.bound_local_port,
               "dynamic client line metadata did not preserve exact handle, worker, generation, and port");
    twfRequire(lineGetRoutingContext(line)->local_listener_port == res.bound_local_port,
               "dynamic client line lost its bound listener port");

    udplistenerTunnelDownStreamPause(fixture.listener, line);
    payload = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(payload, 1);
    udplistenerOnDynamicEndpointRead(ep->wio, payload);
    twfRequireEqualU32(fixture.accepted_payload_calls, 1, "pause did not drop dynamic endpoint ingress");
    udplistenerTunnelDownStreamResume(fixture.listener, line);

    payload = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(payload, 1);
    udplistenerOnDynamicEndpointRead(ep->wio, payload);
    twfRequireEqualU32(fixture.accepted_payload_calls, 2, "resume did not restore dynamic endpoint ingress");

    twfRequire(sockaddrSetIpAddressPort(&peer, "127.0.0.1", 32002) == 0, "failed to build mismatched peer port");
    wioSetPeerAddr(ep->wio, &peer.sa, (int) sockaddrLen(&peer));
    payload = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(payload, 1);
    udplistenerOnDynamicEndpointRead(ep->wio, payload);
    twfRequireEqualU32(fixture.accepted_payload_calls, 2, "pinned endpoint accepted a mismatched source port");
    twfRequire(ep->line == line, "one dynamic endpoint created more than one active client line");

    udplistenerTunnelDownStreamFinish(fixture.listener, line);
    twfRequire(ep->line == NULL, "downstream Finish did not detach the provider-owned client line");
    twfRequireEqualU32(fixture.accepted_finish_calls,
                       0,
                       "downstream Finish reflected a provider-owned line close toward the sending next tunnel");
    fixture.provider.close(fixture.provider.instance, res.handle);

    const udplistener_dynamic_endpoint_open_request_t explicit_port_req = {
        .expected_peer_ip     = peer_ip,
        .expected_source_port = 32010,
    };
    udplistener_dynamic_endpoint_open_result_t explicit_port_res = {0};
    twfRequire(fixture.provider.open(fixture.provider.instance, 0, &explicit_port_req, &explicit_port_res),
               "explicit-source-port provider.open failed");
    twfRequire(fixture.provider.activate(fixture.provider.instance, explicit_port_res.handle),
               "explicit-source-port provider.activate failed");
    ep = udplistenerFindDynamicEndpoint(fixture.listener, explicit_port_res.handle);
    twfRequire(ep != NULL, "explicit-source-port endpoint is absent from registry");
    twfRequire(sockaddrSetIpAddressPort(&peer, "127.0.0.1", 32011) == 0, "failed to build wrong explicit source port");
    wioSetPeerAddr(ep->wio, &peer.sa, (int) sockaddrLen(&peer));
    payload = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(payload, 1);
    udplistenerOnDynamicEndpointRead(ep->wio, payload);
    twfRequire(ep->line == NULL, "configured nonzero source port accepted a mismatch");
    twfRequire(sockaddrSetIpAddressPort(&peer, "127.0.0.1", 32010) == 0, "failed to build configured source port");
    wioSetPeerAddr(ep->wio, &peer.sa, (int) sockaddrLen(&peer));
    payload = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(payload, 1);
    udplistenerOnDynamicEndpointRead(ep->wio, payload);
    twfRequire(ep->line != NULL, "configured nonzero source port rejected the legitimate sender");
    fixture.provider.close(fixture.provider.instance, explicit_port_res.handle);

    twfRequireEqualU32(masterpoolGetCheckedOut(fixture.lines.master),
                       0,
                       "dynamic endpoint ingress/Finish retained a provider-owned line");
    teardownFixture(&fixture);
}

static void testDynamicEndpointWorkerShutdownDrainsLiveLine(void)
{
    twfSetCase("udplistener worker quiesce and stop drain a live dynamic endpoint exactly once");
    udplistener_test_fixture_t fixture;
    setupFixture(&fixture);
    attachRecordingNext(&fixture);

    ip_addr_t peer_ip = {.type = IPADDR_TYPE_V4};
    twfRequire(ip4AddrAddressToNetwork("127.0.0.1", &peer_ip.u_addr.ip4) != 0, "failed to parse 127.0.0.1");
    const udplistener_dynamic_endpoint_open_request_t req = {
        .expected_peer_ip     = peer_ip,
        .expected_source_port = 32100,
    };
    udplistener_dynamic_endpoint_open_result_t res = {0};
    twfRequire(fixture.provider.open(fixture.provider.instance, 0, &req, &res), "provider.open failed");
    twfRequire(fixture.provider.activate(fixture.provider.instance, res.handle), "provider.activate failed");

    udplistener_dynamic_endpoint_t *ep = udplistenerFindDynamicEndpoint(fixture.listener, res.handle);
    twfRequire(ep != NULL, "opened endpoint is absent from registry");
    sockaddr_u peer = {0};
    twfRequire(sockaddrSetIpAddressPort(&peer, "127.0.0.1", 32100) == 0, "failed to build peer");
    wioSetPeerAddr(ep->wio, &peer.sa, (int) sockaddrLen(&peer));
    sbuf_t *payload = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(payload, 1);
    udplistenerOnDynamicEndpointRead(ep->wio, payload);
    twfRequire(ep->line != NULL, "live endpoint did not create a provider-owned client line");

    wio_t                       *endpoint_wio = ep->wio;
    const ww_lifecycle_context_t context      = {0};
    udplistenerTunnelOnQuiesceRequest(fixture.listener, &context);
    udplistenerTunnelOnWorkerQuiesce(fixture.listener, 0, &context);

    ep = udplistenerFindDynamicEndpoint(fixture.listener, res.handle);
    twfRequire(ep != NULL && ep->state == kDynamicEndpointClosing && ep->wio == NULL,
               "worker quiesce did not detach the endpoint WIO while retaining drain inventory");
    twfRequire(ep->line != NULL && lineIsAlive(ep->line),
               "worker quiesce destroyed a provider-owned line before worker stop");
    twfRequire(endpoint_wio != NULL && wioIsClosed(endpoint_wio) && wioGetEvents(endpoint_wio) == 0 &&
                   weventGetUserdata(endpoint_wio) == NULL && wioGetCallBackRead(endpoint_wio) == NULL,
               "worker quiesce left the dynamic endpoint WIO able to dispatch callbacks");
    twfRequireEqualU32(
        fixture.accepted_payload_calls, 1, "worker quiesce allowed another dynamic endpoint payload callback");
    twfRequireEqualU32(fixture.accepted_finish_calls, 0, "worker quiesce prematurely finished the provider-owned line");

    udplistenerTunnelOnWorkerStop(fixture.listener, 0, &context);
    twfRequireEqualU32(fixture.accepted_finish_calls,
                       1,
                       "provider lifecycle close did not send one upstream Finish to the next tunnel");
    twfRequire(udplistenerFindDynamicEndpoint(fixture.listener, res.handle) == NULL,
               "worker stop left a dynamic endpoint registry entry behind");
    twfRequireEqualU32(
        masterpoolGetCheckedOut(fixture.lines.master), 0, "worker stop retained a provider-owned client line");
    teardownFixture(&fixture);
}

static void illegalEndpointFinishBody(void *argument)
{
    (void) argument;

    udplistener_test_fixture_t fixture;
    setupFixture(&fixture);

    fixture.next = tunnelCreate(NULL, 0, 0);
    twfRequire(fixture.next != NULL, "failed to create invalid dynamic endpoint next tunnel");
    fixture.next->fnFinU = illegalEndpointFinishDestroysProviderLine;
    tunnelBind(fixture.listener, fixture.next);

    ip_addr_t peer_ip = {.type = IPADDR_TYPE_V4};
    twfRequire(ip4AddrAddressToNetwork("127.0.0.1", &peer_ip.u_addr.ip4) != 0, "failed to parse 127.0.0.1");
    const udplistener_dynamic_endpoint_open_request_t req = {
        .expected_peer_ip     = peer_ip,
        .expected_source_port = 12345,
    };
    udplistener_dynamic_endpoint_open_result_t res = {0};
    twfRequire(fixture.provider.open(fixture.provider.instance, 0, &req, &res), "provider.open failed");

    udplistener_dynamic_endpoint_t *ep = udplistenerFindDynamicEndpoint(fixture.listener, res.handle);
    twfRequire(ep != NULL, "opened endpoint is absent from the provider registry");

    line_t               *line = twfLinePoolCreateLine(&fixture.lines);
    udplistener_lstate_t *ls   = lineGetState(line, fixture.listener);
    *ls                        = (udplistener_lstate_t) {
                               .tunnel           = fixture.listener,
                               .line             = line,
                               .source_kind      = kUdpListenerSourceDynamic,
                               .dynamic_handle   = res.handle,
                               .bound_local_port = res.bound_local_port,
    };
    ep->line = line;

    /* A child may not destroy a provider-owned normal line during Finish. */
    fixture.provider.close(fixture.provider.instance, res.handle);
    twfRequire(false, "provider close accepted downstream destruction of its owned line");
}

static void testDynamicEndpointOwnerRejectsDownstreamLineDestruction(void)
{
    twfSetCase("udplistener dynamic endpoint owner rejects downstream line destruction");
    tosResetProcessApi(true);
    tosRequireChildExit(
        "downstream destruction during dynamic endpoint close", illegalEndpointFinishBody, NULL, kTosChildDirectAbort);
    tosResetProcessApi(true);
}

typedef enum udplistener_wrong_worker_entry_e
{
    kUdpListenerWrongWorkerPayload,
    kUdpListenerWrongWorkerFinish,
} udplistener_wrong_worker_entry_t;

#if defined(OS_UNIX)
static tunnel_t *makeWrongWorkerProtectedTunnel(uint32_t tstate_size, uint32_t lstate_size)
{
    const long page_size_long = sysconf(_SC_PAGESIZE);
    twfRequire(page_size_long > 0, "failed to determine page size for wrong-worker tunnel guard test");
    const size_t page_size = (size_t) page_size_long;
    const size_t state_at  = offsetof(tunnel_t, state);
    twfRequire(state_at < page_size, "tunnel header does not fit before wrong-worker state guard page");

    uint8_t *mapping = mmap(NULL, page_size * 2U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    twfRequire(mapping != MAP_FAILED, "failed to allocate wrong-worker tunnel guard pages");

    tunnel_t *t    = (tunnel_t *) (mapping + page_size - state_at);
    t->tstate_size = tstate_size;
    t->lstate_size = lstate_size;
    twfRequire(mprotect(mapping + page_size, page_size, PROT_NONE) == 0,
               "failed to protect wrong-worker tunnel state page");
    return t;
}

static line_t *makeWrongWorkerProtectedLine(void)
{
    const long page_size_long = sysconf(_SC_PAGESIZE);
    twfRequire(page_size_long > 0, "failed to determine page size for wrong-worker guard test");
    const size_t page_size     = (size_t) page_size_long;
    const size_t line_state_at = offsetof(line_t, tunnels_line_state);
    twfRequire(line_state_at < page_size, "line header does not fit before wrong-worker guard page");

    uint8_t *mapping = mmap(NULL, page_size * 2U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    twfRequire(mapping != MAP_FAILED, "failed to allocate wrong-worker guard pages");

    line_t *line = (line_t *) (mapping + page_size - line_state_at);
    atomic_init(&line->refc, 1);
    line->alive = true;
    line->wid   = 0;
    twfRequire(mprotect(mapping + page_size, page_size, PROT_NONE) == 0,
               "failed to protect wrong-worker line state page");
    return line;
}
#endif

static void wrongWorkerDownstreamEntryBody(void *argument)
{
    const udplistener_wrong_worker_entry_t entry = (udplistener_wrong_worker_entry_t) (uintptr_t) argument;
    udplistener_test_fixture_t             fixture;
    setupFixture(&fixture);

#if defined(OS_UNIX)
    tunnel_t *listener = makeWrongWorkerProtectedTunnel(sizeof(udplistener_tstate_t), sizeof(udplistener_lstate_t));
    line_t   *line     = makeWrongWorkerProtectedLine();
#else
    tunnel_t *listener = fixture.listener;
    line_t   *line     = twfLinePoolCreateLine(&fixture.lines);
#endif

    if (entry == kUdpListenerWrongWorkerPayload)
    {
        sbuf_t *payload = bufferpoolGetSmallBuffer(fixture.env.pool);
        sbufSetLength(payload, 1);
        testWorkerUnbindWID();
        udplistenerTunnelDownStreamPayload(listener, line, payload);
        return;
    }

    testWorkerUnbindWID();
    udplistenerTunnelDownStreamFinish(listener, line);
}

static void testWrongWorkerDownstreamCallbacksAbortBeforeLineStateAccess(void)
{
    twfSetCase("udplistener rejects foreign-worker downstream callbacks before line state access");
    tosResetProcessApi(true);
    tosRequireChildExit("downstream Payload from a foreign worker",
                        wrongWorkerDownstreamEntryBody,
                        (void *) (uintptr_t) kUdpListenerWrongWorkerPayload,
                        kTosChildDirectAbort);
    tosRequireChildExit("downstream Finish from a foreign worker",
                        wrongWorkerDownstreamEntryBody,
                        (void *) (uintptr_t) kUdpListenerWrongWorkerFinish,
                        kTosChildDirectAbort);
    tosResetProcessApi(true);
}

int main(void)
{
    testWrongWorkerDownstreamCallbacksAbortBeforeLineStateAccess();
    testDynamicEndpointOpenActivateClose();
    testDynamicEndpointNonzeroOwnerWorker();
    testDynamicEndpointAdmissionShutdown();
    testDynamicEndpointFailedActivationReclaimsPreparedEndpoint();
#if defined(OS_LINUX)
    testDynamicEndpointOpenRollbackFailures();
#endif
    testDynamicEndpointInitCanCloseItselfReentrantly();
    testDynamicEndpointIngressPinningPauseAndFinish();
    testDynamicEndpointWorkerShutdownDrainsLiveLine();
    testDynamicEndpointOwnerRejectsDownstreamLineDestruction();

    puts("udplistener_dynamic_endpoint_test: all cases passed");
    return 0;
}
