#include "PacketsToConnection/structure.h"

#include "devices/device_reader_session.h"
#include "lwip_test_runtime.h"
#include "worker_registry_fixture.h"

#include "lwip/tcpip.h"

#include <pthread.h>

typedef struct test_env_s
{
    master_pool_t         *large_master;
    master_pool_t         *small_master;
    buffer_pool_t         *worker_pool;
    buffer_pool_t         *buffer_pools[1];
    wloop_t               *loops[1];
    test_worker_registry_t worker_registry;
} test_env_t;

typedef struct input_probe_s
{
    unsigned int input_calls;
} input_probe_t;

typedef struct resource_tracking_s
{
    buffer_pool_t                     *pool;
    device_frag_affinity_publication_t publication;
    sbuf_t                            *reused[4];
    unsigned int                       reuse_counts[4];
    unsigned int                       reused_count;
    unsigned int                       settlement_count;
    device_frag_settlement_t           settlement;
} resource_tracking_t;

typedef struct close_reopen_probe_s
{
    device_reader_session_t *session;
    sbuf_t                  *original;
    bool                     expect_aligned_copy;
    bool                     hook_ran;
} close_reopen_probe_t;

typedef struct residue_gate_probe_s
{
    device_reader_session_t *session;
    atomic_bool              request_close;
    atomic_bool              closed;
    atomic_bool              completed;
    atomic_bool              boundary_observed;
} residue_gate_probe_t;

typedef struct admission_boundary_probe_s
{
    unsigned int before_stack_calls;
    unsigned int after_stack_calls;
} admission_boundary_probe_t;

static resource_tracking_t *resource_tracking;

void __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void __real_deviceFragAffinitySettlePublication(device_frag_affinity_table_t             *table,
                                                const device_frag_affinity_publication_t *publication,
                                                device_frag_settlement_t                  settlement);
void __wrap_deviceFragAffinitySettlePublication(device_frag_affinity_table_t             *table,
                                                const device_frag_affinity_publication_t *publication,
                                                device_frag_settlement_t                  settlement);

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "packetstoconnection_fragment_admission_test: %s\n", message);
        exit(1);
    }
}

static void resetResourceTracking(resource_tracking_t *tracking, buffer_pool_t *pool,
                                  const device_frag_affinity_publication_t *publication)
{
    *tracking = (resource_tracking_t) {
        .pool        = pool,
        .publication = *publication,
        .settlement  = kDeviceFragSettlementUnknown,
    };
    resource_tracking = tracking;
}

static void requireSettledAndReused(const resource_tracking_t *tracking, unsigned int expected_buffers,
                                    device_frag_settlement_t expected_settlement)
{
    require(tracking->settlement_count == 1, "fragment publication did not settle exactly once");
    require(tracking->settlement == expected_settlement, "fragment publication settled with the wrong result");
    require(tracking->reused_count == expected_buffers, "fragment path recycled the wrong number of buffers");
    for (unsigned int i = 0; i < tracking->reused_count; ++i)
    {
        require(tracking->reuse_counts[i] == 1, "fragment buffer was recycled more than once");
    }
}

void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf)
{
    if (resource_tracking != NULL && pool == resource_tracking->pool)
    {
        unsigned int index = 0;
        while (index < resource_tracking->reused_count && resource_tracking->reused[index] != buf)
        {
            ++index;
        }
        if (index == resource_tracking->reused_count)
        {
            require(index < ARRAY_SIZE(resource_tracking->reused), "fragment test observed too many recycled buffers");
            resource_tracking->reused[resource_tracking->reused_count++] = buf;
        }
        ++resource_tracking->reuse_counts[index];
        require(resource_tracking->reuse_counts[index] == 1, "fragment test observed a duplicate buffer recycle");
    }
    __real_bufferpoolReuseBuffer(pool, buf);
}

void __wrap_deviceFragAffinitySettlePublication(device_frag_affinity_table_t             *table,
                                                const device_frag_affinity_publication_t *publication,
                                                device_frag_settlement_t                  settlement)
{
    if (resource_tracking != NULL && publication != NULL && publication->valid &&
        publication->serial == resource_tracking->publication.serial &&
        publication->slot == resource_tracking->publication.slot &&
        publication->count == resource_tracking->publication.count)
    {
        ++resource_tracking->settlement_count;
        resource_tracking->settlement = settlement;
        require(resource_tracking->settlement_count == 1, "fragment test observed duplicate publication settlement");
    }
    __real_deviceFragAffinitySettlePublication(table, publication, settlement);
}

static void writeIpv4Checksum(uint8_t *packet)
{
    uint32_t sum = 0;
    PUT_BE16(packet + 10, 0);
    for (uint32_t offset = 0; offset < 20; offset += 2)
    {
        sum += GET_BE16(packet + offset);
    }
    while ((sum >> 16U) != 0)
    {
        sum = (sum & UINT32_C(0xFFFF)) + (sum >> 16U);
    }
    PUT_BE16(packet + 10, (uint16_t) ~sum);
}

static void fillFragment(sbuf_t *buf, uint16_t identification, bool shifted)
{
    enum
    {
        kPayloadBytes = 64,
        kPacketBytes  = 20 + kPayloadBytes,
    };

    sbufSetLength(buf, kPacketBytes + (shifted ? 1U : 0U));
    if (shifted)
    {
        sbufShiftRight(buf, 1);
    }

    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, kPacketBytes);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = IP_PROTO_UDP;
    PUT_BE16(packet + 2, kPacketBytes);
    PUT_BE16(packet + 4, identification);
    PUT_BE16(packet + 6, UINT16_C(0x2000));
    PUT_BE32(packet + 12, UINT32_C(0x0A000001));
    PUT_BE32(packet + 16, UINT32_C(0xC0000201));
    PUT_BE16(packet + 20, 5900);
    PUT_BE16(packet + 22, 53);
    writeIpv4Checksum(packet);
}

static void discardDeliveredPacket(void *device, sbuf_t *buf, wid_t wid)
{
    discard device;
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static device_reader_session_t *createSession(test_env_t *env)
{
    device_reader_session_t *session = deviceReaderSessionCreate(4, 1, env, discardDeliveredPacket, env->worker_pool);
    require(session != NULL, "failed to create fragment-admission reader session");
    require(deviceReaderSessionBegin(session) != 0, "failed to begin fragment-admission reader session");
    return session;
}

static sbuf_t *createClaimedFragment(test_env_t *env, device_reader_session_t *session, uint16_t identification,
                                     bool shifted, device_frag_affinity_publication_t *publication_out)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(env->worker_pool);
    fillFragment(buf, identification, shifted);

    device_frag_affinity_result_t result;
    require(deviceFragAffinityOffer(session->frag_affinity, sbufGetRawPtr(buf), sbufGetLength(buf), buf, &result) ==
                kDeviceFragAffinityDispatch,
            "fragment fixture did not create a tracked publication");
    require(result.publication.valid, "fragment fixture publication was invalid");
    require(
        deviceFragClaimAttach(session, (uint32_t) atomicLoadRelaxed(&session->generation), &result.publication, buf),
        "failed to attach fragment fixture claim");
    *publication_out = result.publication;
    return buf;
}

static err_t captureInput(struct pbuf *p, struct netif *inp)
{
    input_probe_t *probe = inp->state;
    ++probe->input_calls;
    pbuf_free(p);
    return ERR_OK;
}

static void initializeInputNetif(struct netif *netif, input_probe_t *probe)
{
    memoryZero(netif, sizeof(*netif));
    netif->state = probe;
    netif->input = captureInput;
}

static void closeAndReopenBeforeAdmission(sbuf_t *buf, struct netif *inp, void *context)
{
    close_reopen_probe_t *probe = context;
    discard               inp;

    require(! probe->hook_ran, "before-admission hook ran more than once");
    if (probe->expect_aligned_copy)
    {
        require(buf != probe->original, "shifted fragment did not obtain a distinct aligned copy");
        require(sbufGetLifetime(probe->original) == NULL && sbufGetLifetime(buf) != NULL,
                "shifted fragment claim did not transfer exactly once to the aligned copy");
    }
    else
    {
        require(buf == probe->original, "aligned fragment unexpectedly changed buffer before final admission");
    }

    deviceReaderSessionEnd(probe->session);
    require(deviceReaderSessionBegin(probe->session) != 0, "failed to reopen session at final-admission race seam");
    probe->hook_ran = true;
}

static void recordBeforeStackAdmission(sbuf_t *buf, struct netif *inp, void *context)
{
    admission_boundary_probe_t *probe = context;
    discard                     buf;
    discard                     inp;
    ++probe->before_stack_calls;
}

static void recordAfterStackAdmission(sbuf_t *buf, struct netif *inp, void *context)
{
    admission_boundary_probe_t *probe = context;
    discard                     buf;
    discard                     inp;
    ++probe->after_stack_calls;
}

static void *endAtResidueQueryRoutine(void *userdata)
{
    residue_gate_probe_t *probe = userdata;
    while (! atomicLoadExplicit(&probe->request_close, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    deviceReaderSessionEndRequest(probe->session);
    atomicStoreExplicit(&probe->closed, true, memory_order_release);
    deviceReaderSessionEndWait(probe->session);
    atomicStoreExplicit(&probe->completed, true, memory_order_release);
    return NULL;
}

static void proveGateHeldAtResidueQuery(sbuf_t *buf, struct netif *inp, void *context)
{
    residue_gate_probe_t *probe = context;
    discard               buf;
    discard               inp;

    atomicStoreExplicit(&probe->request_close, true, memory_order_release);
    while (! atomicLoadExplicit(&probe->closed, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    require(! quiescenceGateIsActive(&probe->session->delivery_gate),
            "reader EndRequest left delivery admission open at the residue boundary");
    require(! quiescenceGateIsClosedAndQuiesced(&probe->session->delivery_gate),
            "reader EndWait quiesced before the authoritative residue query returned");
    atomicStoreExplicit(&probe->boundary_observed, true, memory_order_release);
}

static void invokeSubmission(sbuf_t *buf, struct netif *netif)
{
    LOCK_TCPIP_CORE();
    ptcFragmentAdmissionTestSubmitPacketToStack(buf, netif);
    UNLOCK_TCPIP_CORE();
}

static void testCloseReopenRejectsAlignedFragment(test_env_t *env)
{
    device_reader_session_t            *session = createSession(env);
    device_frag_affinity_publication_t  publication;
    sbuf_t                             *buf = createClaimedFragment(env, session, 41001, false, &publication);
    resource_tracking_t                 tracking;
    close_reopen_probe_t                hook_probe  = {.session = session, .original = buf};
    input_probe_t                       input_probe = {0};
    struct netif                        netif;
    ptc_fragment_admission_test_hooks_t hooks = {
        .before_stack_admission = closeAndReopenBeforeAdmission,
        .context                = &hook_probe,
    };

    initializeInputNetif(&netif, &input_probe);
    resetResourceTracking(&tracking, env->worker_pool, &publication);
    ptcFragmentAdmissionTestInstallHooks(&hooks);
    invokeSubmission(buf, &netif);
    ptcFragmentAdmissionTestInstallHooks(NULL);

    require(hook_probe.hook_ran, "aligned close/reopen seam did not run");
    require(input_probe.input_calls == 0, "stale aligned fragment reached netif input");
    requireSettledAndReused(&tracking, 1, kDeviceFragSettlementNoResidue);

    resource_tracking = NULL;
    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testCloseReopenRejectsShiftedFragmentAndBalancesCopy(test_env_t *env)
{
    device_reader_session_t           *session = createSession(env);
    device_frag_affinity_publication_t publication;
    sbuf_t                            *buf = createClaimedFragment(env, session, 41002, true, &publication);
    resource_tracking_t                tracking;
    close_reopen_probe_t               hook_probe = {
                      .session             = session,
                      .original            = buf,
                      .expect_aligned_copy = true,
    };
    input_probe_t                       input_probe = {0};
    struct netif                        netif;
    ptc_fragment_admission_test_hooks_t hooks = {
        .before_stack_admission = closeAndReopenBeforeAdmission,
        .context                = &hook_probe,
    };

    initializeInputNetif(&netif, &input_probe);
    resetResourceTracking(&tracking, env->worker_pool, &publication);
    ptcFragmentAdmissionTestInstallHooks(&hooks);
    invokeSubmission(buf, &netif);
    ptcFragmentAdmissionTestInstallHooks(NULL);

    require(hook_probe.hook_ran, "shifted close/reopen seam did not run");
    require(input_probe.input_calls == 0, "stale shifted fragment reached netif input");
    requireSettledAndReused(&tracking, 2, kDeviceFragSettlementNoResidue);

    resource_tracking = NULL;
    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testAlignedCopyAllocationFailurePurgesAndSettles(test_env_t *env)
{
    device_reader_session_t            *session = createSession(env);
    device_frag_affinity_publication_t  publication;
    sbuf_t                             *buf = createClaimedFragment(env, session, 41003, true, &publication);
    resource_tracking_t                 tracking;
    input_probe_t                       input_probe = {0};
    struct netif                        netif;
    admission_boundary_probe_t          boundary_probe = {0};
    ptc_fragment_admission_test_hooks_t hooks          = {
                 .before_stack_admission = recordBeforeStackAdmission,
                 .context                = &boundary_probe,
                 .fail_aligned_copy      = true,
    };

    initializeInputNetif(&netif, &input_probe);
    resetResourceTracking(&tracking, env->worker_pool, &publication);
    ptcFragmentAdmissionTestInstallHooks(&hooks);
    invokeSubmission(buf, &netif);
    ptcFragmentAdmissionTestInstallHooks(NULL);

    require(input_probe.input_calls == 0, "aligned-copy allocation failure reached netif input");
    require(boundary_probe.before_stack_calls == 0,
            "aligned-copy allocation failure reached the pre-stack-admission boundary");
    requireSettledAndReused(&tracking, 1, kDeviceFragSettlementNoResidue);

    resource_tracking = NULL;
    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testRxWrapperAllocationFailureLeavesGateAndSettles(test_env_t *env)
{
    device_reader_session_t            *session = createSession(env);
    device_frag_affinity_publication_t  publication;
    sbuf_t                             *buf = createClaimedFragment(env, session, 41004, false, &publication);
    resource_tracking_t                 tracking;
    input_probe_t                       input_probe = {0};
    struct netif                        netif;
    admission_boundary_probe_t          boundary_probe = {0};
    ptc_fragment_admission_test_hooks_t hooks          = {
                 .after_stack_admission      = recordAfterStackAdmission,
                 .context                    = &boundary_probe,
                 .fail_rx_wrapper_allocation = true,
    };

    initializeInputNetif(&netif, &input_probe);
    resetResourceTracking(&tracking, env->worker_pool, &publication);
    ptcFragmentAdmissionTestInstallHooks(&hooks);
    invokeSubmission(buf, &netif);
    ptcFragmentAdmissionTestInstallHooks(NULL);

    require(input_probe.input_calls == 0, "RX-wrapper allocation failure reached netif input");
    require(boundary_probe.after_stack_calls == 1,
            "RX-wrapper allocation failure did not pass authoritative stack admission exactly once");
    requireSettledAndReused(&tracking, 1, kDeviceFragSettlementNoResidue);

    resource_tracking = NULL;
    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testSuccessfulAdmissionHoldsGateThroughResidueQuery(test_env_t *env)
{
    device_reader_session_t           *session = createSession(env);
    device_frag_affinity_publication_t publication;
    sbuf_t                            *buf = createClaimedFragment(env, session, 41005, false, &publication);
    resource_tracking_t                tracking;
    input_probe_t                      input_probe = {0};
    struct netif                       netif;
    residue_gate_probe_t               gate_probe = {
                      .session           = session,
                      .request_close     = false,
                      .closed            = false,
                      .completed         = false,
                      .boundary_observed = false,
    };
    ptc_fragment_admission_test_hooks_t hooks = {
        .before_residue_query = proveGateHeldAtResidueQuery,
        .context              = &gate_probe,
    };
    pthread_t end_thread;

    initializeInputNetif(&netif, &input_probe);
    resetResourceTracking(&tracking, env->worker_pool, &publication);
    require(pthread_create(&end_thread, NULL, endAtResidueQueryRoutine, &gate_probe) == 0,
            "failed to create residue-query End waiter");
    ptcFragmentAdmissionTestInstallHooks(&hooks);
    invokeSubmission(buf, &netif);
    ptcFragmentAdmissionTestInstallHooks(NULL);
    require(pthread_join(end_thread, NULL) == 0, "failed to join residue-query End waiter");

    require(atomicLoadExplicit(&gate_probe.boundary_observed, memory_order_acquire),
            "successful fragment path skipped the residue-query seam");
    require(atomicLoadExplicit(&gate_probe.completed, memory_order_acquire),
            "reader EndWait did not complete after residue query and gate leave");
    require(input_probe.input_calls == 1, "successful fragment was not delivered to netif input");
    requireSettledAndReused(&tracking, 1, kDeviceFragSettlementNoResidue);

    resource_tracking = NULL;
    deviceReaderSessionUnref(session);
}

static void envSetup(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    env->large_master = masterpoolCreateWithCapacity(16);
    env->small_master = masterpoolCreateWithCapacity(16);
    env->worker_pool  = bufferpoolCreate(env->large_master, env->small_master, 16, 4096, 1024);
    require(env->large_master != NULL && env->small_master != NULL && env->worker_pool != NULL,
            "failed to create fragment-admission test pools");

    env->buffer_pools[0]                 = env->worker_pool;
    env->loops[0]                        = (wloop_t *) (void *) env;
    GSTATE.workers_count                 = 2;
    GSTATE.shortcut_buffer_pools         = env->buffer_pools;
    GSTATE.shortcut_loops                = env->loops;
    GSTATE.masterpool_buffer_pools_large = env->large_master;
    GSTATE.masterpool_buffer_pools_small = env->small_master;
    testWorkerRegistryInstall(&env->worker_registry);
    testWorkerBindWID(0);
}

static void envTeardown(test_env_t *env)
{
    testWorkerUnbindWID();
    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.shortcut_loops                = NULL;
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    GSTATE.workers_count                 = 0;
    testWorkerRegistryRestore(&env->worker_registry);

    bufferpoolDestroy(env->worker_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

static atomic_bool lwip_initialized;

static void lwipInitialized(void *argument)
{
    discard argument;
    frandInit();
    atomicStoreExplicit(&lwip_initialized, true, memory_order_release);
}

int main(void)
{
    require(lwipTestRuntimeInitialize(), "failed to initialize the lwIP random runtime");
    atomic_init(&lwip_initialized, false);
    tcpip_init(lwipInitialized, NULL);
    while (! atomicLoadExplicit(&lwip_initialized, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    ptcRxWrapperPoolInitializeOnce();

    test_env_t env;
    envSetup(&env);
    testCloseReopenRejectsAlignedFragment(&env);
    testCloseReopenRejectsShiftedFragmentAndBalancesCopy(&env);
    testAlignedCopyAllocationFailurePurgesAndSettles(&env);
    testRxWrapperAllocationFailureLeavesGateAndSettles(&env);
    testSuccessfulAdmissionHoldsGateThroughResidueQuery(&env);
    envTeardown(&env);

    require(wwLwipShutdown(), "failed to shut down the fragment-admission lwIP thread");
    lwipTestRuntimeCleanup();
    puts("PacketsToConnection fragment-admission tests passed");
    return 0;
}
