/* Production Windows reader with real threadpool waits and substituted Wintun
 * ring I/O. Covers owner confinement, bounded drains, empty-ring rearm,
 * coalescing, receive failure, startup refusal and late generation settlement.
 * CTest: waterwall.tun_windows_reader_unit */
#include "devices/device_flow_affinity.h"
#include "fixtures/worker_registry_fixture.h"
#include "loggers/log_rate_limiter.h"
#include "test_assert.h"
#include "wintun.h"
#include "worker_messages.h"
#include "wwapi.h"
#include <iphlpapi.h>
#include <netioapi.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef struct captured_s
{
    wid_t                        wid;
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *arg1;
    void                        *arg2;
    void                        *arg3;
} captured_t;

static CRITICAL_SECTION capture_lock;
static captured_t       captured[1024];
static size_t           captured_count;
static HANDLE           receive_event;
static unsigned int     remaining;
static unsigned int     fixture_received;
static unsigned int     released;
static unsigned int     delivered;
static unsigned int     shutdowns;
static unsigned int     ends;
static DWORD            fixture_packet_size;
static DWORD            receive_error;
static BYTE             native_packet[65535];
static bool             packet_outstanding;
static bool             reject_next;
static bool             fail_wait_create;
static bool             fail_get_event;
static HANDLE           arm_reached;
static HANDLE           stop_done;
static bool             stop_during_rearm;
static atomic_uint      foreign_notifications;
static atomic_uint      refusals;
static uint64_t         warning_now_ms;
static unsigned         packet_warnings, output_recycles;
static bool             count_output_recycles;

static bool fixtureWarningGate(atomic_log_rate_limiter_t *limiter, uint64_t interval)
{
    return atomicLogRateLimiterShouldLogAt(limiter, interval, warning_now_ms);
}

static void captureWarning(int level, const char *bytes, int length)
{
    discard      level;
    char         text[512];
    const size_t size = min((size_t) max(length, 0), sizeof(text) - 1);
    memcpy(text, bytes, size);
    text[size] = '\0';
    if (strstr(text, "exceeds device MTU") != NULL)
        ++packet_warnings;
}

static void fixtureReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer)
{
    if (count_output_recycles)
        ++output_recycles;
    bufferpoolReuseBuffer(pool, buffer);
}

static worker_message_submit_result_e fixtureQueue(wid_t wid, WorkerMessageCallback callback,
                                                   WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2,
                                                   void *arg3)
{
    const bool foreign = ! currentThreadIsWorker();
    EnterCriticalSection(&capture_lock);
    if (reject_next)
    {
        reject_next = false;
        LeaveCriticalSection(&capture_lock);
        cleanup(arg1, arg2, arg3, kWorkerMessageCancelAdmissionClosed);
        atomicIncRelaxed(&refusals);
        return kWorkerMessageSubmitRejectedCleanupRan;
    }
    require(captured_count < ARRAY_SIZE(captured), "worker token capacity");
    captured[captured_count++] = (captured_t) {wid, callback, cleanup, arg1, arg2, arg3};
    LeaveCriticalSection(&capture_lock);
    if (foreign)
        atomicIncRelaxed(&foreign_notifications);
    return kWorkerMessageSubmitAccepted;
}

static bool fixtureShutdownRequest(int status)
{
    require(status == 1, "reader failure selected wrong status");
    shutdowns++;
    return true;
}

static PTP_WAIT WINAPI fixtureCreateWait(PTP_WAIT_CALLBACK callback, PVOID context, PTP_CALLBACK_ENVIRON environment)
{
    if (fail_wait_create)
    {
        fail_wait_create = false;
        SetLastError(ERROR_NO_SYSTEM_RESOURCES);
        return NULL;
    }
    return CreateThreadpoolWait(callback, context, environment);
}

static void fixtureDistribute(device_reader_session_t *session, sbuf_t **buffers, unsigned int count)
{
    require(currentThreadOwnsWorker(0), "packet distribution escaped reader owner");
    for (unsigned int i = 0; i < count; ++i)
    {
        require(sbufGetLength(buffers[i]) == fixture_packet_size, "native packet length changed");
        require(((const BYTE *) sbufGetRawPtr(buffers[i]))[0] == (BYTE) delivered, "packet copy or FIFO changed");
        delivered++;
        bufferpoolReuseBuffer(session->reader_buffer_pool, buffers[i]);
    }
}

static void WINAPI fixtureSetWait(PTP_WAIT wait, HANDLE event, PFILETIME timeout);

static NETIO_STATUS mtu_query_status;
static NETIO_STATUS mtu_set_status;
static unsigned int mtu_queries, mtu_sets;

static void WINAPI fixtureInitializeIpInterface(PMIB_IPINTERFACE_ROW row)
{
    memoryZero(row, sizeof(*row));
}

static NETIO_STATUS WINAPI fixtureGetIpInterface(PMIB_IPINTERFACE_ROW row)
{
    require(row->Family == AF_INET && row->InterfaceLuid.Value == 789, "MTU query selected wrong interface");
    ++mtu_queries;
    row->NlMtu              = 1500;
    row->Metric             = 17;
    row->UseAutomaticMetric = FALSE;
    row->SitePrefixLength   = 64;
    return mtu_query_status;
}

static NETIO_STATUS WINAPI fixtureSetIpInterface(PMIB_IPINTERFACE_ROW row)
{
    ++mtu_sets;
    require(row->Family == AF_INET && row->InterfaceLuid.Value == 789 && row->NlMtu == 1400 &&
                row->SitePrefixLength == 0 && row->Metric == 17 && ! row->UseAutomaticMetric,
            "MTU update changed interface identity/settings or omitted IPv4 prefix normalization");
    return mtu_set_status;
}

static void WINAPI fixtureAdapterLuid(WINTUN_ADAPTER_HANDLE adapter, NET_LUID *luid)
{
    require(adapter == (WINTUN_ADAPTER_HANDLE) (uintptr_t) 456, "MTU query used wrong adapter");
    luid->Value = 789;
}

#define sendWorkerMessageForceQueueWithCleanup fixtureQueue
#define requestProgramShutdown                 fixtureShutdownRequest
#define SetThreadpoolWait                      fixtureSetWait
#define CreateThreadpoolWait                   fixtureCreateWait
#define deviceReaderDistributeBatchDroppingOverflow fixtureDistribute
#define GetIpInterfaceEntry                         fixtureGetIpInterface
#define SetIpInterfaceEntry                         fixtureSetIpInterface
#define InitializeIpInterfaceEntry                  fixtureInitializeIpInterface
#define atomicLogRateLimiterShouldLog               fixtureWarningGate
#define bufferpoolReuseBuffer                       fixtureReuseBuffer
#include "../../../ww/devices/tun/tun_windows.c"
#undef sendWorkerMessageForceQueueWithCleanup
#undef requestProgramShutdown
#undef CreateThreadpoolWait
#undef SetThreadpoolWait
#undef deviceReaderDistributeBatchDroppingOverflow
#undef GetIpInterfaceEntry
#undef SetIpInterfaceEntry
#undef InitializeIpInterfaceEntry
#undef atomicLogRateLimiterShouldLog
#undef bufferpoolReuseBuffer

static void testOversizedOutputWarnings(buffer_pool_t *pool)
{
    atomicLogRateLimiterInitialize(&tun_oversized_output_log);
    loggerSetHandler(getInternalLogger(), captureWarning);
    warning_now_ms  = 0;
    packet_warnings = output_recycles = 0;
    tun_device_t device               = {.mtu = 1500};
    atomic_init(&device.lifecycle, kTunLifecycleUp);
    for (unsigned burst = 0; burst < 2; ++burst)
    {
        sbuf_t        *buffers[4];
        const unsigned count = burst == 0 ? 4 : 1;
        for (unsigned i = 0; i < count; ++i)
        {
            buffers[i] = bufferpoolGetSmallBuffer(pool);
            sbufSetLength(buffers[i], 1501);
        }
        count_output_recycles = true;
        require(tunWriteBatch(&device, getCurrentWorker(), buffers, count), "oversized drop failed device lifecycle");
        count_output_recycles = false;
        require(packet_warnings == burst + 1 && output_recycles == 4 + burst,
                "oversized output warnings were unbounded or leaked a buffer");
        warning_now_ms += kTunDiscardReportIntervalMs;
    }
}

static void testIpv4MtuConfiguration(void)
{
    tun_device_t device         = {.adapter_handle = (HANDLE) (uintptr_t) 456, .mtu = 1400};
    wintun_api.get_adapter_luid = fixtureAdapterLuid;
    require(tunWindowsSetMtu(&device) && mtu_queries == 1 && mtu_sets == 1, "MTU success did not update IP row");
    mtu_query_status = ERROR_NOT_FOUND;
    require(! tunWindowsSetMtu(&device) && mtu_queries == 2 && mtu_sets == 1, "MTU query failure was ignored");
    mtu_query_status = NO_ERROR;
    mtu_set_status   = ERROR_ACCESS_DENIED;
    require(! tunWindowsSetMtu(&device) && mtu_queries == 3 && mtu_sets == 2, "MTU set failure was ignored");
    device.adapter_handle = NULL;
    require(! tunWindowsSetMtu(&device) && mtu_queries == 3, "missing adapter reached IP configuration");
}

static void testMinimumIpv4Write(void)
{
    tun_device_t device = {0};
    tunWriterInit(&device.writer);
    sbuf_t *packet = sbufCreate(20);
    sbufSetLength(packet, 20);
    memoryZero(sbufGetMutablePtr(packet), 20);
    uint8_t *bytes = sbufGetMutablePtr(packet);
    bytes[0]       = 0x45;
    PUT_BE16(bytes + 2, 20);
    require(! tundeviceWrite(&device, packet), "closed writer accepted a minimum IPv4 packet");
    require(sbufGetLength(packet) == 20, "writer refusal changed caller-owned packet");
    sbufDestroy(packet);
    tunWriterDestroy(&device.writer);
}

static void WINAPI fixtureSetWait(PTP_WAIT wait, HANDLE event, PFILETIME timeout)
{
    if (event != NULL && stop_during_rearm)
    {
        stop_during_rearm = false;
        require(SetEvent(arm_reached), "could not publish rearm boundary");
        require(WaitForSingleObject(stop_done, 5000) == WAIT_OBJECT_0, "stop did not close admitted reader");
    }
    SetThreadpoolWait(wait, event, timeout);
}

static DWORD WINAPI fixtureStopOnRearm(LPVOID context)
{
    require(! currentThreadIsWorker(), "stop fixture borrowed an event-worker identity");
    require(WaitForSingleObject(arm_reached, 5000) == WAIT_OBJECT_0, "reader did not reach rearm boundary");
    require(tundeviceRequestStop(context), "foreign lifecycle owner could not close admission");
    require(SetEvent(stop_done), "could not publish closed admission");
    return 0;
}

static HANDLE WINAPI fixtureReadEvent(WINTUN_SESSION_HANDLE session)
{
    require(session == (WINTUN_SESSION_HANDLE) (uintptr_t) 123, "wrong Wintun session");
    if (fail_get_event)
    {
        fail_get_event = false;
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }
    return receive_event;
}

static BYTE *WINAPI fixtureReceive(WINTUN_SESSION_HANDLE session, DWORD *size)
{
    require(session == (WINTUN_SESSION_HANDLE) (uintptr_t) 123 && currentThreadOwnsWorker(0),
            "receive did not execute on selected worker");
    require(! packet_outstanding, "received again before native packet release");
    if (remaining == 0)
    {
        require(ResetEvent(receive_event), "failed to reset empty ring event");
        SetLastError(receive_error);
        return NULL;
    }
    remaining--;
    native_packet[0]   = (BYTE) fixture_received++;
    *size              = fixture_packet_size;
    packet_outstanding = true;
    return native_packet;
}

static VOID WINAPI fixtureRelease(WINTUN_SESSION_HANDLE session, const BYTE *packet)
{
    require(session == (WINTUN_SESSION_HANDLE) (uintptr_t) 123 && currentThreadOwnsWorker(0),
            "native packet release escaped owner worker");
    require(packet_outstanding && packet == native_packet, "native packet released twice");
    packet_outstanding = false;
    released++;
}

static VOID WINAPI fixtureEnd(WINTUN_SESSION_HANDLE session)
{
    require(session == (WINTUN_SESSION_HANDLE) (uintptr_t) 123 && ! packet_outstanding,
            "ended Wintun with an outstanding native packet");
    require(CloseHandle(receive_event), "could not close retired Wintun receive event");
    receive_event = NULL;
    ends++;
}

static size_t tokenCount(void)
{
    EnterCriticalSection(&capture_lock);
    const size_t count = captured_count;
    LeaveCriticalSection(&capture_lock);
    return count;
}

static captured_t takeToken(void)
{
    EnterCriticalSection(&capture_lock);
    require(captured_count != 0, "no token to settle");
    const captured_t token = captured[0];
    memoryMove(captured, captured + 1, --captured_count * sizeof(captured[0]));
    LeaveCriticalSection(&capture_lock);
    return token;
}

static void runOne(void)
{
    const captured_t token = takeToken();
    testWorkerBindWID(token.wid);
    token.callback(getWorker(token.wid), token.arg1, token.arg2, token.arg3);
}

static void runAll(void)
{
    while (tokenCount() != 0)
        runOne();
}

static void waitForToken(void)
{
    const DWORD start = GetTickCount();
    while (tokenCount() == 0 && (DWORD) (GetTickCount() - start) < 5000)
        Sleep(1);
    require(tokenCount() != 0, "threadpool notification did not queue reader work");
}

static void ignoreDelivery(void *context, sbuf_t *buf, wid_t wid)
{
    discard context;
    discard wid;
    sbufDestroy(buf);
    require(false, "fixture unexpectedly invoked packet-chain delivery");
}

static void openSession(tun_device_t *device)
{
    fixture_received = released = delivered = remaining = 0;
    fixture_packet_size                                 = 64;
    receive_error                                       = ERROR_NO_MORE_ITEMS;
    receive_event                                       = CreateEventW(NULL, TRUE, FALSE, NULL);
    require(receive_event != NULL, "cannot create fixture receive event");
    device->session_handle = (HANDLE) (uintptr_t) 123;
    require(deviceReaderSessionBegin(device->reader_session) != 0, "cannot begin reader generation");
    device->reader_generation_open = true;
    atomicStoreRelaxed(&device->lifecycle, kTunLifecycleUp);
}

static tun_device_t *newDevice(void)
{
    tun_device_t *device       = memoryAllocate(sizeof(*device));
    *device                    = (tun_device_t) {.name = stringDuplicate("fixture"), .mtu = 1500};
    device->reader_buffer_pool = devicePoolCreate(getCurrentWorkerBufferPool(), device->mtu);
    tunWriterInit(&device->writer);
    atomic_init(&device->lifecycle, kTunLifecycleDown);
    device->reader_session = deviceReaderSessionCreate(
        8, kMaxReadDistributeQueueSize, device, ignoreDelivery, device->reader_buffer_pool, kDeviceFragmentPreserve);
    openSession(device);
    return device;
}

static void testDeferredBoundedReadAndWake(void)
{
    tun_device_t *device = newDevice();
    remaining            = 300;
    require(tunWindowsReaderStart(device), "reader startup failed");
    require(fixture_received == 0 && tokenCount() == 1, "startup read before queued packet Init");
    /* Duplicate notifications must not create parallel ring consumers. */
    testWorkerUnbindWID();
    tunWindowsReaderReady(NULL, device->reader, NULL, WAIT_OBJECT_0);
    tunWindowsReaderReady(NULL, device->reader, NULL, WAIT_OBJECT_0);
    testWorkerBindWID(0);
    require(tokenCount() == 1, "duplicate native notifications were not coalesced");
    runOne();
    require(fixture_received == 128 && released == 128 && delivered == 128 && tokenCount() == 1,
            "reader did not yield after packet quantum");
    runAll();
    require(fixture_received == 300 && delivered == 300 && released == 300, "continuations lost receive packets");
    remaining = 3;
    require(SetEvent(receive_event), "failed to signal arriving packets");
    waitForToken();
    require(fixture_received == 300, "foreign notification consumed native packets");
    runAll();
    require(fixture_received == 303 && delivered == 303 && released == 303, "native wake lost packets");
    require(tundeviceRequestStop(device), "reader stop request failed");
    tundeviceWorkerQuiesce(device, 0);
    tundeviceDestroy(device);
}

static void testByteAndOversizedQuanta(void)
{
    tun_device_t *device = newDevice();
    device->mtu          = 65535;
    fixture_packet_size  = 65535;
    remaining            = 6;
    require(tunWindowsReaderStart(device), "large packet reader startup failed");
    runOne();
    require(fixture_received == 5 && tokenCount() == 1, "reader did not yield at byte quantum");
    runAll();
    require(fixture_received == 6 && released == 6 && delivered == 6, "byte quantum lost valid packets");
    tundeviceDestroy(device);

    device              = newDevice();
    fixture_packet_size = 1501;
    remaining           = 140;
    require(tunWindowsReaderStart(device), "oversized reader startup failed");
    runOne();
    require(fixture_received == 128 && released == 128 && delivered == 0 && tokenCount() == 1,
            "oversized packets bypassed reader quantum or release");
    runAll();
    require(fixture_received == 140 && released == 140 && tundeviceIsUp(device), "oversized input killed reader");
    tundeviceDestroy(device);
}

static void testStopRestartAndLateSettlement(void)
{
    tun_device_t *device = newDevice();
    require(tunWindowsReaderStart(device), "old reader startup failed");
    require(tundeviceBringDown(device), "queued reader stop failed");
    require(tokenCount() == 1, "stop unexpectedly required queued callback execution");
    openSession(device);
    remaining = 2;
    require(tunWindowsReaderStart(device), "reader restart failed");
    runOne();
    require(fixture_received == 0, "old reader generation consumed restarted session");
    runAll();
    require(fixture_received == 2 && delivered == 2, "new reader generation did not run");
    remaining = 1;
    require(SetEvent(receive_event), "failed to signal stale-generation fixture");
    waitForToken();
    tundeviceDestroy(device);
    runAll();
    require(fixture_received == 2, "late callback accessed destroyed device");

    device = newDevice();
    require(tunWindowsReaderStart(device), "cancel fixture startup failed");
    tundeviceDestroy(device);
    const captured_t token = takeToken();
    testWorkerUnbindWID();
    token.cleanup(token.arg1, token.arg2, token.arg3, kWorkerMessageCancelTeardown);
    testWorkerBindWID(0);
}

static void testStartupRefusalAndTerminalReceive(void)
{
    for (unsigned int failure = 0; failure < 3; ++failure)
    {
        tun_device_t *device = newDevice();
        fail_get_event       = failure == 0;
        fail_wait_create     = failure == 1;
        reject_next          = failure == 2;
        require(! tunWindowsReaderStart(device), "required reader setup refusal reported success");
        tundeviceDestroy(device);
        require(tokenCount() == 0 && receive_event == NULL, "startup rollback retained native roots");
    }
    tun_device_t *device      = newDevice();
    receive_error             = ERROR_INVALID_DATA;
    const unsigned int before = shutdowns;
    require(tunWindowsReaderStart(device), "terminal receive fixture startup failed");
    runAll();
    require(shutdowns == before + 1 && ! tundeviceIsUp(device) && tokenCount() == 0,
            "terminal receive error did not stop reader and request shutdown");
    tundeviceDestroy(device);
}

static void testStopRacesWithAdmittedRearm(void)
{
    tun_device_t *device = newDevice();
    arm_reached          = CreateEventW(NULL, TRUE, FALSE, NULL);
    stop_done            = CreateEventW(NULL, TRUE, FALSE, NULL);
    require(arm_reached != NULL && stop_done != NULL, "cannot create rearm race events");
    stop_during_rearm = true;
    HANDLE stopper    = CreateThread(NULL, 0, fixtureStopOnRearm, device, 0, NULL);
    require(stopper != NULL && tunWindowsReaderStart(device), "cannot start rearm race fixture");
    runOne();
    require(WaitForSingleObject(stopper, 5000) == WAIT_OBJECT_0, "foreign stop owner did not finish");
    require(SetEvent(receive_event), "could not signal the wait rearmed after stop");
    /* CloseWait must disarm again after the admitted reader returns, then
     * quiesce even the native callback that raced the first request-side disarm. */
    tundeviceDestroy(device);
    require(tokenCount() == 0 && fixture_received == 0, "closed reader admitted a rearm notification");
    require(CloseHandle(stopper) && CloseHandle(arm_reached) && CloseHandle(stop_done), "race handle cleanup failed");
    arm_reached = stop_done = NULL;
}

static void testRefusedNativeNotification(void)
{
    tun_device_t *device = newDevice();
    require(tunWindowsReaderStart(device), "notification refusal fixture startup failed");
    runAll();
    EnterCriticalSection(&capture_lock);
    reject_next = true;
    LeaveCriticalSection(&capture_lock);
    const unsigned int before = atomicLoadRelaxed(&refusals);
    remaining                 = 1;
    require(SetEvent(receive_event), "failed to signal refused notification");
    const DWORD start = GetTickCount();
    while (atomicLoadRelaxed(&refusals) == before && (DWORD) (GetTickCount() - start) < 5000)
        Sleep(1);
    require(atomicLoadRelaxed(&refusals) == before + 1 && fixture_received == 0,
            "refused notification fixture_received data on foreign thread");
    tundeviceDestroy(device);
}

int main(void)
{
    testCaseSet("tun_windows_reader");
    InitializeCriticalSection(&capture_lock);
    require(createInternalLogger(NULL, false) != NULL, "cannot initialize logger");
    testIpv4MtuConfiguration();
    test_worker_registry_t registry = {0};
    GSTATE.workers_count            = 1;
    GSTATE.ram_profile              = 1;
    testWorkerRegistryInstall(&registry);
    testWorkerBindWID(0);
    master_pool_t *large                  = masterpoolCreateWithCapacity(16);
    master_pool_t *medium                 = masterpoolCreateWithCapacity(16);
    master_pool_t *small                  = masterpoolCreateWithCapacity(16);
    GSTATE.masterpool_buffer_pools_large  = large;
    GSTATE.masterpool_buffer_pools_medium = medium;
    GSTATE.masterpool_buffer_pools_small  = small;
    buffer_pool_t *pool               = bufferpoolCreate(large, medium, small, 16, 65536, 32768, 4096, 65536, 65536);
    GSTATE.workers[0].buffer_pool     = pool;
    buffer_pool_t *pools[1]           = {pool};
    GSTATE.shortcut_buffer_pools      = pools;
    wintun_api.get_read_wait_event    = fixtureReadEvent;
    wintun_api.receive_packet         = fixtureReceive;
    wintun_api.release_receive_packet = fixtureRelease;
    wintun_api.end_session            = fixtureEnd;
    testDeferredBoundedReadAndWake();
    testMinimumIpv4Write();
    testByteAndOversizedQuanta();
    testStopRestartAndLateSettlement();
    testStartupRefusalAndTerminalReceive();
    testStopRacesWithAdmittedRearm();
    testRefusedNativeNotification();
    testOversizedOutputWarnings(pool);
    require(tokenCount() == 0 && atomicLoadRelaxed(&foreign_notifications) > 0 && ends == 12,
            "fixture missed foreign notification or leaked sessions");
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large);
    masterpoolMakeEmpty(medium);
    masterpoolMakeEmpty(small);
    masterpoolDestroy(large);
    masterpoolDestroy(medium);
    masterpoolDestroy(small);
    testWorkerRegistryRestore(&registry);
    testWorkerUnbindWID();
    internaloggerDestroy();
    DeleteCriticalSection(&capture_lock);
    return 0;
}
