/* Exercises the production RawSocket Windows backend and shared worker FIFO
 * with real Windows threadpool notifications and substituted driver I/O. No
 * WinDivert driver is loaded. Covers pending ownership, per-worker FIFO,
 * independent workers, completion refusal, stop/restart and terminal failure.
 * CTest: waterwall.raw_windows_writer_unit */
#include "devices/raw/raw_writer.h"
#include "fixtures/worker_registry_fixture.h"
#include "managers/windivert_manager.h"
#include "test_assert.h"
#include "wwapi.h"

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

typedef struct native_operation_s
{
    OVERLAPPED *overlapped;
    const void *packet;
    DWORD       error;
    bool        active;
    bool        complete;
} native_operation_t;

static CRITICAL_SECTION   capture_lock;
static captured_t         captured[1024];
static size_t             captured_count;
static native_operation_t operations[2];
static DWORD              outcomes[256];
static unsigned           observed[1024];
static size_t             observed_count;
static unsigned           disposals;
static unsigned           shutdowns;
static unsigned           cancel_calls;
static unsigned           wait_calls;
static atomic_uint        foreign_notifications;
static atomic_uint        refused_notifications;
static bool               reject_next;
static bool               fail_wait_create;

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
        atomicIncRelaxed(&refused_notifications);
        return kWorkerMessageSubmitRejectedCleanupRan;
    }
    require(captured_count < ARRAY_SIZE(captured), "captured-token capacity");
    captured[captured_count++] = (captured_t) {wid, callback, cleanup, arg1, arg2, arg3};
    LeaveCriticalSection(&capture_lock);
    if (foreign)
        atomicIncRelaxed(&foreign_notifications);
    return kWorkerMessageSubmitAccepted;
}

static worker_message_submit_result_e fixtureTimed(wid_t wid, WorkerMessageCallback callback,
                                                   WorkerMessageCleanupCallback cleanup, uint32_t delay, void *arg1,
                                                   void *arg2, void *arg3)
{
    discard wid;
    discard callback;
    discard cleanup;
    discard delay;
    discard arg1;
    discard arg2;
    discard arg3;
    require(false, "Windows output used a polling retry instead of completion notification");
    return kWorkerMessageSubmitRejectedCleanupRan;
}

static void fixtureDestroyBuffer(sbuf_t *buf)
{
    for (size_t i = 0; i < ARRAY_SIZE(operations); ++i)
        require(! operations[i].active || operations[i].packet != sbufGetRawPtr(buf),
                "buffer freed while native operation retained its bytes");
    disposals++;
    sbufDestroy(buf);
}

static bool fixtureShutdownRequest(int status)
{
    require(status == 1, "native failure selected wrong shutdown status");
    shutdowns++;
    return true;
}

#define sendWorkerMessageForceQueueWithCleanup fixtureQueue
#define sendWorkerMessageTimedWithCleanup      fixtureTimed
#define requestProgramShutdown                 fixtureShutdownRequest
#define sbufDestroy                            fixtureDestroyBuffer
#include "../../../ww/devices/raw/raw_writer.c"
#undef sendWorkerMessageForceQueueWithCleanup
#undef sendWorkerMessageTimedWithCleanup
#undef requestProgramShutdown
#undef sbufDestroy

static bool fixtureEnsureLoaded(void)
{
    return true;
}
static HANDLE fixtureOpen(const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags)
{
    require(strcmp(filter, "false") == 0 && layer == WINDIVERT_LAYER_NETWORK && priority == 0 &&
                flags == WINDIVERT_FLAG_SEND_ONLY,
            "wrong raw WinDivert handle mode");
    return (HANDLE) (uintptr_t) 123;
}
static bool fixtureShutdown(HANDLE handle, WINDIVERT_SHUTDOWN how)
{
    require(handle == (HANDLE) (uintptr_t) 123 && how == WINDIVERT_SHUTDOWN_BOTH, "wrong native shutdown");
    return true;
}
static bool fixtureClose(HANDLE handle)
{
    require(handle == (HANDLE) (uintptr_t) 123, "wrong native close handle");
    for (size_t i = 0; i < ARRAY_SIZE(operations); ++i)
        require(! operations[i].active, "closed handle before native operations retired");
    return true;
}
static bool fixtureSend(HANDLE handle, const void *packet, UINT length, UINT *written, const WINDIVERT_ADDRESS *address,
                        UINT address_length, OVERLAPPED *overlapped)
{
    require(handle == (HANDLE) (uintptr_t) 123 && currentThreadIsWorker(), "native send escaped event worker");
    require(length == 24 && written == NULL && address_length == sizeof(*address), "native send arguments");
    require(address->Outbound && address->Layer == WINDIVERT_LAYER_NETWORK, "native packet direction");
    require(! address->IPChecksum && ! address->TCPChecksum && ! address->UDPChecksum,
            "backend asserted unverified checksum validity");
    const unsigned sequence = ((const uint8_t *) packet)[20];
    require(observed_count < ARRAY_SIZE(observed), "native observation capacity");
    observed[observed_count++] = sequence;
    const wid_t wid            = getCurrentWorkerWID();
    require(! operations[wid].active, "worker submitted another packet before native completion");
    if (outcomes[sequence] == ERROR_IO_PENDING)
        operations[wid] = (native_operation_t) {overlapped, packet, ERROR_SUCCESS, true, false};
    if (outcomes[sequence] != ERROR_SUCCESS)
    {
        SetLastError(outcomes[sequence]);
        return false;
    }
    return true;
}
static native_operation_t *findOperation(OVERLAPPED *overlapped)
{
    for (size_t i = 0; i < ARRAY_SIZE(operations); ++i)
        if (operations[i].overlapped == overlapped && operations[i].active)
            return &operations[i];
    require(false, "queried an unowned native operation");
    return NULL;
}
static BOOL WINAPI fixtureResult(HANDLE handle, OVERLAPPED *overlapped, DWORD *written, BOOL wait)
{
    require(handle == (HANDLE) (uintptr_t) 123, "wrong completion handle");
    native_operation_t *operation = findOperation(overlapped);
    if (wait)
    {
        wait_calls++;
        require(operation->complete, "coordinator waited before cancellation/completion");
    }
    if (! operation->complete)
    {
        SetLastError(ERROR_IO_INCOMPLETE);
        return FALSE;
    }
    operation->active = false;
    *written          = operation->error == ERROR_SUCCESS ? 24 : 0;
    if (operation->error != ERROR_SUCCESS)
    {
        SetLastError(operation->error);
        return FALSE;
    }
    return TRUE;
}
static BOOL WINAPI fixtureCancel(HANDLE handle, OVERLAPPED *overlapped)
{
    require(handle == (HANDLE) (uintptr_t) 123, "wrong cancellation handle");
    native_operation_t *operation = findOperation(overlapped);
    cancel_calls++;
    if (operation->complete)
    {
        SetLastError(ERROR_NOT_FOUND);
        return FALSE;
    }
    operation->complete = true;
    operation->error    = ERROR_OPERATION_ABORTED;
    require(SetEvent(overlapped->hEvent), "could not signal canceled completion");
    return TRUE;
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
static void fixtureReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer)
{
    require(currentThreadIsWorker() && pool == getCurrentWorker()->buffer_pool,
            "native completion used a foreign worker pool");
    fixtureDestroyBuffer(buffer);
}

#define windivertManagerEnsureLoaded fixtureEnsureLoaded
#define windivertOpen                fixtureOpen
#define windivertShutdown            fixtureShutdown
#define windivertClose               fixtureClose
#define windivertSendEx              fixtureSend
#define GetOverlappedResult          fixtureResult
#define CancelIoEx                   fixtureCancel
#define CreateThreadpoolWait         fixtureCreateWait
#define bufferpoolReuseBuffer        fixtureReuseBuffer
#include "../../../ww/devices/raw/raw_windows.c"
#undef windivertManagerEnsureLoaded
#undef windivertOpen
#undef windivertShutdown
#undef windivertClose
#undef windivertSendEx
#undef GetOverlappedResult
#undef CancelIoEx
#undef CreateThreadpoolWait
#undef bufferpoolReuseBuffer

static size_t tokenCount(void)
{
    EnterCriticalSection(&capture_lock);
    size_t count = captured_count;
    LeaveCriticalSection(&capture_lock);
    return count;
}
static void runAll(void)
{
    while (tokenCount() != 0)
    {
        EnterCriticalSection(&capture_lock);
        captured_t token = captured[0];
        memoryMove(captured, captured + 1, --captured_count * sizeof(captured[0]));
        LeaveCriticalSection(&capture_lock);
        testWorkerBindWID(token.wid);
        token.callback(getWorker(token.wid), token.arg1, token.arg2, token.arg3);
    }
    testWorkerBindWID(0);
}
static void waitForToken(void)
{
    DWORD start = GetTickCount();
    while (tokenCount() == 0 && (DWORD) (GetTickCount() - start) < 5000)
        Sleep(1);
    require(tokenCount() != 0, "threadpool completion did not notify owner worker");
}
static void complete(wid_t wid, DWORD error)
{
    native_operation_t *operation = &operations[wid];
    require(operation->active && ! operation->complete, "invalid native completion fixture");
    operation->complete = true;
    operation->error    = error;
    require(SetEvent(operation->overlapped->hEvent), "could not signal native completion");
}
static sbuf_t *packet(unsigned sequence)
{
    sbuf_t  *buffer = sbufCreate(24);
    uint8_t *bytes  = sbufGetMutablePtr(buffer);
    memoryZero(bytes, 24);
    bytes[0]  = 0x45;
    bytes[3]  = 24;
    bytes[9]  = 17;
    bytes[20] = (uint8_t) sequence;
    sbufSetLength(buffer, 24);
    return buffer;
}
static raw_device_t *startDevice(void)
{
    require(tokenCount() == 0, "previous fixture retained worker tokens");
    memoryZero(outcomes, sizeof(outcomes));
    observed_count       = 0;
    raw_device_t *device = rawdeviceCreate("fixture", 0, false, NULL);
    require(device != NULL && rawdeviceBringUp(device), "worker-output startup failed");
    return device;
}
static void submit(raw_device_t *device, wid_t wid, unsigned sequence)
{
    testWorkerBindWID(wid);
    require(rawdeviceWrite(device, packet(sequence)), "worker packet admission failed");
    testWorkerBindWID(0);
}
static void testImmediateAndPendingFifo(void)
{
    raw_device_t  *device = startDevice();
    const unsigned before = disposals;
    submit(device, 0, 0);
    submit(device, 0, 1);
    require(observed_count == 0 && tokenCount() == 1, "Payload invoked native I/O synchronously");
    runAll();
    require(observed_count == 2 && observed[0] == 0 && observed[1] == 1 && disposals == before + 2,
            "immediate sends changed FIFO or buffer settlement");
    outcomes[2] = outcomes[4] = ERROR_IO_PENDING;
    submit(device, 0, 2);
    submit(device, 0, 3);
    submit(device, 1, 4);
    submit(device, 1, 5);
    runAll();
    require(operations[0].active && operations[1].active && observed_count == 4,
            "independent workers did not submit concurrent pending writes");
    complete(0, ERROR_SUCCESS);
    waitForToken();
    runAll();
    require(observed_count == 5 && observed[4] == 3 && operations[1].active,
            "worker FIFO overtook a pending native packet");
    complete(1, ERROR_HOST_UNREACHABLE);
    waitForToken();
    runAll();
    require(rawdeviceIsUp(device) && observed_count == 6 && observed[5] == 5 &&
                device->writer_states[1].packet_local_send_error_total == 1,
            "packet-local asynchronous error stopped the device");
    require(disposals == before + 6, "pending completions did not recycle exactly once");
    rawdeviceDestroy(device);
}
static void testStopAndStaleCompletion(void)
{
    raw_device_t  *device = startDevice();
    const unsigned before = disposals;
    outcomes[10]          = ERROR_IO_PENDING;
    submit(device, 0, 10);
    submit(device, 0, 11);
    runAll();
    complete(0, ERROR_SUCCESS);
    waitForToken();
    require(rawdeviceBringDown(device), "stop after native completion failed");
    require(disposals == before + 2, "stop failed to settle completed and queued packets");
    require(rawdeviceBringUp(device), "restart after pending completion failed");
    submit(device, 0, 12);
    runAll();
    require(observed_count == 2 && observed[1] == 12 && disposals == before + 3,
            "old completion token reached reopened native state");
    outcomes[13] = ERROR_IO_PENDING;
    submit(device, 0, 13);
    submit(device, 0, 14);
    runAll();
    const unsigned cancels = cancel_calls;
    require(rawdeviceBringDown(device), "pending native cancellation failed");
    require(cancel_calls == cancels + 1 && ! operations[0].active && disposals == before + 5,
            "stop freed pending buffer before cancel completion");
    rawdeviceDestroy(device);
    runAll();
}
static void testCompletionRefusalAndFailure(void)
{
    raw_device_t *device = startDevice();
    outcomes[20]         = ERROR_IO_PENDING;
    submit(device, 0, 20);
    runAll();
    EnterCriticalSection(&capture_lock);
    reject_next = true;
    LeaveCriticalSection(&capture_lock);
    const unsigned refusals = atomicLoadRelaxed(&refused_notifications);
    complete(0, ERROR_SUCCESS);
    DWORD start = GetTickCount();
    while (atomicLoadRelaxed(&refused_notifications) == refusals && (DWORD) (GetTickCount() - start) < 5000)
        Sleep(1);
    require(atomicLoadRelaxed(&refused_notifications) == refusals + 1 && operations[0].active,
            "completion refusal released pending ownership early");
    rawdeviceDestroy(device);
    require(! operations[0].active, "refused completion was not retired at stop");

    device                  = startDevice();
    outcomes[21]            = ERROR_IO_PENDING;
    outcomes[22]            = ERROR_RETRY;
    const unsigned failures = shutdowns;
    submit(device, 0, 21);
    submit(device, 1, 22);
    runAll();
    require(shutdowns == failures + 1 && ! rawdeviceIsUp(device) && operations[0].active,
            "terminal failure lost another worker's pending native ownership");
    rawdeviceDestroy(device);
    require(! operations[0].active, "terminal failure did not cancel other worker's pending native operation");
}
static void testStartupRefusal(void)
{
    raw_device_t *device = rawdeviceCreate("fixture", 0, false, NULL);
    fail_wait_create     = true;
    require(! rawdeviceBringUp(device) && device->writer_states == NULL && device->writer.current == NULL,
            "native wait allocation refusal retained partial startup state");
    require(rawdeviceBringUp(device), "restart after native wait refusal failed");
    rawdeviceDestroy(device);
}
int main(void)
{
    testCaseSet("raw_windows_writer");
    InitializeCriticalSection(&capture_lock);
    require(createInternalLogger(NULL, false) != NULL, "cannot initialize fixture logger");
    test_worker_registry_t registry = {0};
    GSTATE.workers_count            = 2;
    testWorkerRegistryInstall(&registry);
    testWorkerBindWID(0);
    testImmediateAndPendingFifo();
    testStopAndStaleCompletion();
    testCompletionRefusalAndFailure();
    testStartupRefusal();
    require(tokenCount() == 0 && atomicLoadRelaxed(&foreign_notifications) > 0 && wait_calls > 0,
            "fixture did not exercise foreign completions and coordinator settlement");
    testWorkerRegistryRestore(&registry);
    testWorkerUnbindWID();
    internaloggerDestroy();
    DeleteCriticalSection(&capture_lock);
    puts("Windows asynchronous raw writer tests passed");
    return 0;
}
