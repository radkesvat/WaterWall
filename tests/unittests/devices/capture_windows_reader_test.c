/* Exercises the production Windows capture reader and its thread-exit wrapper
 * with substituted WinDivert receive/delivery boundaries on an unregistered
 * thread. Truncated packets are recycled, warnings are bounded, and the next
 * complete packet survives; shutdown races and terminal errors stay distinct.
 * No native WinDivert driver is loaded.
 * CTest: waterwall.capture_windows_reader_unit */
#include "devices/capture/capture_private.h"
#include "managers/windivert_manager.h"
#include "test_assert.h"
#include "wwapi.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kTruncatedBurst = 65,
    kPacketSize     = 24
};

static capture_device_t *active_device;
static sbuf_t           *outstanding;
static unsigned int      reads, acquisitions, recycles, deliveries, shutdowns, warnings;
static unsigned int      truncations;
static DWORD             terminal_error;
static bool              stop_during_truncation;
static uint64_t          warning_now_ms;
static uint8_t           valid_packet[kPacketSize] = {0x45, 0, 0, kPacketSize, 0,   0, 0, 0, 64, 253, 0, 0,
                                                      192,  0, 2, 1,           192, 0, 2, 2, 1,  2,   3, 4};

static sbuf_t *fixtureGetBuffer(buffer_pool_t *pool)
{
    require(pool == active_device->reader_buffer_pool && outstanding == NULL,
            "reader lost its preceding buffer or borrowed another pool");
    ++acquisitions;
    outstanding = bufferpoolGetSmallBuffer(pool);
    return outstanding;
}

static void fixtureReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer)
{
    require(pool == active_device->reader_buffer_pool && buffer == outstanding,
            "reader recycled an unowned buffer or used another pool");
    ++recycles;
    outstanding = NULL;
    bufferpoolReuseBuffer(pool, buffer);
}

static bool fixtureReceive(HANDLE handle, void *packet, UINT capacity, UINT *length, WINDIVERT_ADDRESS *address)
{
    require(handle == active_device->handle && packet == sbufGetMutablePtr(outstanding) &&
                capacity == kMaxAllowedPacketLength,
            "reader changed its native handle or configured capture bound");
    ++reads;
    if (terminal_error != ERROR_SUCCESS)
    {
        SetLastError(terminal_error);
        return false;
    }
    if (reads <= truncations)
    {
        memorySet(packet, 0xa5, capacity);
        *length        = capacity;
        warning_now_ms = reads < kTruncatedBurst ? 1000 : 2000;
        if (stop_during_truncation)
        {
            captureLifecycleTransitionToStopping(&active_device->lifecycle);
        }
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return false;
    }
    if (reads == truncations + 1)
    {
        require(captureLifecycleLoad(&active_device->lifecycle) == kCaptureLifecycleUp &&
                    atomicLoadRelaxed(&active_device->up) && shutdowns == 0,
                "truncation failed the device before the next complete packet");
        memoryCopy(packet, valid_packet, sizeof(valid_packet));
        *length             = sizeof(valid_packet);
        address->IPChecksum = 1;
        return true;
    }
    captureLifecycleTransitionToStopping(&active_device->lifecycle);
    SetLastError(ERROR_NO_DATA);
    return false;
}

static void fixtureDistribute(device_reader_session_t *session, sbuf_t **buffers, unsigned int count)
{
    require(! currentThreadIsWorker() && session == active_device->reader_session && count == 1,
            "reader distribution changed its context or session");
    require(sbufGetLength(buffers[0]) == sizeof(valid_packet) &&
                memoryEqual(sbufGetRawPtr(buffers[0]), valid_packet, sizeof(valid_packet)),
            "truncated contents were delivered or complete packet bytes changed");
    ++deliveries;
    fixtureReuseBuffer(active_device->reader_buffer_pool, buffers[0]);
}

static bool fixtureShutdownRequest(int status)
{
    require(status == 1, "terminal reader error selected the wrong shutdown status");
    ++shutdowns;
    return true;
}

static inline bool fixtureWarningGate(atomic_log_rate_limiter_t *limiter, uint64_t interval_ms)
{
    return atomicLogRateLimiterShouldLogAt(limiter, interval_ms, warning_now_ms);
}

static void fixtureLog(int level, const char *bytes, int length)
{
    discard      level;
    char         text[512];
    const size_t size = min((size_t) max(length, 0), sizeof(text) - 1);
    memoryCopy(text, bytes, size);
    text[size] = '\0';
    if (strstr(text, "truncated packet") != NULL)
    {
        ++warnings;
    }
}

#define windivertRecv                 fixtureReceive
#define bufferpoolGetSmallBuffer      fixtureGetBuffer
#define bufferpoolReuseBuffer         fixtureReuseBuffer
#define deviceReaderDistributeBatch   fixtureDistribute
#define requestProgramShutdown        fixtureShutdownRequest
#define atomicLogRateLimiterShouldLog fixtureWarningGate
#include "../../../ww/devices/capture/capture_windows.c"
#undef windivertRecv
#undef bufferpoolGetSmallBuffer
#undef bufferpoolReuseBuffer
#undef deviceReaderDistributeBatch
#undef requestProgramShutdown
#undef atomicLogRateLimiterShouldLog

static void runReader(buffer_pool_t *pool, unsigned int truncated, DWORD error, bool stop)
{
    char             name[] = "capture-reader-fixture";
    capture_device_t device = {.name               = name,
                               .handle             = (HANDLE) (uintptr_t) 123,
                               .reader_buffer_pool = pool,
                               .routine_reader     = routineReadFromCapture};
    atomic_init(&device.lifecycle, kCaptureLifecycleUp);
    atomic_init(&device.running, true);
    atomic_init(&device.up, true);
    active_device          = &device;
    truncations            = truncated;
    terminal_error         = error;
    stop_during_truncation = stop;
    reads = acquisitions = recycles = deliveries = shutdowns = warnings = 0;

    discard capturedeviceReaderThreadMain(&device);
    require(outstanding == NULL && acquisitions == recycles && acquisitions == reads,
            "reader exit leaked or double-recycled a receive buffer");
    if (error != ERROR_SUCCESS)
    {
        require(reads == 1 && deliveries == 0 && shutdowns == 1 && warnings == 0 &&
                    captureLifecycleLoad(&device.lifecycle) == kCaptureLifecycleFailed &&
                    ! atomicLoadRelaxed(&device.up) && ! atomicLoadRelaxed(&device.running),
                "genuine receive failure no longer failed the device and requested shutdown");
    }
    else if (stop)
    {
        require(reads == 1 && deliveries == 0 && shutdowns == 0 && warnings == 0 &&
                    captureLifecycleLoad(&device.lifecycle) == kCaptureLifecycleStopping,
                "truncation racing stop resumed capture or failed the device");
    }
    else
    {
        require(reads == kTruncatedBurst + 2 && deliveries == 1 && shutdowns == 0 &&
                    captureLifecycleLoad(&device.lifecycle) == kCaptureLifecycleStopping,
                "oversized capture ended the reader instead of delivering the next valid packet");
        require(warnings == 2, "truncation burst warnings were missing or not rate limited");
    }
    active_device = NULL;
}

int main(void)
{
    testCaseSet("capture_windows_reader");
    require(! currentThreadIsWorker(), "fixture must run as the unregistered capture reader");
    require(createInternalLogger(NULL, false) != NULL, "cannot initialize logger");
    loggerSetHandler(getInternalLogger(), fixtureLog);
    require(calcIpv4HeaderChecksum(valid_packet, sizeof(valid_packet)), "cannot initialize valid IPv4 packet");
    master_pool_t *large  = masterpoolCreateWithCapacity(16);
    master_pool_t *medium = masterpoolCreateWithCapacity(16);
    master_pool_t *small  = masterpoolCreateWithCapacity(16);
    buffer_pool_t *pool   = bufferpoolCreate(large, medium, small, 16, 65536, 32768, 4096, 65536, 65536);
    require(pool != NULL, "cannot initialize reader pool");
    testCaseSet("capture_recovers_after_truncation");
    runReader(pool, kTruncatedBurst, ERROR_SUCCESS, false);
    testCaseSet("capture_terminal_error_still_fails");
    runReader(pool, 0, ERROR_INVALID_HANDLE, false);
    testCaseSet("capture_stop_wins_truncation");
    runReader(pool, 1, ERROR_SUCCESS, true);
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large);
    masterpoolMakeEmpty(medium);
    masterpoolMakeEmpty(small);
    masterpoolDestroy(large);
    masterpoolDestroy(medium);
    masterpoolDestroy(small);
    internaloggerDestroy();
    return 0;
}
