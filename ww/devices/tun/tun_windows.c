#include "devices/device_pool.h"
#include "devices/windows_session_effects.h"
#include "tun.h"
#include "tun_windows_dns.h"
#include "tun_windows_lifetime.h"
#include "tun_windows_ownership.h"
#include "tun_windows_receive_policy.h"
#include "tun_writer.h"

#include "buffer_pool.h"
#include "devices/tun/tun_lifecycle.h"
#include "devices/windows_driver_artifacts.h"
#include "global_state.h"
#include "managers/signal_manager.h"
#include "master_pool.h"
#include "watomic.h"
#include "wintun.h"
#include "worker_messages.h"
#include "wplatform.h"
#include "wproc.h"
#include <iphlpapi.h>
#include <netioapi.h>

#include <tchar.h>
#include <wchar.h>

#include "devices/device_flow_affinity.h"
#include "devices/device_reader_session.h"
#include "loggers/internal_logger.h"
#include "loggers/log_rate_limiter.h"

enum
{
    kTunWriteQueueMax           = 4096,
    kMaxReadDistributeQueueSize = 128,
    kTunReaderBatchBytes        = 256 * 1024,
    kTunDiscardReportIntervalMs = 1000
};

static_assert(kMaxReadDistributeQueueSize <= UINT16_MAX, "TUN read batch count must fit in the reader session");

// tun_windows_receive_policy.h is included before <windows.h> and is compiled on
// non-Windows hosts for its unit test, so it restates this value. Pin it here,
// where the real Win32 macro is visible.
static_assert(kTunWintunErrorNoMoreItems == ERROR_NO_MORE_ITEMS,
              "the Wintun receive policy's ERROR_NO_MORE_ITEMS value drifted from the Win32 definition");

typedef struct tun_windows_reader_s
{
    quiescence_gate_t gate;
    atomic_uint       references;
    atomic_bool       pending;
    atomic_bool       submission_failed;
    tun_device_t     *device;
    wid_t             wid;
    PTP_WAIT          wait;
    HANDLE            event;
} tun_windows_reader_t;

struct tun_device_s
{
    char                    *name;
    wchar_t                 *name_w;
    HANDLE                   adapter_handle;
    HANDLE                   ownership;
    HANDLE                   session_handle;
    HANDLE                   stop_event; /* Cancels supervised DNS setup, not reader notification. */
    tun_windows_dns_result_e dns_result;
    bool                     dns_cleanup_needed;
    MIB_UNICASTIPADDRESS_ROW address_row;

    void                 *userdata;
    tun_windows_reader_t *reader;
    bool                  reader_generation_open;

    device_reader_session_t *reader_session;
    buffer_pool_t           *reader_buffer_pool;

    TunReadEventHandle read_event_callback;

    tun_writer_t writer;
    uint16_t     mtu;

    // Reader-worker-owned accounting for oversized receive packets that are
    // dropped instead of terminating the process.
    log_rate_limiter_t oversized_read_discard_limiter;

    atomic_int lifecycle;
};

// External variables
extern unsigned char wintun_dll[];
extern unsigned int  wintun_dll_len;

typedef struct wintun_api_s
{
    WINTUN_CREATE_ADAPTER_FUNC             *create_adapter;
    WINTUN_CLOSE_ADAPTER_FUNC              *close_adapter;
    WINTUN_OPEN_ADAPTER_FUNC               *open_adapter;
    WINTUN_GET_ADAPTER_LUID_FUNC           *get_adapter_luid;
    WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *get_running_driver_version;
    WINTUN_DELETE_DRIVER_FUNC              *delete_driver;
    WINTUN_SET_LOGGER_FUNC                 *set_logger;
    WINTUN_START_SESSION_FUNC              *start_session;
    WINTUN_END_SESSION_FUNC                *end_session;
    WINTUN_GET_READ_WAIT_EVENT_FUNC        *get_read_wait_event;
    WINTUN_RECEIVE_PACKET_FUNC             *receive_packet;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC     *release_receive_packet;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC       *allocate_send_packet;
    WINTUN_SEND_PACKET_FUNC                *send_packet;
} wintun_api_t;

static wintun_api_t wintun_api;

// A failed FreeLibrary keeps its module and immutable artifact alive. Startup
// is serialized and retries this one pending transaction before loading again.
static HMODULE wintun_pending_module;

#define WintunCreateAdapter           (wintun_api.create_adapter)
#define WintunCloseAdapter            (wintun_api.close_adapter)
#define WintunOpenAdapter             (wintun_api.open_adapter)
#define WintunGetAdapterLUID          (wintun_api.get_adapter_luid)
#define WintunGetRunningDriverVersion (wintun_api.get_running_driver_version)
#define WintunDeleteDriver            (wintun_api.delete_driver)
#define WintunSetLogger               (wintun_api.set_logger)
#define WintunStartSession            (wintun_api.start_session)
#define WintunEndSession              (wintun_api.end_session)
#define WintunGetReadWaitEvent        (wintun_api.get_read_wait_event)
#define WintunReceivePacket           (wintun_api.receive_packet)
#define WintunReleaseReceivePacket    (wintun_api.release_receive_packet)
#define WintunAllocateSendPacket      (wintun_api.allocate_send_packet)
#define WintunSendPacket              (wintun_api.send_packet)

static inline uint16_t tunDeviceMtu(const tun_device_t *tdev)
{
    return tdev->mtu;
}

bool tundeviceIsUp(const tun_device_t *tdev)
{
    return tdev != NULL && tunLifecycleLoad(&tdev->lifecycle) == kTunLifecycleUp;
}

static bool tunWindowsSetMtu(tun_device_t *tdev)
{
    NET_LUID    luid;
    NET_IFINDEX index;
    MIB_IFROW   if_row;

    if (tdev->adapter_handle == NULL)
    {
        LOGE("TunDevice: Cannot set MTU -> No Adapter!");
        return false;
    }

    WintunGetAdapterLUID(tdev->adapter_handle, &luid);

    NETIO_STATUS status = ConvertInterfaceLuidToIndex(&luid, &index);
    if (status != NO_ERROR)
    {
        LOGE("TunDevice: failed to resolve adapter interface index, code: %lu", status);
        return false;
    }

    memoryZero(&if_row, sizeof(if_row));
    if_row.dwIndex   = index;
    DWORD last_error = GetIfEntry(&if_row);
    if (last_error != NO_ERROR)
    {
        LOGE("TunDevice: failed to query adapter interface row, code: %lu", last_error);
        return false;
    }

    if_row.dwMtu = tunDeviceMtu(tdev);
    last_error   = SetIfEntry(&if_row);
    if (last_error != NO_ERROR)
    {
        LOGE("TunDevice: failed to set adapter MTU, code: %lu", last_error);
        return false;
    }

    return true;
}

static bool tunWindowsDetectDefaultRouteForFamily(int family, uint32_t *out_index, char *out_name, size_t out_name_len)
{
    SOCKADDR_INET dest;
    memoryZero(&dest, sizeof(dest));

    if (family == AF_INET)
    {
        dest.Ipv4.sin_family = AF_INET;
        inet_pton(AF_INET, "8.8.8.8", &dest.Ipv4.sin_addr);
    }
    else
    {
        dest.Ipv6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, "2001:4860:4860::8888", &dest.Ipv6.sin6_addr);
    }

    MIB_IPFORWARD_ROW2 row;
    SOCKADDR_INET      best_src;
    NETIO_STATUS       status = GetBestRoute2(NULL, 0, NULL, &dest, 0, &row, &best_src);
    if (status != NO_ERROR)
    {
        return false;
    }

    NET_IFINDEX ifindex = 0;
    status              = ConvertInterfaceLuidToIndex(&row.InterfaceLuid, &ifindex);
    if (status != NO_ERROR || ifindex == 0)
    {
        return false;
    }

    *out_index = (uint32_t) ifindex;

    char ifname[256];
    memoryZero(ifname, sizeof(ifname));
    if (ConvertInterfaceLuidToNameA(&row.InterfaceLuid, ifname, sizeof(ifname)) == NO_ERROR && ifname[0] != '\0')
    {
        stringCopyN(out_name, ifname, out_name_len);
    }

    return true;
}

bool tundeviceDetectDefaultInterface(tun_default_route_t *out)
{
    memoryZero(out, sizeof(*out));

    char ifname_v4[64] = {0};
    char ifname_v6[64] = {0};

    out->have_v4 = tunWindowsDetectDefaultRouteForFamily(AF_INET, &out->ifindex_v4, ifname_v4, sizeof(ifname_v4));
    out->have_v6 = tunWindowsDetectDefaultRouteForFamily(AF_INET6, &out->ifindex_v6, ifname_v6, sizeof(ifname_v6));

    if (ifname_v4[0] != '\0')
    {
        stringCopyN(out->ifname, ifname_v4, sizeof(out->ifname));
    }
    else if (ifname_v6[0] != '\0')
    {
        stringCopyN(out->ifname, ifname_v6, sizeof(out->ifname));
    }

    return out->have_v4 || out->have_v6;
}

bool tundeviceDisableReversePathFiltering(const char *ifname)
{
    discard ifname;
    return true;
}

static bool routeTableIsMain(const char *route_table)
{
    return route_table == NULL || stringCompare(route_table, "main") == 0 || stringCompare(route_table, "auto") == 0;
}

static bool tunWindowsDnsInterfaceName(tun_device_t *tdev, wchar_t name[11])
{
    uint64_t value;
    if (! tundeviceGetLuid(tdev, &value))
    {
        LOGE("TunDevice: DNS requires an owned adapter");
        return false;
    }
    NET_LUID     luid = {.Value = value};
    NET_IFINDEX  index;
    NETIO_STATUS status = ConvertInterfaceLuidToIndex(&luid, &index);
    if (status != NO_ERROR)
    {
        LOGE("TunDevice: failed to resolve DNS adapter identity, code: %lu", status);
        return false;
    }
    /* Wintun may assign a different alias on a naming collision. netsh accepts
     * an interface index, so policy
     * follows the returned adapter's identity. */
    int written = swprintf(name, 11, L"%lu", (unsigned long) index);
    return written > 0 && written < 11;
}

static bool tunWindowsDnsServerIsSafe(const char *arg)
{
    if (arg == NULL || arg[0] == '\0')
    {
        return false;
    }

    for (const char *p = arg; *p != '\0'; ++p)
    {
        if (! (isdigit((unsigned char) *p) || *p == '.'))
        {
            return false;
        }
    }

    return true;
}

static bool tunWindowsParseRouteCidr(const char *cidr, SOCKADDR_INET *addr, UINT8 *prefix)
{
    if (cidr == NULL || cidr[0] == '\0')
    {
        return false;
    }

    const char *slash = stringChr(cidr, '/');
    if (slash == NULL || slash == cidr || slash[1] == '\0')
    {
        return false;
    }

    size_t ip_len = (size_t) (slash - cidr);
    if (ip_len >= INET6_ADDRSTRLEN)
    {
        return false;
    }

    char ip_part[INET6_ADDRSTRLEN];
    memoryCopy(ip_part, cidr, ip_len);
    ip_part[ip_len] = '\0';

    errno          = 0;
    char *end_ptr  = NULL;
    long  prefix_l = strtol(slash + 1, &end_ptr, 10);
    if (errno != 0 || end_ptr == slash + 1 || *end_ptr != '\0')
    {
        return false;
    }

    memoryZero(addr, sizeof(*addr));
    if (inet_pton(AF_INET, ip_part, &addr->Ipv4.sin_addr) == 1)
    {
        if (prefix_l < 0 || prefix_l > 32)
        {
            return false;
        }
        addr->Ipv4.sin_family = AF_INET;
        *prefix               = (UINT8) prefix_l;
        return true;
    }

    if (inet_pton(AF_INET6, ip_part, &addr->Ipv6.sin6_addr) == 1)
    {
        if (prefix_l < 0 || prefix_l > 128)
        {
            return false;
        }
        addr->Ipv6.sin6_family = AF_INET6;
        *prefix                = (UINT8) prefix_l;
        return true;
    }

    return false;
}

static bool tunWindowsPendingCleanupTry(const char *context)
{
    if (wintun_pending_module != NULL)
    {
        if (! FreeLibrary(wintun_pending_module))
        {
            LOGE("TunDevice: retained Wintun module %s after unload failed, code: %lu", context, GetLastError());
            return false;
        }
        wintun_pending_module = NULL;
    }
    return windowsDriverArtifactRelease(kWindowsDriverWintun);
}

static bool tunWindowsLoadFunction(HMODULE module, const char *function_name, void *target, size_t target_size,
                                   DWORD *error_out)
{
    FARPROC proc = GetProcAddress(module, function_name);
    if (proc == NULL)
    {
        *error_out = GetLastError();
        return false;
    }
    assert(target_size == sizeof(proc));
    memoryCopy(target, &proc, target_size);
    return true;
}

static bool tunWindowsStartup(void)
{
    const wchar_t *temp_dll_path = NULL;
    HMODULE        module        = NULL;
    wintun_api_t   api           = {0};
    DWORD          error         = ERROR_SUCCESS;
    const char    *operation     = "extract embedded DLL";

    if (! tunWindowsPendingCleanupTry("before Wintun startup"))
    {
        LOGE("TunDevice: refusing Wintun startup while an earlier loader transaction still owns resources");
        return false;
    }

    if (! windowsDriverArtifactPrepare(kWindowsDriverWintun, wintun_dll, wintun_dll_len, &temp_dll_path))
    {
        LOGE("TunDevice: failed to prepare protected Wintun artifact, code: %lu", GetLastError());
        return false;
    }

    module = LoadLibraryExW(temp_dll_path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module == NULL)
    {
        error     = GetLastError();
        operation = "load protected DLL with constrained dependency search (safe-loader support required)";
        goto fail;
    }

#define LOAD_WINTUN_FUNCTION(member, symbol)                                                                           \
    do                                                                                                                 \
    {                                                                                                                  \
        operation = "resolve " symbol;                                                                                 \
        if (! tunWindowsLoadFunction(module, symbol, &api.member, sizeof(api.member), &error))                         \
        {                                                                                                              \
            goto fail;                                                                                                 \
        }                                                                                                              \
    } while (0)

    LOAD_WINTUN_FUNCTION(create_adapter, "WintunCreateAdapter");
    LOAD_WINTUN_FUNCTION(close_adapter, "WintunCloseAdapter");
    LOAD_WINTUN_FUNCTION(open_adapter, "WintunOpenAdapter");
    LOAD_WINTUN_FUNCTION(get_adapter_luid, "WintunGetAdapterLUID");
    LOAD_WINTUN_FUNCTION(get_running_driver_version, "WintunGetRunningDriverVersion");
    LOAD_WINTUN_FUNCTION(delete_driver, "WintunDeleteDriver");
    LOAD_WINTUN_FUNCTION(set_logger, "WintunSetLogger");
    LOAD_WINTUN_FUNCTION(start_session, "WintunStartSession");
    LOAD_WINTUN_FUNCTION(end_session, "WintunEndSession");
    LOAD_WINTUN_FUNCTION(get_read_wait_event, "WintunGetReadWaitEvent");
    LOAD_WINTUN_FUNCTION(receive_packet, "WintunReceivePacket");
    LOAD_WINTUN_FUNCTION(release_receive_packet, "WintunReleaseReceivePacket");
    LOAD_WINTUN_FUNCTION(allocate_send_packet, "WintunAllocateSendPacket");
    LOAD_WINTUN_FUNCTION(send_packet, "WintunSendPacket");

#undef LOAD_WINTUN_FUNCTION

    /* Publish the module, path and complete API as one serialized commit. */
    wintun_api                             = api;
    GSTATE.wintun_dll_handle               = module;
    GSTATE.wintun_dll_path                 = (void *) temp_dll_path;
    GSTATE.flag_tundev_windows_initialized = true;
    LOGD("TunDevice: Wintun DLL loaded successfully");
    return true;

fail:
    assert(wintun_pending_module == NULL);
    wintun_pending_module = module;
    if (! tunWindowsPendingCleanupTry("after startup error"))
    {
        LOGW("TunDevice: Wintun startup resources remain pending after cleanup failure");
    }
    LOGE("TunDevice: failed to %s, code: %lu", operation, error);
    return false;
}

static void reuseTunReadBuffers(tun_device_t *tdev, sbuf_t **bufs, unsigned int count)
{
    for (unsigned int i = 0; i < count; i++)
    {
        bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[i]);
    }
}

static void tunDeliverPacket(void *device, sbuf_t *buf, wid_t wid)
{
    tun_device_t *tdev = device;
    tdev->read_event_callback(tdev, tdev->userdata, buf, wid);
}

// Counts one oversized-read drop and emits a rate-limited aggregate warning.
// Only the selected reader worker calls this, so the counters need no atomics.
static void tunWindowsRecordOversizedReadDiscard(tun_device_t *tdev)
{
    log_rate_limiter_report_t report =
        logRateLimiterRecord(&tdev->oversized_read_discard_limiter, kTunDiscardReportIntervalMs);

    if (! report.should_log)
    {
        return;
    }

    LOGW("TunDevice: reader: discarded %llu packet(s) larger than configured MTU %u over %llums (total=%llu)",
         LLU(report.events),
         (unsigned int) tunDeviceMtu(tdev),
         LLU(report.elapsed_ms),
         LLU(report.total));
}

// Flushes any still-suppressed oversized-read drops once, e.g. on reader exit.
static void tunWindowsReportPendingOversizedReadDiscards(tun_device_t *tdev)
{
    log_rate_limiter_report_t report = logRateLimiterFlush(&tdev->oversized_read_discard_limiter);

    if (! report.should_log)
    {
        return;
    }

    LOGW("TunDevice: reader: discarded %llu packet(s) larger than configured MTU %u before reader exit (total=%llu)",
         LLU(report.events),
         (unsigned int) tunDeviceMtu(tdev),
         LLU(report.total));
}

/* Each queued token owns only this generation. Closing its gate makes old
 * notifications and cancellation safe after device destruction or restart. */
static void tunWindowsReaderUnref(tun_windows_reader_t *reader)
{
    const w_atomic_uint_value_t before = atomicSubExplicit(&reader->references, 1, memory_order_acq_rel);
    assert(before > 0);
    if (before == 1)
    {
        assert(quiescenceGateIsClosedAndQuiesced(&reader->gate));
        assert(reader->wait == NULL);
        memoryFree(reader);
    }
}

static bool tunWindowsReaderFailed(tun_device_t *tdev, DWORD error)
{
    tun_lifecycle_state_t failed_from;
    if (! tunLifecycleTransitionToFailed(&tdev->lifecycle, &failed_from))
        return false;
    LOGE("TunDevice: reader failed on device %s, code: %lu", tdev->name, error);
    return failed_from == kTunLifecycleUp;
}

static void tunWindowsReaderRequestShutdown(bool failed)
{
    if (failed && ! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

static void tunWindowsReaderRun(worker_t *worker, void *arg1, void *arg2, void *arg3);

static void tunWindowsReaderCancelled(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard               arg2;
    discard               arg3;
    tun_windows_reader_t *reader = arg1;
    /* Cancellation has no device, pool, wait-handle, or worker authority. */
    if (reason == kWorkerMessageCancelEnqueueFailure || reason == kWorkerMessageCancelTargetUnavailable)
        atomicStoreExplicit(&reader->submission_failed, true, memory_order_release);
    atomicStoreExplicit(&reader->pending, false, memory_order_release);
    tunWindowsReaderUnref(reader);
}

/* The caller holds the generation gate or exclusive startup ownership. */
static bool tunWindowsReaderSchedule(tun_windows_reader_t *reader)
{
    if (atomicExchangeExplicit(&reader->pending, true, memory_order_acq_rel))
        return true;
    discard atomicIncExplicit(&reader->references, memory_order_relaxed);
    return sendWorkerMessageForceQueueWithCleanup(reader->wid,
                                                  (WorkerMessageCallback) tunWindowsReaderRun,
                                                  tunWindowsReaderCancelled,
                                                  reader,
                                                  NULL,
                                                  NULL) == kWorkerMessageSubmitAccepted;
}

static VOID CALLBACK tunWindowsReaderReady(PTP_CALLBACK_INSTANCE instance, PVOID context, PTP_WAIT wait,
                                           TP_WAIT_RESULT result)
{
    discard               instance;
    discard               wait;
    discard               result;
    tun_windows_reader_t *reader = context;
    if (! quiescenceGateEnter(&reader->gate))
        return;
    /* Wintun's wait is one-shot. Foreign notification only publishes one owner
     * message; it never drains the ring or borrows either buffer pool. */
    bool failed = false;
    if (! tunWindowsReaderSchedule(reader) && atomicLoadExplicit(&reader->submission_failed, memory_order_acquire))
        failed = tunWindowsReaderFailed(reader->device, ERROR_NOT_READY);
    quiescenceGateLeave(&reader->gate);
    tunWindowsReaderRequestShutdown(failed);
}

static void tunWindowsReaderRun(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard               arg2;
    discard               arg3;
    tun_windows_reader_t *reader = arg1;
    assert(currentThreadOwnsWorker(worker->wid) && worker->wid == reader->wid);
    discard worker;
    if (! quiescenceGateEnter(&reader->gate))
    {
        atomicStoreExplicit(&reader->pending, false, memory_order_release);
        tunWindowsReaderUnref(reader);
        return;
    }

    tun_device_t *tdev = reader->device;
    sbuf_t       *bufs[kMaxReadDistributeQueueSize];
    unsigned int  count    = 0;
    unsigned int  received = 0;
    size_t        bytes    = 0;
    bool          empty    = false;
    bool          failed   = false;
    while (received < kMaxReadDistributeQueueSize && bytes < kTunReaderBatchBytes &&
           tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
    {
        DWORD packet_size;
        BYTE *packet = WintunReceivePacket(tdev->session_handle, &packet_size);
        if (packet == NULL)
        {
            /* Preserve Wintun's thread-local error before any other call. */
            const DWORD error = GetLastError();
            if (tunWindowsClassifyReceiveError(error) == kTunWindowsReceiveWaitForData)
                empty = true;
            else
                failed = tunWindowsReaderFailed(tdev, error);
            break;
        }
        received++;
        bytes += packet_size;
        if (tunWindowsReceivePacketExceedsMtu(tunDeviceMtu(tdev), packet_size))
        {
            WintunReleaseReceivePacket(tdev->session_handle, packet);
            tunWindowsRecordOversizedReadDiscard(tdev);
            continue;
        }
        sbuf_t *buf = bufferpoolGetSmallBuffer(tdev->reader_buffer_pool);
        buf         = sbufReserveSpace(buf, tunDeviceMtu(tdev));
        sbufSetLength(buf, packet_size);
        memoryCopyLarge(sbufGetMutablePtr(buf), packet, packet_size);
        WintunReleaseReceivePacket(tdev->session_handle, packet);
        bufs[count++] = buf;
    }

    if (tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
    {
        if (count != 0)
            deviceFlowAffinityPostBatch(tdev->reader_session, bufs, count);
        /* Clear before rearming: an already-signaled event can notify at once. */
        atomicStoreExplicit(&reader->pending, false, memory_order_release);
        if (empty)
            SetThreadpoolWait(reader->wait, reader->event, NULL);
        else if (! tunWindowsReaderSchedule(reader) &&
                 atomicLoadExplicit(&reader->submission_failed, memory_order_acquire))
            failed = tunWindowsReaderFailed(tdev, ERROR_NOT_READY);
    }
    else
    {
        reuseTunReadBuffers(tdev, bufs, count);
        atomicStoreExplicit(&reader->pending, false, memory_order_release);
    }
    quiescenceGateLeave(&reader->gate);
    tunWindowsReaderUnref(reader);
    tunWindowsReaderRequestShutdown(failed);
}

static bool tunWindowsReaderStart(tun_device_t *tdev)
{
    tun_windows_reader_t *reader = memoryAllocate(sizeof(*reader));
    *reader                      = (tun_windows_reader_t) {.device = tdev, .wid = 0};
    atomic_init(&reader->references, 1);
    atomic_init(&reader->pending, false);
    atomic_init(&reader->submission_failed, false);
    quiescenceGateInit(&reader->gate);
    tdev->reader  = reader;
    reader->event = WintunGetReadWaitEvent(tdev->session_handle);
    if (reader->event == NULL)
    {
        LOGE("TunDevice: cannot obtain Wintun receive event, code: %lu", GetLastError());
        return false;
    }
    reader->wait = CreateThreadpoolWait(tunWindowsReaderReady, reader, NULL);
    if (reader->wait == NULL)
    {
        LOGE("TunDevice: cannot create Wintun receive notification, code: %lu", GetLastError());
        return false;
    }
    if (! quiescenceGateOpen(&reader->gate))
        return false;
    /* Startup queues this behind packet Init; native notification is armed only
     * after this owner callback has first drained the ring to empty. */
    if (! tunWindowsReaderSchedule(reader))
    {
        LOGE("TunDevice: cannot admit initial Wintun reader callback");
        return false;
    }
    return true;
}

static bool tunWriteBatch(void *context, worker_t *worker, sbuf_t **buffers, size_t count)
{
    tun_device_t         *tdev    = context;
    WINTUN_SESSION_HANDLE Session = tdev->session_handle;
    bool                  failed  = false;

    for (size_t i = 0; i < count; ++i)
    {
        sbuf_t *buf = buffers[i];
        if (! tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
        {
            bufferpoolReuseBuffer(worker->buffer_pool, buf);
            continue;
        }

        if (UNLIKELY(tunDeviceMtu(tdev) < sbufGetLength(buf)))
        {
            LOGW("TunDevice: discarded a packet -> size %d exceeds device MTU %u",
                 sbufGetLength(buf),
                 tunDeviceMtu(tdev));

            bufferpoolReuseBuffer(worker->buffer_pool, buf);
            continue;
        }

        BYTE *Packet = WintunAllocateSendPacket(Session, sbufGetLength(buf));
        if (! Packet)
        {
            DWORD last_error = GetLastError();
            bufferpoolReuseBuffer(worker->buffer_pool, buf);

            if (last_error == ERROR_BUFFER_OVERFLOW)
            {
                // A full Wintun send ring is transient; drop this packet and keep consuming the queue.
                continue;
            }

            tun_lifecycle_state_t failed_from;
            if (tunLifecycleTransitionToFailed(&tdev->lifecycle, &failed_from))
            {
                LOGE("TunDevice: failed to allocate Wintun write packet, code: %lu", last_error);
                failed = failed_from == kTunLifecycleUp;
            }
            continue;
        }

        memoryCopyLarge(Packet, sbufGetRawPtr(buf), sbufGetLength(buf));

        WintunSendPacket(Session, Packet);

        bufferpoolReuseBuffer(worker->buffer_pool, buf);
    }

    // The queue requests shutdown after all buffers and its write gate settle.
    return ! failed;
}

static void tundeviceCloseLifetimeGates(tun_device_t *tdev)
{
    tunWriterCloseRequest(&tdev->writer);
    deviceReaderSessionEndRequest(tdev->reader_session);
}

static void tundeviceBeginSessionShutdown(void *context)
{
    tun_device_t *tdev = context;
    tunLifecycleTransitionToStopping(&tdev->lifecycle);
    tundeviceCloseLifetimeGates(tdev);
    if (tdev->reader != NULL)
    {
        quiescenceGateClose(&tdev->reader->gate);
        if (tdev->reader->wait != NULL)
            SetThreadpoolWait(tdev->reader->wait, NULL, NULL);
    }
}

void tundeviceWorkerQuiesce(tun_device_t *tdev, wid_t wid)
{
    assert(currentThreadOwnsWorker(wid));
    if (tdev->reader != NULL && tdev->reader->wid == wid && tdev->reader->wait != NULL)
        SetThreadpoolWait(tdev->reader->wait, NULL, NULL);
}

static void tundeviceQuiesceReader(void *context)
{
    tun_device_t         *tdev   = context;
    tun_windows_reader_t *reader = tdev->reader;
    if (reader == NULL)
        return;
    quiescenceGateWaitQuiesced(&reader->gate, quiescenceGateYieldThread, NULL);
    if (reader->wait != NULL)
    {
        /* An admitted worker may have rearmed after the request-side disarm.
         * Once its gate is empty no further rearm is possible. */
        SetThreadpoolWait(reader->wait, NULL, NULL);
        WaitForThreadpoolWaitCallbacks(reader->wait, TRUE);
        CloseThreadpoolWait(reader->wait);
        reader->wait = NULL;
    }
    reader->device = NULL;
    tdev->reader   = NULL;
    tunWindowsReaderUnref(reader);
    tunWindowsReportPendingOversizedReadDiscards(tdev);
}

static void tundeviceWaitReaderDelivery(void *context)
{
    tun_device_t *tdev = context;
    deviceReaderSessionEndWait(tdev->reader_session);
}

static bool tundeviceRetireReader(void *context)
{
    tun_device_t *tdev = context;
    if (! tdev->reader_generation_open)
    {
        return true;
    }
    bufferpoolResetThreadOwnership(tdev->reader_buffer_pool);
    deviceReaderSessionRetireGenerationBuffers(tdev->reader_session);
    tdev->reader_generation_open = false;
    return true;
}

static void tundeviceWaitWrites(void *context)
{
    tun_device_t *tdev = context;
    tunWriterCloseWait(&tdev->writer);
}

static void tundeviceEndSession(void *context)
{
    tun_device_t *tdev = context;

    WINTUN_SESSION_HANDLE session = tdev->session_handle;
    if (session != NULL)
    {
        LOGI("TunDevice: Ending WinTun session");
        WintunEndSession(session);
        tdev->session_handle = NULL;
    }
}

static bool tundeviceShutdownSession(tun_device_t *tdev)
{
    static const tun_windows_lifetime_ops_t ops = {
        .begin_shutdown       = tundeviceBeginSessionShutdown,
        .quiesce_reader       = tundeviceQuiesceReader,
        .wait_reader_delivery = tundeviceWaitReaderDelivery,
        .wait_writes          = tundeviceWaitWrites,
        .retire_reader        = tundeviceRetireReader,
        .end_session          = tundeviceEndSession,
    };

    return tunWindowsLifetimeShutdown(tdev, &ops);
}

bool tundeviceRequestStop(tun_device_t *tdev)
{
    tundeviceBeginSessionShutdown(tdev);
    if (tdev->stop_event != NULL && ! SetEvent(tdev->stop_event))
    {
        LOGE("TunDevice: failed to cancel pending DNS setup, code: %lu", GetLastError());
        return false;
    }
    return true;
}

bool tundeviceBringUp(tun_device_t *tdev)
{
    if (tdev->session_handle != NULL || tdev->writer.current != NULL || tdev->reader != NULL)
    {
        LOGE("TunDevice: Device shutdown is incomplete");
        return false;
    }
    if (! tunLifecycleTransitionDownToStarting(&tdev->lifecycle))
    {
        LOGE("TunDevice: device cannot be started in current lifecycle state");
        return false;
    }

    /*
     * Finalize the dedicated receive pool before handing it to the selected
     * event worker for this generation.
     */
    buffer_pool_t *worker_pool = getCurrentWorkerBufferPool();

    devicePoolUpdatePadding(tdev->reader_buffer_pool, worker_pool);

    if (! tunWindowsSetMtu(tdev))
    {
        LOGE("TunDevice: error setting MTU size");
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
        return false;
    }

    if (! ResetEvent(tdev->stop_event))
    {
        LOGE("TunDevice: failed to reset DNS cancellation event, code: %lu", GetLastError());
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
        return false;
    }

    if (deviceReaderSessionBegin(tdev->reader_session) == 0)
    {
        LOGE("TunDevice: failed to open reader delivery generation");
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
        return false;
    }
    tdev->reader_generation_open = true;

    LOGI("TunDevice: Starting WinTun session");
    WINTUN_SESSION_HANDLE Session = WintunStartSession(tdev->adapter_handle, 0x400000);
    if (! Session)
    {
        DWORD lastError = GetLastError();
        LOGE("TunDevice: Failed to start session, code: %lu", lastError);
        tundeviceCloseLifetimeGates(tdev);
        deviceReaderSessionEndWait(tdev->reader_session);
        discard tundeviceRetireReader(tdev);
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
        return false;
    }

    tdev->session_handle = Session;

    if (! tunWriterOpen(&tdev->writer, kTunWriteQueueMax, SIZE_MAX, tdev, tunWriteBatch))
    {
        LOGE("TunDevice: failed to open worker output queues");
        goto rollback;
    }

    if (! tunWindowsReaderStart(tdev))
        goto rollback;

    if (tunLifecycleLoad(&tdev->lifecycle) == kTunLifecycleFailed)
    {
        goto rollback;
    }

    if (! tunLifecycleTransitionStartingToUp(&tdev->lifecycle))
    {
        LOGE("TunDevice: reader failed during startup");
        goto rollback;
    }

    return true;

rollback:
    if (tundeviceShutdownSession(tdev))
    {
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
    }
    else
    {
        LOGE("TunDevice: reader-startup rollback is incomplete; retained resources require a shutdown retry");
    }
    return false;
}

bool tundeviceBringDown(tun_device_t *tdev)
{
    if (tunLifecycleLoad(&tdev->lifecycle) == kTunLifecycleDown && tdev->session_handle == NULL &&
        tdev->writer.current == NULL && tdev->reader == NULL)
    {
        return true;
    }

    discard tundeviceRequestStop(tdev);
    bool    res = tundeviceShutdownSession(tdev);
    if (res)
    {
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
    }
    return res;
}

bool tundeviceAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet)
{
    if (tdev->adapter_handle == NULL)
    {
        LOGE("TunDevice: Cannot set IP -> No Adapter!");
        return false;
    }

    if (tdev->session_handle != NULL)
    {
        LOGE("TunDevice: Cannot set IP -> Session already started");
        return false;
    }

    MIB_UNICASTIPADDRESS_ROW *AddressRow = &tdev->address_row;
    InitializeUnicastIpAddressEntry(AddressRow);
    WintunGetAdapterLUID(tdev->adapter_handle, &AddressRow->InterfaceLuid);

    if (inet_pton(AF_INET, ip_presentation, &AddressRow->Address.Ipv4.sin_addr) == 1)
    {
        if (subnet > 32)
        {
            LOGE("TunDevice: Cannot set IP -> Invalid IPv4 prefix: %u", subnet);
            return false;
        }
        AddressRow->Address.Ipv4.sin_family = AF_INET;
    }
    else if (inet_pton(AF_INET6, ip_presentation, &AddressRow->Address.Ipv6.sin6_addr) == 1)
    {
        if (subnet > 128)
        {
            LOGE("TunDevice: Cannot set IP -> Invalid IPv6 prefix: %u", subnet);
            return false;
        }
        AddressRow->Address.Ipv6.sin6_family = AF_INET6;
    }
    else
    {
        LOGE("TunDevice: Cannot set IP -> Invalid IP address: %s", ip_presentation);
        return false;
    }

    AddressRow->OnLinkPrefixLength = (uint8_t) subnet;
    AddressRow->DadState           = IpDadStatePreferred;
    DWORD LastError                = CreateUnicastIpAddressEntry(AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        LOGE("TunDevice: Failed to set IP address, code: %lu", LastError);
        return false;
    }
    return true;
}

bool tundeviceUnAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet)
{
    if (tdev->adapter_handle == NULL)
    {
        LOGE("TunDevice: Cannot unset IP -> No Adapter!");
        return false;
    }

    if (tdev->session_handle != NULL)
    {
        LOGE("TunDevice: Cannot unset IP -> Session already started");
        return false;
    }

    MIB_UNICASTIPADDRESS_ROW *AddressRow = &tdev->address_row;
    InitializeUnicastIpAddressEntry(AddressRow);
    WintunGetAdapterLUID(tdev->adapter_handle, &AddressRow->InterfaceLuid);
    if (inet_pton(AF_INET, ip_presentation, &AddressRow->Address.Ipv4.sin_addr) == 1)
    {
        if (subnet > 32)
        {
            LOGE("TunDevice: Cannot unset IP -> Invalid IPv4 prefix: %u", subnet);
            return false;
        }
        AddressRow->Address.Ipv4.sin_family = AF_INET;
    }
    else if (inet_pton(AF_INET6, ip_presentation, &AddressRow->Address.Ipv6.sin6_addr) == 1)
    {
        if (subnet > 128)
        {
            LOGE("TunDevice: Cannot unset IP -> Invalid IPv6 prefix: %u", subnet);
            return false;
        }
        AddressRow->Address.Ipv6.sin6_family = AF_INET6;
    }
    else
    {
        LOGE("TunDevice: Cannot unset IP -> Invalid IP address: %s", ip_presentation);
        return false;
    }

    AddressRow->OnLinkPrefixLength = (uint8_t) subnet;
    DWORD LastError                = DeleteUnicastIpAddressEntry(AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_NOT_FOUND)
    {
        LOGE("TunDevice: Failed to unassign IP address, code: %lu", LastError);
        return false;
    }
    return true;
}

bool tundeviceAddRoute(tun_device_t *tdev, const char *cidr, const char *route_table)
{
    if (! routeTableIsMain(route_table))
    {
        LOGE("TunDevice: route-table '%s' is not supported on Windows", route_table);
        return false;
    }

    if (tdev->adapter_handle == NULL)
    {
        LOGE("TunDevice: Cannot add route -> No Adapter!");
        return false;
    }

    SOCKADDR_INET prefix_addr;
    UINT8         prefix_len;
    if (! tunWindowsParseRouteCidr(cidr, &prefix_addr, &prefix_len))
    {
        LOGE("TunDevice: invalid route CIDR: %s", cidr);
        return false;
    }

    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);
    WintunGetAdapterLUID(tdev->adapter_handle, &row.InterfaceLuid);
    row.DestinationPrefix.Prefix       = prefix_addr;
    row.DestinationPrefix.PrefixLength = prefix_len;
    row.NextHop.si_family              = prefix_addr.si_family;
    row.Protocol                       = MIB_IPPROTO_NETMGMT;
    row.Metric                         = 0;
    row.ValidLifetime                  = 0xFFFFFFFF;
    row.PreferredLifetime              = 0xFFFFFFFF;

    NETIO_STATUS status = CreateIpForwardEntry2(&row);
    if (status != NO_ERROR)
    {
        LOGE("TunDevice: failed to add system route %s, code: %lu", cidr, status);
        return false;
    }

    LOGI("TunDevice: added system route %s on %s", cidr, tdev->name);
    return true;
}

bool tundeviceRemoveRoute(tun_device_t *tdev, const char *cidr, const char *route_table)
{
    if (! routeTableIsMain(route_table))
    {
        LOGE("TunDevice: route-table '%s' is not supported on Windows", route_table);
        return false;
    }

    if (tdev->adapter_handle == NULL)
    {
        LOGE("TunDevice: Cannot remove route -> No Adapter!");
        return false;
    }

    SOCKADDR_INET prefix_addr;
    UINT8         prefix_len;
    if (! tunWindowsParseRouteCidr(cidr, &prefix_addr, &prefix_len))
    {
        LOGE("TunDevice: invalid route CIDR: %s", cidr);
        return false;
    }

    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);
    WintunGetAdapterLUID(tdev->adapter_handle, &row.InterfaceLuid);
    row.DestinationPrefix.Prefix       = prefix_addr;
    row.DestinationPrefix.PrefixLength = prefix_len;
    row.NextHop.si_family              = prefix_addr.si_family;

    NETIO_STATUS status = DeleteIpForwardEntry2(&row);
    if (status != NO_ERROR && status != ERROR_NOT_FOUND)
    {
        LOGE("TunDevice: failed to remove system route %s, code: %lu", cidr, status);
        return false;
    }

    LOGI("TunDevice: removed system route %s on %s", cidr, tdev->name);
    return true;
}

bool tundeviceSetDnsServers(tun_device_t *tdev, const char *const *servers, size_t count)
{
    tdev->dns_result = kTunWindowsDnsFailed;
    if (count == 0)
    {
        tdev->dns_result = kTunWindowsDnsSuccess;
        return true;
    }

    if (count > kTunDeviceMaxDnsServers)
    {
        LOGE("TunDevice: at most %d DNS servers are supported", kTunDeviceMaxDnsServers);
        return false;
    }

    wchar_t interface_name[11];
    if (! tunWindowsDnsInterfaceName(tdev, interface_name))
    {
        return false;
    }

    for (size_t i = 0; i < count; ++i)
    {
        if (! tunWindowsDnsServerIsSafe(servers[i]))
        {
            LOGE("TunDevice: invalid DNS server argument");
            return false;
        }
    }

    bool may_have_changed = false;
    tdev->dns_result =
        tunWindowsDnsSet(interface_name, tdev->ownership, servers, count, tdev->stop_event, &may_have_changed);
    tdev->dns_cleanup_needed |= may_have_changed;
    if (tdev->dns_result != kTunWindowsDnsSuccess)
    {
        if (tdev->dns_result == kTunWindowsDnsCancelled)
        {
            LOGI("TunDevice: DNS installation cancelled");
        }
        else
        {
            LOGE("TunDevice: failed to configure DNS servers");
        }
        /* The tunnel owner inspects possible partial installation and supplies
         * a separate bounded
         * rollback/cleanup operation. */
        return false;
    }

    LOGI("TunDevice: configured %zu DNS server(s) on %s", count, tdev->name);
    return true;
}

bool tundeviceWindowsDnsWasCancelled(const tun_device_t *tdev)
{
    return tdev->dns_result == kTunWindowsDnsCancelled;
}

bool tundeviceWindowsDnsNeedsCleanup(const tun_device_t *tdev)
{
    return tdev->dns_cleanup_needed;
}

bool tundeviceClearDnsServers(tun_device_t *tdev)
{
    wchar_t interface_name[11];
    if (! tunWindowsDnsInterfaceName(tdev, interface_name))
    {
        return false;
    }

    if (! tunWindowsDnsClear(interface_name, tdev->ownership))
    {
        LOGE("TunDevice: failed to clear DNS servers on %s", tdev->name);
        return false;
    }

    tdev->dns_cleanup_needed = false;
    LOGI("TunDevice: cleared DNS servers on %s", tdev->name);
    return true;
}

bool tundeviceGetLuid(tun_device_t *tdev, uint64_t *out)
{
    *out = 0;
    if (tdev == NULL || tdev->adapter_handle == NULL)
    {
        return false;
    }

    NET_LUID luid;
    WintunGetAdapterLUID(tdev->adapter_handle, &luid);
    *out = luid.Value;
    return true;
}

/* Full is expected bounded overload.  Keep only exponentially sparse Down and
 * Closed diagnostics, with no shared counter or successful-path work. */
static bool tundeviceShouldLogRefusal(void)
{
    static thread_local uint32_t refusal_count;
    const uint32_t               ordinal = ++refusal_count;

    return ordinal == 1 || (ordinal & (ordinal - 1U)) == 0;
}

bool tundeviceWrite(tun_device_t *tdev, sbuf_t *buf)
{
    // minimum length of an IP header is 20 bytes
    assert(sbufGetLength(buf) >= 20);

    switch (tunWriterTrySend(&tdev->writer, buf))
    {
    case kTunWriterSendOk:
        return true;
    case kTunWriterSendDown:
        if (tundeviceShouldLogRefusal())
        {
            LOGE("TunDevice: Write failed, device is down");
        }
        return false;
    case kTunWriterSendClosed:
        if (tundeviceShouldLogRefusal())
        {
            LOGE("TunDevice: Write failed, output admission was closed");
        }
        return false;
    case kTunWriterSendFull:
        return false;
    }

    return false;
}

// just destroy this device on tunnel destroy handle
// /**
//  * Handles exit signal and cleans up TUN device
//  * @param userdata User data (TUN device handle)
//  * @param signum Signal number
//  */
// static void exitHandle(void *userdata, int signum)
// {
//     // Sleep(2200);
//     // LOGW("called close handle");
//     discard       signum;
//     tun_device_t *tdev = userdata;
//     if (tundeviceIsUp(tdev))
//     {
//         tundeviceBringDown(tdev);
//     }

//     assert(tdev->session_handle == NULL);

//     if (tdev->adapter_handle)
//     {
//         WintunCloseAdapter(tdev->adapter_handle);
//         tdev->adapter_handle = NULL;
//     }
//     // Sleep(2200);
// }

tun_device_t *tundeviceCreate(const char *name, bool offload, bool multi_queue_requested, uint16_t mtu, void *userdata,
                              TunReadEventHandle cb, device_fragment_policy_t fragment_policy)
{
    return tundeviceCreateOwned(name, offload, multi_queue_requested, mtu, userdata, cb, fragment_policy, NULL);
}

tun_device_t *tundeviceCreateOwned(const char *name, bool offload, bool multi_queue_requested, uint16_t mtu,
                                   void *userdata, TunReadEventHandle cb, device_fragment_policy_t fragment_policy,
                                   tun_windows_ownership_t *ownership)
{
    discard offload;
    discard multi_queue_requested;
    if (mtu <= 16)
    {
        LOGE("TunDevice: Invalid MTU size: %u", mtu);
        return NULL;
    }

    DWORD LastError;

    if (! GSTATE.flag_tundev_windows_initialized)
    {
        if (! tunWindowsStartup())
        {
            return NULL;
        }
    }

    assert(GSTATE.wintun_dll_handle != NULL);

    LOGI("TunDevice: WinTun loaded successfully");

    /*
     * One worker owns the private receive pool and fragment staging. Output
     * workers use their existing local pools.
     */
    buffer_pool_t *worker_pool = getCurrentWorkerBufferPool();

    buffer_pool_t *reader_bpool = devicePoolCreate(worker_pool, mtu);
    if (UNLIKELY(reader_bpool == NULL))
    {
        LOGE("TunDevice: failed to construct reader buffer pool");
        return NULL;
    }

    tun_device_t *tdev = memoryAllocate(sizeof(tun_device_t));

    char *device_name = stringDuplicate(name);
    if (UNLIKELY(device_name == NULL))
    {
        memoryFree(tdev);
        bufferpoolDestroy(reader_bpool);
        return NULL;
    }

    *tdev = (tun_device_t) {
        .name                           = device_name,
        .read_event_callback            = cb,
        .userdata                       = userdata,
        .reader_session                 = NULL,
        .reader_buffer_pool             = reader_bpool,
        .adapter_handle                 = NULL,
        .session_handle                 = NULL,
        .reader                         = NULL,
        .mtu                            = mtu,
        .oversized_read_discard_limiter = {0},
    };
    atomic_init(&tdev->lifecycle, kTunLifecycleDown);

    tunWriterInit(&tdev->writer);
    tdev->reader_session = deviceReaderSessionCreate(
        RAM_PROFILE * 2, kMaxReadDistributeQueueSize, tdev, tunDeliverPacket, reader_bpool, fragment_policy);
    if (UNLIKELY(tdev->reader_session == NULL))
    {
        LOGE("TunDevice: failed to allocate reader session");
        tunWriterDestroy(&tdev->writer);
        memoryFree(tdev->name);
        bufferpoolDestroy(tdev->reader_buffer_pool);
        memoryFree(tdev);
        return NULL;
    }

    tdev->stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (tdev->stop_event == NULL)
    {
        LOGE("TunDevice: failed to create DNS cancellation event, code: %lu", GetLastError());
        tundeviceDestroy(tdev);
        return NULL;
    }

    int wide_size = MultiByteToWideChar(CP_UTF8, 0, name, -1, NULL, 0);
    if (wide_size <= 0)
    {
        LOGE("TunDevice: Failed to calculate UTF-16 length for adapter name");
        tundeviceDestroy(tdev);
        return NULL;
    }

    /* A positive int count of Windows UTF-16 code units fits even 32-bit size_t. */
    const size_t wide_bytes = (size_t) wide_size * sizeof(wchar_t);
    tdev->name_w = (wchar_t *) memoryAllocate(wide_bytes);

    if (MultiByteToWideChar(CP_UTF8, 0, name, -1, (tdev->name_w), wide_size) <= 0)
    {
        LOGE("TunDevice: Failed to convert adapter name to UTF-16");
        tundeviceDestroy(tdev);
        return NULL;
    }

    tun_windows_ownership_t local_ownership = {0};
    if (ownership == NULL)
    {
        ownership = &local_ownership;
        if (! tunWindowsOwnershipPrepare(name, ownership))
        {
            LOGE("TunDevice: could not acquire or prepare adapter ownership, code: %lu", GetLastError());
            tundeviceDestroy(tdev);
            return NULL;
        }
    }
    assert(ownership->lease != NULL);
    tdev->ownership  = ownership->lease;
    ownership->lease = NULL;

    /* Wintun's alias-collision handling can rename an existing interface. A
     * current name conflict is a startup error; never use it as recovery. */
    MIB_IF_TABLE2 *interfaces = NULL;
    LastError                 = GetIfTable2(&interfaces);
    if (LastError != NO_ERROR)
    {
        LOGE("TunDevice: could not query current interface names, code: %lu", LastError);
        tundeviceDestroy(tdev);
        return NULL;
    }
    bool name_in_use = false;
    for (ULONG i = 0; i < interfaces->NumEntries; ++i)
    {
        if (CompareStringOrdinal(interfaces->Table[i].Alias, -1, tdev->name_w, -1, TRUE) == CSTR_EQUAL)
        {
            name_in_use = true;
            break;
        }
    }
    FreeMibTable(interfaces);
    if (name_in_use)
    {
        LOGE("TunDevice: requested device-name is still in use by a current interface");
        tundeviceDestroy(tdev);
        return NULL;
    }

    unsigned session_slot;
    if (! windowsSessionAdapterBegin(&session_slot))
    {
        LOGE("TunDevice: session adapter inventory is full");
        tundeviceDestroy(tdev);
        return NULL;
    }
    WINTUN_ADAPTER_HANDLE adapter = NULL;
    for (unsigned attempt = 0; attempt < 3; ++attempt)
    {
        adapter = WintunCreateAdapter(tdev->name_w, ownership->tag, NULL);
        if (adapter != NULL)
            break;
        LastError = GetLastError();
        if (attempt == 2 || (LastError != ERROR_BUSY && LastError != ERROR_ALREADY_EXISTS &&
                             LastError != ERROR_SHARING_VIOLATION && LastError != ERROR_DEVICE_NOT_AVAILABLE))
            break;
        Sleep(100);
        SetLastError(LastError);
    }
    if (! adapter)
    {
        LastError = GetLastError();
        LOGE("TunDevice: Failed to create adapter! code: %lu", LastError);
        tundeviceDestroy(tdev);
        return NULL;
    }
    tdev->adapter_handle = adapter;
    NET_LUID session_luid;
    WintunGetAdapterLUID(adapter, &session_luid);
    if (! windowsSessionAdapterConfirm(session_slot, &session_luid))
    {
        LOGE("TunDevice: could not record the owned adapter identity");
        tundeviceDestroy(tdev);
        return NULL;
    }

    return tdev;
}

/**
 * Destroys the TUN device and releases resources
 * @param tdev TUN device handle
 * the creator worker thread has to call this function
 */
void tundeviceDestroy(tun_device_t *tdev)
{

    if (tunLifecycleLoad(&tdev->lifecycle) != kTunLifecycleDown || tdev->session_handle != NULL ||
        tdev->writer.current != NULL || tdev->reader != NULL)
    {
        if (! tundeviceBringDown(tdev))
        {
            /*
             * I/O resources may still be live, so the validity of the remaining
             * device state is unknown and continuing to free it would be a
             * use-after-free risk. Hard-abort with an explicit diagnostic rather
             * than trying to run more cleanup. Mirrors tun_linux.c.
             */
            LOGF("TunDevice: refusing to destroy device while I/O callbacks may still be running");
            abortProgramNow(1);
        }
    }

    assert(tdev->session_handle == NULL);
    /*
     * Device destruction follows worker/lwIP shutdown, so no producer can
     * retain a generation pointer while retired queues are reclaimed.
     */
    tunWriterDestroy(&tdev->writer);

    if (tdev->adapter_handle)
    {

        WintunCloseAdapter(tdev->adapter_handle);
        tdev->adapter_handle = NULL;
    }

    if (tdev->stop_event != NULL)
    {
        CloseHandle(tdev->stop_event);
        tdev->stop_event = NULL;
    }

    if (tdev->ownership != NULL)
    {
        CloseHandle(tdev->ownership);
        tdev->ownership = NULL;
    }

    memoryFree(tdev->name);
    memoryFree(tdev->name_w);
    deviceReaderSessionRetireProducerBuffers(tdev->reader_session);
    bufferpoolDestroy(tdev->reader_buffer_pool);
    deviceReaderSessionUnref(tdev->reader_session);

    memoryFree(tdev);
}

void tundevicePlatformShutdown(void)
{
    HMODULE module = (HMODULE) GSTATE.wintun_dll_handle;

    /* All adapter sessions and native notifications have stopped before this hook. */
    GSTATE.flag_tundev_windows_initialized = false;
    GSTATE.wintun_dll_handle               = NULL;
    GSTATE.wintun_dll_path                 = NULL;
    wintun_api                             = (wintun_api_t) {0};

    if (module != NULL)
    {
        assert(wintun_pending_module == NULL);
        wintun_pending_module = module;
    }
    if (! tunWindowsPendingCleanupTry("during platform shutdown"))
    {
        LOGE("TunDevice: protected Wintun platform cleanup remains pending");
    }
}
