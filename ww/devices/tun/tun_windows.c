#include "tun.h"
#include "tun_windows_lifetime.h"
#include "tun_windows_receive_policy.h"

#include "buffer_pool.h"
#include "devices/tun/tun_lifecycle.h"
#include "global_state.h"
#include "managers/signal_manager.h"
#include "master_pool.h"
#include "watomic.h"
#include "wchan.h"
#include "wintun.h"
#include "wplatform.h"
#include "wproc.h"
#include "wthread.h"
#include <iphlpapi.h>
#include <netioapi.h>

#include <tchar.h>
#include <wchar.h>

#include "devices/device_flow_affinity.h"
#include "devices/device_reader_session.h"
#include "devices/device_writer_channel.h"
#include "loggers/internal_logger.h"
#include "loggers/log_rate_limiter.h"

enum
{
    kTunWriteChannelQueueMax     = 4096,
    kMaxReadDistributeQueueSize  = 128,
    kTunReaderStopFallbackWaitMs = 500,
    kTunDiscardReportIntervalMs  = 1000
};

static_assert(kMaxReadDistributeQueueSize <= UINT16_MAX, "TUN read batch count must fit in the reader session");

// tun_windows_receive_policy.h is included before <windows.h> and is compiled on
// non-Windows hosts for its unit test, so it restates this value. Pin it here,
// where the real Win32 macro is visible.
static_assert(kTunWintunErrorNoMoreItems == ERROR_NO_MORE_ITEMS,
              "the Wintun receive policy's ERROR_NO_MORE_ITEMS value drifted from the Win32 definition");

struct tun_device_s
{
    char                    *name;
    wchar_t                 *name_w;
    HANDLE                   adapter_handle;
    HANDLE                   session_handle;
    HANDLE                   stop_event;
    MIB_UNICASTIPADDRESS_ROW address_row;

    void     *userdata;
    wthread_t read_thread;
    wthread_t write_thread;
    bool      reader_generation_open;

    wthread_routine routine_reader;
    wthread_routine routine_writer;

    device_reader_session_t *reader_session;
    buffer_pool_t           *reader_buffer_pool;
    buffer_pool_t           *writer_buffer_pool;

    TunReadEventHandle read_event_callback;

    device_writer_channel_t writer_channel;
    uint16_t                mtu;

    // Reader-thread-owned accounting for oversized receive packets that are
    // dropped instead of terminating the process.
    log_rate_limiter_t oversized_read_discard_limiter;

    atomic_int lifecycle;

    // Bring-down gates on owned resources here, so no joinable flags are needed:
    // read_thread/write_thread are the authority and are nulled on join.
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

typedef struct tun_windows_pending_cleanup_s
{
    HANDLE   file;
    HMODULE  module;
    wchar_t *path;
    wchar_t  inline_path[MAX_PATH];
} tun_windows_pending_cleanup_t;

// Process-lifecycle ownership for one incomplete loader transaction. Startup is
// serialized and refuses to create a second transaction until this slot is
// empty, so cleanup failures cannot grow an unbounded resource list.
static tun_windows_pending_cleanup_t wintun_pending_cleanup;

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

static bool tunWindowsDnsNameIsSafe(const char *arg)
{
    if (arg == NULL || arg[0] == '\0')
    {
        return false;
    }

    for (const char *p = arg; *p != '\0'; ++p)
    {
        if (! (isalnum((unsigned char) *p) || *p == ' ' || *p == '_' || *p == '-' || *p == '.'))
        {
            return false;
        }
    }

    return true;
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

static int tunWindowsRunCommand(const char *command_line)
{
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;

    memoryZero(&si, sizeof(si));
    memoryZero(&pi, sizeof(pi));
    si.cb = sizeof(si);

    char *command = stringDuplicate(command_line);
    if (command == NULL)
    {
        LOGE("TunDevice: failed to allocate command line");
        return -1;
    }

    BOOL created = CreateProcessA(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (! created)
    {
        DWORD last_error = GetLastError();
        LOGE("TunDevice: failed to run command, code: %lu", last_error);
        memoryFree(command);
        return -1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exit_code = 1;
    if (! GetExitCodeProcess(pi.hProcess, &exit_code))
    {
        DWORD last_error = GetLastError();
        LOGE("TunDevice: failed to get command exit code, code: %lu", last_error);
        exit_code = 1;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    memoryFree(command);

    return (int) exit_code;
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

typedef enum tun_windows_delete_outcome_e
{
    kTunWindowsDeleteImmediate = 0,
    kTunWindowsDeleteDeferred,
    kTunWindowsDeleteOutstanding,
} tun_windows_delete_outcome_t;

static bool tunWindowsDeleteErrorMeansAbsent(DWORD error)
{
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

static tun_windows_delete_outcome_t tunWindowsDeleteOrSchedule(const wchar_t *path, const char *context)
{
    if (DeleteFileW(path))
    {
        return kTunWindowsDeleteImmediate;
    }
    const DWORD delete_error = GetLastError();
    if (tunWindowsDeleteErrorMeansAbsent(delete_error))
    {
        return kTunWindowsDeleteImmediate;
    }
    if (MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
    {
        LOGW("TunDevice: failed to delete temporary Wintun DLL %s, code: %lu; deletion is scheduled",
             context,
             delete_error);
        return kTunWindowsDeleteDeferred;
    }

    const DWORD schedule_error = GetLastError();
    if (tunWindowsDeleteErrorMeansAbsent(schedule_error))
    {
        LOGW("TunDevice: temporary Wintun DLL disappeared while scheduling cleanup %s; original delete code: %lu",
             context,
             delete_error);
        return kTunWindowsDeleteImmediate;
    }
    LOGE("TunDevice: temporary Wintun DLL remains owned by the OS %s; delete code: %lu, schedule code: %lu",
         context,
         delete_error,
         schedule_error);
    return kTunWindowsDeleteOutstanding;
}

static bool tunWindowsPendingCleanupIsEmpty(void)
{
    return wintun_pending_cleanup.file == NULL && wintun_pending_cleanup.module == NULL &&
           wintun_pending_cleanup.path == NULL && wintun_pending_cleanup.inline_path[0] == L'\0';
}

static const wchar_t *tunWindowsPendingCleanupPath(void)
{
    if (wintun_pending_cleanup.path != NULL)
    {
        return wintun_pending_cleanup.path;
    }
    return wintun_pending_cleanup.inline_path[0] == L'\0' ? NULL : wintun_pending_cleanup.inline_path;
}

static void tunWindowsPendingCleanupAdopt(HANDLE file, HMODULE module, wchar_t *owned_path, const wchar_t *inline_path)
{
    assert(tunWindowsPendingCleanupIsEmpty());
    assert(owned_path == NULL || inline_path == NULL);

    wintun_pending_cleanup.file   = file;
    wintun_pending_cleanup.module = module;
    wintun_pending_cleanup.path   = owned_path;
    if (inline_path != NULL)
    {
        const size_t length = wcslen(inline_path);
        assert(length < ARRAY_SIZE(wintun_pending_cleanup.inline_path));
        memoryCopy(wintun_pending_cleanup.inline_path, inline_path, (length + 1U) * sizeof(*inline_path));
    }
}

static bool tunWindowsPendingCleanupTry(const char *context)
{
    if (wintun_pending_cleanup.file != NULL)
    {
        if (! CloseHandle(wintun_pending_cleanup.file))
        {
            LOGE("TunDevice: retained temporary Wintun file handle %s after close failed, code: %lu",
                 context,
                 GetLastError());
            return false;
        }
        wintun_pending_cleanup.file = NULL;
    }

    if (wintun_pending_cleanup.module != NULL)
    {
        if (! FreeLibrary(wintun_pending_cleanup.module))
        {
            LOGE("TunDevice: retained Wintun module %s after unload failed, code: %lu", context, GetLastError());
            return false;
        }
        wintun_pending_cleanup.module = NULL;
    }

    const wchar_t *path = tunWindowsPendingCleanupPath();
    if (path != NULL)
    {
        if (tunWindowsDeleteOrSchedule(path, context) == kTunWindowsDeleteOutstanding)
        {
            return false;
        }
        if (wintun_pending_cleanup.path != NULL)
        {
            memoryFree(wintun_pending_cleanup.path);
            wintun_pending_cleanup.path = NULL;
        }
        wintun_pending_cleanup.inline_path[0] = L'\0';
    }

    return true;
}

/**
 * Writes the Wintun DLL bytes to a temporary file on disk
 * @param dllBytes Pointer to the DLL binary data
 * @param dllSize Size of the DLL data in bytes
 * @param path_out Receives an owned UTF-16 path on success.
 * @return true on success.
 */
static bool writeDllToTempFile(const unsigned char *dllBytes, size_t dllSize, wchar_t **path_out)
{
    wchar_t  temp_path[MAX_PATH];
    wchar_t  temp_file_name[MAX_PATH];
    bool     file_created = false;
    HANDLE   file         = INVALID_HANDLE_VALUE;
    wchar_t *owned_path   = NULL;
    DWORD    error        = ERROR_SUCCESS;

    *path_out = NULL;
    if (dllSize > UINT32_MAX)
    {
        LOGE("TunDevice: embedded Wintun DLL is too large");
        return false;
    }

    DWORD temp_path_len = GetTempPathW((DWORD) ARRAY_SIZE(temp_path), temp_path);
    if (temp_path_len == 0 || temp_path_len >= ARRAY_SIZE(temp_path))
    {
        error = temp_path_len == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
        LOGE("TunDevice: failed to get temporary path, code: %lu", error);
        return false;
    }

    if (GetTempFileNameW(temp_path, L"dll", 0, temp_file_name) == 0)
    {
        error = GetLastError();
        LOGE("TunDevice: failed to create temporary filename, code: %lu", error);
        return false;
    }
    file_created = true;

    size_t path_bytes;
    if (! memoryTryComputeArraySize(wcslen(temp_file_name) + 1U, sizeof(*temp_file_name), &path_bytes))
    {
        error = ERROR_ARITHMETIC_OVERFLOW;
        goto fail;
    }

    owned_path = memoryAllocate(path_bytes);
    if (owned_path == NULL)
    {
        error = ERROR_NOT_ENOUGH_MEMORY;
        goto fail;
    }
    memoryCopy(owned_path, temp_file_name, path_bytes);

    file = CreateFileW(
        temp_file_name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        error = GetLastError();
        goto fail;
    }

    DWORD bytes_written = 0;
    if (! WriteFile(file, dllBytes, (DWORD) dllSize, &bytes_written, NULL) || bytes_written != (DWORD) dllSize)
    {
        error = GetLastError();
        if (error == ERROR_SUCCESS)
        {
            error = ERROR_WRITE_FAULT;
        }
        goto fail;
    }

    if (! CloseHandle(file))
    {
        error = GetLastError();
        goto fail;
    }
    file      = INVALID_HANDLE_VALUE;
    *path_out = owned_path;
    return true;

fail:
    assert(tunWindowsPendingCleanupIsEmpty());
    tunWindowsPendingCleanupAdopt(file == INVALID_HANDLE_VALUE ? NULL : file,
                                  NULL,
                                  owned_path,
                                  file_created && owned_path == NULL ? temp_file_name : NULL);
    if (! tunWindowsPendingCleanupTry("after extraction error"))
    {
        LOGW("TunDevice: temporary Wintun extraction resources remain pending after cleanup failure");
    }
    LOGE("TunDevice: failed to extract Wintun DLL, code: %lu", error);
    return false;
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
    wchar_t     *temp_dll_path = NULL;
    HMODULE      module        = NULL;
    wintun_api_t api           = {0};
    DWORD        error         = ERROR_SUCCESS;
    const char  *operation     = "extract embedded DLL";

    if (! tunWindowsPendingCleanupTry("before Wintun startup"))
    {
        LOGE("TunDevice: refusing Wintun startup while an earlier loader transaction still owns resources");
        return false;
    }

    if (! writeDllToTempFile(&wintun_dll[0], wintun_dll_len, &temp_dll_path))
    {
        return false;
    }

    module = LoadLibraryExW(temp_dll_path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module == NULL)
    {
        error     = GetLastError();
        operation = "load extracted DLL";
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
    GSTATE.wintun_dll_path                 = temp_dll_path;
    GSTATE.flag_tundev_windows_initialized = true;
    LOGD("TunDevice: Wintun DLL loaded successfully");
    return true;

fail:
    assert(tunWindowsPendingCleanupIsEmpty());
    tunWindowsPendingCleanupAdopt(NULL, module, temp_dll_path, NULL);
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

static bool tundeviceReaderStopRequested(tun_device_t *tdev, DWORD *routine_result)
{
    if (! tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
    {
        return true;
    }

    DWORD wait_result = WaitForSingleObject(tdev->stop_event, 0);
    if (wait_result == WAIT_OBJECT_0)
    {
        return true;
    }
    if (wait_result == WAIT_TIMEOUT)
    {
        return false;
    }
    if (wait_result == WAIT_FAILED)
    {
        *routine_result = GetLastError();
        LOGE("TunDevice: ReadThread: stop-event check failed, code: %lu", *routine_result);
        return true;
    }

    LOGE("TunDevice: ReadThread: unexpected stop-event check result: %lu", wait_result);
    return true;
}

// Counts one oversized-read drop and emits a rate-limited aggregate warning.
// Only the reader thread calls this, so the counters need no atomics.
static void tunWindowsRecordOversizedReadDiscard(tun_device_t *tdev)
{
    log_rate_limiter_report_t report =
        logRateLimiterRecord(&tdev->oversized_read_discard_limiter, kTunDiscardReportIntervalMs);

    if (! report.should_log)
    {
        return;
    }

    LOGW("TunDevice: ReadThread: discarded %llu packet(s) larger than configured MTU %u over %llums (total=%llu)",
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

    LOGW(
        "TunDevice: ReadThread: discarded %llu packet(s) larger than configured MTU %u before reader exit (total=%llu)",
        LLU(report.events),
        (unsigned int) tunDeviceMtu(tdev),
        LLU(report.total));
}

/**
 * Reader thread routine - reads packets from TUN device
 */
static WTHREAD_ROUTINE(routineReadFromTun)
{
    tun_device_t         *tdev    = userdata;
    WINTUN_SESSION_HANDLE Session = tdev->session_handle;
    sbuf_t               *bufs[kMaxReadDistributeQueueSize];
    uint8_t               queued_count   = 0;
    DWORD                 routine_result = ERROR_SUCCESS;
    HANDLE                wait_handles[] = {
        WintunGetReadWaitEvent(Session),
        tdev->stop_event,
    };

    if (wait_handles[0] == NULL || wait_handles[1] == NULL)
    {
        routine_result = GetLastError();
        if (routine_result == ERROR_SUCCESS)
        {
            routine_result = ERROR_INVALID_HANDLE;
        }
        LOGE("TunDevice: ReadThread: failed to prepare wait handles, code: %lu", routine_result);
        return routine_result;
    }

    while (tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
    {
        bufs[queued_count] = bufferpoolGetSmallBuffer(tdev->reader_buffer_pool);
        bufs[queued_count] = sbufReserveSpace(bufs[queued_count], tunDeviceMtu(tdev));

        DWORD packet_size;
        BYTE *packet = WintunReceivePacket(Session, &packet_size);

        if (packet)
        {
            if (UNLIKELY(tunWindowsReceivePacketExceedsMtu(tunDeviceMtu(tdev), packet_size)))
            {
                // Drop only this oversized packet; valid packets already queued at
                // bufs[0..queued_count-1] stay queued and the reader keeps running.
                WintunReleaseReceivePacket(Session, packet);
                bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);
                tunWindowsRecordOversizedReadDiscard(tdev);
                continue;
            }

            sbufSetLength(bufs[queued_count], packet_size);
            memoryCopyLarge(sbufGetMutablePtr(bufs[queued_count]), packet, packet_size);

            WintunReleaseReceivePacket(Session, packet);

            if (TUN_LOG_EVERYTHING)
            {
                LOGD("TunDevice: ReadThread: Read %lu bytes from device %s", packet_size, tdev->name);
                // printPacket(Packet, PacketSize);
            }

            queued_count++;
            if (queued_count == kMaxReadDistributeQueueSize)
            {
                if (tundeviceReaderStopRequested(tdev, &routine_result))
                {
                    goto cleanup;
                }
                deviceFlowAffinityPostBatch(tdev->reader_session, &bufs[0], queued_count);
                queued_count = 0;
            }
        }
        else
        {
            // The thread-local last error is only meaningful right here:
            // recycling the buffer below runs arbitrary code that can overwrite
            // it, which would misclassify a real device loss as a transient.
            DWORD last_error = GetLastError();

            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);

            if (tunWindowsClassifyReceiveError(last_error) == kTunWindowsReceiveTerminal)
            {
                /*
                 * Anything but an exhausted ring means this session is finished,
                 * including ERROR_HANDLE_EOF and ERROR_INVALID_DATA. Returning
                 * is what lets the thread wrapper publish FAILED and request the
                 * orderly shutdown; swallowing it would leave a dead adapter
                 * advertised as up while the reader spins.
                 */
                LOGE("TunDevice: ReadThread: Packet read failed: error %lu", last_error);
                LOGE("TunDevice: ReadThread: Terminating");
                routine_result = last_error;
                goto cleanup;
            }

            // ERROR_NO_MORE_ITEMS: the ring is empty, so flush what is queued and
            // then wait for the session to signal more data.
            if (queued_count > 0)
            {
                if (tundeviceReaderStopRequested(tdev, &routine_result))
                {
                    goto cleanup;
                }
                deviceFlowAffinityPostBatch(tdev->reader_session, &bufs[0], queued_count);
                queued_count = 0;
                continue;
            }

            DWORD wait_result = WaitForMultipleObjects(2, wait_handles, FALSE, kTunReaderStopFallbackWaitMs);
            if (wait_result == WAIT_OBJECT_0)
            {
                continue;
            }
            if (wait_result == WAIT_OBJECT_0 + 1)
            {
                goto cleanup;
            }
            if (wait_result == WAIT_TIMEOUT)
            {
                if (! tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
                {
                    goto cleanup;
                }
                continue;
            }
            if (wait_result == WAIT_FAILED)
            {
                routine_result = GetLastError();
                LOGE("TunDevice: ReadThread: wait failed, code: %lu", routine_result);
                goto cleanup;
            }
            LOGE("TunDevice: ReadThread: unexpected wait result: %lu", wait_result);
            goto cleanup;
        }
    }
    LOGD("TunDevice: ReadThread: Terminating due to inactive lifecycle");

cleanup:
    if (queued_count > 0)
    {
        reuseTunReadBuffers(tdev, &bufs[0], queued_count);
    }

    tunWindowsReportPendingOversizedReadDiscards(tdev);

    return routine_result;
}

/**
 * Writer thread routine - writes packets to TUN device
 */
static WTHREAD_ROUTINE(routineWriteToTun)
{
    tun_device_t         *tdev    = userdata;
    WINTUN_SESSION_HANDLE Session = tdev->session_handle;
    sbuf_t               *buf;
    struct wchan_s       *writer_channel = deviceWriterChannelGetConsumerChannel(&tdev->writer_channel);

    while (tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
    {
        if (! chanRecv(writer_channel, (void **) &buf))
        {
            LOGD("TunDevice: WriteThread: Terminating due to closed channel");
            return 0;
        }

        if (UNLIKELY(tunDeviceMtu(tdev) < sbufGetLength(buf)))
        {
            LOGW("TunDevice: WriteThread: discarded a packet -> size %d exceeds device MTU %u",
                 sbufGetLength(buf),
                 tunDeviceMtu(tdev));

            bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
            continue;
        }

        BYTE *Packet = WintunAllocateSendPacket(Session, sbufGetLength(buf));
        if (! Packet)
        {
            DWORD last_error = GetLastError();
            bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);

            if (last_error == ERROR_BUFFER_OVERFLOW)
            {
                // A full Wintun send ring is transient; drop this packet and keep consuming the queue.
                continue;
            }

            LOGE("TunDevice: WriteThread: Failed to allocate memory for write packet, code: %lu", last_error);
            LOGE("TunDevice: WriteThread: Terminating");
            return last_error;
        }

        memoryCopyLarge(Packet, sbufGetRawPtr(buf), sbufGetLength(buf));

        WintunSendPacket(Session, Packet);

        bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
    }

    LOGD("TunDevice: WriteThread: Terminating due to inactive lifecycle");

    return 0;
}

static void tundeviceCloseLifetimeGates(tun_device_t *tdev)
{
    deviceWriterChannelClose(&tdev->writer_channel);
    deviceReaderSessionEndRequest(tdev->reader_session);
}

static bool tundeviceJoinThread(wthread_t *thread, const char *name)
{
    if (*thread == NULL)
    {
        return true;
    }

    DWORD thread_id = GetThreadId(*thread);
    if (thread_id == 0)
    {
        LOGE("TunDevice: failed to identify %s thread, code: %lu", name, GetLastError());
        return false;
    }

    if (GetCurrentThreadId() == thread_id)
    {
        LOGE("TunDevice: cannot join %s thread from the same thread", name);
        return false;
    }

    DWORD wait_result = WaitForSingleObject(*thread, INFINITE);
    if (wait_result != WAIT_OBJECT_0)
    {
        DWORD last_error = wait_result == WAIT_FAILED ? GetLastError() : ERROR_INVALID_FUNCTION;
        LOGE("TunDevice: failed to join %s thread, wait result: %lu, code: %lu", name, wait_result, last_error);
        return false;
    }

    if (! CloseHandle(*thread))
    {
        LOGE("TunDevice: failed to close joined %s thread handle, code: %lu", name, GetLastError());
        return false;
    }

    *thread = NULL;
    return true;
}

static void tundeviceBeginSessionShutdown(void *context)
{
    tun_device_t *tdev = context;

    tunLifecycleTransitionToStopping(&tdev->lifecycle);
    tundeviceCloseLifetimeGates(tdev);
}

static bool tundeviceSignalStopEvent(void *context)
{
    tun_device_t *tdev = context;

    if (tdev->stop_event == NULL)
    {
        LOGE("TunDevice: stop event is not initialized");
        return false;
    }

    if (! SetEvent(tdev->stop_event))
    {
        LOGE("TunDevice: failed to signal stop event, code: %lu", GetLastError());
        LOGW("TunDevice: reader will use the bounded shutdown wait fallback");
        return false;
    }

    return true;
}

static bool tundeviceJoinReader(void *context)
{
    tun_device_t *tdev = context;
    if (! tundeviceJoinThread(&tdev->read_thread, "reader"))
    {
        return false;
    }
    return true;
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

static bool tundeviceJoinWriter(void *context)
{
    tun_device_t *tdev = context;
    if (! tundeviceJoinThread(&tdev->write_thread, "writer"))
    {
        return false;
    }
    bufferpoolResetThreadOwnership(tdev->writer_buffer_pool);
    return true;
}

static bool tundeviceReleaseWriter(void *context)
{
    tun_device_t *tdev = context;

    return deviceWriterChannelRetireCurrent(&tdev->writer_channel);
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
        .signal_reader        = tundeviceSignalStopEvent,
        .wait_reader_delivery = tundeviceWaitReaderDelivery,
        .join_reader          = tundeviceJoinReader,
        .retire_reader        = tundeviceRetireReader,
        .join_writer          = tundeviceJoinWriter,
        .release_writer       = tundeviceReleaseWriter,
        .end_session          = tundeviceEndSession,
    };

    return tunWindowsLifetimeShutdown(tdev, &ops);
}

bool tundeviceRequestStop(tun_device_t *tdev)
{
    tundeviceBeginSessionShutdown(tdev);
    return tundeviceSignalStopEvent(tdev);
}

/*
 * Single place where an unexpected TUN I/O thread exit becomes process policy.
 * Keep this behaviorally identical to the tun_linux.c and tun_darwin.c copies.
 *
 * A device I/O routine that returns while the lifecycle is STARTING or UP was
 * not asked to stop: it hit a real error (a Wintun receive failure, a failed
 * wait). Such exits used to leave the device published as healthy while reads
 * had silently stopped and writes piled into a channel nobody drains.
 *
 * The routine has already returned, so it has released or transferred every
 * buffer it owned, and this wrapper owns no locks. That is what makes it the
 * correct point to request shutdown: requestProgramShutdown() returns, the
 * wrapper returns, and worker 0 is then free to join this thread.
 *
 * Deliberately NOT done here: closing channels, waking the peer,
 * tundeviceBringDown(), pre-down scripts, route/DNS restoration, or joining
 * threads. A device thread that did any of those would eventually join itself.
 * The lifecycle coordinator reaches all of it through the quiesce/wait hooks.
 */
static void tundeviceNoteUnexpectedThreadExit(tun_device_t *tdev, const char *which)
{
    tun_lifecycle_state_t failed_from;
    if (! tunLifecycleTransitionToFailed(&tdev->lifecycle, &failed_from))
    {
        // Either normal teardown already moved the device to STOPPING (this
        // routine returned because it was asked to), or the peer thread already
        // published the failure. Neither case logs or requests again.
        return;
    }

    LOGE("TunDevice: %s thread for device %s exited unexpectedly; the device is no longer usable", which, tdev->name);

    /*
     * STARTING -> FAILED is a startup failure: tundeviceBringUp() observes the
     * failed publication, rolls back what it owns and returns false, and the
     * main-thread TunDevice::onStart path decides what happens next. Requesting
     * shutdown from here would race that synchronous rollback.
     *
     * UP -> FAILED is an already published device losing a required I/O thread
     * at runtime. The packet chain cannot continue correctly, so this is
     * process-fatal: request the orderly, worker-0-owned shutdown.
     */
    if (failed_from == kTunLifecycleUp && ! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

static WTHREAD_ROUTINE(tundeviceReaderThreadMain) // NOLINT
{
    // Auxiliary device thread: it must stay unregistered and use only
    // device-owned pools/channels, posting work to explicit event workers.
    assert(! currentThreadHasRegisteredWID());
    tun_device_t *tdev = userdata;
    discard       tdev->routine_reader(tdev);
    tundeviceNoteUnexpectedThreadExit(tdev, "reader");
    return 0;
}

static WTHREAD_ROUTINE(tundeviceWriterThreadMain) // NOLINT
{
    // Auxiliary device thread: it must stay unregistered and use only
    // device-owned pools/channels, posting work to explicit event workers.
    assert(! currentThreadHasRegisteredWID());
    tun_device_t *tdev = userdata;
    discard       tdev->routine_writer(tdev);
    tundeviceNoteUnexpectedThreadExit(tdev, "writer");
    return 0;
}

bool tundeviceBringUp(tun_device_t *tdev)
{
    if (tdev->session_handle != NULL || deviceWriterChannelHasCurrent(&tdev->writer_channel) ||
        tdev->read_thread != NULL || tdev->write_thread != NULL)
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
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    bufferpoolUpdateAllocationPaddings(tdev->reader_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(worker_pool),
                                       bufferpoolGetSmallBufferPadding(worker_pool));

    bufferpoolUpdateAllocationPaddings(tdev->writer_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(worker_pool),
                                       bufferpoolGetSmallBufferPadding(worker_pool));

    if (! tunWindowsSetMtu(tdev))
    {
        LOGE("TunDevice: error setting MTU size");
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
        return false;
    }

    if (! ResetEvent(tdev->stop_event))
    {
        LOGE("TunDevice: failed to reset stop event, code: %lu", GetLastError());
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
        return false;
    }

    if (! deviceWriterChannelOpen(&tdev->writer_channel, kTunWriteChannelQueueMax))
    {
        LOGE("TunDevice: failed to open writer channel");
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
        return false;
    }
    if (deviceReaderSessionBegin(tdev->reader_session) == 0)
    {
        LOGE("TunDevice: failed to open reader delivery generation");
        deviceWriterChannelClose(&tdev->writer_channel);
        discard deviceWriterChannelRetireCurrent(&tdev->writer_channel);
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
        discard deviceWriterChannelRetireCurrent(&tdev->writer_channel);
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
        return false;
    }

    tdev->session_handle = Session;
    tdev->read_thread    = NULL;
    tdev->write_thread   = NULL;

    wthread_error_t error = threadCreate(&tdev->read_thread, tundeviceReaderThreadMain, tdev);
    if (error != kWThreadErrorNone)
    {
        LOGE("TunDevice: failed to create reader thread, code: %u", error);
        goto rollback;
    }

    if (tunLifecycleLoad(&tdev->lifecycle) == kTunLifecycleFailed)
    {
        goto rollback;
    }

    error = threadCreate(&tdev->write_thread, tundeviceWriterThreadMain, tdev);
    if (error != kWThreadErrorNone)
    {
        LOGE("TunDevice: failed to create writer thread, code: %u", error);
        goto rollback;
    }

    if (! tunLifecycleTransitionStartingToUp(&tdev->lifecycle))
    {
        LOGE("TunDevice: an I/O thread failed during startup");
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
        LOGE("TunDevice: thread-startup rollback is incomplete; retained resources require a shutdown retry");
    }
    return false;
}

bool tundeviceBringDown(tun_device_t *tdev)
{
    if (! tundeviceIsUp(tdev) && tdev->session_handle == NULL &&
        ! deviceWriterChannelHasCurrent(&tdev->writer_channel) && tdev->read_thread == NULL &&
        tdev->write_thread == NULL)
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
    if (count == 0)
    {
        return true;
    }

    if (count > kTunDeviceMaxDnsServers)
    {
        LOGE("TunDevice: at most %d DNS servers are supported", kTunDeviceMaxDnsServers);
        return false;
    }

    if (! tunWindowsDnsNameIsSafe(tdev->name))
    {
        LOGE("TunDevice: invalid DNS interface argument");
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

    char command[512];
    stringNPrintf(command,
                  sizeof(command),
                  "netsh interface ipv4 set dnsservers name=\"%s\" source=static address=%s register=none "
                  "validate=no",
                  tdev->name,
                  servers[0]);
    if (tunWindowsRunCommand(command) != 0)
    {
        LOGE("TunDevice: failed to set primary DNS server on %s", tdev->name);
        return false;
    }

    if (count > 1)
    {
        stringNPrintf(command,
                      sizeof(command),
                      "netsh interface ipv4 add dnsservers name=\"%s\" address=%s index=2 validate=no",
                      tdev->name,
                      servers[1]);
        if (tunWindowsRunCommand(command) != 0)
        {
            LOGE("TunDevice: failed to set secondary DNS server on %s", tdev->name);
            discard tundeviceClearDnsServers(tdev);
            return false;
        }
    }

    LOGI("TunDevice: configured %zu DNS server(s) on %s", count, tdev->name);
    return true;
}

bool tundeviceClearDnsServers(tun_device_t *tdev)
{
    if (! tunWindowsDnsNameIsSafe(tdev->name))
    {
        LOGE("TunDevice: invalid DNS interface argument");
        return false;
    }

    char command[512];
    stringNPrintf(
        command, sizeof(command), "netsh interface ipv4 delete dnsservers name=\"%s\" all validate=no", tdev->name);
    if (tunWindowsRunCommand(command) != 0)
    {
        LOGE("TunDevice: failed to clear DNS servers on %s", tdev->name);
        return false;
    }

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
    assert(sbufGetLength(buf) > 20);

    switch (deviceWriterChannelTrySend(&tdev->writer_channel, buf))
    {
    case kDeviceWriterSendOk:
        return true;
    case kDeviceWriterSendDown:
        if (tundeviceShouldLogRefusal())
        {
            LOGE("TunDevice: Write failed, device is down");
        }
        return false;
    case kDeviceWriterSendClosed:
        if (tundeviceShouldLogRefusal())
        {
            LOGE("TunDevice: Write failed, channel was closed");
        }
        return false;
    case kDeviceWriterSendFull:
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

tun_device_t *tundeviceCreate(const char *name, bool offload, uint16_t mtu, void *userdata, TunReadEventHandle cb)
{
    discard offload;
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
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    uint32_t worker_large_buffer_size = bufferpoolGetLargeBufferSize(worker_pool);
    uint32_t worker_small_buffer_size = bufferpoolGetSmallBufferSize(worker_pool);
    worker_small_buffer_size          = max(worker_small_buffer_size, (uint32_t) mtu);

    buffer_pool_t *reader_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   RAM_PROFILE,

                                                   worker_large_buffer_size,
                                                   worker_small_buffer_size

    );
    if (UNLIKELY(reader_bpool == NULL))
    {
        LOGE("TunDevice: failed to construct reader buffer pool");
        return NULL;
    }

    buffer_pool_t *writer_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   RAM_PROFILE,

                                                   worker_large_buffer_size,
                                                   worker_small_buffer_size

    );
    if (UNLIKELY(writer_bpool == NULL))
    {
        LOGE("TunDevice: failed to construct writer buffer pool");
        bufferpoolDestroy(reader_bpool);
        return NULL;
    }

    tun_device_t *tdev = memoryAllocate(sizeof(tun_device_t));
    if (UNLIKELY(tdev == NULL))
    {
        bufferpoolDestroy(reader_bpool);
        bufferpoolDestroy(writer_bpool);
        return NULL;
    }

    char *device_name = stringDuplicate(name);
    if (UNLIKELY(device_name == NULL))
    {
        memoryFree(tdev);
        bufferpoolDestroy(reader_bpool);
        bufferpoolDestroy(writer_bpool);
        return NULL;
    }

    *tdev = (tun_device_t) {
        .name                           = device_name,
        .routine_reader                 = routineReadFromTun,
        .routine_writer                 = routineWriteToTun,
        .read_event_callback            = cb,
        .userdata                       = userdata,
        .reader_session                 = NULL,
        .reader_buffer_pool             = reader_bpool,
        .writer_buffer_pool             = writer_bpool,
        .adapter_handle                 = NULL,
        .session_handle                 = NULL,
        .stop_event                     = NULL,
        .read_thread                    = NULL,
        .write_thread                   = NULL,
        .mtu                            = mtu,
        .oversized_read_discard_limiter = {0},
    };
    atomic_init(&tdev->lifecycle, kTunLifecycleDown);

    deviceWriterChannelInit(&tdev->writer_channel);
    tdev->reader_session =
        deviceReaderSessionCreate(RAM_PROFILE * 2, kMaxReadDistributeQueueSize, tdev, tunDeliverPacket, reader_bpool);
    if (UNLIKELY(tdev->reader_session == NULL))
    {
        LOGE("TunDevice: failed to allocate reader session");
        discard deviceWriterChannelDestroy(&tdev->writer_channel);
        memoryFree(tdev->name);
        bufferpoolDestroy(tdev->reader_buffer_pool);
        bufferpoolDestroy(tdev->writer_buffer_pool);
        memoryFree(tdev);
        return NULL;
    }

    tdev->stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (tdev->stop_event == NULL)
    {
        LOGE("TunDevice: failed to create stop event, code: %lu", GetLastError());
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

    size_t wide_bytes;
    if (! memoryTryComputeArraySize((size_t) wide_size, sizeof(wchar_t), &wide_bytes))
    {
        LOGE("TunDevice: UTF-16 adapter name is too large");
        tundeviceDestroy(tdev);
        return NULL;
    }
    tdev->name_w = (wchar_t *) memoryAllocate(wide_bytes);
    if (! tdev->name_w)
    {
        LOGE("TunDevice: Memory allocation failed!");
        tundeviceDestroy(tdev);
        return NULL;
    }

    if (MultiByteToWideChar(CP_UTF8, 0, name, -1, (tdev->name_w), wide_size) <= 0)
    {
        LOGE("TunDevice: Failed to convert adapter name to UTF-16");
        tundeviceDestroy(tdev);
        return NULL;
    }

    WINTUN_ADAPTER_HANDLE adapter = WintunCreateAdapter(tdev->name_w, L"Waterwall Adapter", NULL);
    if (! adapter)
    {
        LastError = GetLastError();
        LOGE("TunDevice: Failed to create adapter! code: %lu", LastError);
        tundeviceDestroy(tdev);
        return NULL;
    }
    tdev->adapter_handle = adapter;

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
        deviceWriterChannelHasCurrent(&tdev->writer_channel) || tdev->read_thread != NULL || tdev->write_thread != NULL)
    {
        if (! tundeviceBringDown(tdev))
        {
            /*
             * I/O resources may still be live, so the validity of the remaining
             * device state is unknown and continuing to free it would be a
             * use-after-free risk. Hard-abort with an explicit diagnostic rather
             * than trying to run more cleanup. Mirrors tun_linux.c.
             */
            LOGF("TunDevice: refusing to destroy device while I/O threads may still be running");
            abortProgramNow(1);
        }
    }

    assert(tdev->session_handle == NULL);
    /*
     * Device destruction follows worker/lwIP shutdown, so no producer can
     * retain a generation pointer while retired queues are reclaimed.
     */
    if (! deviceWriterChannelDestroy(&tdev->writer_channel))
    {
        LOGF("TunDevice: refusing to destroy a published writer generation");
        abortProgramNow(1);
    }

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

    memoryFree(tdev->name);
    memoryFree(tdev->name_w);
    deviceReaderSessionRetireProducerBuffers(tdev->reader_session);
    bufferpoolDestroy(tdev->reader_buffer_pool);
    bufferpoolDestroy(tdev->writer_buffer_pool);
    deviceReaderSessionUnref(tdev->reader_session);

    memoryFree(tdev);
}

void tundevicePlatformShutdown(void)
{
    HMODULE  module   = (HMODULE) GSTATE.wintun_dll_handle;
    wchar_t *dll_path = (wchar_t *) GSTATE.wintun_dll_path;

    /* Stop publication first; global teardown is serialized after all devices. */
    GSTATE.flag_tundev_windows_initialized = false;
    GSTATE.wintun_dll_handle               = NULL;
    GSTATE.wintun_dll_path                 = NULL;
    wintun_api                             = (wintun_api_t) {0};

    if (module != NULL || dll_path != NULL)
    {
        assert(tunWindowsPendingCleanupIsEmpty());
        tunWindowsPendingCleanupAdopt(NULL, module, dll_path, NULL);
    }

    if (! tunWindowsPendingCleanupTry("during platform shutdown"))
    {
        LOGE("TunDevice: Wintun platform cleanup remains pending and will be retried before another startup");
    }
}
