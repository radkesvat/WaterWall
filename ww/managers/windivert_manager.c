#include "managers/windivert_manager.h"

#ifdef OS_WIN

#include "devices/windows_driver_artifacts.h"
#include "global_state.h"
#include "loggers/internal_logger.h"

// Exact paired artifacts provided by the generated embedded sources.
extern const unsigned char windivert_dll[];
extern const unsigned int  windivert_dll_len;
extern const unsigned char windivert_sys[];
extern const unsigned int  windivert_sys_len;

typedef struct windivert_api_s
{
    HANDLE(WINAPI *open)(const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);
    BOOL(WINAPI *recv)(HANDLE handle, VOID *packet, UINT packet_len, UINT *received, WINDIVERT_ADDRESS *address);
    BOOL(WINAPI *send)(HANDLE handle, const VOID *packet, UINT packet_len, UINT *sent,
                       const WINDIVERT_ADDRESS *address);
    BOOL(WINAPI *shutdown)(HANDLE handle, WINDIVERT_SHUTDOWN how);
    BOOL(WINAPI *close)(HANDLE handle);
    BOOL(WINAPI *format_ipv4)(UINT32 address, char *buffer, UINT length);
    BOOL(WINAPI *format_ipv6)(const UINT32 *address, char *buffer, UINT length);
} windivert_api_t;

static windivert_api_t windivert_api;
static HMODULE         pending_module;
static volatile LONG   active_handles;

static bool windivertCleanupPending(void)
{
    if (pending_module != NULL)
    {
        if (! FreeLibrary(pending_module))
        {
            LOGE("WinDivertManager: retained module after unload failed, code: %lu", GetLastError());
            return false;
        }
        pending_module = NULL;
    }
    bool dll_removed = windowsDriverArtifactRelease(kWindowsDriverWinDivertDll);
    bool sys_removed = windowsDriverArtifactRelease(kWindowsDriverWinDivertSys);
    return dll_removed && sys_removed;
}

static bool windivertLoadFunction(HMODULE module, const char *name, void *target, size_t size)
{
    FARPROC proc = GetProcAddress(module, name);
    if (proc == NULL)
    {
        LOGE("WinDivertManager: required export %s is unavailable, code: %lu", name, GetLastError());
        return false;
    }
    assert(size == sizeof(proc));
    memoryCopy(target, &proc, size);
    return true;
}

bool windivertManagerEnsureLoaded(void)
{
    if (GSTATE.windivert_dll_handle != NULL)
        return true;
    if (! windivertCleanupPending())
        return false;

    const wchar_t  *sys_path = NULL, *dll_path = NULL;
    HMODULE         module = NULL;
    windivert_api_t api    = {0};
    if (! windowsDriverArtifactPrepare(kWindowsDriverWinDivertSys, windivert_sys, windivert_sys_len, &sys_path) ||
        ! windowsDriverArtifactPrepare(kWindowsDriverWinDivertDll, windivert_dll, windivert_dll_len, &dll_path))
    {
        LOGE("WinDivertManager: failed to prepare protected paired artifacts, code: %lu", GetLastError());
        goto fail;
    }
    discard sys_path;
    module = LoadLibraryExW(dll_path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module == NULL)
    {
        LOGE("WinDivertManager: constrained DLL loading failed (safe-loader support required), code: %lu",
             GetLastError());
        goto fail;
    }

#define LOAD_WINDIVERT(member, name)                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! windivertLoadFunction(module, name, &api.member, sizeof(api.member)))                                    \
            goto fail;                                                                                                 \
    } while (0)
    LOAD_WINDIVERT(open, "WinDivertOpen");
    LOAD_WINDIVERT(recv, "WinDivertRecv");
    LOAD_WINDIVERT(send, "WinDivertSend");
    LOAD_WINDIVERT(shutdown, "WinDivertShutdown");
    LOAD_WINDIVERT(close, "WinDivertClose");
    LOAD_WINDIVERT(format_ipv4, "WinDivertHelperFormatIPv4Address");
    LOAD_WINDIVERT(format_ipv6, "WinDivertHelperFormatIPv6Address");
#undef LOAD_WINDIVERT

    /* Serialized startup publishes only a complete API and its retained module. */
    windivert_api               = api;
    GSTATE.windivert_dll_handle = module;
    LOGI("WinDivertManager: WinDivert loaded successfully");
    return true;

fail:
    pending_module = module;
    if (! windivertCleanupPending())
        LOGW("WinDivertManager: protected startup resources remain pending after cleanup failure");
    return false;
}

void windivertManagerShutdown(void)
{
    /* Node destruction has already stopped producers and closed their handles.
     * Retain the module/artifacts if a user could not release its native handle. */
    if (InterlockedCompareExchange(&active_handles, 0, 0) != 0)
    {
        LOGE("WinDivertManager: retained module and artifacts while device handles remain open");
        return;
    }
    if (GSTATE.windivert_dll_handle != NULL)
    {
        assert(pending_module == NULL);
        pending_module              = (HMODULE) GSTATE.windivert_dll_handle;
        GSTATE.windivert_dll_handle = NULL;
        windivert_api               = (windivert_api_t) {0};
    }
    if (! windivertCleanupPending())
        LOGW("WinDivertManager: protected platform cleanup remains pending");
}

HANDLE windivertOpen(const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags)
{
    HANDLE handle = windivert_api.open(filter, layer, priority, flags);
    if (handle != INVALID_HANDLE_VALUE)
        InterlockedIncrement(&active_handles);
    return handle;
}

bool windivertRecv(HANDLE handle, void *packet, UINT packet_len, UINT *recv_len, WINDIVERT_ADDRESS *addr)
{
    return windivert_api.recv(handle, packet, packet_len, recv_len, addr) != FALSE;
}

bool windivertSend(HANDLE handle, const void *packet, UINT packet_len, UINT *send_len, const WINDIVERT_ADDRESS *addr)
{
    return windivert_api.send(handle, packet, packet_len, send_len, addr) != FALSE;
}

bool windivertShutdown(HANDLE handle, WINDIVERT_SHUTDOWN how)
{
    return windivert_api.shutdown(handle, how) != FALSE;
}

bool windivertClose(HANDLE handle)
{
    if (! windivert_api.close(handle))
        return false;
    LONG remaining = InterlockedDecrement(&active_handles);
    assert(remaining >= 0);
    discard remaining;
    return true;
}

bool windivertHelperFormatIPv4Address(UINT32 addr, char *buffer, UINT buffer_len)
{
    return windivert_api.format_ipv4(addr, buffer, buffer_len) != FALSE;
}

bool windivertHelperFormatIPv6Address(const UINT32 *addr, char *buffer, UINT buffer_len)
{
    return windivert_api.format_ipv6(addr, buffer, buffer_len) != FALSE;
}

#endif // OS_WIN
