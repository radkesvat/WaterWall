/* Native filesystem/ACL fixture. The embedded bytes and module/driver APIs are
 * replaced below; this test never loads a real DLL or installs a driver. */
#include "devices/windows_driver_artifacts.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "managers/windivert_manager.h"
#include <aclapi.h>
#include <stdio.h>

static bool         short_write;
static bool         oversized_temp;
static bool         deny_delete;
static bool         fail_load;
static bool         fail_unload;
static bool         missing_export;
static unsigned int load_calls;
static unsigned int unload_calls;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s (Win32 %lu)\n", message, GetLastError());
        exit(1);
    }
}

static BOOL WINAPI fixtureWrite(HANDLE file, LPCVOID bytes, DWORD length, LPDWORD written, LPOVERLAPPED overlapped)
{
    return WriteFile(file, bytes, short_write && length != 0 ? length - 1 : length, written, overlapped);
}

static DWORD WINAPI fixtureTemp(DWORD length, LPWSTR path)
{
    return oversized_temp ? length + 1 : GetTempPathW(length, path);
}

static BOOL WINAPI fixtureDelete(LPCWSTR path)
{
    if (deny_delete)
    {
        SetLastError(ERROR_SHARING_VIOLATION);
        return FALSE;
    }
    return DeleteFileW(path);
}

static HMODULE WINAPI fixtureLoad(LPCWSTR path, HANDLE file, DWORD flags)
{
    ++load_calls;
    require(file == NULL && flags == (LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32),
            "loader widened dependency search");
    require(wcsstr(path, L"Waterwall-drivers-") != NULL, "loader did not use the protected directory");
    if (fail_load)
    {
        SetLastError(ERROR_MOD_NOT_FOUND);
        return NULL;
    }
    return (HMODULE) (uintptr_t) 123;
}

static BOOL WINAPI fixtureUnload(HMODULE module)
{
    require(module == (HMODULE) (uintptr_t) 123, "unloading an unowned module");
    ++unload_calls;
    if (fail_unload)
    {
        SetLastError(ERROR_BUSY);
        return FALSE;
    }
    return TRUE;
}

static HANDLE WINAPI fixtureOpen(const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags)
{
    discard filter;
    discard layer;
    discard priority;
    discard flags;
    return (HANDLE) (uintptr_t) 456;
}

static BOOL WINAPI fixtureClose(HANDLE handle)
{
    require(handle == (HANDLE) (uintptr_t) 456, "closing an unowned device handle");
    return TRUE;
}

static void WINAPI fixtureUnused(void)
{
}

static FARPROC WINAPI fixtureExport(HMODULE module, LPCSTR name)
{
    require(module == (HMODULE) (uintptr_t) 123, "resolving an unowned module");
    if (missing_export && strcmp(name, "WinDivertSend") == 0)
    {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return NULL;
    }
    if (strcmp(name, "WinDivertOpen") == 0)
        return (FARPROC) fixtureOpen;
    if (strcmp(name, "WinDivertClose") == 0)
        return (FARPROC) fixtureClose;
    return (FARPROC) fixtureUnused;
}

#define windivert_dll     fixture_windivert_dll
#define windivert_dll_len fixture_windivert_dll_len
#define windivert_sys     fixture_windivert_sys
#define windivert_sys_len fixture_windivert_sys_len

const unsigned char windivert_dll[]   = "fixture DLL bytes";
const unsigned int  windivert_dll_len = sizeof(windivert_dll);
const unsigned char windivert_sys[]   = "fixture SYS bytes";
const unsigned int  windivert_sys_len = sizeof(windivert_sys);

#define WriteFile    fixtureWrite
#define GetTempPathW fixtureTemp
#define DeleteFileW  fixtureDelete
#include "../../ww/devices/windows_driver_artifacts.c"
#undef WriteFile
#undef GetTempPathW
#undef DeleteFileW

#define LoadLibraryExW fixtureLoad
#define FreeLibrary    fixtureUnload
#define GetProcAddress fixtureExport
#include "../../ww/managers/windivert_manager.c"
#undef LoadLibraryExW
#undef FreeLibrary
#undef GetProcAddress

static unsigned int modal_calls;

static bool fixtureNotAdmin(void)
{
    return false;
}

static int WINAPI fixtureMessageBox(HWND window, LPCSTR text, LPCSTR caption, UINT flags)
{
    discard window;
    discard text;
    discard caption;
    discard flags;
    ++modal_calls;
    return IDOK;
}

#define isAdmin fixtureNotAdmin
#undef MessageBox
#define MessageBox            fixtureMessageBox
#define tundeviceTunnelCreate fixtureTunnelCreate
#include "../../tunnels/TunDevice/instance/create.c"
#undef tundeviceTunnelCreate
#undef isAdmin
#undef MessageBox

static void testAdminRefusal(bool restricted)
{
    if (restricted)
        configPolicyRestrict();
    cJSON *settings = cJSON_Parse("{\"device-name\":\"fixture\",\"device-ip\":\"192.0.2.1/24\",\"device-mtu\":1500}");
    require(settings != NULL, "cannot parse constructor fixture");
    node_t               node    = {.node_settings_json = settings};
    ww_startup_context_t context = {0};
    unsigned int         before  = modal_calls;
    wwStartupContextBegin(&context);
    require(fixtureTunnelCreate(&node) == NULL, "admin denial accepted a device");
    require(! wwStartupSucceeded(wwStartupContextEnd(&context)), "admin denial lost startup failure");
    require(modal_calls == before + (restricted ? 0U : 1U), "restricted/ordinary modal policy regressed");
    cJSON_Delete(settings);
}

static void requireEmpty(void)
{
    windowsDriverArtifactsShutdown();
    require(directory[0] == 0 && directory_lock == NULL && ancestor_count == 0, "lost directory cleanup ownership");
    for (int i = 0; i < kWindowsDriverArtifactCount; ++i)
        require(! artifacts[i].in_use && ! artifacts[i].created && artifacts[i].file == NULL,
                "artifact remained after successful cleanup");
}

int main(void)
{
    require(createInternalLogger(NULL, false) != NULL, "cannot initialize fixture logger");
    static const unsigned char bytes[] = "immutable fixture bytes";
    const wchar_t             *path    = NULL;

    oversized_temp = true;
    require(! windowsDriverArtifactPrepare(kWindowsDriverWintun, bytes, sizeof(bytes), &path) && path == NULL,
            "oversized TEMP result was accepted");
    oversized_temp = false;
    requireEmpty();

    short_write = true;
    require(! windowsDriverArtifactPrepare(kWindowsDriverWintun, bytes, sizeof(bytes), &path) && path == NULL,
            "short write was published");
    short_write = false;
    requireEmpty();

    require(windowsDriverArtifactPrepare(kWindowsDriverWintun, bytes, sizeof(bytes), &path), "prepare failed");
    const wchar_t *again = NULL;
    require(windowsDriverArtifactPrepare(kWindowsDriverWintun, bytes, sizeof(bytes), &again) && path == again,
            "immutable reuse did not retain the same artifact");
    HANDLE writable = CreateFileW(
        path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    require(writable == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION,
            "published artifact could be replaced or written");
    require(! DeleteFileW(path), "published artifact could be deleted");
    PSECURITY_DESCRIPTOR security = NULL;
    require(GetNamedSecurityInfoW(
                directory, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &security) ==
                ERROR_SUCCESS,
            "cannot inspect protected directory ACL");
    SECURITY_DESCRIPTOR_CONTROL control;
    DWORD                       revision;
    require(GetSecurityDescriptorControl(security, &control, &revision) && (control & SE_DACL_PROTECTED),
            "directory inherited an ordinary TEMP DACL");
    LocalFree(security);

    /* A collision is never reused, even if it has the required SYS basename. */
    wchar_t stale_sys[kDriverPathCapacity];
    require(swprintf(stale_sys, kDriverPathCapacity, L"%ls\\WinDivert64.sys", directory) > 0,
            "cannot construct stale SYS fixture path");
    HANDLE stale = CreateFileW(stale_sys, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    require(stale != INVALID_HANDLE_VALUE, "cannot create stale SYS fixture");
    DWORD written = 0;
    require(WriteFile(stale, "wrong", 5, &written, NULL) && written == 5 && CloseHandle(stale),
            "cannot write stale SYS fixture");
    const wchar_t *rejected = NULL;
    require(! windowsDriverArtifactPrepare(kWindowsDriverWinDivertSys, windivert_sys, windivert_sys_len, &rejected) &&
                rejected == NULL && GetFileAttributesW(stale_sys) != INVALID_FILE_ATTRIBUTES,
            "existing SYS was accepted or an unowned file was deleted");
    require(DeleteFileW(stale_sys), "cannot remove owned stale SYS fixture");

    deny_delete = true;
    require(! windowsDriverArtifactRelease(kWindowsDriverWintun) && artifacts[kWindowsDriverWintun].created &&
                ! artifacts[kWindowsDriverWintun].in_use && directory[0] != 0,
            "failed deletion discarded residue ownership");
    deny_delete = false;
    require(windowsDriverArtifactRelease(kWindowsDriverWintun), "retained deletion retry failed");
    requireEmpty();

    fail_load = true;
    require(! windivertManagerEnsureLoaded() && GSTATE.windivert_dll_handle == NULL && windivert_api.open == NULL,
            "failed module load was published");
    fail_load = false;
    requireEmpty();
    missing_export = true;
    require(! windivertManagerEnsureLoaded() && GSTATE.windivert_dll_handle == NULL && windivert_api.open == NULL,
            "missing export published a partial API");
    requireEmpty();

    fail_unload = true;
    require(! windivertManagerEnsureLoaded() && pending_module != NULL &&
                artifacts[kWindowsDriverWinDivertDll].in_use && artifacts[kWindowsDriverWinDivertSys].in_use,
            "failed unload lost module/artifact ownership");
    unsigned int before_load = load_calls;
    require(! windivertManagerEnsureLoaded() && load_calls == before_load,
            "startup overlapped a pending module transaction");
    fail_unload    = false;
    missing_export = false;
    windivertManagerShutdown();
    requireEmpty();

    require(windivertManagerEnsureLoaded(), "complete loader transaction failed");
    before_load = load_calls;
    require(windivertManagerEnsureLoaded() && load_calls == before_load, "repeated startup reloaded the module");
    require(wcsncmp(artifacts[kWindowsDriverWinDivertDll].path, directory, wcslen(directory)) == 0 &&
                wcsncmp(artifacts[kWindowsDriverWinDivertSys].path, directory, wcslen(directory)) == 0,
            "paired artifacts have different directories");
    HANDLE       handle        = windivertOpen("false", WINDIVERT_LAYER_NETWORK, 0, 0);
    unsigned int before_unload = unload_calls;
    windivertManagerShutdown();
    require(GSTATE.windivert_dll_handle != NULL && unload_calls == before_unload,
            "teardown unloaded a module with an active device user");
    require(windivertClose(handle), "fixture close failed");
    windivertManagerShutdown();
    require(GSTATE.windivert_dll_handle == NULL && windivert_api.open == NULL, "teardown retained API publication");
    requireEmpty();
    windivertManagerShutdown();
    requireEmpty();
    testAdminRefusal(false);
    testAdminRefusal(true);
    internaloggerDestroy();
    puts("Windows protected driver artifact and loader tests passed");
    return 0;
}
