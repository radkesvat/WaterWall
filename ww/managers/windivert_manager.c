#include "managers/windivert_manager.h"

#ifdef OS_WIN

#include "global_state.h"
#include "wplatform.h"
#include <tchar.h>

#include "loggers/internal_logger.h"

// Embedded WinDivert binaries (provided by the generated *.bytes.c sources).
extern const unsigned char windivert_dll[];
extern const unsigned int  windivert_dll_len;

extern const unsigned char windivert_sys[];
extern const unsigned int  windivert_sys_len;

// Resolved WinDivert exports.
static HANDLE (*pWinDivertOpen)(const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);
static BOOL (*pWinDivertRecv)(HANDLE handle, VOID *pPacket, UINT packetLen, UINT *pRecvLen, WINDIVERT_ADDRESS *pAddr);
static BOOL (*pWinDivertSend)(HANDLE handle, const VOID *pPacket, UINT packetLen, UINT *pSendLen,
                              const WINDIVERT_ADDRESS *pAddr);
static BOOL (*pWinDivertShutdown)(HANDLE handle, WINDIVERT_SHUTDOWN how);
static BOOL (*pWinDivertClose)(HANDLE handle);
static BOOL (*pWinDivertHelperFormatIPv4Address)(UINT32 addr, char *buffer, UINT bufLen);
static BOOL (*pWinDivertHelperFormatIPv6Address)(const UINT32 *addr, char *buffer, UINT bufLen);

static bool g_windivert_api_resolved = false;

/**
 * Writes the WinDivert DLL bytes to a temporary file on disk.
 * @return Path to the temporary file or NULL on failure (caller frees with free()).
 */
static TCHAR *windivertWriteDllToTempFile(const unsigned char *dllBytes, size_t dllSize)
{
    TCHAR tempPath[MAX_PATH];
    TCHAR tempFileName[MAX_PATH];

    if (GetTempPath(MAX_PATH, tempPath) == 0)
    {
        LOGE("WinDivertManager: Failed to get temporary path");
        return NULL;
    }

    if (GetTempFileName(tempPath, _T("dll"), 0, tempFileName) == 0)
    {
        LOGE("WinDivertManager: Failed to create dll filename");
        return NULL;
    }

    HANDLE hFile = CreateFile(tempFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LOGE("WinDivertManager: Failed to create dll file");
        return NULL;
    }

    DWORD bytesWritten;
    if (! WriteFile(hFile, dllBytes, (DWORD) dllSize, &bytesWritten, NULL))
    {
        LOGE("WinDivertManager: Failed to write dll file");
        CloseHandle(hFile);
        DeleteFile(tempFileName);
        return NULL;
    }

    CloseHandle(hFile);
    return _tcsdup(tempFileName);
}

/**
 * Writes the WinDivert SYS (driver) bytes to a well-known temporary path.
 * WinDivert requires the driver to sit next to the DLL with a fixed name.
 * @return Path to the file or NULL on failure (caller frees with free()).
 */
static TCHAR *windivertWriteSYSToTempFile(const unsigned char *sysBytes, size_t sysSize)
{
    TCHAR tempPath[MAX_PATH];

    if (GetTempPath(MAX_PATH, tempPath) == 0)
    {
        LOGE("WinDivertManager: Failed to get temporary path");
        return NULL;
    }

    size_t len = _tcslen(tempPath);
    if (tempPath[len - 1] != _T('\\'))
    {
        _tcscat(tempPath, _T("\\"));
    }

    _tcscat(tempPath, _T("WinDivert64.sys"));

    HANDLE hFile = CreateFile(tempPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD last_error = GetLastError();
        if (last_error == ERROR_FILE_EXISTS || last_error == ERROR_ALREADY_EXISTS)
        {
            LOGD("WinDivertManager: the sys file may already exist");
            return _tcsdup(tempPath);
        }
        LOGE("WinDivertManager: Failed to create sys file, error %lu", last_error);
        return NULL;
    }

    DWORD bytesWritten;
    if (! WriteFile(hFile, sysBytes, (DWORD) sysSize, &bytesWritten, NULL))
    {
        LOGE("WinDivertManager: Failed to write sys file");
        CloseHandle(hFile);
        DeleteFile(tempPath);
        return NULL;
    }

    CloseHandle(hFile);
    return _tcsdup(tempPath);
}

/**
 * Extracts the embedded driver + DLL and loads the DLL into the process.
 * Stores the module handle on GSTATE so it survives for the process lifetime.
 */
static void windivertLoadLibrary(void)
{
    if (GSTATE.windivert_dll_handle != NULL)
    {
        LOGD("WinDivertManager: WinDivert DLL already loaded");
        return;
    }

    TCHAR *tempSysPath = windivertWriteSYSToTempFile(&windivert_sys[0], windivert_sys_len);
    if (! tempSysPath)
    {
        LOGE("WinDivertManager: Failed to write SYS file to temporary file");
        return;
    }

    TCHAR *tempDllPath = windivertWriteDllToTempFile(&windivert_dll[0], windivert_dll_len);
    if (! tempDllPath)
    {
        LOGE("WinDivertManager: Failed to write DLL to temporary file");
        free(tempSysPath);
        return;
    }

    WCHAR widePath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, tempDllPath, -1, widePath, MAX_PATH);
    HMODULE hModule = LoadLibraryExW(widePath, NULL, 0);
    if (! hModule)
    {
        LOGE("WinDivertManager: Failed to load DLL: error %lu", GetLastError());
        DeleteFile(tempDllPath);
        free(tempDllPath);
        free(tempSysPath);
        return;
    }

    GSTATE.windivert_dll_handle = hModule;
    free(tempDllPath);
    free(tempSysPath);
}

static bool windivertLoadFunctionFromDLL(const char *function_name, void *target)
{
    FARPROC proc = GetProcAddress(GSTATE.windivert_dll_handle, function_name);
    if (proc == NULL)
    {
        LOGE("WinDivertManager: Failed to load function '%s' from WinDivert DLL.", function_name);
        return false;
    }
    memoryCopy(target, &proc, sizeof(FARPROC));
    return true;
}

bool windivertManagerEnsureLoaded(void)
{
    if (g_windivert_api_resolved)
    {
        return true;
    }

    if (GSTATE.windivert_dll_handle == NULL)
    {
        windivertLoadLibrary();
    }

    if (GSTATE.windivert_dll_handle == NULL)
    {
        LOGE("WinDivertManager: WinDivert DLL not loaded");
        return false;
    }

    if (! windivertLoadFunctionFromDLL("WinDivertOpen", &pWinDivertOpen))
        return false;
    if (! windivertLoadFunctionFromDLL("WinDivertRecv", &pWinDivertRecv))
        return false;
    if (! windivertLoadFunctionFromDLL("WinDivertSend", &pWinDivertSend))
        return false;
    if (! windivertLoadFunctionFromDLL("WinDivertShutdown", &pWinDivertShutdown))
        return false;
    if (! windivertLoadFunctionFromDLL("WinDivertClose", &pWinDivertClose))
        return false;
    if (! windivertLoadFunctionFromDLL("WinDivertHelperFormatIPv4Address", &pWinDivertHelperFormatIPv4Address))
        return false;
    if (! windivertLoadFunctionFromDLL("WinDivertHelperFormatIPv6Address", &pWinDivertHelperFormatIPv6Address))
        return false;

    g_windivert_api_resolved = true;
    LOGI("WinDivertManager: WinDivert loaded successfully");
    return true;
}

HANDLE windivertOpen(const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags)
{
    return pWinDivertOpen(filter, layer, priority, flags);
}

bool windivertRecv(HANDLE handle, void *packet, UINT packet_len, UINT *recv_len, WINDIVERT_ADDRESS *addr)
{
    return pWinDivertRecv(handle, packet, packet_len, recv_len, addr) != FALSE;
}

bool windivertSend(HANDLE handle, const void *packet, UINT packet_len, UINT *send_len, const WINDIVERT_ADDRESS *addr)
{
    return pWinDivertSend(handle, packet, packet_len, send_len, addr) != FALSE;
}

bool windivertShutdown(HANDLE handle, WINDIVERT_SHUTDOWN how)
{
    return pWinDivertShutdown(handle, how) != FALSE;
}

bool windivertClose(HANDLE handle)
{
    return pWinDivertClose(handle) != FALSE;
}

bool windivertHelperFormatIPv4Address(UINT32 addr, char *buffer, UINT buffer_len)
{
    return pWinDivertHelperFormatIPv4Address(addr, buffer, buffer_len) != FALSE;
}

bool windivertHelperFormatIPv6Address(const UINT32 *addr, char *buffer, UINT buffer_len)
{
    return pWinDivertHelperFormatIPv6Address(addr, buffer, buffer_len) != FALSE;
}

#endif // OS_WIN
