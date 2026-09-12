#include "tun_windows_ownership.h"

#include <assert.h>
#include <bcrypt.h>
#include <sddl.h>
#include <setupapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static const GUID network_class = {0x4d36e972, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};
enum
{
    kOwnershipWaitMs = 5000,
    kOwnershipPollMs = 50
};

static bool ownershipTag(const wchar_t *name, wchar_t tag[TUN_WINDOWS_OWNERSHIP_TAG_CAPACITY])
{
    /* Match the case-insensitive logical adapter name, without placing user
     * input in the pipe namespace or relying on a collision-prone short hash. */
    wchar_t canonical[256];
    if (name[0] == L'\0' || wcslen(name) >= 128)
    {
        SetLastError(ERROR_INVALID_NAME);
        return false;
    }
    int length = LCMapStringW(LOCALE_INVARIANT, LCMAP_UPPERCASE, name, -1, canonical, 256);
    if (length == 0)
        return false;
    BCRYPT_ALG_HANDLE  algorithm = NULL;
    BCRYPT_HASH_HANDLE hash      = NULL;
    unsigned char      digest[32];
    bool               ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0 &&
              BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0) == 0 &&
              BCryptHashData(hash, (PUCHAR) canonical, (ULONG) ((length - 1) * sizeof(wchar_t)), 0) == 0 &&
              BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0;
    if (hash != NULL)
        BCryptDestroyHash(hash);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    if (! ok)
    {
        SetLastError(ERROR_GEN_FAILURE);
        return false;
    }
    wcscpy(tag, L"WaterWall.");
    for (unsigned i = 0; i < sizeof(digest); ++i)
        swprintf(tag + 10 + i * 2, 3, L"%02x", digest[i]);
    return true;
}

HANDLE tunWindowsOwnershipAcquire(const wchar_t *name, wchar_t tag[TUN_WINDOWS_OWNERSHIP_TAG_CAPACITY])
{
    if (! ownershipTag(name, tag))
        return NULL;
    PSECURITY_DESCRIPTOR security = NULL;
    if (! ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &security, NULL))
        return NULL;
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), security, FALSE};
    wchar_t             pipe_name[128];
    swprintf(pipe_name, 128, L"\\\\.\\pipe\\%ls.TunOwner", tag);
    ULONGLONG deadline = GetTickCount64() + kOwnershipWaitMs;
    for (;;)
    {
        /* No client connection or I/O is used. FIRST_PIPE_INSTANCE provides
         * exclusive kernel ownership until the last duplicated server handle
         * closes, including after process termination. No stale lock file. */
        HANDLE lease = CreateNamedPipeW(pipe_name,
                                        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                        PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
                                        1,
                                        0,
                                        0,
                                        0,
                                        &attributes);
        if (lease != INVALID_HANDLE_VALUE)
        {
            LocalFree(security);
            return lease;
        }
        DWORD error = GetLastError();
        if ((error != ERROR_ACCESS_DENIED && error != ERROR_PIPE_BUSY) || GetTickCount64() >= deadline)
        {
            LocalFree(security);
            SetLastError(error);
            return NULL;
        }
        Sleep(kOwnershipPollMs);
    }
}

static bool removeOwnedDevices(const wchar_t *tag, bool *found)
{
    *found = false;
    wchar_t description[TUN_WINDOWS_OWNERSHIP_TAG_CAPACITY + 8];
    swprintf(description, TUN_WINDOWS_OWNERSHIP_TAG_CAPACITY + 8, L"%ls Tunnel", tag);
    HDEVINFO devices = SetupDiGetClassDevsW(&network_class, NULL, NULL, DIGCF_PRESENT);
    if (devices == INVALID_HANDLE_VALUE)
        return false;
    DWORD error = ERROR_SUCCESS;
    for (DWORD i = 0;; ++i)
    {
        SP_DEVINFO_DATA device = {.cbSize = sizeof(device)};
        if (! SetupDiEnumDeviceInfo(devices, i, &device))
        {
            error = GetLastError();
            if (error == ERROR_NO_MORE_ITEMS)
                error = ERROR_SUCCESS;
            break;
        }
        wchar_t value[256] = {0};
        DWORD   type, bytes;
        if (! SetupDiGetDeviceRegistryPropertyW(
                devices, &device, SPDRP_DEVICEDESC, &type, (BYTE *) value, sizeof(value), &bytes))
        {
            error = GetLastError();
            if (error == ERROR_INVALID_DATA || error == ERROR_INSUFFICIENT_BUFFER)
                continue;
            break;
        }
        if (type != REG_SZ || bytes < sizeof(wchar_t) || bytes > sizeof(value) ||
            value[bytes / sizeof(wchar_t) - 1] != L'\0' || wcscmp(value, description) != 0)
            continue;
        /* A matching description is supplied inside Wintun creation, before
         * the adapter can receive WaterWall's IP/routes/DNS. Require its hardware
         * identity too (empty for Wintun's temporary creation stub); never
         * reclaim a device merely sharing a friendly name. */
        if (! SetupDiGetDeviceRegistryPropertyW(
                devices, &device, SPDRP_HARDWAREID, &type, (BYTE *) value, sizeof(value), &bytes))
        {
            error = GetLastError();
            /* Wintun's temporary software-device stub can have no hardware IDs. */
            if (error != ERROR_INVALID_DATA)
                break;
        }
        else if (type != REG_MULTI_SZ || bytes < 2 * sizeof(wchar_t) || bytes > sizeof(value) ||
                 value[bytes / sizeof(wchar_t) - 1] != L'\0' || (value[0] != L'\0' && _wcsicmp(value, L"Wintun") != 0))
        {
            error = ERROR_INVALID_DATA;
            break;
        }
        SP_DEVINSTALL_PARAMS_W params = {.cbSize = sizeof(params)};
        if (! SetupDiGetDeviceInstallParamsW(devices, &device, &params))
        {
            error = GetLastError();
            break;
        }
        params.Flags |= DI_QUIETINSTALL;
        SP_REMOVEDEVICE_PARAMS removal = {.ClassInstallHeader = {sizeof(SP_CLASSINSTALL_HEADER), DIF_REMOVE},
                                          .Scope              = DI_REMOVEDEVICE_GLOBAL};
        if (! SetupDiSetDeviceInstallParamsW(devices, &device, &params) ||
            ! SetupDiSetClassInstallParamsW(devices, &device, &removal.ClassInstallHeader, sizeof(removal)) ||
            ! SetupDiCallClassInstaller(DIF_REMOVE, devices, &device))
        {
            error = GetLastError();
            break;
        }
        *found = true;
        if (! SetupDiGetDeviceInstallParamsW(devices, &device, &params))
        {
            error = GetLastError();
            break;
        }
        if ((params.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART)) != 0)
        {
            error = ERROR_SUCCESS_REBOOT_REQUIRED;
            break;
        }
    }
    SetupDiDestroyDeviceInfoList(devices);
    SetLastError(error);
    return error == ERROR_SUCCESS;
}

bool tunWindowsOwnershipReconcile(const wchar_t *tag)
{
    ULONGLONG deadline = GetTickCount64() + kOwnershipWaitMs;
    for (;;)
    {
        bool found;
        if (! removeOwnedDevices(tag, &found))
        {
            DWORD error = GetLastError();
            if (error == ERROR_IN_WOW64)
                fputs("TunDevice: device removal requires a WaterWall build matching the Windows architecture.\n",
                      stderr);
            else if (error == ERROR_SUCCESS_REBOOT_REQUIRED)
                fputs("TunDevice: Windows requires a restart to finish removing the previous adapter.\n", stderr);
            SetLastError(error);
            return false;
        }
        if (! found)
            return true;
        if (GetTickCount64() >= deadline)
        {
            SetLastError(ERROR_BUSY);
            return false;
        }
        Sleep(kOwnershipPollMs);
    }
}

bool tunWindowsOwnershipPrepare(const char *name, tun_windows_ownership_t *ownership)
{
    assert(ownership->lease == NULL);
    wchar_t wide[128];
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name, -1, wide, 128) == 0)
        return false;
    ownership->lease = tunWindowsOwnershipAcquire(wide, ownership->tag);
    if (ownership->lease == NULL)
        return false;
    if (! tunWindowsOwnershipReconcile(ownership->tag))
    {
        DWORD error = GetLastError();
        CloseHandle(ownership->lease);
        ownership->lease = NULL;
        SetLastError(error);
        return false;
    }
    return true;
}

bool tunWindowsOwnershipStartHelper(HANDLE lease, const wchar_t *executable, wchar_t *command, void *environment,
                                    const wchar_t *directory, PROCESS_INFORMATION *child)
{
    assert(lease != NULL);
    HANDLE inherited;
    if (! DuplicateHandle(GetCurrentProcess(), lease, GetCurrentProcess(), &inherited, SYNCHRONIZE, TRUE, 0))
        return false;
    STARTUPINFOEXW startup = {0};
    SIZE_T         size    = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    startup.lpAttributeList = malloc(size);
    bool initialized =
        startup.lpAttributeList != NULL && InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size);
    bool ok = false;
    if (initialized &&
        UpdateProcThreadAttribute(
            startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherited, sizeof(inherited), NULL, NULL))
    {
        startup.StartupInfo.cb      = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        ok                          = CreateProcessW(executable,
                            command,
                            NULL,
                            NULL,
                            TRUE,
                            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                            environment,
                            directory,
                            &startup.StartupInfo,
                            child) != FALSE;
    }
    DWORD error = startup.lpAttributeList == NULL ? ERROR_NOT_ENOUGH_MEMORY : GetLastError();
    if (initialized)
        DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    CloseHandle(inherited);
    SetLastError(error);
    return ok;
}
