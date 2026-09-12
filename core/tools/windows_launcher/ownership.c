/* Real kernel lease/helper lifetime; deterministic PnP enumeration/removal.
 * This fixture never installs or removes a host network device. */
#include "tun_windows_ownership.h"
#include <setupapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static void require(bool value, const char *message)
{
    if (! value)
    {
        fprintf(stderr, "%s (Windows error %lu)\n", message, GetLastError());
        ExitProcess(1);
    }
}

static wchar_t        descriptions[3][128];
static const wchar_t *hardware[3] = {L"Wintun", L"Wintun", L"Foreign"};
static bool           present[3];
static bool           query_failure;
static bool           removal_wow64;
static bool           removal_reboot;
static unsigned       removed;

static HDEVINFO WINAPI mockDevices(const GUID *kind, PCWSTR enumerator, HWND parent, DWORD flags)
{
    require(kind != NULL && enumerator == NULL && parent == NULL && flags == DIGCF_PRESENT,
            "reconciliation included phantom or unrelated device classes");
    return (HDEVINFO) (uintptr_t) 123;
}
static BOOL WINAPI mockEnum(HDEVINFO set, DWORD index, PSP_DEVINFO_DATA device)
{
    (void) set;
    unsigned current = 0;
    for (unsigned i = 0; i < 3; ++i)
        if (present[i] && current++ == index)
        {
            device->DevInst = i;
            return TRUE;
        }
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FALSE;
}
static BOOL WINAPI mockProperty(HDEVINFO set, PSP_DEVINFO_DATA device, DWORD property, PDWORD type, PBYTE data,
                                DWORD capacity, PDWORD required)
{
    (void) set;
    if (query_failure)
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    bool description = property == SPDRP_DEVICEDESC;
    require(description || property == SPDRP_HARDWAREID, "unexpected device property");
    const wchar_t *value = description ? descriptions[device->DevInst] : hardware[device->DevInst];
    if (value == NULL)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    *type     = description ? REG_SZ : REG_MULTI_SZ;
    *required = (DWORD) ((wcslen(value) + (description ? 1 : 2)) * sizeof(wchar_t));
    require(*required <= capacity, "property buffer too small");
    memset(data, 0, *required);
    memcpy(data, value, wcslen(value) * sizeof(wchar_t));
    return TRUE;
}
static BOOL WINAPI mockGetParams(HDEVINFO set, PSP_DEVINFO_DATA device, PSP_DEVINSTALL_PARAMS_W params)
{
    (void) set;
    (void) device;
    if (removal_reboot)
        params->Flags |= DI_NEEDREBOOT;
    return TRUE;
}
static BOOL WINAPI mockSetParams(HDEVINFO set, PSP_DEVINFO_DATA device, PSP_DEVINSTALL_PARAMS_W params)
{
    (void) set;
    (void) device;
    require((params->Flags & DI_QUIETINSTALL) != 0, "removal can show UI");
    return TRUE;
}
static BOOL WINAPI mockRemovalParams(HDEVINFO set, PSP_DEVINFO_DATA device, PSP_CLASSINSTALL_HEADER header, DWORD size)
{
    (void) set;
    (void) device;
    require(size == sizeof(SP_REMOVEDEVICE_PARAMS) && header->InstallFunction == DIF_REMOVE &&
                ((SP_REMOVEDEVICE_PARAMS *) header)->Scope == DI_REMOVEDEVICE_GLOBAL,
            "incorrect removal scope");
    return TRUE;
}
static BOOL WINAPI mockRemove(DI_FUNCTION operation, HDEVINFO set, PSP_DEVINFO_DATA device)
{
    (void) set;
    require(operation == DIF_REMOVE && device->DevInst == 1, "removed an unrelated network device");
    if (removal_wow64)
    {
        SetLastError(ERROR_IN_WOW64);
        return FALSE;
    }
    present[1] = false;
    ++removed;
    return TRUE;
}
static BOOL WINAPI mockDestroySet(HDEVINFO set)
{
    (void) set;
    return TRUE;
}

#define SetupDiGetClassDevsW              mockDevices
#define SetupDiEnumDeviceInfo             mockEnum
#define SetupDiGetDeviceRegistryPropertyW mockProperty
#define SetupDiGetDeviceInstallParamsW    mockGetParams
#define SetupDiSetDeviceInstallParamsW    mockSetParams
#define SetupDiSetClassInstallParamsW     mockRemovalParams
#define SetupDiCallClassInstaller         mockRemove
#define SetupDiDestroyDeviceInfoList      mockDestroySet
#include "../../../ww/devices/tun/tun_windows_ownership.c"

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--hold-lease") == 0)
    {
        Sleep(30000);
        return 0;
    }
    wchar_t name[128], tag[TUN_WINDOWS_OWNERSHIP_TAG_CAPACITY], other_tag[TUN_WINDOWS_OWNERSHIP_TAG_CAPACITY];
    swprintf(name, 128, L"WaterWall Lease Test %lu", GetCurrentProcessId());
    HANDLE lease = tunWindowsOwnershipAcquire(name, tag);
    require(lease != NULL, "could not acquire ownership");
    CharUpperBuffW(name, (DWORD) wcslen(name));
    require(tunWindowsOwnershipAcquire(name, other_tag) == NULL && wcscmp(tag, other_tag) == 0,
            "second owner or differently cased name bypassed ownership");
    wcscat(name, L" independent");
    HANDLE independent = tunWindowsOwnershipAcquire(name, other_tag);
    require(independent != NULL, "independent device was blocked");
    CloseHandle(independent);

    wcscpy(descriptions[0], L"Unrelated Wintun Tunnel");
    swprintf(descriptions[1], 128, L"%ls Tunnel", tag);
    wcscpy(descriptions[2], L"Unrelated physical interface");
    present[0] = present[1] = present[2] = true;
    require(tunWindowsOwnershipReconcile(tag) && removed == 1 && present[0] && present[2],
            "owned stale device was not reconciled independently of foreign devices");
    require(tunWindowsOwnershipReconcile(tag) && removed == 1, "reconciliation was not idempotent");
    wcscpy(descriptions[2], descriptions[1]);
    require(! tunWindowsOwnershipReconcile(tag) && present[2] && removed == 1,
            "matching description allowed removal of foreign hardware");
    wcscpy(descriptions[2], L"Unrelated physical interface");
    hardware[1] = L"";
    present[1]  = true;
    require(tunWindowsOwnershipReconcile(tag) && removed == 2,
            "interrupted Wintun stub creation prevented preparation");
    hardware[1] = NULL;
    present[1]  = true;
    require(tunWindowsOwnershipReconcile(tag) && removed == 3,
            "creation stub with absent hardware property prevented preparation");
    hardware[1]   = L"Wintun";
    present[1]    = true;
    removal_wow64 = true;
    require(! tunWindowsOwnershipReconcile(tag) && GetLastError() == ERROR_IN_WOW64 && present[1],
            "unsupported removal bitness became successful preparation");
    removal_wow64  = false;
    removal_reboot = true;
    require(! tunWindowsOwnershipReconcile(tag) && GetLastError() == ERROR_SUCCESS_REBOOT_REQUIRED,
            "Windows reboot requirement became successful preparation");
    removal_reboot = false;
    query_failure  = true;
    require(! tunWindowsOwnershipReconcile(tag) && GetLastError() == ERROR_ACCESS_DENIED,
            "device query failure became successful initialization");
    query_failure = false;

    wchar_t image[32768], command[32768];
    require(GetModuleFileNameW(NULL, image, 32768) != 0, "fixture executable path");
    swprintf(command, 32768, L"\"%ls\" --hold-lease", image);
    PROCESS_INFORMATION child;
    require(tunWindowsOwnershipStartHelper(lease, image, command, NULL, NULL, &child), "helper creation");
    CloseHandle(child.hThread);
    CloseHandle(lease);
    swprintf(name, 128, L"WaterWall Lease Test %lu", GetCurrentProcessId());
    require(tunWindowsOwnershipAcquire(name, other_tag) == NULL,
            "runtime handle close released ownership while its helper still ran");
    require(TerminateProcess(child.hProcess, 93) && WaitForSingleObject(child.hProcess, 5000) == WAIT_OBJECT_0,
            "helper termination");
    CloseHandle(child.hProcess);
    lease = tunWindowsOwnershipAcquire(name, other_tag);
    require(lease != NULL && wcscmp(tag, other_tag) == 0, "crashed helper left ownership permanently blocked");
    CloseHandle(lease);
    puts("TUN ownership fixture passed");
    return 0;
}
