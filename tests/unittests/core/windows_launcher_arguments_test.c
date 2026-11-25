/*
 * Covers: The actual Windows launcher backend's CRT quoting, PE identification and temporary-directory
 * pinning.
 * Setup: Compiles the backend into the fixture with inert packed bytes and uses real Win32
 * parsing/filesystem handles.
 * Cases: Empty/spaced/quoted/backslash arguments, PE identity and machine checks, directory write/delete
 * sharing denial, protected-run lease retained by a child, unverifiable owners, stale owner PID reuse,
 * physical IPv4 default-route selection.
 * Checks: CommandLineToArgvW recovers the original arguments, PE checks retain their expected verdicts
 * and directory handles/paths are settled. A reused PID or wrong Job cannot authorize stop or unlock.
 * Limits: Requires Windows shell/filesystem APIs; it does not start a packed application or qualify
 * UAC/ACL/antivirus deployment.
 * CTest: waterwall.windows_launcher_arguments_unit
 */
/* Exercise the actual backend's quoting, PE identification, and directory pins. */
#include "../../../core/launcher/launcher_windows.c"
#include <shellapi.h>

const unsigned char waterwallPackedBytes[] = {0};
const size_t        waterwallPackedLength  = 1;
const uint64_t      waterwallRuntimeLength = 1;
#ifdef _WIN64
const char waterwallPackedTarget[] = "windows-x86_64";
#else
const char waterwallPackedTarget[] = "windows-x86";
#endif

/* Supply routing and interface rows to the launcher's normal uplink selection.
 * Ethernet owns a host route to 8.8.8.8. Only the default routes compete. */
static const struct
{
    NET_IFINDEX index;
    UCHAR       prefix;
    ULONG       metric;
} uplink_routes[] = {{1, 32, 0}, {2, 0, 1}, {3, 0, 10}, {4, 0, 0}, {5, 0, 0}};
static ULONG uplink_route_count;

static DWORD fixtureGetIpForwardTable2(ADDRESS_FAMILY family, MIB_IPFORWARD_TABLE2 **routes)
{
    if (family != AF_INET)
        return ERROR_INVALID_PARAMETER;
    *routes = calloc(1, offsetof(MIB_IPFORWARD_TABLE2, Table) + uplink_route_count * sizeof(MIB_IPFORWARD_ROW2));
    if (*routes == NULL)
        return ERROR_OUTOFMEMORY;
    (*routes)->NumEntries = uplink_route_count;
    for (ULONG i = 0; i < uplink_route_count; ++i)
    {
        MIB_IPFORWARD_ROW2 *route  = &(*routes)->Table[i];
        route->InterfaceLuid.Value = route->InterfaceIndex = uplink_routes[i].index;
        route->DestinationPrefix.Prefix.Ipv4.sin_family    = AF_INET;
        route->DestinationPrefix.PrefixLength              = uplink_routes[i].prefix;
        if (route->DestinationPrefix.PrefixLength == 32)
            route->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = UINT32_C(0x08080808);
        route->Metric        = uplink_routes[i].metric;
        route->ValidLifetime = UINT32_MAX;
    }
    return NO_ERROR;
}

static DWORD fixtureGetIfEntry2(MIB_IF_ROW2 *row)
{
    row->InterfaceIndex                                = (NET_IFINDEX) row->InterfaceLuid.Value;
    row->OperStatus                                    = IfOperStatusUp;
    row->InterfaceAndOperStatusFlags.HardwareInterface = row->InterfaceIndex != 4;
    return NO_ERROR;
}

static DWORD fixtureGetIpInterfaceEntry(MIB_IPINTERFACE_ROW *ip)
{
    ip->Connected            = TRUE;
    ip->Metric               = ip->InterfaceLuid.Value == 2 ? 50 : 0;
    ip->DisableDefaultRoutes = ip->InterfaceLuid.Value == 5;
    return NO_ERROR;
}

#define GetIpForwardTable2  fixtureGetIpForwardTable2
#define GetIfEntry2         fixtureGetIfEntry2
#define GetIpInterfaceEntry fixtureGetIpInterfaceEntry
#define FreeMibTable        free
#include "../../../ww/devices/tun/tun_windows_route.h"
#undef FreeMibTable
#undef GetIpInterfaceEntry
#undef GetIfEntry2
#undef GetIpForwardTable2

static bool checkPhysicalUplink(void)
{
    ww_kill_switch_message_t uplink;
    uplink_route_count = ARRAYSIZE(uplink_routes);
    if (! wwWindowsKillSwitchGetUplink(&uplink) || uplink.index != 3 || uplink.luid != 3)
        return false;
    uplink_route_count = 1;
    return ! wwWindowsKillSwitchGetUplink(&uplink);
}

static int checkDirectoryLocks(void)
{
    wchar_t temporary[32768], directory[32768], canonical[32768];
    DWORD   length = GetTempPathW(32768, temporary);
    if (length == 0 || length > 32700 ||
        swprintf(directory,
                 32768,
                 L"%lsWaterwall-pin-%lu-%llu",
                 temporary,
                 GetCurrentProcessId(),
                 (unsigned long long) GetTickCount64()) < 0 ||
        ! CreateDirectoryW(directory, NULL))
        return 0;
    HANDLE  root     = CreateFileW(directory,
                              FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL,
                              OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                              NULL);
    HANDLE *locks    = NULL;
    size_t  count    = 0;
    int     pinned   = root != INVALID_HANDLE_VALUE && pinTemporaryRoot(root, canonical, &locks, &count);
    HANDLE  deletion = INVALID_HANDLE_VALUE, writing = INVALID_HANDLE_VALUE;
    DWORD   delete_error = 0, write_error = 0;
    if (pinned)
    {
        deletion     = CreateFileW(directory,
                               DELETE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS,
                               NULL);
        delete_error = GetLastError();
        writing      = CreateFileW(directory,
                              FILE_WRITE_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL,
                              OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS,
                              NULL);
        write_error  = GetLastError();
    }
    if (deletion != INVALID_HANDLE_VALUE)
        CloseHandle(deletion);
    if (writing != INVALID_HANDLE_VALUE)
        CloseHandle(writing);
    while (count != 0)
        CloseHandle(locks[--count]);
    free(locks);
    if (root != INVALID_HANDLE_VALUE)
        CloseHandle(root);
    int removed = RemoveDirectoryW(directory);
    int passed  = pinned && removed && deletion == INVALID_HANDLE_VALUE && delete_error == ERROR_SHARING_VIOLATION &&
                 writing == INVALID_HANDLE_VALUE && write_error == ERROR_SHARING_VIOLATION;
    if (! passed)
        fprintf(stderr,
                "directory pin: pinned=%d removed=%d delete error=%lu write error=%lu\n",
                pinned,
                removed,
                delete_error,
                write_error);
    return passed;
}

/* Keep a real suspended child as the sole holder, as can happen when a
 * recovery process holds the Job after the public launcher has died. */
static bool checkRunOwnership(void)
{
    wchar_t temporary[MAX_PATH], path[MAX_PATH], image[MAX_PATH];
    DWORD   length = GetTempPathW(ARRAYSIZE(temporary), temporary);
    if (length == 0 || length >= ARRAYSIZE(temporary) || ! GetTempFileNameW(temporary, L"wks", 0, path))
        return false;

    HANDLE              lease = NULL, inheritable = NULL, competing = NULL;
    HANDLE              self    = GetCurrentProcess();
    PROCESS_INFORMATION child   = {0};
    STARTUPINFOW        startup = {.cb = sizeof(startup)};
    bool                pass    = SetEnvironmentVariableW(L"WW_FIXTURE_KILL_SWITCH_LEASE", path) &&
                launcherKillSwitchAcquire(&lease) == ERROR_SUCCESS &&
                DuplicateHandle(self, lease, self, &inheritable, SYNCHRONIZE, TRUE, 0) &&
                GetModuleFileNameW(NULL, image, ARRAYSIZE(image)) > 0 &&
                CreateProcessW(image, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &startup, &child) &&
                retainChildOwnership(child.hProcess, inheritable);
    if (inheritable != NULL)
        CloseHandle(inheritable);
    if (lease != NULL)
        CloseHandle(lease);
    if (pass)
        pass = launcherKillSwitchAcquire(&competing) == ERROR_BUSY && competing == NULL;
    if (child.hProcess != NULL)
    {
        bool settled =
            TerminateProcess(child.hProcess, 0) && WaitForSingleObject(child.hProcess, 5000) == WAIT_OBJECT_0;
        CloseHandle(child.hThread);
        CloseHandle(child.hProcess);
        pass = pass && settled;
    }
    if (pass)
        pass = launcherKillSwitchAcquire(&competing) == ERROR_SUCCESS;
    if (competing != NULL)
        CloseHandle(competing);
    SetEnvironmentVariableW(L"WW_FIXTURE_KILL_SWITCH_LEASE", NULL);
    return DeleteFileW(path) && pass;
}

typedef struct fixture_owner_record_s
{
    DWORD                           magic, size;
    launcher_kill_switch_identity_t owner, successor;
    DWORD                           owner_effects_handle;
} fixture_owner_record_t;

static bool writeOwnerFixture(const wchar_t *path, const fixture_owner_record_t *record)
{
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    DWORD written;
    bool  pass = WriteFile(file, record, record->size, &written, NULL) && written == record->size;
    CloseHandle(file);
    return pass;
}

/* Leave a stale record at a PID whose new process denies lookup. Retain its
 * creation handle so the fixture alone can settle the suspended child. */
static bool checkStaleOwner(const wchar_t *owner_path, fixture_owner_record_t record, HANDLE stop, HANDLE effects)
{
    wchar_t             image[MAX_PATH];
    PROCESS_INFORMATION child   = {0};
    STARTUPINFOW        startup = {.cb = sizeof(startup)};
    if (GetModuleFileNameW(NULL, image, ARRAYSIZE(image)) == 0 ||
        ! CreateProcessW(image, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup, &child))
        return false;
    SECURITY_DESCRIPTOR descriptor;
    ACL                 empty;
    bool                pass = InitializeAcl(&empty, sizeof(empty), ACL_REVISION) &&
                InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) &&
                SetSecurityDescriptorDacl(&descriptor, TRUE, &empty, FALSE) &&
                SetKernelObjectSecurity(child.hProcess, DACL_SECURITY_INFORMATION, &descriptor);
    const launcher_kill_switch_identity_t self = record.owner;
    record.owner.pid                           = child.dwProcessId;
    /* A free lease grants recovery authority even for a record written
     * without an effects mapping. Keep checking live successor reservations. */
    HANDLE lease = NULL, guard = NULL;
    record.size      = offsetof(fixture_owner_record_t, owner_effects_handle);
    record.successor = self;
    pass =
        pass && writeOwnerFixture(owner_path, &record) && launcherKillSwitchBeginUnlock(&guard, &lease) == ERROR_BUSY;
    if (guard != NULL)
    {
        launcherKillSwitchEndUnlock(guard, lease, false);
        guard = lease = NULL;
    }
    record.successor = (launcher_kill_switch_identity_t) {0};
    pass             = pass && writeOwnerFixture(owner_path, &record) &&
           launcherKillSwitchBeginUnlock(&guard, &lease) == ERROR_SUCCESS;
    if (guard != NULL)
        pass = launcherKillSwitchEndUnlock(guard, lease, true) == ERROR_SUCCESS && pass;
    lease       = NULL;
    record.size = sizeof(record);
    pass        = pass && writeOwnerFixture(owner_path, &record) &&
           launcherKillSwitchTakeOwnership(&lease, &self, effects, stop, GetTickCount64() + 1000) == ERROR_SUCCESS &&
           WaitForSingleObject(child.hProcess, 0) == WAIT_TIMEOUT && WaitForSingleObject(stop, 0) == WAIT_TIMEOUT;
    if (lease != NULL)
        CloseHandle(lease);
    bool settled = TerminateProcess(child.hProcess, 0) && WaitForSingleObject(child.hProcess, 5000) == WAIT_OBJECT_0;
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return pass && settled;
}

static bool checkUnverifiedOwner(void)
{
    wchar_t temporary[MAX_PATH], path[MAX_PATH], owner_path[MAX_PATH + 8], guard_path[MAX_PATH + 8];
    DWORD   length = GetTempPathW(ARRAYSIZE(temporary), temporary);
    if (length == 0 || length >= ARRAYSIZE(temporary) || ! GetTempFileNameW(temporary, L"wks", 0, path))
        return false;
    swprintf(owner_path, ARRAYSIZE(owner_path), L"%ls.owner", path);
    swprintf(guard_path, ARRAYSIZE(guard_path), L"%ls.coord", path);

    launcher_kill_switch_identity_t identity = {.pid = GetCurrentProcessId()};
    swprintf(identity.job_name,
             ARRAYSIZE(identity.job_name),
             L"Local\\Waterwall.Session.%08lx%016llx%08lx",
             identity.pid,
             (unsigned long long) GetTickCount64(),
             GetCurrentThreadId());
    wchar_t stop_name[96];
    launcherSessionStopName(identity.job_name, stop_name);
    HANDLE stop    = CreateEventW(NULL, TRUE, FALSE, stop_name);
    HANDLE job     = CreateJobObjectW(NULL, identity.job_name);
    HANDLE effects = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, NULL);
    HANDLE lease = NULL, incoming = NULL;
    identity.stop_handle = (DWORD) (uintptr_t) stop;
    identity.job_handle  = (DWORD) (uintptr_t) job;
    FILETIME                             exited, kernel, user;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags     = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    bool pass                                   = stop != NULL && job != NULL && effects != NULL &&
                SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) &&
                GetProcessTimes(GetCurrentProcess(), &identity.created, &exited, &kernel, &user) &&
                launcherSessionIdentityValid(&identity) &&
                SetEnvironmentVariableW(L"WW_FIXTURE_KILL_SWITCH_LEASE", path) &&
                launcherKillSwitchAcquire(&lease) == ERROR_SUCCESS;

    fixture_owner_record_t record = {.magic                = 0x57574b53UL,
                                     .size                 = sizeof(record),
                                     .owner                = identity,
                                     .owner_effects_handle = (DWORD) (uintptr_t) effects};
    if (pass)
        pass = launcherKillSwitchTakeOwnership(&incoming, &identity, effects, stop, GetTickCount64() + 1000) ==
                   ERROR_INVALID_OWNER &&
               incoming == NULL;
    for (int i = 0; pass && i < 2; ++i)
    {
        /* First emulate a reused PID. Then use the exact creation time but a
         * Job the recorded process never joined. The stop event belongs to us. */
        record.owner.created.dwLowDateTime = identity.created.dwLowDateTime ^ (i == 0 ? 1 : 0);
        pass                               = writeOwnerFixture(owner_path, &record) &&
               launcherKillSwitchTakeOwnership(&incoming, &identity, effects, stop, GetTickCount64() + 1000) ==
                   ERROR_INVALID_OWNER &&
               incoming == NULL && WaitForSingleObject(stop, 0) == WAIT_TIMEOUT;
    }
    if (incoming != NULL)
        CloseHandle(incoming);
    if (lease != NULL)
        CloseHandle(lease);
    if (pass)
        pass = checkStaleOwner(owner_path, record, stop, effects);
    if (effects != NULL)
        CloseHandle(effects);
    if (job != NULL)
        CloseHandle(job);
    if (stop != NULL)
        CloseHandle(stop);
    SetEnvironmentVariableW(L"WW_FIXTURE_KILL_SWITCH_LEASE", NULL);
    DeleteFileW(owner_path);
    DeleteFileW(guard_path);
    return DeleteFileW(path) && pass;
}

int main(void)
{
    const wchar_t *arguments[] = {L"fixture with spaces\\",
                                  L"",
                                  L"plain",
                                  L"with spaces",
                                  L"\"quote\"",
                                  L"trailing\\",
                                  L"back\\\\\"quote",
                                  L"\\",
                                  L"\u00e9"};
    wchar_t        command[32768];
    size_t         used = 0;
    for (size_t i = 0; i < sizeof(arguments) / sizeof(arguments[0]); ++i)
        if (! appendArgument(command, &used, arguments[i]))
            return 1;
    int       argc = 0;
    wchar_t **argv = CommandLineToArgvW(command, &argc);
    if (argv == NULL || argc != sizeof(arguments) / sizeof(arguments[0]))
        return 2;
    for (int i = 0; i < argc; ++i)
        if (wcscmp(argv[i], arguments[i]) != 0)
            return 3;
    LocalFree(argv);
    used           = 32766;
    command[32767] = L'X';
    if (appendArgument(command, &used, L"x") || command[32767] != L'X')
        return 4;
    unsigned char    tiny[512] = {0};
    IMAGE_DOS_HEADER dos       = {0};
    dos.e_magic                = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew               = 64;
    memcpy(tiny, &dos, sizeof(dos));
    for (size_t length = 0; length < sizeof(tiny); ++length)
        if (validImage(tiny, length))
            return 5;
    /* Ordinary characters need no escaping: the complete quoted argument fits
     * exactly within CreateProcessW's 32767-character limit including NUL. */
    wchar_t long_argument[32765];
    for (size_t i = 0; i < 32764; ++i)
        long_argument[i] = L'a';
    long_argument[32764] = 0;
    used                 = 0;
    if (! appendArgument(command, &used, long_argument) || used != 32766 || command[used] != 0)
        return 6;
    if (appendArgument(command, &used, L""))
        return 7;
    /* A trailing backslash needs doubling and no longer fits. */
    long_argument[32762] = 0;
    long_argument[32761] = L'\\';
    command[0]           = L'x';
    used                 = 1;
    if (appendArgument(command, &used, long_argument) || used != 1)
        return 8;
    if (! checkDirectoryLocks())
        return 9;
    if (! checkRunOwnership())
        return 10;
    if (! checkPhysicalUplink())
        return 11;
    if (! checkUnverifiedOwner())
        return 12;
    puts("Windows launcher arguments, directory pins, protected run ownership and physical uplink selection passed");
    return 0;
}
