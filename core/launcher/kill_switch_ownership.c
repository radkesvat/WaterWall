#include "kill_switch_ownership.h"
#include "lifecycle_capabilities_windows.h"
#include "session_windows.h"
#include <aclapi.h>
#include <assert.h>
#include <sddl.h>
#include <string.h>
#include <wchar.h>

#define OWNER_RECORD_MAGIC 0x57574b53UL

enum
{
    kOwnershipPollMs = 25,
    kCleanupLockMs   = 3000
};

typedef struct ownership_record_s
{
    DWORD                           magic;
    DWORD                           size;
    launcher_kill_switch_identity_t owner;
    launcher_kill_switch_identity_t successor;
    DWORD                           owner_effects_handle;
} ownership_record_t;

_Static_assert(sizeof(launcher_kill_switch_identity_t) == 180, "Windows kill switch identity must be portable");
_Static_assert(offsetof(ownership_record_t, owner_effects_handle) == 368 && sizeof(ownership_record_t) == 372,
               "Windows kill switch record must be portable");

typedef struct ownership_files_s
{
    wchar_t             path[32768];
    size_t              lease_length;
    SECURITY_ATTRIBUTES security;
    PSID                installer;
} ownership_files_t;

typedef struct verified_owner_s
{
    HANDLE process;
    HANDLE job;
    HANDLE stop;
    HANDLE effects;
} verified_owner_t;

static const wchar_t record_suffix[]  = L".owner";
static const wchar_t staging_suffix[] = L".owner.tmp";
static const wchar_t guard_suffix[]   = L".coord";

#ifdef WATERWALL_LAUNCHER_TEST_HOOKS
void launcherKillSwitchFixtureHandoff(bool stop_requested);
#endif

#ifndef WATERWALL_LAUNCHER_TEST_HOOKS
/* Common Files is a machine location. Request the native registry view so
 * 32-bit and 64-bit packed launchers open the same file from every logon. */
static bool trustedPrincipal(PSID sid, PSID installer)
{
    return IsWellKnownSid(sid, WinBuiltinAdministratorsSid) || IsWellKnownSid(sid, WinLocalSystemSid) ||
           (installer != NULL && EqualSid(sid, installer));
}

static DWORD verifyAccess(HANDLE handle, SE_OBJECT_TYPE type, DWORD forbidden, PSID installer)
{
    PSID                 owner      = NULL;
    PACL                 acl        = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD                error      = GetSecurityInfo(
        handle, type, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &acl, NULL, &descriptor);
    if (error != ERROR_SUCCESS)
        return error;
    if (owner == NULL || ! trustedPrincipal(owner, installer) || acl == NULL)
        error = ERROR_ACCESS_DENIED;
    for (DWORD i = 0; error == ERROR_SUCCESS && i < acl->AceCount; ++i)
    {
        ACE_HEADER *header;
        if (! GetAce(acl, i, (void **) &header))
            error = GetLastError();
        else if ((header->AceFlags & INHERIT_ONLY_ACE) == 0 && header->AceType != ACCESS_DENIED_ACE_TYPE)
        {
            /* Fail closed for unfamiliar effective ACE types. */
            ACCESS_ALLOWED_ACE *allow = (ACCESS_ALLOWED_ACE *) header;
            if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
                ((allow->Mask & forbidden) != 0 && ! trustedPrincipal(&allow->SidStart, installer)))
                error = ERROR_ACCESS_DENIED;
        }
    }
    LocalFree(descriptor);
    return error;
}

static DWORD verifyDirectory(const wchar_t *path, bool parent, PSID installer)
{
    HANDLE dir = CreateFileW(path,
                             READ_CONTROL | FILE_READ_ATTRIBUTES,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL,
                             OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                             NULL);
    if (dir == INVALID_HANDLE_VALUE)
        return GetLastError();
    BY_HANDLE_FILE_INFORMATION info;
    DWORD                      error = ERROR_SUCCESS;
    if (! GetFileInformationByHandle(dir, &info))
        error = GetLastError();
    else if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
             FILE_ATTRIBUTE_DIRECTORY)
        error = ERROR_ACCESS_DENIED;
    else
    {
        /* Some volume roots allow creating new subdirectories. Once the next
         * component exists, that grant alone cannot replace it. For the final
         * parent even creating a file or directory at the lock name is unsafe. */
        DWORD forbidden = DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL | FILE_DELETE_CHILD |
                          FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA;
        if (parent)
            forbidden |= FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY;
        error = verifyAccess(dir, SE_FILE_OBJECT, forbidden, installer);
    }
    CloseHandle(dir);
    return error;
}

static DWORD getLeasePath(wchar_t *path, DWORD capacity, PSID installer)
{
    HKEY  key;
    DWORD error = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                                0,
                                KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                                &key);
    if (error != ERROR_SUCCESS)
        return error;
    DWORD size = capacity * sizeof(*path);
    error      = RegGetValueW(key, NULL, L"CommonFilesDir", RRF_RT_REG_SZ, NULL, path, &size);
    RegCloseKey(key);
    if (error != ERROR_SUCCESS)
        return error;
    size_t        length   = wcslen(path);
    const wchar_t suffix[] = L"\\WaterWall-KillSwitch.lock";
    if (length < 4 || length + ARRAYSIZE(suffix) > capacity || path[1] != L':' || path[2] != L'\\')
        return ERROR_BAD_PATHNAME;
    wchar_t root[]       = {path[0], L':', L'\\', L'\0'};
    DWORD   volume_flags = 0;
    if (GetDriveTypeW(root) != DRIVE_FIXED ||
        ! GetVolumeInformationW(root, NULL, 0, NULL, NULL, &volume_flags, NULL, 0) ||
        (volume_flags & FILE_PERSISTENT_ACLS) == 0)
        return ERROR_ACCESS_DENIED;
    error = verifyDirectory(root, false, installer);
    for (size_t start = 3; start < length && error == ERROR_SUCCESS;)
    {
        size_t end = start;
        while (end < length && path[end] != L'\\')
            ++end;
        if (end == start || path[end - 1] == L'.' || path[end - 1] == L' ')
            return ERROR_BAD_PATHNAME;
        wchar_t saved = path[end];
        path[end]     = 0;
        error         = verifyDirectory(path, end == length, installer);
        path[end]     = saved;
        start         = end + 1;
    }
    if (path[length - 1] == L'\\')
        return ERROR_BAD_PATHNAME;
    if (error == ERROR_SUCCESS)
        memcpy(path + length, suffix, sizeof(suffix));
    return error;
}
#endif

PSECURITY_DESCRIPTOR launcherKillSwitchMachineSecurity(void)
{
#ifndef WATERWALL_LAUNCHER_TEST_HOOKS
    PSECURITY_DESCRIPTOR descriptor = NULL;
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &descriptor, NULL);
    return descriptor;
#else
    return waterwallLauncherPrivateSecurity();
#endif
}

static DWORD initFiles(ownership_files_t *files)
{
#ifndef WATERWALL_LAUNCHER_TEST_HOOKS
    /* NT SERVICE\TrustedInstaller is an owner of system directories. */
    if (! ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &files->installer))
        return GetLastError();
    DWORD error = getLeasePath(files->path, ARRAYSIZE(files->path), files->installer);
    if (error != ERROR_SUCCESS)
        return error;
#else
    /* The fixture uses its private directory and the same file-sharing rules. */
    DWORD size = GetEnvironmentVariableW(L"WW_FIXTURE_KILL_SWITCH_LEASE", files->path, ARRAYSIZE(files->path));
    if (size == 0 || size >= ARRAYSIZE(files->path))
        return ERROR_BAD_PATHNAME;
#endif
    files->lease_length = wcslen(files->path);
    if (files->lease_length + ARRAYSIZE(staging_suffix) > ARRAYSIZE(files->path))
        return ERROR_BAD_PATHNAME;
    files->security = (SECURITY_ATTRIBUTES) {sizeof(files->security), launcherKillSwitchMachineSecurity(), FALSE};
    if (files->security.lpSecurityDescriptor == NULL)
        return ERROR_ACCESS_DENIED;
    return ERROR_SUCCESS;
}

static void closeFiles(ownership_files_t *files)
{
    LocalFree(files->security.lpSecurityDescriptor);
    LocalFree(files->installer);
}

static DWORD openFile(ownership_files_t *files, const wchar_t *suffix, DWORD access, DWORD disposition, HANDLE *out)
{
    *out = NULL;
    wcscpy(files->path + files->lease_length, suffix);
    HANDLE file = CreateFileW(files->path,
                              access | READ_CONTROL,
                              0,
                              &files->security,
                              disposition,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                              NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        DWORD error = GetLastError();
        return error == ERROR_SHARING_VIOLATION ? ERROR_BUSY : error;
    }

    BY_HANDLE_FILE_INFORMATION info;
    DWORD                      error = ERROR_SUCCESS;
    if (! GetFileInformationByHandle(file, &info))
        error = GetLastError();
    else if (GetFileType(file) != FILE_TYPE_DISK || info.nNumberOfLinks != 1 ||
             (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
        error = ERROR_ACCESS_DENIED;
#ifndef WATERWALL_LAUNCHER_TEST_HOOKS
    else
        /* Even a read grant lets an untrusted caller hold the file busy. */
        error = verifyAccess(file, SE_FILE_OBJECT, MAXDWORD, files->installer);
#endif
    if (error == ERROR_SUCCESS)
        *out = file;
    else
        CloseHandle(file);
    return error;
}

static DWORD openLease(ownership_files_t *files, HANDLE *lease)
{
    return openFile(files, L"", GENERIC_READ, OPEN_ALWAYS, lease);
}

DWORD launcherKillSwitchAcquire(HANDLE *lease)
{
    *lease                  = NULL;
    ownership_files_t files = {0};
    DWORD             error = initFiles(&files);
    if (error == ERROR_SUCCESS)
        error = openLease(&files, lease);
    closeFiles(&files);
    return error;
}

static bool cancellationRequested(HANDLE stop)
{
    return launcherSessionStopRequested() || (stop != NULL && WaitForSingleObject(stop, 0) == WAIT_OBJECT_0);
}

static DWORD lockCoordination(ownership_files_t *files, ULONGLONG deadline, HANDLE stop, HANDLE *guard)
{
    for (;;)
    {
        if (stop != NULL && cancellationRequested(stop))
            return ERROR_CANCELLED;
        DWORD error = openFile(files, guard_suffix, GENERIC_READ, OPEN_ALWAYS, guard);
        if (error != ERROR_BUSY)
            return error;
        ULONGLONG now = GetTickCount64();
        if (now >= deadline)
            return ERROR_TIMEOUT;
        DWORD slice = deadline - now < kOwnershipPollMs ? (DWORD) (deadline - now) : kOwnershipPollMs;
        if (stop == NULL)
            Sleep(slice);
        else if (WaitForSingleObject(stop, slice) == WAIT_OBJECT_0)
            return ERROR_CANCELLED;
    }
}

static bool sameIdentity(const launcher_kill_switch_identity_t *a, const launcher_kill_switch_identity_t *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

static DWORD readRecord(ownership_files_t *files, ownership_record_t *record)
{
    *record = (ownership_record_t) {0};
    HANDLE file;
    DWORD  error = openFile(files, record_suffix, GENERIC_READ, OPEN_EXISTING, &file);
    if (error == ERROR_FILE_NOT_FOUND)
        return ERROR_SUCCESS;
    if (error != ERROR_SUCCESS)
        return error;

    LARGE_INTEGER size;
    DWORD         bytes;
    if (! GetFileSizeEx(file, &size))
        error = GetLastError();
    /* Records without an effects handle can still identify a reserved successor.
     * Their owner is authoritative only while the lease is held. */
    else if (size.QuadPart != sizeof(*record) && size.QuadPart != offsetof(ownership_record_t, owner_effects_handle))
        error = ERROR_INVALID_DATA;
    else if (! ReadFile(file, record, sizeof(*record), &bytes, NULL))
        error = GetLastError();
    else if (bytes != size.QuadPart || record->magic != OWNER_RECORD_MAGIC || record->size != bytes ||
             ! launcherSessionIdentityValid(&record->owner))
        error = ERROR_INVALID_DATA;
    else
    {
        const launcher_kill_switch_identity_t no_successor = {0};
        if (record->successor.pid != 0 ? (! launcherSessionIdentityValid(&record->successor) ||
                                          sameIdentity(&record->owner, &record->successor))
                                       : ! sameIdentity(&record->successor, &no_successor))
            error = ERROR_INVALID_DATA;
    }
    CloseHandle(file);
    return error;
}

static DWORD writeRecord(ownership_files_t *files, const ownership_record_t *record)
{
    HANDLE file;
    DWORD  error = openFile(files, staging_suffix, GENERIC_WRITE, OPEN_ALWAYS, &file);
    if (error != ERROR_SUCCESS)
        return error;

    DWORD bytes;
    if (! WriteFile(file, record, sizeof(*record), &bytes, NULL))
        error = GetLastError();
    else if (bytes != sizeof(*record))
        error = ERROR_WRITE_FAULT;
    else if (! SetEndOfFile(file) || ! FlushFileBuffers(file))
        error = GetLastError();
    CloseHandle(file);

    /* A crash while writing leaves the previous record intact. The guard and
     * protected directory let the next publisher safely reuse the staging path. */
    if (error == ERROR_SUCCESS)
    {
        wchar_t staging[ARRAYSIZE(files->path)];
        wcscpy(staging, files->path);
        wcscpy(files->path + files->lease_length, record_suffix);
        if (! MoveFileExW(staging, files->path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            error = GetLastError();
    }
    return error;
}

static DWORD removeRecord(ownership_files_t *files)
{
    wcscpy(files->path + files->lease_length, record_suffix);
    if (DeleteFileW(files->path))
        return ERROR_SUCCESS;
    DWORD error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : error;
}

/* A missing process or a reused PID proves the recorded process is gone.
 * An access failure does not. The returned handle pins the verified identity. */
static DWORD openRecordedProcess(const launcher_kill_switch_identity_t *identity, DWORD extra, HANDLE *process)
{
    *process = NULL;
    if (identity->pid == 0)
        return ERROR_SUCCESS;
    HANDLE handle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | extra, FALSE, identity->pid);
    if (handle == NULL)
    {
        DWORD error = GetLastError();
        return error == ERROR_INVALID_PARAMETER ? ERROR_SUCCESS : error;
    }
    DWORD    error = ERROR_SUCCESS;
    FILETIME created, ended, kernel, user;
    if (! GetProcessTimes(handle, &created, &ended, &kernel, &user))
        error = GetLastError();
    else if (CompareFileTime(&created, &identity->created) == 0)
    {
        DWORD wait = WaitForSingleObject(handle, 0);
        if (wait == WAIT_TIMEOUT)
        {
            *process = handle;
            return ERROR_SUCCESS;
        }
        if (wait != WAIT_OBJECT_0)
            error = wait == WAIT_FAILED ? GetLastError() : ERROR_INVALID_DATA;
    }
    CloseHandle(handle);
    return error;
}

static DWORD requireInactive(const launcher_kill_switch_identity_t *identity)
{
    HANDLE process;
    DWORD  error = openRecordedProcess(identity, 0, &process);
    if (process != NULL)
    {
        CloseHandle(process);
        return ERROR_BUSY;
    }
    return error;
}

static DWORD verifyOwner(const ownership_record_t *record, verified_owner_t *owner)
{
    const launcher_kill_switch_identity_t *identity = &record->owner;
    if (record->owner_effects_handle == 0)
        return ERROR_INVALID_OWNER;
    bool wine_fixture = false;
#ifdef WATERWALL_LAUNCHER_TEST_HOOKS
    /* Older Wine requires full process query rights for IsProcessInJob and
     * does not report the configured kill-on-close bit in its Job query. */
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    wine_fixture  = ntdll != NULL && GetProcAddress(ntdll, "wine_get_version") != NULL;
#endif
    DWORD process_access = PROCESS_DUP_HANDLE | (wine_fixture ? PROCESS_QUERY_INFORMATION : 0);
    DWORD error          = openRecordedProcess(identity, process_access, &owner->process);
    if (error != ERROR_SUCCESS || owner->process == NULL)
        return ERROR_INVALID_OWNER;

    HANDLE self = GetCurrentProcess();
    if (! DuplicateHandle(owner->process,
                          LongToHandle((LONG) identity->job_handle),
                          self,
                          &owner->job,
                          0,
                          FALSE,
                          DUPLICATE_SAME_ACCESS) ||
        ! DuplicateHandle(owner->process,
                          LongToHandle((LONG) identity->stop_handle),
                          self,
                          &owner->stop,
                          0,
                          FALSE,
                          DUPLICATE_SAME_ACCESS) ||
        ! DuplicateHandle(owner->process,
                          ULongToHandle(record->owner_effects_handle),
                          self,
                          &owner->effects,
                          FILE_MAP_READ,
                          FALSE,
                          0))
        return ERROR_INVALID_OWNER;

    DWORD                                required_limits = wine_fixture ? 0 : JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    BOOL                                 member;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    if (! waterwallCapabilityValidate(owner->job, L"Job", JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE | READ_CONTROL) ||
        ! waterwallCapabilityValidate(owner->stop, L"Event", SYNCHRONIZE | EVENT_MODIFY_STATE | READ_CONTROL) ||
        ! waterwallCapabilityValidate(owner->effects, L"Section", FILE_MAP_READ) ||
        ! IsProcessInJob(owner->process, owner->job, &member) || ! member ||
        ! QueryInformationJobObject(owner->job, JobObjectExtendedLimitInformation, &limits, sizeof(limits), NULL) ||
        (limits.BasicLimitInformation.LimitFlags &
         (required_limits | JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)) != required_limits)
        return ERROR_INVALID_OWNER;
    if (! launcherSessionJobNameMatches(owner->job, identity) ||
        ! launcherSessionStopNameMatches(owner->stop, identity))
        return ERROR_INVALID_OWNER;
#ifndef WATERWALL_LAUNCHER_TEST_HOOKS
    if (verifyAccess(owner->job, SE_KERNEL_OBJECT, MAXDWORD, NULL) != ERROR_SUCCESS ||
        verifyAccess(owner->stop, SE_KERNEL_OBJECT, MAXDWORD, NULL) != ERROR_SUCCESS)
        return ERROR_INVALID_OWNER;
#endif
    return ERROR_SUCCESS;
}

static void closeVerifiedOwner(verified_owner_t *owner)
{
    if (owner->effects != NULL)
        CloseHandle(owner->effects);
    if (owner->stop != NULL)
        CloseHandle(owner->stop);
    if (owner->job != NULL)
        CloseHandle(owner->job);
    if (owner->process != NULL)
        CloseHandle(owner->process);
}

static DWORD reserveAndSignal(ownership_files_t *files, const ownership_record_t *previous,
                              const launcher_kill_switch_identity_t *self, HANDLE stop, ULONGLONG startup_deadline,
                              const verified_owner_t *old, ULONGLONG *requested_at)
{
    if (cancellationRequested(stop))
        return ERROR_CANCELLED;
    if (GetTickCount64() >= startup_deadline)
        return ERROR_TIMEOUT;

    ownership_record_t pending = *previous;
    pending.successor          = *self;
    DWORD error                = writeRecord(files, &pending);
    if (error != ERROR_SUCCESS)
        return error;
#ifdef WATERWALL_LAUNCHER_TEST_HOOKS
    launcherKillSwitchFixtureHandoff(false);
#endif
    /* Old owner finalization and manual unlock cannot enter between the
     * reservation and stop. Restore the old record on a handled refusal. */
    if (cancellationRequested(stop))
        error = ERROR_CANCELLED;
    else if ((*requested_at = GetTickCount64()) >= startup_deadline)
        error = ERROR_TIMEOUT;
    else if (SetEvent(old->stop))
        return ERROR_SUCCESS;
    else
        error = GetLastError();

    DWORD restored = writeRecord(files, previous);
    return restored == ERROR_SUCCESS ? error : restored;
}

static DWORD claimHandoff(ownership_files_t *files, const launcher_kill_switch_identity_t *previous,
                          const ownership_record_t *current, ULONGLONG deadline, HANDLE *lease)
{
    HANDLE guard;
    DWORD  error = lockCoordination(files, deadline, NULL, &guard);
    if (error != ERROR_SUCCESS)
        return error;

    ownership_record_t pending;
    error = readRecord(files, &pending);
    if (error == ERROR_SUCCESS &&
        (! sameIdentity(&pending.owner, previous) || ! sameIdentity(&pending.successor, &current->owner)))
        error = ERROR_INVALID_OWNER;
    if (error == ERROR_SUCCESS)
        error = openLease(files, lease);
    if (error == ERROR_SUCCESS)
    {
        /* A failed write leaves our reservation intact. The lease now proves
         * settlement, so the caller can finish cleanup through that identity. */
        error = writeRecord(files, current);
    }
    CloseHandle(guard);
    return error;
}

static DWORD takeAfterHandoff(ownership_files_t *files, const launcher_kill_switch_identity_t *previous,
                              const ownership_record_t *current, const verified_owner_t *old, ULONGLONG requested_at,
                              HANDLE *lease)
{
    /* A stop sent during startup creates the same settlement obligation as recovery,
     * even if this incoming run is subsequently cancelled. */
    ULONGLONG deadline = requested_at + kLauncherSessionRecoveryMs;
    DWORD error = launcherSessionWaitForJob(old->job, old->process, requested_at + kLauncherSessionStopMs, deadline);
    if (error == ERROR_SUCCESS)
        error = launcherSessionWaitForOwnerAdapters(old->effects, previous, deadline);
    if (error != ERROR_SUCCESS)
        return error;

    for (;;)
    {
        error = claimHandoff(files, previous, current, deadline, lease);
        if (error != ERROR_BUSY || *lease != NULL)
            return error;
        ULONGLONG now = GetTickCount64();
        if (now >= deadline)
            return ERROR_TIMEOUT;
        Sleep(deadline - now < kOwnershipPollMs ? (DWORD) (deadline - now) : kOwnershipPollMs);
    }
}

static DWORD claimFreshRun(ownership_files_t *files, const ownership_record_t *current, HANDLE stop,
                           ULONGLONG startup_deadline)
{
    if (cancellationRequested(stop))
        return ERROR_CANCELLED;
    if (GetTickCount64() >= startup_deadline)
        return ERROR_TIMEOUT;

    /* Holding the lease excludes both the previous launcher and its runtime.
     * Its recorded PID may now belong to an inaccessible, unrelated process. */
    return writeRecord(files, current);
}

DWORD launcherKillSwitchTakeOwnership(HANDLE *lease, const launcher_kill_switch_identity_t *self, HANDLE effects,
                                      HANDLE stop, ULONGLONG startup_deadline)
{
    assert(launcherSessionIdentityValid(self));
    assert(effects != NULL);
    assert(stop != NULL);
    *lease                  = NULL;
    ownership_files_t files = {0};
    HANDLE            guard = NULL;
    DWORD             error = initFiles(&files);
    if (error == ERROR_SUCCESS)
        error = lockCoordination(&files, startup_deadline, stop, &guard);
    if (error != ERROR_SUCCESS)
    {
        closeFiles(&files);
        return error;
    }

    const ownership_record_t current = {.magic                = OWNER_RECORD_MAGIC,
                                        .size                 = sizeof(current),
                                        .owner                = *self,
                                        .owner_effects_handle = (DWORD) (uintptr_t) effects};
    ownership_record_t       previous;
    verified_owner_t         old          = {0};
    ULONGLONG                requested_at = 0;
    DWORD                    lease_error  = openLease(&files, lease);
    if (lease_error == ERROR_SUCCESS || lease_error == ERROR_BUSY)
    {
        error = readRecord(&files, &previous);
        if (error != ERROR_SUCCESS && lease_error == ERROR_BUSY)
            error = ERROR_INVALID_OWNER;
    }
    else
        error = lease_error;
    if (error == ERROR_SUCCESS)
        error = requireInactive(&previous.successor);
    if (error == ERROR_SUCCESS && *lease != NULL)
        error = claimFreshRun(&files, &current, stop, startup_deadline);
    if (error == ERROR_SUCCESS && *lease == NULL)
    {
        error = verifyOwner(&previous, &old);
        if (error == ERROR_SUCCESS)
            error = reserveAndSignal(&files, &previous, self, stop, startup_deadline, &old, &requested_at);
    }
    if (error != ERROR_SUCCESS && *lease != NULL)
    {
        CloseHandle(*lease);
        *lease = NULL;
    }
    bool requested = error == ERROR_SUCCESS && *lease == NULL;
    CloseHandle(guard);
    if (requested)
    {
#ifdef WATERWALL_LAUNCHER_TEST_HOOKS
        launcherKillSwitchFixtureHandoff(true);
#endif
        error = takeAfterHandoff(&files, &previous.owner, &current, &old, requested_at, lease);
        if (error == ERROR_SUCCESS && GetTickCount64() >= startup_deadline)
            error = ERROR_TIMEOUT;
    }
    closeVerifiedOwner(&old);
    closeFiles(&files);
    return error;
}

static DWORD cleanupDecision(ownership_files_t *files, const launcher_kill_switch_identity_t *self,
                             bool *remove_baseline)
{
    ownership_record_t record;
    DWORD              error = readRecord(files, &record);
    if (error != ERROR_SUCCESS)
        return error;
    /* A durable reservation transfers responsibility even if its successor
     * later dies. The next verified owner can reclaim an abandoned record. */
    if (sameIdentity(&record.owner, self))
        *remove_baseline = record.successor.pid == 0;
    else if (sameIdentity(&record.successor, self))
        *remove_baseline = true;
    else
        return ERROR_INVALID_OWNER;
    return ERROR_SUCCESS;
}

DWORD launcherKillSwitchBeginCleanup(HANDLE lease, const launcher_kill_switch_identity_t *self, HANDLE *coordination,
                                     bool *remove_baseline)
{
    assert(lease != NULL);
    (void) lease;
    *coordination = NULL;

    ownership_files_t files = {0};
    DWORD             error = initFiles(&files);
    if (error == ERROR_SUCCESS)
        error = lockCoordination(&files, GetTickCount64() + kCleanupLockMs, NULL, coordination);
    if (error == ERROR_SUCCESS)
        error = cleanupDecision(&files, self, remove_baseline);
    if (error != ERROR_SUCCESS && *coordination != NULL)
    {
        CloseHandle(*coordination);
        *coordination = NULL;
    }
    closeFiles(&files);
    return error;
}

DWORD launcherKillSwitchEndCleanup(HANDLE *lease, const launcher_kill_switch_identity_t *self, HANDLE coordination,
                                   bool removed)
{
    DWORD error = ERROR_SUCCESS;
    if (removed)
    {
        ownership_files_t files           = {0};
        bool              remove_baseline = false;
        error                             = initFiles(&files);
        if (error == ERROR_SUCCESS)
            error = cleanupDecision(&files, self, &remove_baseline);
        if (error == ERROR_SUCCESS && ! remove_baseline)
            error = ERROR_INVALID_OWNER;
        if (error == ERROR_SUCCESS)
        {
            error = removeRecord(&files);
            /* The baseline is gone even if record deletion failed. A stale
             * record must not direct a subsequent launch into a live handoff. */
            CloseHandle(*lease);
            *lease = NULL;
        }
        closeFiles(&files);
    }
    CloseHandle(coordination);
    return error;
}

static DWORD checkUnlockRecord(ownership_files_t *files)
{
    ownership_record_t record;
    DWORD              error = readRecord(files, &record);
    if (error == ERROR_SUCCESS)
        error = requireInactive(&record.successor);
    return error;
}

DWORD launcherKillSwitchBeginUnlock(HANDLE *coordination, HANDLE *lease)
{
    *coordination           = NULL;
    *lease                  = NULL;
    ownership_files_t files = {0};
    DWORD             error = initFiles(&files);
    if (error == ERROR_SUCCESS)
        error = lockCoordination(&files, GetTickCount64() + kCleanupLockMs, NULL, coordination);
    if (error == ERROR_SUCCESS)
        error = openLease(&files, lease);
    if (error == ERROR_SUCCESS)
        error = checkUnlockRecord(&files);
    if (error != ERROR_SUCCESS)
    {
        if (*lease != NULL)
            CloseHandle(*lease);
        if (*coordination != NULL)
            CloseHandle(*coordination);
        *coordination = NULL;
        *lease        = NULL;
    }
    closeFiles(&files);
    return error;
}

DWORD launcherKillSwitchEndUnlock(HANDLE coordination, HANDLE lease, bool removed)
{
    DWORD error = ERROR_SUCCESS;
    if (removed)
    {
        ownership_files_t files = {0};
        error                   = initFiles(&files);
        if (error == ERROR_SUCCESS)
            error = checkUnlockRecord(&files);
        if (error == ERROR_SUCCESS)
            error = removeRecord(&files);
        closeFiles(&files);
    }
    CloseHandle(lease);
    CloseHandle(coordination);
    return error;
}
