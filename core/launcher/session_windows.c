#include "session_windows.h"
#include "../../ww/devices/windows_session_effects.h"
#include "lazy_loader.h"
#include "lifecycle_capabilities_windows.h"
#include <aclapi.h>
#include <fcntl.h>
#include <io.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static lazy_dll_t lazy_kernel32 = {transf_kernel32, sizeof(transf_kernel32), NULL};
static lazy_dll_t lazy_advapi32 = {transf_advapi32, sizeof(transf_advapi32), NULL};

LAZY_WRAPPER(HANDLE, NULL, lazy_kernel32, CreateJobObjectW, (LPSECURITY_ATTRIBUTES lpJobAttributes, LPCWSTR lpName),
             (lpJobAttributes, lpName))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, AssignProcessToJobObject, (HANDLE hJob, HANDLE hProcess), (hJob, hProcess))
LAZY_WRAPPER(HANDLE, NULL, lazy_kernel32, CreateFileMappingW,
             (HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh,
              DWORD dwMaximumSizeLow, LPCWSTR lpName),
             (hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName))
LAZY_WRAPPER(LPVOID, NULL, lazy_kernel32, MapViewOfFile,
             (HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow,
              SIZE_T dwNumberOfBytesToMap),
             (hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, UnmapViewOfFile, (LPCVOID lpBaseAddress), (lpBaseAddress))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, TerminateProcess, (HANDLE hProcess, UINT uExitCode), (hProcess, uExitCode))
LAZY_WRAPPER(HANDLE, NULL, lazy_kernel32, OpenProcess, (DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId),
             (dwDesiredAccess, bInheritHandle, dwProcessId))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, ReadProcessMemory,
             (HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead),
             (hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead))
LAZY_WRAPPER(BOOLEAN, FALSE, lazy_advapi32, SystemFunction036, (PVOID RandomBuffer, ULONG RandomBufferLength),
             (RandomBuffer, RandomBufferLength))

#define CreateJobObjectW         lazy_CreateJobObjectW
#define AssignProcessToJobObject lazy_AssignProcessToJobObject
#define CreateFileMappingW       lazy_CreateFileMappingW
#define MapViewOfFile            lazy_MapViewOfFile
#define UnmapViewOfFile          lazy_UnmapViewOfFile
#define TerminateProcess         lazy_TerminateProcess
#define OpenProcess              lazy_OpenProcess
#define ReadProcessMemory        lazy_ReadProcessMemory
#define SystemFunction036        lazy_SystemFunction036

/* An existing record is never reused. The containing directory must be protected
 * by the client throughout launch/recovery. All dynamic fields use Interlocked
 * publication; no stdio, file I/O, or runtime lock is used by the deadline thread. */
#define SESSION_MAGIC UINT64_C(0x575753455353494f)
enum
{
    kStartupMs = 60000,
    kPollMs    = 25
};
enum
{
    kReasonNone,
    kReasonStop,
    kReasonController,
    kReasonStartup,
    kReasonRuntime,
    kReasonDeadline,
    kReasonForced
};
typedef struct session_record_s
{
    windows_session_effects_t effects;
    uint64_t                  magic;
    DWORD                     size;
    DWORD                     pid;
    FILETIME                  created;
    wchar_t                   job_name[80];
    volatile LONG             reason;
    volatile LONG             started;
    volatile LONG             ready;
    volatile LONG             runtime_status;
    volatile LONG             runtime_status_known;
    volatile LONG             orderly;
    volatile LONG             residue;
    volatile LONG             members_settled;
    volatile LONG             final;
} session_record_t;

static session_record_t  local_record;
static session_record_t *record = &local_record;
static session_record_t *persisted;
static void *volatile published_record;
static HANDLE    session_job, stop_event, ready_event, completion_event;
static HANDLE    supplied_stop, supplied_ready, controller;
static HANDLE    record_file = INVALID_HANDLE_VALUE, record_mapping;
static ULONGLONG started_at;
static _Alignas(8) volatile LONG64 stop_deadline;
static volatile LONG finished;
static bool          session_started;
static bool          closed_streams[3];
static bool          members_checked;

static LONG readField(volatile LONG *field)
{
    return InterlockedCompareExchange(field, 0, 0);
}
static void setReason(LONG reason)
{
    InterlockedCompareExchange(&record->reason, reason, kReasonNone);
    session_record_t *shared = InterlockedCompareExchangePointer(&published_record, NULL, NULL);
    if (shared != NULL)
        InterlockedCompareExchange(&shared->reason, readField(&record->reason), kReasonNone);
}

static void forceExit(void)
{
    /* Self termination closes our sole Job handle even with a hung loader/CRT.
     * Recovery may hold another handle, and owns bounded termination in that case. */
    TerminateProcess(GetCurrentProcess(), 0xe0570001U);
}

void launcherSessionCancel(void)
{
    /* Handles live for the entire process, including console-handler entrants. */
    if (stop_event != NULL)
        SetEvent(stop_event);
}

bool launcherSessionStopRequested(void)
{
    if (stop_event == NULL)
        return false;
    if (controller != NULL && WaitForSingleObject(controller, 0) == WAIT_OBJECT_0)
    {
        setReason(kReasonController);
        launcherSessionCancel();
    }
    if (supplied_stop != NULL && WaitForSingleObject(supplied_stop, 0) == WAIT_OBJECT_0)
    {
        setReason(kReasonStop);
        launcherSessionCancel();
    }
    return WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0;
}

void launcherSessionProtectionFailed(void)
{
    setReason(WaitForSingleObject(ready_event, 0) == WAIT_OBJECT_0 ? kReasonRuntime : kReasonStartup);
    launcherSessionCancel();
}

static ULONGLONG startStopDeadline(ULONGLONG now)
{
    LONG64 deadline = (LONG64) (now + kLauncherSessionStopMs);
    LONG64 previous = InterlockedCompareExchange64(&stop_deadline, deadline, 0);
    return previous == 0 ? (ULONGLONG) deadline : (ULONGLONG) previous;
}

void launcherSessionSettleChild(void)
{
    startStopDeadline(GetTickCount64());
}

ULONGLONG launcherSessionSettlementDeadline(void)
{
    /* Leave one observer poll to report a timeout before the hard stop. */
    return startStopDeadline(GetTickCount64()) - kPollMs;
}

static BOOL WINAPI sessionConsoleHandler(DWORD event)
{
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT && event != CTRL_CLOSE_EVENT && event != CTRL_LOGOFF_EVENT &&
        event != CTRL_SHUTDOWN_EVENT)
        return FALSE;
    launcherSessionCancel();
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT)
    {
        /* Returning from a close handler lets Windows terminate the process.
         * Wait for the main thread to finish cleanup or Windows to enforce its deadline. */
        WaitForSingleObject(GetCurrentProcess(), INFINITE);
    }
    return TRUE;
}

static DWORD WINAPI deadlineMain(void *unused)
{
    (void) unused;
    bool published = false;
    for (;;)
    {
        ULONGLONG now = GetTickCount64();

        bool stopped = WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0;
        if (controller != NULL && WaitForSingleObject(controller, 0) == WAIT_OBJECT_0)
        {
            setReason(kReasonController);
            stopped = true;
        }
        if (supplied_stop != NULL && WaitForSingleObject(supplied_stop, 0) == WAIT_OBJECT_0)
        {
            setReason(kReasonStop);
            stopped = true;
        }
        if (stopped)
        {
            setReason(kReasonStop);
            SetEvent(stop_event);
        }
        if (! published && ! stopped && WaitForSingleObject(ready_event, 0) == WAIT_OBJECT_0)
        {
            InterlockedExchange(&record->ready, 1);
            published = true;
            if (supplied_ready != NULL && ! SetEvent(supplied_ready))
            {
                setReason(kReasonRuntime);
                stopped = true;
                SetEvent(stop_event);
            }
        }
        if (! published && now - started_at >= kStartupMs)
        {
            setReason(kReasonDeadline);
            stopped = true;
            SetEvent(stop_event);
        }
        ULONGLONG deadline =
            stopped ? startStopDeadline(now) : (ULONGLONG) InterlockedCompareExchange64(&stop_deadline, 0, 0);
        if (deadline != 0 && now >= deadline)
            forceExit();
        Sleep(kPollMs);
    }
}

static bool takeCapability(uintptr_t supplied, HANDLE *owned, const wchar_t *type, ACCESS_MASK access)
{
    if (supplied == 0)
        return true;
    HANDLE handle = (HANDLE) supplied;
    if (! waterwallCapabilityValidate(handle, type, access))
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }
    bool ok = DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), owned, access, FALSE, 0) != FALSE;
    CloseHandle(handle);
    return ok;
}

static void normalReturn(void)
{
    if (session_started && ! readField(&finished))
        launcherSessionFinish(1, false);
}

void launcherSessionStopName(const wchar_t *job_name, wchar_t stop_name[96])
{
    wchar_t format[16];
    lazyLoadWideString(transf_session_stop_format, sizeof(transf_session_stop_format), format, ARRAYSIZE(format));
    swprintf(stop_name, 96, format, job_name);
    SecureZeroMemory(format, sizeof(format));
}

bool launcherSessionStart(waterwall_startup_options_t *options)
{
    /* Resolve before observer admission: deadline termination must not enter the loader. */
    if (lazyProcAddress(&lazy_proc_TerminateProcess) == NULL)
    {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return false;
    }
    if (! takeCapability(options->stop_event, &supplied_stop, L"Event", SYNCHRONIZE) ||
        ! takeCapability(options->ready_event, &supplied_ready, L"Event", EVENT_MODIFY_STATE) ||
        ! takeCapability(options->controller_process, &controller, L"Process", SYNCHRONIZE))
        return false;
    /* No descendants exist before self-admission. Job inheritance closes the
     * create-to-assign interval, including on Windows 7. No breakaway flags. */
    PSECURITY_DESCRIPTOR security = waterwallLauncherPrivateSecurity();
    if (security == NULL)
        return false;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), security, FALSE};
    unsigned char       random[16];
    if (! SystemFunction036(random, sizeof(random)))
    {
        LocalFree(security);
        return false;
    }
    wchar_t job_prefix[40];
    lazyLoadWideString(
        transf_session_job_prefix, sizeof(transf_session_job_prefix), job_prefix, sizeof(job_prefix) / sizeof(wchar_t));
    wcscpy(local_record.job_name, job_prefix);
    size_t prefix = wcslen(job_prefix);
    SecureZeroMemory(job_prefix, sizeof(job_prefix));
    for (size_t i = 0; i < sizeof(random); ++i)
        swprintf(local_record.job_name + prefix + i * 2, 3, L"%02x", random[i]);
    session_job = CreateJobObjectW(&sa, local_record.job_name);
    if (session_job == NULL || GetLastError() == ERROR_ALREADY_EXISTS)
    {
        LocalFree(security);
        return false;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags     = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (! SetInformationJobObject(session_job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
        ! AssignProcessToJobObject(session_job, GetCurrentProcess()))
    {
        LocalFree(security);
        return false;
    }
    wchar_t stop_name[96];
    launcherSessionStopName(local_record.job_name, stop_name);
    stop_event       = CreateEventW(&sa, TRUE, FALSE, stop_name);
    if (stop_event == NULL || GetLastError() == ERROR_ALREADY_EXISTS)
    {
        LocalFree(security);
        return false;
    }
    ready_event      = CreateEventW(&sa, TRUE, FALSE, NULL);
    completion_event = CreateEventW(&sa, TRUE, FALSE, NULL);
    if (stop_event == NULL || ready_event == NULL || completion_event == NULL)
    {
        LocalFree(security);
        return false;
    }
    FILETIME exit_time, kernel, user;
    if (! GetProcessTimes(GetCurrentProcess(), &local_record.created, &exit_time, &kernel, &user))
    {
        LocalFree(security);
        return false;
    }
    local_record.effects.magic = WW_SESSION_EFFECT_MAGIC;
    local_record.magic         = SESSION_MAGIC;
    local_record.size          = sizeof(local_record);
    local_record.pid           = GetCurrentProcessId();
    /* The observer may publish reason/ready while record I/O is blocked. Never
     * copy its mutable storage concurrently into the initial on-disk image. */
    const session_record_t initial_record = local_record;
    started_at                            = GetTickCount64();
    HANDLE thread                         = CreateThread(NULL, 0, deadlineMain, NULL, 0, NULL);
    if (thread == NULL)
    {
        LocalFree(security);
        return false;
    }
    CloseHandle(thread);
    session_started = true;
    if (! SetConsoleCtrlHandler(sessionConsoleHandler, TRUE))
    {
        LocalFree(security);
        return false;
    }
    if (atexit(normalReturn) != 0)
    {
        LocalFree(security);
        return false;
    }
    if (options->session_file != NULL)
    {
        wchar_t *path = waterwallWindowsWide(options->session_file);
        if (path != NULL)
            record_file = CreateFileW(path,
                                      GENERIC_READ | GENERIC_WRITE,
                                      FILE_SHARE_READ,
                                      &sa,
                                      CREATE_NEW,
                                      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                                      NULL);
        free(path);
        DWORD written;
        if (record_file == INVALID_HANDLE_VALUE ||
            ! WriteFile(record_file, &initial_record, sizeof(initial_record), &written, NULL) ||
            written != sizeof(local_record) || ! FlushFileBuffers(record_file))
        {
            LocalFree(security);
            return false;
        }
        record_mapping = CreateFileMappingW(record_file, NULL, PAGE_READWRITE, 0, sizeof(local_record), NULL);
        if (record_mapping == NULL ||
            (persisted = MapViewOfFile(record_mapping, FILE_MAP_WRITE, 0, 0, sizeof(local_record))) == NULL)
        {
            record = &local_record;
            LocalFree(security);
            return false;
        }
    }
    if (record_mapping == NULL)
    {
        record_mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(local_record), NULL);
        if (record_mapping == NULL ||
            (persisted = MapViewOfFile(record_mapping, FILE_MAP_WRITE, 0, 0, sizeof(local_record))) == NULL)
        {
            LocalFree(security);
            return false;
        }
        memcpy(persisted, &initial_record, sizeof(initial_record));
    }
    InterlockedExchangePointer(&published_record, persisted);
    setReason(readField(&record->reason));
    LocalFree(security);
    /* Presentation changes apply to this process only. Preserve configuration
     * stdin when AllocConsole replaces the Win32 standard-handle table. */
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (options->console_mode == 1)
    {
        FreeConsole();
    }
    else if (options->console_mode == 2)
    {
        // Close CRT streams before detaching. Reopening them first can reuse console
        // handle values that FreeConsole still closes. Preserve redirected stdin.
        DWORD input_mode;
        bool  replace_input = input == NULL || input == INVALID_HANDLE_VALUE || GetConsoleMode(input, &input_mode);
        if (replace_input)
            fclose(stdin);
        fclose(stdout);
        fclose(stderr);
        /* An explicit visible console must not share the controller's console:
         * closing it would otherwise deliver close events to the controller too. */
        if (GetConsoleWindow() != NULL)
        {
            DWORD member;
            DWORD count = GetConsoleProcessList(&member, 1);
            if (count == 0 || (count > 1 && ! FreeConsole()))
                return false;
        }
        // CREATE_NO_WINDOW can leave a windowless console attached. FreeConsole also
        // succeeds when the process is already detached.
        if (GetConsoleWindow() == NULL && (! FreeConsole() || ! AllocConsole()))
            return false;
        if (replace_input)
        {
            if (freopen("NUL", "r", stdin) == NULL)
                return false;
            input = (HANDLE) _get_osfhandle(_fileno(stdin));
        }
        /* A detached MSVC process can have _fileno(stdout/stderr) == -2.
         * Reopen the FILE streams rather than passing those values to _dup2's
         * invalid-parameter handler. Configuration stdin stays redirected. */
        if (! SetStdHandle(STD_INPUT_HANDLE, input) || freopen("CONOUT$", "w", stdout) == NULL ||
            freopen("CONOUT$", "w", stderr) == NULL)
            return false;
        if (! SetStdHandle(STD_OUTPUT_HANDLE, (HANDLE) _get_osfhandle(_fileno(stdout))) ||
            ! SetStdHandle(STD_ERROR_HANDLE, (HANDLE) _get_osfhandle(_fileno(stderr))))
            return false;
    }
    /* Attach/detach resets the OS console handler table. */
    if (! SetConsoleCtrlHandler(sessionConsoleHandler, TRUE))
        return false;
    options->stop_event         = (uintptr_t) stop_event;
    options->ready_event        = (uintptr_t) ready_event;
    options->controller_process = (uintptr_t) controller;
    if (launcherSessionStopRequested())
    {
        setReason(kReasonStop);
        SetLastError(ERROR_CANCELLED);
        return false;
    }
    return true;
}

#ifndef WATERWALL_LAUNCHER_TEST_HOOKS
static DWORD setMachineOwnershipSecurity(HANDLE object, PSECURITY_DESCRIPTOR descriptor)
{
    PSID owner = NULL;
    PACL acl   = NULL;
    BOOL present, defaulted;
    if (! GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) ||
        ! GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted))
        return GetLastError();
    if (owner == NULL || ! present || acl == NULL)
        return ERROR_INVALID_SECURITY_DESCR;
    return SetSecurityInfo(object,
                           SE_KERNEL_OBJECT,
                           OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                           owner,
                           NULL,
                           acl,
                           NULL);
}

static DWORD grantCrossLoginProcessAccess(void)
{
    BYTE  administrators[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(administrators);
    if (! CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, administrators, &size))
        return GetLastError();
    HANDLE               process    = GetCurrentProcess();
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PACL                 existing   = NULL;
    DWORD                error =
        GetSecurityInfo(process, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &existing, NULL, &descriptor);
    if (error != ERROR_SUCCESS)
        return error;
    EXPLICIT_ACCESSW entry     = {0};
    entry.grfAccessPermissions = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE;
    entry.grfAccessMode        = GRANT_ACCESS;
    BuildTrusteeWithSidW(&entry.Trustee, administrators);
    PACL updated = NULL;
    error        = existing != NULL ? SetEntriesInAclW(1, &entry, existing, &updated) : ERROR_ACCESS_DENIED;
    if (error == ERROR_SUCCESS)
        error = SetSecurityInfo(process, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, updated, NULL);
    LocalFree(updated);
    LocalFree(descriptor);
    return error;
}
#endif

DWORD launcherSessionIdentity(launcher_kill_switch_identity_t *identity)
{
#ifndef WATERWALL_LAUNCHER_TEST_HOOKS
    PSECURITY_DESCRIPTOR security = launcherKillSwitchMachineSecurity();
    if (security == NULL)
        return GetLastError();
    DWORD error = setMachineOwnershipSecurity(session_job, security);
    if (error == ERROR_SUCCESS)
        error = setMachineOwnershipSecurity(stop_event, security);
    LocalFree(security);
    if (error == ERROR_SUCCESS)
        error = grantCrossLoginProcessAccess();
    if (error != ERROR_SUCCESS)
        return error;
#endif
    /* Windows kernel handle values fit in 32 bits across WOW64 boundaries. */
    identity->pid         = local_record.pid;
    identity->created     = local_record.created;
    identity->job_handle  = (DWORD) (uintptr_t) session_job;
    identity->stop_handle = (DWORD) (uintptr_t) stop_event;
    memcpy(identity->job_name, local_record.job_name, sizeof(identity->job_name));
    return ERROR_SUCCESS;
}

ULONGLONG launcherSessionStartupDeadline(void)
{
    return started_at + kStartupMs;
}

bool launcherSessionJobNameMatches(HANDLE job, const launcher_kill_switch_identity_t *identity)
{
    return waterwallCapabilityNameMatches(job, identity->job_name + wcslen(L"Local\\"));
}

bool launcherSessionStopNameMatches(HANDLE stop, const launcher_kill_switch_identity_t *identity)
{
    wchar_t name[96];
    launcherSessionStopName(identity->job_name, name);
    return waterwallCapabilityNameMatches(stop, name + wcslen(L"Local\\"));
}

HANDLE launcherSessionEffectsMapping(void)
{
    return record_mapping;
}
HANDLE launcherSessionCompletionEvent(void)
{
    return completion_event;
}
void launcherSessionChildStarted(void)
{
    /* Publish admission intent before CreateProcess, not after it returns. */
    InterlockedExchange(&record->started, 1);
    InterlockedExchange(&persisted->started, 1);
}
void launcherSessionChildAborted(void)
{
    /* Only the creation owner can prove that runtime code never ran. Keep
     * admission published until a suspended child has actually terminated. */
    InterlockedExchange(&record->started, 0);
    InterlockedExchange(&persisted->started, 0);
}
void launcherSessionChildExited(DWORD status, bool status_known)
{
    if (WaitForSingleObject(ready_event, 0) == WAIT_OBJECT_0)
        InterlockedExchange(&record->ready, 1);
    InterlockedExchange(&record->runtime_status, (LONG) status);
    InterlockedExchange(&record->runtime_status_known, status_known);
    if (status_known)
    {
        /* Publish the actual exit code before any later diagnostic can block. */
        InterlockedExchange(&persisted->runtime_status, (LONG) status);
        InterlockedExchange(&persisted->runtime_status_known, 1);
    }
}

static void closeSessionStreams(bool console_only)
{
    FILE *const streams[] = {stdin, stdout, stderr};
    const DWORD handles[] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    for (unsigned i = 0; i < ARRAYSIZE(streams); ++i)
    {
        if (closed_streams[i])
            continue;
        DWORD mode;
        if (console_only && ! GetConsoleMode(GetStdHandle(handles[i]), &mode))
            continue;
        fclose(streams[i]);
        closed_streams[i] = true;
    }
    FreeConsole();
}

bool launcherSessionDiagnosticsAvailable(void)
{
    return ! closed_streams[2];
}

static DWORD waitForMembers(ULONGLONG deadline)
{
    members_checked = true;
    bool detached   = false;
    for (;;)
    {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
        if (! QueryInformationJobObject(
                session_job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL))
            return GetLastError();
        if (accounting.ActiveProcesses == 1)
        {
            InterlockedExchange(&record->members_settled, 1);
            return ERROR_SUCCESS;
        }
        if (! detached)
        {
            /* A console host can retain membership after the runtime exits. */
            closeSessionStreams(true);
            detached = true;
        }
        ULONGLONG now = GetTickCount64();
        if (now >= deadline)
            return ERROR_TIMEOUT;
        Sleep((DWORD) min(deadline - now, kPollMs));
    }
}

DWORD launcherSessionWaitForMembers(void)
{
    return waitForMembers(launcherSessionSettlementDeadline());
}

void launcherSessionFinish(DWORD status, bool residue)
{
    launcherSessionSettleChild();
    /* A fast runtime can observe controller loss and exit between observer polls. */
    if (controller != NULL && WaitForSingleObject(controller, 0) == WAIT_OBJECT_0)
        setReason(kReasonController);
    if (supplied_stop != NULL && WaitForSingleObject(supplied_stop, 0) == WAIT_OBJECT_0)
        setReason(kReasonStop);
    if (! readField(&record->runtime_status_known))
        InterlockedExchange(&record->runtime_status, (LONG) status);
    if (WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0)
        setReason(kReasonStop);
    if (readField(&record->reason) == kReasonNone)
        setReason(status != 0 ? (readField(&record->ready) ? kReasonRuntime : kReasonStartup) : kReasonStop);
    bool orderly = ! readField(&record->started) || WaitForSingleObject(completion_event, 0) == WAIT_OBJECT_0;
    InterlockedExchange(&record->orderly, orderly);
    InterlockedExchange(&record->residue, residue);
    // No more launcher I/O follows. Close streams before detaching so CONOUT$
    // references cannot keep the console host alive during Job settlement.
    closeSessionStreams(false);
    if (! members_checked)
        waitForMembers(GetTickCount64() + 5000);
    InterlockedExchange(&record->final, 1);
    if (persisted != NULL)
    {
        session_record_t snapshot = {0};
        snapshot.magic            = record->magic;
        snapshot.size             = record->size;
        snapshot.pid              = record->pid;
        snapshot.created          = record->created;
        memcpy(snapshot.job_name, record->job_name, sizeof(snapshot.job_name));
        snapshot.reason               = readField(&record->reason);
        snapshot.started              = readField(&record->started);
        snapshot.ready                = readField(&record->ready);
        snapshot.runtime_status       = readField(&record->runtime_status);
        snapshot.runtime_status_known = readField(&record->runtime_status_known);
        snapshot.orderly              = readField(&record->orderly);
        snapshot.residue              = readField(&record->residue);
        snapshot.members_settled      = readField(&record->members_settled);
        size_t offset                 = sizeof(record->effects);
        memcpy((char *) persisted + offset, (char *) &snapshot + offset, sizeof(snapshot) - offset);
        bool flushed = record_file == INVALID_HANDLE_VALUE ||
                       (FlushViewOfFile(persisted, sizeof(*persisted)) && FlushFileBuffers(record_file));
        if (flushed)
        {
            InterlockedExchange(&persisted->final, 1);
            if (record_file != INVALID_HANDLE_VALUE &&
                (! FlushViewOfFile(persisted, sizeof(*persisted)) || ! FlushFileBuffers(record_file)))
                InterlockedExchange(&persisted->final, 0);
        }
        InterlockedExchange(&record->final, readField(&persisted->final));
    }
    InterlockedExchange(&finished, 1);
    /* Job, journal and observer capabilities are process-lifetime resources.
     * Closing our own kill-on-close Job here would terminate this process. */
}

static DWORD WINAPI recoveryDeadline(void *unused)
{
    (void) unused;
    Sleep(kLauncherSessionRecoveryMs + 5000);
    TerminateProcess(GetCurrentProcess(), 0xe0570002U);
    return 0;
}

static bool sessionJobNameValid(const wchar_t name[80])
{
    wchar_t job_prefix[40];
    lazyLoadWideString(
        transf_session_job_prefix, sizeof(transf_session_job_prefix), job_prefix, sizeof(job_prefix) / sizeof(wchar_t));
    size_t prefix_len   = wcslen(job_prefix);
    bool   prefix_match = wcsncmp(name, job_prefix, prefix_len) == 0;
    SecureZeroMemory(job_prefix, sizeof(job_prefix));
    if (! prefix_match || wcsnlen(name, 80) != prefix_len + 32)
        return false;
    for (size_t i = prefix_len; i < prefix_len + 32; ++i)
        if (! ((name[i] >= L'0' && name[i] <= L'9') || (name[i] >= L'a' && name[i] <= L'f')))
            return false;
    return true;
}

bool launcherSessionIdentityValid(const launcher_kill_switch_identity_t *identity)
{
    return identity->pid != 0 && identity->job_handle != 0 && identity->stop_handle != 0 &&
           identity->job_handle != identity->stop_handle &&
           (identity->created.dwLowDateTime != 0 || identity->created.dwHighDateTime != 0) &&
           sessionJobNameValid(identity->job_name);
}

static bool sessionRecordValid(const session_record_t *saved)
{
    if (saved->magic != SESSION_MAGIC || saved->size != sizeof(*saved) || saved->pid == 0 ||
        saved->effects.magic != WW_SESSION_EFFECT_MAGIC || saved->reason < kReasonNone ||
        saved->reason > kReasonForced || ! sessionJobNameValid(saved->job_name))
        return false;
    const LONG flags[] = {saved->started,
                          saved->ready,
                          saved->runtime_status_known,
                          saved->orderly,
                          saved->residue,
                          saved->members_settled,
                          saved->final,
                          saved->effects.driver_residue};
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i)
        if (flags[i] != 0 && flags[i] != 1)
            return false;
    return true;
}

DWORD launcherSessionWaitForJob(HANDLE job, HANDLE process, ULONGLONG graceful_deadline, ULONGLONG deadline)
{
    if (process != NULL && GetTickCount64() < graceful_deadline)
    {
        ULONGLONG now = GetTickCount64();
        if (now < graceful_deadline && WaitForSingleObject(process, (DWORD) (graceful_deadline - now)) == WAIT_FAILED)
            return GetLastError();
    }
    if (job == NULL)
        return ERROR_INVALID_HANDLE;
    bool forced = false;
    do
    {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
        if (! QueryInformationJobObject(
                job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL))
            return GetLastError();
        if (accounting.ActiveProcesses == 0 && (process == NULL || WaitForSingleObject(process, 0) == WAIT_OBJECT_0))
            return ERROR_SUCCESS;
        /* Our verification handle delays kill-on-close until it is closed. */
        if (! forced)
        {
            if (accounting.ActiveProcesses != 0 && ! TerminateJobObject(job, 0xe0570001U))
                return GetLastError();
            forced = true;
        }
        Sleep(kPollMs);
    } while (GetTickCount64() < deadline);
    return ERROR_TIMEOUT;
}

static bool sessionRecordRead(const session_record_t *view, session_record_t *saved)
{
    /* Runtime writes use mapped pages. ReadFile is not guaranteed coherent
     * with those writes, including unflushed creation intent after a crash.
     * Reading our own mapping through ReadProcessMemory also turns backing-store
     * faults into an ordinary failed read on both MSVC and MinGW. */
    SIZE_T copied;
    return ReadProcessMemory(GetCurrentProcess(), view, saved, sizeof(*saved), &copied) && copied == sizeof(*saved) &&
           sessionRecordValid(saved);
}

/* All creation attempts have stopped. A missing GUID cannot prove that its
 * adapter disappeared. Confirmed GUIDs are compared only to live interfaces. */
static DWORD waitForAdapters(const windows_session_effects_t *effects, ULONGLONG deadline, const char **detail)
{
    bool have_adapters = false;
    for (unsigned i = 0; i < WW_SESSION_ADAPTER_MAX; ++i)
    {
        LONG state = effects->adapters[i].state;
        if (state == 0)
            continue;
        if (state != 2)
        {
            *detail = "adapter_identity_unverified";
            return ERROR_INVALID_DATA;
        }
        have_adapters = true;
    }
    if (! have_adapters)
        return ERROR_SUCCESS;

    for (;;)
    {
        MIB_IF_TABLE2 *interfaces = NULL;
        DWORD          error      = GetIfTable2(&interfaces);
        if (error != NO_ERROR)
        {
            *detail = "adapter_query_failed";
            return error;
        }

        bool present = false;
        for (unsigned i = 0; i < WW_SESSION_ADAPTER_MAX && ! present; ++i)
        {
            if (effects->adapters[i].state != 2)
                continue;
            for (ULONG j = 0; j < interfaces->NumEntries; ++j)
            {
                if (memcmp(&effects->adapters[i].guid, &interfaces->Table[j].InterfaceGuid, sizeof(GUID)) == 0)
                {
                    present = true;
                    break;
                }
            }
        }
        FreeMibTable(interfaces);
        if (! present)
            return ERROR_SUCCESS;
        ULONGLONG now = GetTickCount64();
        if (now >= deadline)
        {
            *detail = "adapter_present";
            return ERROR_TIMEOUT;
        }
        Sleep((DWORD) min(deadline - now, kPollMs));
    }
}

/* The caller has observed Job settlement and holds this launcher's mapping
 * across owner exit. Read the same inventory used by standalone recovery. */
DWORD launcherSessionWaitForOwnerAdapters(HANDLE mapping, const launcher_kill_switch_identity_t *owner,
                                          ULONGLONG deadline)
{
    const session_record_t *view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, sizeof(*view));
    if (view == NULL)
        return GetLastError();
    session_record_t saved;
    bool             valid = sessionRecordRead(view, &saved) && saved.pid == owner->pid &&
                 CompareFileTime(&saved.created, &owner->created) == 0 &&
                 memcmp(saved.job_name, owner->job_name, sizeof(saved.job_name)) == 0;
    UnmapViewOfFile(view);
    if (! valid)
        return ERROR_INVALID_DATA;
    const char *detail = NULL;
    return waitForAdapters(&saved.effects, deadline, &detail);
}

int launcherSessionRecover(const char *path)
{
    int result = 2;
    /* Recovery needs the same loader-independent deadline path. */
    if (lazyProcAddress(&lazy_proc_TerminateProcess) == NULL)
    {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return result;
    }
    HANDLE deadline_thread = CreateThread(NULL, 0, recoveryDeadline, NULL, 0, NULL);
    if (deadline_thread == NULL)
        return result;
    CloseHandle(deadline_thread);
    wchar_t *wide = waterwallWindowsWide(path);
    if (wide == NULL)
        return result;
    HANDLE file = CreateFileW(wide,
                              GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL,
                              OPEN_EXISTING,
                              FILE_FLAG_OPEN_REPARSE_POINT,
                              NULL);
    free(wide);
    if (file == INVALID_HANDLE_VALUE)
        return result;
    session_record_t           saved;
    LARGE_INTEGER              size;
    BY_HANDLE_FILE_INFORMATION info;
    bool valid = GetFileInformationByHandle(file, &info) && ! (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                 GetFileSizeEx(file, &size) && size.QuadPart == sizeof(saved);
    HANDLE                  mapping = valid ? CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL) : NULL;
    const session_record_t *view = mapping != NULL ? MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, sizeof(saved)) : NULL;
    if (mapping != NULL)
        CloseHandle(mapping);
    if (view == NULL || ! sessionRecordRead(view, &saved))
    {
        if (view != NULL)
            UnmapViewOfFile(view);
        CloseHandle(file);
        return result;
    }
    HANDLE job         = OpenJobObjectW(JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE, FALSE, saved.job_name);
    HANDLE process     = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, saved.pid);
    bool   public_dead = process == NULL && GetLastError() == ERROR_INVALID_PARAMETER;
    if (process != NULL)
    {
        FILETIME created, ended, kernel, user;
        bool     queried = GetProcessTimes(process, &created, &ended, &kernel, &user) != FALSE;
        if (! queried || memcmp(&created, &saved.created, sizeof(created)) != 0)
        {
            /* PID reuse proves the old process object is gone; failed access does not. */
            public_dead = queried;
            CloseHandle(process);
            process = NULL;
        }
    }
    wchar_t stop_name[96];
    launcherSessionStopName(saved.job_name, stop_name);
    HANDLE stop = OpenEventW(EVENT_MODIFY_STATE, FALSE, stop_name);
    if (stop != NULL)
    {
        SetEvent(stop);
        CloseHandle(stop);
    }
    ULONGLONG start    = GetTickCount64();
    ULONGLONG deadline = start + kLauncherSessionRecoveryMs;
    bool inactive = launcherSessionWaitForJob(job, process, start + kLauncherSessionStopMs, deadline) == ERROR_SUCCESS;
    if (job != NULL)
        CloseHandle(job);
    if (process != NULL)
    {
        public_dead = WaitForSingleObject(process, 0) == WAIT_OBJECT_0;
        inactive    = inactive && public_dead;
        CloseHandle(process);
    }
    /* Refresh the result only after settlement. A missing receipt is never
     * fabricated after abrupt death. The private Job proves process containment;
     * it does not prove adapter removal or other OS effects. */
    session_record_t refreshed;
    bool             receipt_read = sessionRecordRead(view, &refreshed) && refreshed.pid == saved.pid &&
                        memcmp(&refreshed.created, &saved.created, sizeof(saved.created)) == 0 &&
                        memcmp(refreshed.job_name, saved.job_name, sizeof(saved.job_name)) == 0;
    if (receipt_read)
        saved = refreshed;
    else
    {
        /* A failed/partial refresh cannot authenticate status or effect state.
         * Retain only the independently observed process-inactivity fact. */
        saved.final                = 0;
        saved.runtime_status_known = 0;
    }
    UnmapViewOfFile(view);
    CloseHandle(file);
    /* A temporary object's name disappears at last-handle close, potentially
     * before termination settles. Only a final one-member barrier plus public
     * process death can replace live Job accounting. Never infer this from absence. */
    if (receipt_read && ! inactive && public_dead && saved.final && saved.members_settled)
        inactive = true;
    /* Driver-file residue does not imply that a session still owns an interface. */
    const char *cleanup_detail = ! receipt_read ? "record_unverified" : ! inactive ? "processes_unverified" : NULL;
    bool        settled =
        cleanup_detail == NULL && waitForAdapters(&saved.effects, deadline, &cleanup_detail) == ERROR_SUCCESS;
    if (cleanup_detail == NULL)
        cleanup_detail = "settled";
    result = settled ? 0 : 2;
    printf("{\"reason\":%ld,\"runtime_status\":%lu,\"runtime_status_known\":%s,"
           "\"termination\":\"%s\",\"processes_inactive\":%s,\"cleanup\":\"%s\","
           "\"cleanup_detail\":\"%s\",\"file_residue\":%s}\n",
           saved.reason != kReasonNone ? saved.reason : kReasonForced,
           (unsigned long) (DWORD) saved.runtime_status,
           receipt_read && saved.runtime_status_known ? "true" : "false",
           saved.final && saved.orderly ? "orderly"
           : inactive                   ? "abrupt"
                                        : "unverified",
           inactive ? "true" : "false",
           settled ? "settled" : "unverified",
           cleanup_detail,
           saved.residue || saved.effects.driver_residue || ! saved.final || ! saved.orderly ? "true" : "false");
    return result;
}
