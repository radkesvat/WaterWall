#include "session_windows.h"
#include "../../ww/devices/windows_session_effects.h"
#include "lifecycle_capabilities_windows.h"
#include <fcntl.h>
#include <io.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

/* An existing record is never reused. The containing directory must be protected
 * by the client throughout launch/recovery. All dynamic fields use Interlocked
 * publication; no stdio, file I/O, or runtime lock is used by the deadline thread. */
#define SESSION_MAGIC UINT64_C(0x575753455353494f)
enum
{
    kStartupMs  = 60000,
    kStopMs     = 15000,
    kRecoveryMs = 20000,
    kPollMs     = 25
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
static HANDLE        session_job, stop_event, ready_event, completion_event;
static HANDLE        supplied_stop, supplied_ready, controller;
static HANDLE        record_file = INVALID_HANDLE_VALUE, record_mapping;
static ULONGLONG     started_at;
static volatile LONG child_exited;
static volatile LONG finished;
static bool          session_started;

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

static BOOL WINAPI sessionConsoleHandler(DWORD event)
{
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT && event != CTRL_CLOSE_EVENT && event != CTRL_LOGOFF_EVENT &&
        event != CTRL_SHUTDOWN_EVENT)
        return FALSE;
    launcherSessionCancel();
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT)
        Sleep(4000);
    return TRUE;
}

static DWORD WINAPI deadlineMain(void *unused)
{
    (void) unused;
    ULONGLONG stop_deadline = 0;
    bool      published     = false;
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
        if ((stopped || readField(&child_exited)) && stop_deadline == 0)
            stop_deadline = now + kStopMs;
        if (stop_deadline != 0 && now >= stop_deadline)
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

bool launcherSessionStart(waterwall_startup_options_t *options)
{
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
    typedef BOOLEAN(WINAPI * random_fn)(PVOID, ULONG);
    HMODULE   advapi = LoadLibraryW(L"advapi32.dll");
    random_fn random_bytes =
        advapi == NULL ? NULL : (random_fn) (uintptr_t) GetProcAddress(advapi, "SystemFunction036");
    if (random_bytes == NULL || ! random_bytes(random, sizeof(random)))
    {
        LocalFree(security);
        return false;
    }
    wcscpy(local_record.job_name, L"Local\\Waterwall.Session.");
    size_t prefix = wcslen(local_record.job_name);
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
    swprintf(stop_name, 96, L"%ls.Stop", local_record.job_name);
    stop_event       = CreateEventW(&sa, TRUE, FALSE, stop_name);
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
        /* Retire old CRT console handles before detach/allocation can recycle
         * their numeric values for new console or configuration handles. */
        if (freopen("NUL", "w", stdout) == NULL || freopen("NUL", "w", stderr) == NULL)
            return false;
        /* An explicit visible console must not share the controller's console:
         * closing it would otherwise deliver close events to the controller too. */
        if (GetConsoleWindow() != NULL)
        {
            DWORD member;
            DWORD count = GetConsoleProcessList(&member, 1);
            if (count == 0 || (count > 1 && ! FreeConsole()))
                return false;
        }
        if (GetConsoleWindow() == NULL && ! AllocConsole())
            return false;
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
    if (WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0 ||
        (controller != NULL && WaitForSingleObject(controller, 0) == WAIT_OBJECT_0) ||
        (supplied_stop != NULL && WaitForSingleObject(supplied_stop, 0) == WAIT_OBJECT_0))
    {
        setReason(controller != NULL && WaitForSingleObject(controller, 0) == WAIT_OBJECT_0 ? kReasonController
                                                                                            : kReasonStop);
        SetEvent(stop_event);
        return false;
    }
    return true;
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
    InterlockedExchange(&child_exited, 1);
}
void launcherSessionFinish(DWORD status, bool residue)
{
    InterlockedExchange(&child_exited, 1);
    /* A fast runtime can observe controller loss and exit between observer polls. */
    if (controller != NULL && WaitForSingleObject(controller, 0) == WAIT_OBJECT_0)
        setReason(kReasonController);
    if (supplied_stop != NULL && WaitForSingleObject(supplied_stop, 0) == WAIT_OBJECT_0)
        setReason(kReasonStop);
    InterlockedExchange(&record->runtime_status, (LONG) status);
    if (WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0)
        setReason(kReasonStop);
    if (readField(&record->reason) == kReasonNone)
        setReason(status != 0 ? (readField(&record->ready) ? kReasonRuntime : kReasonStartup) : kReasonStop);
    bool orderly = ! readField(&record->started) || WaitForSingleObject(completion_event, 0) == WAIT_OBJECT_0;
    InterlockedExchange(&record->orderly, orderly);
    InterlockedExchange(&record->residue, residue);
    /* After this boundary no code creates another process. Console infrastructure
     * may itself be a Job member, so detach before counting the remaining member. */
    FreeConsole();
    ULONGLONG settlement_deadline = GetTickCount64() + 5000;
    do
    {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
        if (! QueryInformationJobObject(
                session_job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL))
            break;
        if (accounting.ActiveProcesses == 1)
        {
            InterlockedExchange(&record->members_settled, 1);
            break;
        }
        Sleep(kPollMs);
    } while (GetTickCount64() < settlement_deadline);
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
    Sleep(kRecoveryMs + 5000);
    TerminateProcess(GetCurrentProcess(), 0xe0570002U);
    return 0;
}

static bool sessionRecordValid(const session_record_t *saved)
{
    if (saved->magic != SESSION_MAGIC || saved->size != sizeof(*saved) || saved->pid == 0 ||
        saved->effects.magic != WW_SESSION_EFFECT_MAGIC || saved->reason < kReasonNone ||
        saved->reason > kReasonForced || wcsncmp(saved->job_name, L"Local\\Waterwall.Session.", 24) != 0 ||
        wcsnlen(saved->job_name, 80) != 56)
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
    for (size_t i = 24; i < 56; ++i)
        if (! ((saved->job_name[i] >= L'0' && saved->job_name[i] <= L'9') ||
               (saved->job_name[i] >= L'a' && saved->job_name[i] <= L'f')))
            return false;
    return true;
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

int launcherSessionRecover(const char *path)
{
    int    result          = 2;
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
    swprintf(stop_name, 96, L"%ls.Stop", saved.job_name);
    HANDLE stop = OpenEventW(EVENT_MODIFY_STATE, FALSE, stop_name);
    if (stop != NULL)
    {
        SetEvent(stop);
        CloseHandle(stop);
    }
    ULONGLONG deadline = GetTickCount64() + kRecoveryMs;
    if (process != NULL)
        WaitForSingleObject(process, kStopMs);
    bool inactive = false;
    if (job != NULL)
    {
        /* Opening for recovery temporarily prevents last-handle containment.
         * Always terminate after graceful wait, then observe active accounting. */
        TerminateJobObject(job, 0xe0570001U);
        do
        {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
            if (! QueryInformationJobObject(
                    job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL))
                break;
            if (accounting.ActiveProcesses == 0)
            {
                inactive = true;
                break;
            }
            Sleep(kPollMs);
        } while (GetTickCount64() < deadline);
        CloseHandle(job);
    }
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
    const char *cleanup_detail    = ! receipt_read ? "record_unverified" : ! inactive ? "processes_unverified" : NULL;
    bool        adapters_inactive = cleanup_detail == NULL;
    bool        have_adapters     = false;
    for (unsigned i = 0; i < WW_SESSION_ADAPTER_MAX && adapters_inactive; ++i)
    {
        LONG state = saved.effects.adapters[i].state;
        if (state == 0)
            continue;
        if (state != 2)
        {
            adapters_inactive = false;
            cleanup_detail    = "adapter_identity_unverified";
            break;
        }
        have_adapters = true;
    }
    while (adapters_inactive && have_adapters)
    {
        MIB_IF_TABLE2 *interfaces = NULL;
        if (GetIfTable2(&interfaces) != NO_ERROR)
        {
            adapters_inactive = false;
            cleanup_detail    = "adapter_query_failed";
            break;
        }
        bool present = false;
        for (unsigned i = 0; i < WW_SESSION_ADAPTER_MAX && ! present; ++i)
        {
            if (saved.effects.adapters[i].state != 2)
                continue;
            for (ULONG j = 0; j < interfaces->NumEntries; ++j)
            {
                if (memcmp(&saved.effects.adapters[i].guid, &interfaces->Table[j].InterfaceGuid, sizeof(GUID)) == 0)
                {
                    present = true;
                    break;
                }
            }
        }
        FreeMibTable(interfaces);
        if (! present)
            break;
        if (GetTickCount64() >= deadline)
        {
            adapters_inactive = false;
            cleanup_detail    = "adapter_present";
            break;
        }
        Sleep(kPollMs);
    }
    /* Completion certifies the built-in session's process/interface boundaries.
     * An orderly receipt describes how it ended, not whether it is still active.
     * Driver-artifact residue records retained files; after process settlement it
     * cannot establish a live session and must not veto the interface checks. */
    bool settled = adapters_inactive;
    if (cleanup_detail == NULL)
        cleanup_detail = "settled";
    result = settled ? 0 : 2;
    printf("{\"reason\":%ld,\"runtime_status\":%lu,\"runtime_status_known\":%s,"
           "\"termination\":\"%s\",\"processes_inactive\":%s,\"cleanup\":\"%s\","
           "\"cleanup_detail\":\"%s\",\"file_residue\":%s}\n",
           saved.reason != kReasonNone ? saved.reason : kReasonForced,
           (unsigned long) (DWORD) saved.runtime_status,
           saved.final && saved.runtime_status_known ? "true" : "false",
           saved.final && saved.orderly ? "orderly"
           : inactive                   ? "abrupt"
                                        : "unverified",
           inactive ? "true" : "false",
           settled ? "settled" : "unverified",
           cleanup_detail,
           saved.residue || saved.effects.driver_residue || ! saved.final || ! saved.orderly ? "true" : "false");
    return result;
}
