/* Native host for the real packed launcher and its existing PE fixture. */
#include "startup_windows.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>

typedef enum test_case_e
{
    kNormal,
    kNoReady,
    kPreStopped,
    kNoJob,
    kNoKillOnClose,
    kBreakaway,
    kSilentBreakaway,
    kHostClosesJob,
    kLauncherDies,
} test_case_e;

static int jobEmpty(HANDLE job)
{
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info = {0};
    return QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &info, sizeof(info), NULL) &&
           info.ActiveProcesses == 0;
}

static int waitJobEmpty(HANDLE job)
{
    ULONGLONG deadline = GetTickCount64() + 10000;
    do
    {
        if (jobEmpty(job))
            return 1;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    return 0;
}

static int readOutput(HANDLE pipe, char *output, size_t *length)
{
    for (;;)
    {
        DWORD available = 0, count = 0;
        if (! PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL))
            return GetLastError() == ERROR_BROKEN_PIPE;
        if (available == 0)
            return 1;
        if (available > 8191 - *length)
            return 0;
        if (! ReadFile(pipe, output + *length, available, &count, NULL) || count == 0)
            return 0;
        *length += count;
        output[*length] = 0;
    }
}

static HANDLE runtimeProcess(HANDLE job, DWORD runtime_pid)
{
    HANDLE runtime = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, runtime_pid);
    BOOL   in_job  = FALSE;
    if (runtime != NULL && IsProcessInJob(runtime, job, &in_job) && in_job)
        return runtime;
    fprintf(stderr, "Runtime membership: runtime=%lu member=%d error=%lu\n", runtime_pid, in_job, GetLastError());
    if (runtime != NULL)
        CloseHandle(runtime);
    return NULL;
}

static int retainJobProcesses(HANDLE job, HANDLE *processes, DWORD *count)
{
    struct
    {
        DWORD     assigned;
        DWORD     listed;
        ULONG_PTR pids[8];
    } members = {0};
    if (! QueryInformationJobObject(job, JobObjectBasicProcessIdList, &members, sizeof(members), NULL) ||
        members.listed == 0 || members.assigned != members.listed || members.listed > 8)
        return 0;
    for (DWORD i = 0; i < members.listed; ++i)
    {
        HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, (DWORD) members.pids[i]);
        if (process == NULL)
            return 0;
        processes[(*count)++] = process;
    }
    return 1;
}

static HANDLE findProductionRuntime(HANDLE job)
{
    struct
    {
        DWORD     assigned;
        DWORD     listed;
        ULONG_PTR pids[8];
    } members = {0};
    if (! QueryInformationJobObject(job, JobObjectBasicProcessIdList, &members, sizeof(members), NULL) ||
        members.listed > 8)
        return NULL;
    for (DWORD i = 0; i < members.listed; ++i)
    {
        HANDLE  process = runtimeProcess(job, (DWORD) members.pids[i]);
        wchar_t path[32768];
        DWORD   length = 32768;
        if (process == NULL)
            continue;
        if (QueryFullProcessImageNameW(process, 0, path, &length))
        {
            const wchar_t *base = wcsrchr(path, L'\\');
            if (base != NULL && _wcsicmp(base + 1, L"waterwall_application.exe") == 0)
                return process;
        }
        CloseHandle(process);
    }
    return NULL;
}

/* Only the direct launcher-owned directory and its direct files are expected.
 * Forced-exit residue is retired only after both process handles are signaled. */
static int retireResidue(const wchar_t *root, int forced)
{
    wchar_t pattern[MAX_PATH], directory[MAX_PATH], files[MAX_PATH], path[MAX_PATH];
    if (swprintf(pattern, MAX_PATH, L"%ls\\Waterwall-*", root) < 0)
        return 0;
    WIN32_FIND_DATAW entry;
    HANDLE           search = FindFirstFileW(pattern, &entry);
    if (search == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    int result = forced;
    do
    {
        if (! (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
            swprintf(directory, MAX_PATH, L"%ls\\%ls", root, entry.cFileName) < 0 ||
            swprintf(files, MAX_PATH, L"%ls\\*", directory) < 0)
        {
            result = 0;
            continue;
        }
        WIN32_FIND_DATAW file;
        HANDLE           contents = FindFirstFileW(files, &file);
        if (contents == INVALID_HANDLE_VALUE)
        {
            result = 0;
            continue;
        }
        do
        {
            if (wcscmp(file.cFileName, L".") == 0 || wcscmp(file.cFileName, L"..") == 0)
                continue;
            if ((file.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
                swprintf(path, MAX_PATH, L"%ls\\%ls", directory, file.cFileName) < 0 || ! DeleteFileW(path))
                result = 0;
        } while (FindNextFileW(contents, &file));
        if (GetLastError() != ERROR_NO_MORE_FILES)
            result = 0;
        FindClose(contents);
        if (! RemoveDirectoryW(directory))
            result = 0;
    } while (FindNextFileW(search, &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES)
        result = 0;
    FindClose(search);
    return result;
}

static int runCase(const wchar_t *launcher, const wchar_t *root, const wchar_t *config, test_case_e kind,
                   DWORD expected_status, int production)
{
    int                 result = 0, attributes_ready = 0, settled = 0;
    const char         *stage = "preparing host";
    HANDLE              job = NULL, stop = NULL, ready = NULL, child_stop = NULL, child_ready = NULL;
    HANDLE              output = NULL, child_output = NULL, input = INVALID_HANDLE_VALUE, runtime = NULL;
    HANDLE              members[8]      = {0};
    DWORD               member_count    = 0;
    PROCESS_INFORMATION process         = {0};
    STARTUPINFOEXW      startup         = {0};
    SECURITY_ATTRIBUTES security        = {sizeof(security), NULL, TRUE};
    char                observed[8192]  = {0};
    size_t              observed_length = 0;
    int rejection = kind == kPreStopped || kind == kNoJob || kind == kNoKillOnClose || kind == kBreakaway ||
                    kind == kSilentBreakaway;
    if (kind != kNoJob)
    {
        job                                         = CreateJobObjectW(NULL, NULL);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
        /* Windows support processes may also join this Job. The fixture tests
         * containment and settlement without imposing a process-count policy. */
        if (kind != kNoKillOnClose)
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (kind == kBreakaway)
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_BREAKAWAY_OK;
        if (kind == kSilentBreakaway)
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
        if (job == NULL || ! SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
            goto done;
    }
    stop = CreateEventW(NULL, TRUE, kind == kPreStopped, NULL);
    if (kind != kNoReady)
        ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (stop == NULL || (kind != kNoReady && ready == NULL) ||
        ! DuplicateHandle(GetCurrentProcess(), stop, GetCurrentProcess(), &child_stop, SYNCHRONIZE, TRUE, 0) ||
        (ready != NULL &&
         ! DuplicateHandle(
             GetCurrentProcess(), ready, GetCurrentProcess(), &child_ready, EVENT_MODIFY_STATE, TRUE, 0)) ||
        ! CreatePipe(&output, &child_output, &security, 0) || ! SetHandleInformation(output, HANDLE_FLAG_INHERIT, 0))
        goto done;
    input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, NULL);
    if (input == INVALID_HANDLE_VALUE)
        goto done;
    HANDLE inherited[4]   = {child_stop, child_output, input, child_ready};
    SIZE_T attribute_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_size);
    startup.lpAttributeList = malloc(attribute_size);
    if (startup.lpAttributeList == NULL ||
        ! InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attribute_size))
        goto done;
    attributes_ready = 1;
    if (! UpdateProcThreadAttribute(startup.lpAttributeList,
                                    0,
                                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                    inherited,
                                    (child_ready == NULL ? 3 : 4) * sizeof(HANDLE),
                                    NULL,
                                    NULL))
        goto done;
    startup.StartupInfo.cb         = sizeof(startup);
    startup.StartupInfo.dwFlags    = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput  = input;
    startup.StartupInfo.hStdOutput = child_output;
    startup.StartupInfo.hStdError  = child_output;
    wchar_t command[32768], ready_argument[96] = {0};
    if (child_ready != NULL)
        swprintf(ready_argument, 96, L" --host-ready-event:%llu", (unsigned long long) (uintptr_t) child_ready);
    if (swprintf(command,
                 32768,
                 L"\"%ls\" --hosted %ls--host-stop-event:%llu%ls \"-c:%ls\"",
                 launcher,
                 production ? L"--restricted-config " : L"",
                 (unsigned long long) (uintptr_t) child_stop,
                 ready_argument,
                 config) < 0)
        goto done;
    wchar_t status_text[32];
    swprintf(status_text, 32, L"%lu", expected_status);
    if (! SetEnvironmentVariableW(L"WW_FIXTURE_EXIT", status_text) ||
        ! CreateProcessW(launcher,
                         command,
                         NULL,
                         NULL,
                         TRUE,
                         CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                         NULL,
                         root,
                         &startup.StartupInfo,
                         &process))
        goto done;
    CloseHandle(child_output);
    child_output = NULL;
    CloseHandle(child_stop);
    child_stop = NULL;
    if (child_ready != NULL)
        CloseHandle(child_ready);
    child_ready = NULL;
    if ((job != NULL && ! AssignProcessToJobObject(job, process.hProcess)) || ResumeThread(process.hThread) != 1)
        goto done;
    ULONGLONG deadline = GetTickCount64() + 15000;
    stage              = "waiting for fixture startup";
    if (! rejection)
    {
        DWORD runtime_pid = 0;
        for (;;)
        {
            if (! readOutput(output, observed, &observed_length))
                goto done;
            if (production)
            {
                if ((ready == NULL || WaitForSingleObject(ready, 0) == WAIT_OBJECT_0) &&
                    (runtime = findProductionRuntime(job)) != NULL)
                    break;
            }
            else
            {
                const char *marker = strstr(observed, "hosted-fixture-waiting:");
                if (marker != NULL && strchr(marker, '\n') != NULL &&
                    sscanf(marker, "hosted-fixture-waiting:%lu", &runtime_pid) == 1)
                    break;
            }
            if (WaitForSingleObject(process.hProcess, 10) != WAIT_TIMEOUT || GetTickCount64() >= deadline)
                goto done;
        }
        stage = "checking readiness and same-Job membership";
        if (ready != NULL && WaitForSingleObject(ready, 0) != WAIT_OBJECT_0)
        {
            fprintf(stderr, "Ready event was not signaled\n");
            goto done;
        }
        if (! production && (runtime = runtimeProcess(job, runtime_pid)) == NULL)
            goto done;
        if (production && ready == NULL)
        {
            /* Deliberate no-READY fallback observes process survival only. */
            if (WaitForSingleObject(runtime, 250) != WAIT_TIMEOUT)
                goto done;
        }
        if (kind == kHostClosesJob)
        {
            /* CREATE_NO_WINDOW can still have OS-created conhost members.
             * Retain wait handles to all members before losing the Job query. */
            if (! retainJobProcesses(job, members, &member_count))
                goto done;
            /* This is the host's only Job handle, as when host death closes it. */
            CloseHandle(job);
            job = NULL;
        }
        else if (kind == kLauncherDies)
        {
            if (! TerminateProcess(process.hProcess, 93) ||
                WaitForSingleObject(process.hProcess, 10000) != WAIT_OBJECT_0 ||
                WaitForSingleObject(runtime, 0) != WAIT_TIMEOUT || ! TerminateJobObject(job, 94))
                goto done;
        }
        else if (! SetEvent(stop))
            goto done;
    }
    stage = "settling process tree";
    if (WaitForSingleObject(process.hProcess, 15000) != WAIT_OBJECT_0 ||
        (runtime != NULL && WaitForSingleObject(runtime, 10000) != WAIT_OBJECT_0) ||
        (member_count != 0 && WaitForMultipleObjects(member_count, members, TRUE, 10000) != WAIT_OBJECT_0) ||
        (job != NULL && ! waitJobEmpty(job)))
        goto done;
    settled      = 1;
    stage        = "checking exit status";
    DWORD status = 0;
    if (! GetExitCodeProcess(process.hProcess, &status) || ! readOutput(output, observed, &observed_length))
        goto done;
    if (rejection)
    {
        if (status != 1 || strstr(observed, "snapshot:") != NULL ||
            (ready != NULL && WaitForSingleObject(ready, 0) != WAIT_TIMEOUT))
            goto done;
    }
    else if (kind != kHostClosesJob && kind != kLauncherDies && status != expected_status)
    {
        fprintf(stderr, "Expected child status %lu; observed %lu\n", expected_status, status);
        goto done;
    }
    stage  = "checking owned residue";
    result = retireResidue(root, kind == kHostClosesJob || kind == kLauncherDies);
done:
    if (! result)
    {
        DWORD error = GetLastError();
        if (output != NULL)
            (void) readOutput(output, observed, &observed_length);
        DWORD observed_status = STILL_ACTIVE;
        if (process.hProcess != NULL)
            (void) GetExitCodeProcess(process.hProcess, &observed_status);
        fprintf(stderr, "Hosted launcher case %d failed %s (error %lu):\n%s\n", kind, stage, error, observed);
        fprintf(stderr, "Launcher status: 0x%08lx\n", observed_status);
    }
    if (! settled && process.hProcess != NULL)
    {
        if (job != NULL)
            TerminateJobObject(job, 95);
        TerminateProcess(process.hProcess, 95);
        settled = WaitForSingleObject(process.hProcess, 10000) == WAIT_OBJECT_0 &&
                  (runtime == NULL || WaitForSingleObject(runtime, 10000) == WAIT_OBJECT_0) &&
                  (job == NULL || waitJobEmpty(job));
        if (settled)
            (void) retireResidue(root, 1);
    }
    if (attributes_ready)
        DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    for (DWORD i = 0; i < member_count; ++i)
        CloseHandle(members[i]);
    HANDLE handles[] = {process.hProcess,
                        process.hThread,
                        runtime,
                        job,
                        stop,
                        ready,
                        child_stop,
                        child_ready,
                        output,
                        child_output,
                        input};
    for (size_t i = 0; i < sizeof(handles) / sizeof(handles[0]); ++i)
        if (handles[i] != NULL && handles[i] != INVALID_HANDLE_VALUE)
            CloseHandle(handles[i]);
    return result;
}

static int writeConfig(const wchar_t *path, const char *json)
{
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return 0;
    DWORD length = (DWORD) strlen(json), written = 0;
    int   result = WriteFile(file, json, length, &written, NULL) && written == length;
    return CloseHandle(file) && result;
}

static int retireLogs(const wchar_t *root, int report)
{
    wchar_t pattern[MAX_PATH], path[MAX_PATH];
    if (swprintf(pattern, MAX_PATH, L"%ls\\*.log", root) < 0)
        return 0;
    WIN32_FIND_DATAW entry;
    HANDLE           search = FindFirstFileW(pattern, &entry);
    if (search == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    int result = 1;
    do
    {
        if ((entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
            swprintf(path, MAX_PATH, L"%ls\\%ls", root, entry.cFileName) < 0)
        {
            result = 0;
            continue;
        }
        if (report)
        {
            FILE *log = _wfopen(path, L"rb");
            if (log != NULL)
            {
                char   bytes[4096];
                size_t count = fread(bytes, 1, sizeof(bytes), log);
                fprintf(stderr, "%ls:\n", entry.cFileName);
                (void) fwrite(bytes, 1, count, stderr);
                fclose(log);
            }
        }
        if (! DeleteFileW(path))
            result = 0;
    } while (FindNextFileW(search, &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES)
        result = 0;
    FindClose(search);
    return result;
}

int main(int argc, char **argv)
{
    int production = argc == 3 && strcmp(argv[1], "--production") == 0;
    if (argc != 2 && ! production)
        return 1;
    wchar_t *launcher = waterwallWindowsWide(argv[production ? 2 : 1]);
    wchar_t  temporary[MAX_PATH], root[MAX_PATH], config[MAX_PATH];
    if (launcher == NULL || GetTempPathW(MAX_PATH, temporary) == 0 || ! GetTempFileNameW(temporary, L"wwh", 0, root) ||
        ! DeleteFileW(root) || ! CreateDirectoryW(root, NULL) ||
        swprintf(config, MAX_PATH, L"%ls\\core.json", root) < 0)
        return 2;
    const char *core = production ? "{\"configs\":[\"nodes.json\"],\"log\":{\"path\":\"./\","
                                    "\"core\":{\"file\":\"core.log\",\"console\":false},"
                                    "\"network\":{\"file\":\"network.log\",\"console\":false},"
                                    "\"dns\":{\"file\":\"dns.log\",\"console\":false},"
                                    "\"internal\":{\"file\":\"internal.log\",\"console\":false}},"
                                    "\"misc\":{\"workers\":1,\"ram-profile\":\"minimal\",\"try-enabling-bbr\":false}}"
                                  : "{}";
    wchar_t     nodes[MAX_PATH];
    if (! writeConfig(config, core) ||
        (production && (swprintf(nodes, MAX_PATH, L"%ls\\nodes.json", root) < 0 ||
                        ! writeConfig(nodes,
                                      "{\"name\":\"hosted-test\",\"nodes\":["
                                      "{\"name\":\"source\",\"type\":\"TesterClient\","
                                      "\"settings\":{\"chunk-count\":1},\"next\":\"sink\"},"
                                      "{\"name\":\"sink\",\"type\":\"BlackHole\","
                                      "\"settings\":{\"mode\":\"passive\"}}]}"))) ||
        ! SetEnvironmentVariableW(L"TEMP", root) || ! SetEnvironmentVariableW(L"TMP", root))
        return 3;
    BOOL in_job = FALSE;
    int  result = IsProcessInJob(GetCurrentProcess(), NULL, &in_job) != FALSE;
    for (int kind = kNormal; result && kind <= (production ? kPreStopped : kLauncherDies); ++kind)
    {
        if (kind == kNoJob && in_job)
        {
            puts("Missing-Job rejection unverified: the test host already belongs to a Job");
            continue;
        }
        result = runCase(
            launcher, root, config, (test_case_e) kind, ! production && kind == kNormal ? 0xc0000005 : 0, production);
    }
    if (production)
    {
        if (! DeleteFileW(nodes))
            result = 0;
        if (! retireLogs(root, ! result))
            result = 0;
    }
    if (! DeleteFileW(config) || ! RemoveDirectoryW(root))
        result = 0;
    free(launcher);
    if (result)
        puts(production ? "Production hosted packed runtime: READY, stop-only, pre-stop and whole-Job exit passed"
                        : "Hosted packed launch: containment, event rights/forwarding, optional READY, cancellation "
                          "and exit passed");
    return result ? 0 : 4;
}
