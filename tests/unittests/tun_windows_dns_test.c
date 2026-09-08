/* Exercise the actual synchronous helper with a deterministic Win32 process
 * boundary. No netsh process, adapter, route, or DNS setting is touched. */
#include "tun_windows_dns.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef enum mock_wait_e
{
    kMockComplete,
    kMockTimeout,
    kMockWaitFailure,
    kMockHostStop,
    kMockDeviceStop
} mock_wait_t;

typedef struct mock_child_s
{
    mock_wait_t wait;
    DWORD       run_ms;
    DWORD       reap_ms;
    DWORD       exit_code;
    DWORD       create_error;
    bool        query_failure;
    bool        terminate_failure;
    bool        signal_after_exit;
    bool        created;
    bool        completed;
    bool        terminated;
    bool        process_closed;
    bool        thread_closed;
    DWORD       wait_budget;
    DWORD       wait_count;
    wchar_t     command[1200];
} mock_child_t;

static mock_child_t children[4];
static size_t       create_count;
static size_t       terminate_count;
static ULONGLONG    now_ms;
static DWORD        last_error;
static DWORD        host_wait;
static DWORD        device_wait;
static UINT         system_path_result;
static UINT         windows_path_result;
static bool         may_have_changed;

#define HOST_STOP   ((HANDLE) (uintptr_t) 0x10U)
#define DEVICE_STOP ((HANDLE) (uintptr_t) 0x20U)

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static HANDLE processHandle(size_t index)
{
    return (HANDLE) (uintptr_t) (0x100U + index * 0x10U);
}

static mock_child_t *childForHandle(HANDLE handle)
{
    for (size_t i = 0; i < create_count; ++i)
    {
        if (handle == processHandle(i))
        {
            return &children[i];
        }
    }
    require(false, "unexpected process handle");
    return NULL;
}

static ULONGLONG WINAPI mockGetTickCount64(void)
{
    return now_ms;
}

static DWORD WINAPI mockGetLastError(void)
{
    return last_error;
}

static UINT WINAPI mockGetSystemDirectoryW(LPWSTR path, UINT capacity)
{
    if (system_path_result != 1U)
    {
        last_error = ERROR_PATH_NOT_FOUND;
        return system_path_result;
    }
    const wchar_t expected[] = L"C:\\Windows\\System32";
    require(capacity > wcslen(expected), "System32 buffer too small");
    wcscpy(path, expected);
    return (UINT) wcslen(expected);
}

static UINT WINAPI mockGetWindowsDirectoryW(LPWSTR path, UINT capacity)
{
    if (windows_path_result != 1U)
    {
        last_error = ERROR_PATH_NOT_FOUND;
        return windows_path_result;
    }
    const wchar_t expected[] = L"C:\\Windows";
    require(capacity > wcslen(expected), "Windows buffer too small");
    wcscpy(path, expected);
    return (UINT) wcslen(expected);
}

static BOOL WINAPI mockCreateProcessW(LPCWSTR executable, LPWSTR command, LPSECURITY_ATTRIBUTES process_attributes,
                                      LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit, DWORD flags,
                                      LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup,
                                      LPPROCESS_INFORMATION child)
{
    require(create_count < sizeof(children) / sizeof(children[0]), "unbounded helper launch count");
    mock_child_t *entry = &children[create_count];
    require(wcscmp(executable, L"C:\\Windows\\System32\\netsh.exe") == 0,
            "helper executable can resolve from CWD or PATH");
    require(wcsncmp(command, L"\"C:\\Windows\\System32\\netsh.exe\" ", 32U) == 0,
            "command does not quote the explicit executable");
    require(wcscmp(directory, L"C:\\Windows\\System32") == 0, "helper inherits caller CWD");
    require(! inherit && process_attributes == NULL && thread_attributes == NULL, "helper inherits caller handles");
    require(flags == (CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT),
            "helper flags alter containment or show a console");
    require(startup->dwFlags == STARTF_USESTDHANDLES && startup->hStdInput == NULL && startup->hStdOutput == NULL &&
                startup->hStdError == NULL,
            "helper borrows diagnostic or input handles");
    require(environment != NULL, "helper inherits caller environment");
    const wchar_t *env = environment;
    require(wcscmp(env, L"SystemRoot=C:\\Windows") == 0, "unexpected helper SystemRoot");
    env += wcslen(env) + 1U;
    require(wcscmp(env, L"WINDIR=C:\\Windows") == 0, "unexpected helper WINDIR");
    env += wcslen(env) + 1U;
    require(*env == L'\0', "helper retains PATH or other inherited secrets");
    require(wcslen(command) < sizeof(entry->command) / sizeof(entry->command[0]), "command was not bounded");
    wcscpy(entry->command, command);
    child->hProcess = processHandle(create_count);
    child->hThread  = (HANDLE) ((uintptr_t) child->hProcess + 1U);
    ++create_count;
    if (entry->create_error != 0)
    {
        last_error = entry->create_error;
        return FALSE;
    }
    entry->created = true;
    return TRUE;
}

static DWORD WINAPI mockWaitForSingleObject(HANDLE handle, DWORD timeout)
{
    if (handle == HOST_STOP || handle == DEVICE_STOP)
    {
        require(timeout == 0U, "cancellation poll blocked");
        last_error = ERROR_INVALID_HANDLE;
        return handle == HOST_STOP ? host_wait : device_wait;
    }
    mock_child_t *entry = childForHandle(handle);
    require(entry->created && ! entry->process_closed, "wait used an unowned helper");
    require(timeout != INFINITE, "helper process wait is unbounded");
    if (entry->completed)
    {
        return WAIT_OBJECT_0;
    }
    if (timeout == 0U)
    {
        return WAIT_TIMEOUT;
    }
    if (entry->terminated && entry->reap_ms <= timeout)
    {
        now_ms += entry->reap_ms;
        entry->completed = true;
        return WAIT_OBJECT_0;
    }
    now_ms += timeout;
    return WAIT_TIMEOUT;
}

static DWORD WINAPI mockWaitForMultipleObjects(DWORD count, const HANDLE *handles, BOOL all, DWORD timeout)
{
    require(! all && count >= 1U && count <= 3U && timeout != INFINITE, "invalid or unbounded helper wait");
    mock_child_t *entry = childForHandle(handles[count - 1U]);
    require(entry->created && ! entry->process_closed, "wait used an unowned process");
    entry->wait_budget = timeout;
    entry->wait_count  = count;
    for (DWORD i = 0; i + 1U < count; ++i)
    {
        require(handles[i] == HOST_STOP || handles[i] == DEVICE_STOP, "wait includes an unrelated handle");
        for (DWORD j = 0; j < i; ++j)
        {
            require(handles[i] != handles[j], "wait duplicates a cancellation handle");
        }
        if ((handles[i] == HOST_STOP && host_wait == WAIT_OBJECT_0) ||
            (handles[i] == DEVICE_STOP && device_wait == WAIT_OBJECT_0))
        {
            return WAIT_OBJECT_0 + i;
        }
    }
    if (entry->wait == kMockHostStop || entry->wait == kMockDeviceStop)
    {
        HANDLE wanted = entry->wait == kMockHostStop ? HOST_STOP : DEVICE_STOP;
        for (DWORD i = 0; i + 1U < count; ++i)
        {
            if (handles[i] == wanted)
            {
                require(entry->run_ms <= timeout, "scripted cancellation exceeded operation budget");
                now_ms += entry->run_ms;
                if (wanted == HOST_STOP)
                    host_wait = WAIT_OBJECT_0;
                else
                    device_wait = WAIT_OBJECT_0;
                return WAIT_OBJECT_0 + i;
            }
        }
        require(false, "installation omitted requested cancellation event");
    }
    if (entry->wait == kMockTimeout || entry->run_ms > timeout)
    {
        now_ms += timeout;
        return WAIT_TIMEOUT;
    }
    now_ms += entry->run_ms;
    if (entry->wait == kMockWaitFailure)
    {
        last_error = ERROR_INVALID_HANDLE;
        return WAIT_FAILED;
    }
    entry->completed = true;
    if (entry->signal_after_exit)
    {
        host_wait = WAIT_OBJECT_0;
    }
    return WAIT_OBJECT_0 + count - 1U;
}

static BOOL WINAPI mockGetExitCodeProcess(HANDLE process, LPDWORD exit_code)
{
    mock_child_t *entry = childForHandle(process);
    require(entry->completed, "queried exit before process completion");
    if (entry->query_failure)
    {
        last_error = ERROR_ACCESS_DENIED;
        return FALSE;
    }
    *exit_code = entry->exit_code;
    return TRUE;
}

static BOOL WINAPI mockTerminateProcess(HANDLE process, UINT exit_code)
{
    mock_child_t *entry = childForHandle(process);
    require(exit_code == ERROR_CANCELLED && ! entry->process_closed, "invalid termination request");
    ++terminate_count;
    if (entry->terminate_failure)
    {
        last_error = ERROR_ACCESS_DENIED;
        return FALSE;
    }
    entry->terminated = true;
    return TRUE;
}

static BOOL WINAPI mockCloseHandle(HANDLE handle)
{
    if (((uintptr_t) handle & 1U) != 0U)
    {
        mock_child_t *entry = childForHandle((HANDLE) ((uintptr_t) handle - 1U));
        require(entry->created && ! entry->thread_closed, "thread handle closed more than once");
        entry->thread_closed = true;
    }
    else
    {
        mock_child_t *entry = childForHandle(handle);
        require(entry->created && entry->completed && ! entry->process_closed,
                "process handle lost before reap or closed more than once");
        entry->process_closed = true;
    }
    return TRUE;
}

#define GetTickCount64         mockGetTickCount64
#define GetLastError           mockGetLastError
#define GetSystemDirectoryW    mockGetSystemDirectoryW
#define GetWindowsDirectoryW   mockGetWindowsDirectoryW
#define CreateProcessW         mockCreateProcessW
#define WaitForSingleObject    mockWaitForSingleObject
#define WaitForMultipleObjects mockWaitForMultipleObjects
#define GetExitCodeProcess     mockGetExitCodeProcess
#define TerminateProcess       mockTerminateProcess
#define CloseHandle            mockCloseHandle
#include "../../ww/devices/tun/tun_windows_dns.c"

static void resetFixture(void)
{
    require(pending_helper == NULL, "previous scenario retained a helper");
    for (size_t i = 0; i < create_count; ++i)
    {
        require(! children[i].created || (children[i].process_closed && children[i].thread_closed),
                "scenario leaked process ownership");
    }
    memset(children, 0, sizeof(children));
    /* Each scenario represents a fresh process. Production shutdown is terminal. */
    helper_admission_closed = false;
    create_count            = 0;
    terminate_count         = 0;
    now_ms                  = 100U;
    last_error              = 0;
    host_wait               = WAIT_TIMEOUT;
    device_wait             = WAIT_TIMEOUT;
    system_path_result      = 1U;
    windows_path_result     = 1U;
    may_have_changed        = true; /* Every Set must initialize its explicit output. */
    tunWindowsDnsSetStartupStopEvent(HOST_STOP);
}

static const char *servers[] = {"192.0.2.1", "192.0.2.2"};

static void testSuccessAndSharedBudget(void)
{
    resetFixture();
    children[0].run_ms = 6000U;
    children[1].run_ms = 2000U;
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 2U, DEVICE_STOP, &may_have_changed) == kTunWindowsDnsSuccess &&
                may_have_changed,
            "valid two-server install failed");
    require(create_count == 2U && children[0].wait_budget == 9000U && children[1].wait_budget == 3000U &&
                now_ms == 8100U,
            "DNS commands restarted the shared installation budget");
    require(wcsstr(children[0].command, L" set dnsservers name=\"Waterwall Test\" ") != NULL &&
                wcsstr(children[0].command, L"address=192.0.2.1") != NULL &&
                wcsstr(children[1].command, L" add dnsservers name=\"Waterwall Test\" ") != NULL &&
                wcsstr(children[1].command, L"address=192.0.2.2 index=2") != NULL,
            "typed primary/secondary commands were not preserved");

    resetFixture();
    children[0].run_ms  = 6000U;
    children[1].wait    = kMockTimeout;
    children[1].reap_ms = 500U;
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 2U, DEVICE_STOP, &may_have_changed) == kTunWindowsDnsFailed &&
                may_have_changed && children[1].wait_budget == 3000U && terminate_count == 1U && now_ms <= 10100U,
            "second-command timeout exceeded the one installation deadline");
}

static void testCancellationAndCleanup(void)
{
    resetFixture();
    host_wait = WAIT_OBJECT_0;
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 2U, DEVICE_STOP, &may_have_changed) ==
                    kTunWindowsDnsCancelled &&
                create_count == 0 && ! may_have_changed,
            "pre-signaled stop started a DNS helper or claimed DNS changes");
    require(tunWindowsDnsClear(L"Waterwall Test") && create_count == 1U && children[0].wait_count == 1U &&
                children[0].wait_budget == 4000U,
            "cleanup reused installation cancellation or lacked its own budget");

    resetFixture();
    children[0].signal_after_exit = true;
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 2U, DEVICE_STOP, &may_have_changed) ==
                    kTunWindowsDnsCancelled &&
                create_count == 1U && may_have_changed,
            "stop between commands allowed secondary installation or lost partial ownership");

    for (int device = 0; device < 2; ++device)
    {
        resetFixture();
        children[0].wait   = device ? kMockDeviceStop : kMockHostStop;
        children[0].run_ms = 50U;
        require(tunWindowsDnsSet(L"Waterwall Test", servers, 2U, DEVICE_STOP, &may_have_changed) ==
                        kTunWindowsDnsCancelled &&
                    may_have_changed && create_count == 1U && terminate_count == 1U && children[0].process_closed,
                "stop during wait did not terminate and reap its helper");
    }
    resetFixture();
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 1U, HOST_STOP, &may_have_changed) == kTunWindowsDnsSuccess &&
                children[0].wait_count == 2U,
            "identical explicit stop handles were duplicated in the wait");
}

static void testFailureBoundaries(void)
{
    resetFixture();
    children[0].create_error = ERROR_FILE_NOT_FOUND;
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 2U, DEVICE_STOP, &may_have_changed) == kTunWindowsDnsFailed &&
                create_count == 1U && ! may_have_changed,
            "missing System32 helper did not fail without claiming DNS changes");
    resetFixture();
    children[1].exit_code = 5U;
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 2U, DEVICE_STOP, &may_have_changed) == kTunWindowsDnsFailed &&
                create_count == 2U && may_have_changed,
            "failed second command was reported successful or lost partial ownership");
    require(tunWindowsDnsClear(L"Waterwall Test") && create_count == 3U,
            "partial installation could not be independently cleared");
    resetFixture();
    children[0].query_failure = true;
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 1U, DEVICE_STOP, &may_have_changed) == kTunWindowsDnsFailed &&
                may_have_changed,
            "exit-query failure was accepted");
    resetFixture();
    children[0].wait = kMockWaitFailure;
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 1U, DEVICE_STOP, &may_have_changed) == kTunWindowsDnsFailed &&
                terminate_count == 1U && may_have_changed,
            "native wait failure did not fail and reap");
    resetFixture();
    host_wait = WAIT_FAILED;
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 1U, DEVICE_STOP, &may_have_changed) == kTunWindowsDnsFailed &&
                create_count == 0 && ! may_have_changed,
            "invalid cancellation handle was ignored");
    resetFixture();
    system_path_result = 0U;
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 1U, DEVICE_STOP, &may_have_changed) == kTunWindowsDnsFailed &&
                create_count == 0 && ! may_have_changed,
            "missing System32 path was accepted");
    resetFixture();
    windows_path_result = MAX_PATH;
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 1U, DEVICE_STOP, &may_have_changed) == kTunWindowsDnsFailed &&
                create_count == 0 && ! may_have_changed,
            "truncated Windows environment path was accepted");
    resetFixture();
    wchar_t oversized[1100];
    for (size_t i = 0; i + 1U < sizeof(oversized) / sizeof(oversized[0]); ++i)
        oversized[i] = L'A';
    oversized[1099] = L'\0';
    require(tunWindowsDnsSet(oversized, servers, 1U, DEVICE_STOP, &may_have_changed) == kTunWindowsDnsFailed &&
                create_count == 0 && ! may_have_changed,
            "truncated adapter command was launched");
    require(! tunWindowsDnsClear(oversized) && create_count == 0, "truncated cleanup command was launched");
}

static void testPendingOwnership(void)
{
    resetFixture();
    children[0].wait              = kMockTimeout;
    children[0].terminate_failure = true;
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 1U, DEVICE_STOP, &may_have_changed) == kTunWindowsDnsFailed &&
                may_have_changed && ! children[0].process_closed && children[0].thread_closed && now_ms == 10100U,
            "failed termination lost its sole pending ownership handle");
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 1U, DEVICE_STOP, &may_have_changed) == kTunWindowsDnsFailed &&
                create_count == 1U && ! may_have_changed,
            "unsettled helper allowed another installation or claimed a new DNS change");
    ULONGLONG before = now_ms;
    require(! tunWindowsDnsClear(L"Waterwall Test") && ! children[0].process_closed && now_ms - before <= 1000U,
            "pending cleanup settlement was unbounded or discarded live ownership");
    children[0].terminate_failure = false;
    children[0].reap_ms           = 700U;
    children[1].wait              = kMockTimeout;
    children[1].reap_ms           = 900U;
    before                        = now_ms;
    require(! tunWindowsDnsClear(L"Waterwall Test") && children[0].process_closed && children[1].process_closed &&
                now_ms - before <= 5000U,
            "pending reap and cleanup command did not share one cleanup budget");
    require(tunWindowsDnsShutdown(), "completed helpers remained pending");
}

static void testShutdownClosesAdmission(void)
{
    resetFixture();
    children[0].wait              = kMockTimeout;
    children[0].terminate_failure = true;
    require(! tunWindowsDnsClear(L"Waterwall Test") && pending_helper == processHandle(0),
            "failed quiescence cleanup lost its pending helper");
    ULONGLONG before = now_ms;
    require(! tunWindowsDnsShutdown() && pending_helper == processHandle(0) && now_ms - before <= 1000U,
            "failed final settlement lost ownership or exceeded its budget");
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 1U, DEVICE_STOP, &may_have_changed) == kTunWindowsDnsFailed &&
                ! may_have_changed && ! tunWindowsDnsClear(L"Waterwall Test") && create_count == 1U,
            "failed final settlement admitted a new DNS helper");
    children[0].terminate_failure = false;
    children[0].reap_ms           = 700U;
    before                        = now_ms;
    require(tunWindowsDnsShutdown() && pending_helper == NULL && children[0].process_closed && now_ms - before <= 1000U,
            "repeated shutdown could not settle its existing helper");
    /* Node destruction follows finalization and retries retained policy. It
     * must not create another helper after
     * the final settlement boundary. */
    require(! tunWindowsDnsClear(L"Waterwall Test") && create_count == 1U && pending_helper == NULL,
            "DNS cleanup launched a helper after final settlement");
    require(tunWindowsDnsSet(L"Waterwall Test", servers, 1U, DEVICE_STOP, &may_have_changed) == kTunWindowsDnsFailed &&
                ! may_have_changed && create_count == 1U && tunWindowsDnsShutdown(),
            "DNS installation reopened admission after shutdown");
}

int main(void)
{
    testSuccessAndSharedBudget();
    testCancellationAndCleanup();
    testFailureBoundaries();
    testPendingOwnership();
    testShutdownClosesAdmission();
    resetFixture();
    return 0;
}
