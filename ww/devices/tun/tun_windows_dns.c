#include "tun_windows_dns.h"
#include "tun_windows_ownership.h"

#include <assert.h>
#include <stdio.h>
#include <wchar.h>

enum
{
    kDnsInstallBudgetMs = 10000,
    kDnsCleanupBudgetMs = 5000,
    kDnsReapBudgetMs    = 1000,
    kDnsCommandCapacity = 1024
};

/* Startup, DNS operations, and finalization all run on the main owner thread. */
static HANDLE startup_stop_event;
static HANDLE pending_helper;
static bool   helper_admission_closed;

void tunWindowsDnsSetStartupStopEvent(HANDLE stop_event)
{
    startup_stop_event = stop_event;
}

static DWORD dnsRemaining(ULONGLONG deadline)
{
    ULONGLONG now = GetTickCount64();
    return now < deadline ? (DWORD) (deadline - now) : 0;
}

static void dnsError(const char *operation, DWORD error)
{
    fprintf(stderr, "TunDevice: DNS helper %s failed (Windows error %lu)\n", operation, (unsigned long) error);
}

static bool dnsReap(HANDLE process, ULONGLONG deadline)
{
    DWORD wait = WaitForSingleObject(process, 0);
    if (wait != WAIT_OBJECT_0)
    {
        if (! TerminateProcess(process, ERROR_CANCELLED))
        {
            dnsError("termination", GetLastError());
        }
        wait = WaitForSingleObject(process, dnsRemaining(deadline));
    }
    if (wait != WAIT_OBJECT_0)
    {
        dnsError("reap", wait == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT);
        return false;
    }
    CloseHandle(process);
    return true;
}

bool tunWindowsDnsShutdown(void)
{
    /* Node destruction can retry retained DNS policy after this finalizer.
     * Close admission before settlement so those retries cannot create a new
     * helper after the last process owner has drained its inventory. */
    helper_admission_closed = true;
    if (pending_helper == NULL)
    {
        return true;
    }
    if (! dnsReap(pending_helper, GetTickCount64() + kDnsReapBudgetMs))
    {
        return false;
    }
    pending_helper = NULL;
    return true;
}

static tun_windows_dns_result_e dnsCancellation(HANDLE device_stop)
{
    HANDLE events[2] = {startup_stop_event, device_stop};
    for (size_t i = 0; i < 2; ++i)
    {
        if (events[i] == NULL)
        {
            continue;
        }
        DWORD wait = WaitForSingleObject(events[i], 0);
        if (wait == WAIT_OBJECT_0)
        {
            return kTunWindowsDnsCancelled;
        }
        if (wait != WAIT_TIMEOUT)
        {
            dnsError("cancellation wait", wait == WAIT_FAILED ? GetLastError() : ERROR_INVALID_HANDLE);
            return kTunWindowsDnsFailed;
        }
    }
    return kTunWindowsDnsSuccess;
}

static tun_windows_dns_result_e dnsRun(const wchar_t *arguments, HANDLE ownership, ULONGLONG deadline, bool install,
                                       HANDLE device_stop, bool *may_have_changed)
{
    assert(pending_helper == NULL);
    if (install)
    {
        tun_windows_dns_result_e cancelled = dnsCancellation(device_stop);
        if (cancelled != kTunWindowsDnsSuccess)
        {
            return cancelled;
        }
    }
    if (dnsRemaining(deadline) <= kDnsReapBudgetMs)
    {
        dnsError("operation budget", ERROR_TIMEOUT);
        return kTunWindowsDnsFailed;
    }

    wchar_t system_directory[MAX_PATH];
    UINT    length = GetSystemDirectoryW(system_directory, MAX_PATH);
    if (length == 0 || length >= MAX_PATH)
    {
        dnsError("System32 path", length == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER);
        return kTunWindowsDnsFailed;
    }
    wchar_t windows_directory[MAX_PATH];
    length = GetWindowsDirectoryW(windows_directory, MAX_PATH);
    if (length == 0 || length >= MAX_PATH)
    {
        dnsError("Windows path", length == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER);
        return kTunWindowsDnsFailed;
    }
    wchar_t executable[MAX_PATH];
    int     written = swprintf(executable, MAX_PATH, L"%ls\\netsh.exe", system_directory);
    if (written < 0 || written >= MAX_PATH)
    {
        dnsError("executable path", ERROR_INSUFFICIENT_BUFFER);
        return kTunWindowsDnsFailed;
    }
    wchar_t command[kDnsCommandCapacity];
    written = swprintf(command, kDnsCommandCapacity, L"\"%ls\" %ls", executable, arguments);
    if (written < 0 || written >= kDnsCommandCapacity)
    {
        dnsError("command construction", ERROR_INSUFFICIENT_BUFFER);
        return kTunWindowsDnsFailed;
    }
    /* Explicit double-NUL environment; no inherited credentials or PATH. */
    wchar_t environment[2 * MAX_PATH + 32] = {0};
    size_t  capacity                       = sizeof(environment) / sizeof(environment[0]);
    written                                = swprintf(environment, capacity, L"SystemRoot=%ls", windows_directory);
    if (written < 0 || (size_t) written + 2 >= capacity)
    {
        return kTunWindowsDnsFailed;
    }
    size_t offset = (size_t) written + 1;
    written       = swprintf(environment + offset, capacity - offset - 1, L"WINDIR=%ls", windows_directory);
    if (written < 0 || (size_t) written >= capacity - offset - 1)
    {
        return kTunWindowsDnsFailed;
    }

    PROCESS_INFORMATION child = {0};
    if (! tunWindowsOwnershipStartHelper(ownership, executable, command, environment, system_directory, &child))
    {
        dnsError("creation", GetLastError());
        return kTunWindowsDnsFailed;
    }
    CloseHandle(child.hThread);
    if (may_have_changed != NULL)
    {
        *may_have_changed = true;
    }

    HANDLE waits[3];
    DWORD  count = 0;
    if (install && startup_stop_event != NULL)
    {
        waits[count++] = startup_stop_event;
    }
    if (install && device_stop != NULL && device_stop != startup_stop_event)
    {
        waits[count++] = device_stop;
    }
    DWORD process_index = count;
    waits[count++]      = child.hProcess;
    DWORD remaining     = dnsRemaining(deadline);
    DWORD wait =
        WaitForMultipleObjects(count, waits, FALSE, remaining > kDnsReapBudgetMs ? remaining - kDnsReapBudgetMs : 0);
    if (wait == WAIT_OBJECT_0 + process_index)
    {
        DWORD exit_code;
        BOOL  queried = GetExitCodeProcess(child.hProcess, &exit_code);
        DWORD error   = queried ? exit_code : GetLastError();
        CloseHandle(child.hProcess);
        if (! queried || exit_code != 0)
        {
            dnsError("exit", error);
            return kTunWindowsDnsFailed;
        }
        return kTunWindowsDnsSuccess;
    }

    bool cancelled = wait < WAIT_OBJECT_0 + process_index;
    if (! cancelled)
    {
        dnsError("wait", wait == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT);
    }
    if (! dnsReap(child.hProcess, deadline))
    {
        /* Keep the only ownership handle. No further helper may start until
         * bounded final settlement proves this process has exited. */
        pending_helper = child.hProcess;
        return kTunWindowsDnsFailed;
    }
    return cancelled ? kTunWindowsDnsCancelled : kTunWindowsDnsFailed;
}

tun_windows_dns_result_e tunWindowsDnsSet(const wchar_t *adapter, HANDLE ownership, const char *const *servers,
                                          size_t count, HANDLE device_stop, bool *may_have_changed)
{
    assert(count > 0 && count <= 2);
    *may_have_changed = false;
    if (helper_admission_closed)
    {
        dnsError("admission after shutdown", ERROR_OPERATION_ABORTED);
        return kTunWindowsDnsFailed;
    }
    if (pending_helper != NULL)
    {
        dnsError("unsettled previous process", ERROR_BUSY);
        return kTunWindowsDnsFailed;
    }
    ULONGLONG deadline = GetTickCount64() + kDnsInstallBudgetMs;
    for (size_t i = 0; i < count; ++i)
    {
        wchar_t server[16];
        size_t  j = 0;
        for (; servers[i][j] != '\0' && j < 15; ++j)
        {
            server[j] = (wchar_t) (unsigned char) servers[i][j];
        }
        if (servers[i][j] != '\0')
        {
            return kTunWindowsDnsFailed;
        }
        server[j] = L'\0';
        wchar_t arguments[kDnsCommandCapacity];
        int     written =
            i == 0
                    ? swprintf(
                      arguments,
                      kDnsCommandCapacity,
                      L"interface ipv4 set dnsservers name=\"%ls\" source=static address=%ls register=none validate=no",
                      adapter,
                      server)
                    : swprintf(arguments,
                           kDnsCommandCapacity,
                           L"interface ipv4 add dnsservers name=\"%ls\" address=%ls index=2 validate=no",
                           adapter,
                           server);
        if (written < 0 || written >= kDnsCommandCapacity)
        {
            dnsError("DNS argument construction", ERROR_INSUFFICIENT_BUFFER);
            return kTunWindowsDnsFailed;
        }
        tun_windows_dns_result_e result = dnsRun(arguments, ownership, deadline, true, device_stop, may_have_changed);
        if (result != kTunWindowsDnsSuccess)
        {
            return result;
        }
    }
    return kTunWindowsDnsSuccess;
}

bool tunWindowsDnsClear(const wchar_t *adapter, HANDLE ownership)
{
    if (helper_admission_closed)
    {
        dnsError("admission after shutdown", ERROR_OPERATION_ABORTED);
        return false;
    }
    ULONGLONG deadline = GetTickCount64() + kDnsCleanupBudgetMs;
    if (pending_helper != NULL)
    {
        ULONGLONG reap_deadline = GetTickCount64() + kDnsReapBudgetMs;
        if (reap_deadline > deadline)
        {
            reap_deadline = deadline;
        }
        if (! dnsReap(pending_helper, reap_deadline))
        {
            return false;
        }
        pending_helper = NULL;
    }
    wchar_t arguments[kDnsCommandCapacity];
    int     written = swprintf(
        arguments, kDnsCommandCapacity, L"interface ipv4 delete dnsservers name=\"%ls\" all validate=no", adapter);
    if (written < 0 || written >= kDnsCommandCapacity)
    {
        dnsError("cleanup argument construction", ERROR_INSUFFICIENT_BUFFER);
        return false;
    }
    return dnsRun(arguments, ownership, deadline, false, NULL, NULL) == kTunWindowsDnsSuccess;
}
