#include "startup_options.h"
#include "windows_kill_switch_control.h"
#include "windows_session_effects.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

#ifdef _MSC_VER
__declspec(thread) static int tls_value = 42;
#else
static __thread int tls_value = 42;
#endif

__declspec(dllimport) int fixtureCompanion(void);

static HANDLE completion_event;
static void   complete(void)
{
    if (completion_event != NULL)
        SetEvent(completion_event);
}

static bool killSwitchTransfer(HANDLE pipe, ww_kill_switch_message_t *message, bool sending)
{
    OVERLAPPED transfer = {0};
    transfer.hEvent     = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (transfer.hEvent == NULL)
        return false;
    DWORD size = 0;
    BOOL  ok   = sending ? WriteFile(pipe, message, sizeof(*message), &size, &transfer)
                         : ReadFile(pipe, message, sizeof(*message), &size, &transfer);
    if (! ok && GetLastError() == ERROR_IO_PENDING)
    {
        if (WaitForSingleObject(transfer.hEvent, 5000) == WAIT_OBJECT_0)
            ok = GetOverlappedResult(pipe, &transfer, &size, FALSE);
        else
        {
            CancelIoEx(pipe, &transfer);
            GetOverlappedResult(pipe, &transfer, &size, TRUE);
        }
    }
    CloseHandle(transfer.hEvent);
    return ok && size == sizeof(*message);
}

static bool killSwitchTrace(const char *event)
{
    const char *path = getenv("WW_FIXTURE_KILL_SWITCH_TRACE");
    FILE       *file = path == NULL ? NULL : fopen(path, "ab");
    if (file == NULL)
        return false;
    fprintf(file, "%s\n", event);
    return fclose(file) == 0;
}

static bool killSwitchExchange(HANDLE pipe, ww_kill_switch_message_t *request)
{
    if (! killSwitchTransfer(pipe, request, true))
        return false;
    ww_kill_switch_message_t reply;
    if (! killSwitchTransfer(pipe, &reply, false))
        return false;
    request->type = WW_KILL_SWITCH_ACK;
    return memcmp(&reply, request, sizeof(reply)) == 0;
}

static bool publishFixtureReady(const char *path)
{
    FILE *file = fopen(path, "wb");
    return file != NULL && fclose(file) == 0;
}

/* The helper shares the fixture Job and remains alive after the runtime exits. */
static bool startSettlementHelper(void)
{
    wchar_t path[32768];
    DWORD   length = GetModuleFileNameW(NULL, path, ARRAYSIZE(path));
    if (length == 0 || length >= ARRAYSIZE(path))
        return false;
    wchar_t             command[] = L"fixture --settlement-helper";
    STARTUPINFOW        startup   = {.cb = sizeof(startup)};
    PROCESS_INFORMATION process;
    if (! CreateProcessW(path, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process))
        return false;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return true;
}

static bool exerciseKillSwitch(HANDLE pipe, const waterwall_startup_options_t *options)
{
    if (! killSwitchTrace("child"))
        return false;
    const char *granted = getenv("WW_FIXTURE_KILL_SWITCH_IMAGE");
    wchar_t     expected[32768], actual[32768];
    FILE       *report = granted == NULL ? NULL : fopen(granted, "rb");
    if (report == NULL)
        return false;
    size_t count  = fread(expected, sizeof(*expected), sizeof(expected) / sizeof(*expected), report);
    int    closed = fclose(report);
    DWORD  length = GetModuleFileNameW(NULL, actual, sizeof(actual) / sizeof(*actual));
    if (closed != 0 || length == 0 || length >= sizeof(actual) / sizeof(*actual) || count == 0 ||
        expected[count - 1] != L'\0')
        return false;
    /* GetModuleFileNameW can omit the extended-length prefix supplied to
     * CreateProcessW. Both names are absolute drive paths. */
    const wchar_t *expected_dos = wcsncmp(expected, L"\\\\?\\", 4) == 0 ? expected + 4 : expected;
    const wchar_t *actual_dos   = wcsncmp(actual, L"\\\\?\\", 4) == 0 ? actual + 4 : actual;
    if (CompareStringOrdinal(expected_dos, -1, actual_dos, -1, TRUE) != CSTR_EQUAL)
        return false;
    ww_kill_switch_message_t message;
    if (! killSwitchTransfer(pipe, &message, false) || message.magic != WW_KILL_SWITCH_MESSAGE_MAGIC ||
        message.type != WW_KILL_SWITCH_UPLINK || message.luid != 11 || message.index != 12 || message.reserved != 0)
        return false;

    const char *mode = getenv("WW_FIXTURE_KILL_SWITCH_MODE");
    if (mode != NULL && strcmp(mode, "missing") == 0)
        return true;
    const GUID guid = {0xe29ab127, 0x332a, 0x42b8, {0x97, 0x43, 0x17, 0xfa, 0xf2, 0x19, 0x74, 0x11}};
    message.type    = WW_KILL_SWITCH_REGISTER;
    message.luid    = 21;
    message.index   = 22;
    message.guid    = guid;
    if (mode != NULL && strcmp(mode, "mismatch") == 0)
        message.guid.Data1++;
    if (! killSwitchExchange(pipe, &message) || ! killSwitchTrace("register-ack"))
        return false;
    if (mode != NULL && strcmp(mode, "duplicate") == 0)
    {
        message.type = WW_KILL_SWITCH_REGISTER;
        return killSwitchExchange(pipe, &message);
    }
    if (! SetEvent((HANDLE) options->ready_event))
        return false;
    if (mode != NULL && strcmp(mode, "crash") == 0)
        TerminateProcess(GetCurrentProcess(), 0xc0000005U);
    const char *hold = getenv("WW_FIXTURE_KILL_SWITCH_HOLD");
    if (hold != NULL)
    {
        if (! publishFixtureReady(hold))
            return false;
        if (getenv("WW_FIXTURE_CLOSE_CONSOLE") != NULL)
        {
            /* Close only the private fixture window. The detached child continues
             * its delayed teardown after the public launcher's handler requests stop. */
            HWND  window = GetConsoleWindow();
            DWORD clients[2];
            ULONG launcher_pid;
            if (window == NULL || GetConsoleProcessList(clients, 2) != 2 ||
                ! GetNamedPipeServerProcessId(pipe, &launcher_pid) ||
                (clients[0] != launcher_pid && clients[1] != launcher_pid) || ! FreeConsole() ||
                ! PostMessageW(window, WM_CLOSE, 0, 0))
                return false;
        }
        if (WaitForSingleObject((HANDLE) options->stop_event, 60000) != WAIT_OBJECT_0)
            return false;
        if (getenv("WW_FIXTURE_KILL_SWITCH_HANG_AT_STOP") != NULL)
            Sleep(INFINITE);
        const char *delay = getenv("WW_FIXTURE_KILL_SWITCH_STOP_DELAY_MS");
        if (delay != NULL)
            Sleep((DWORD) strtoul(delay, NULL, 10));
    }
    message.type = WW_KILL_SWITCH_REVOKE;
    return killSwitchExchange(pipe, &message) && killSwitchTrace("revoke-ack");
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--settlement-helper") == 0)
    {
        Sleep(7000);
        return 0;
    }
    waterwall_handoff_t handoff  = {0};
    int                 received = waterwallStartupHandoffExtract(&argc, argv, &handoff);
    if (received < 0 || tls_value != 42 || fixtureCompanion() != 73)
        return 81;
    waterwall_startup_options_t          options = {0};
    waterwall_startup_arguments_result_e result  = waterwallStartupOptionsParse(argc, argv, &options);
    if (result != kWaterwallStartupArgumentsRun)
    {
        waterwallStartupHandoffCleanup(&handoff);
        return result == kWaterwallStartupArgumentsExitSuccess ? 0 : 1;
    }
    completion_event = (HANDLE) handoff.completion_event;
    atexit(complete);
    char  *content = NULL;
    size_t length  = 0;
    if (received)
    {
        const char *expected_exe = getenv("WW_FIXTURE_ORIGINAL");
        if (expected_exe != NULL && strcmp(expected_exe, handoff.orig_exe) != 0)
        {
            fprintf(stderr,
                    "Original executable mismatch: expected \"%s\", received \"%s\"\n",
                    expected_exe,
                    handoff.orig_exe);
            return 84;
        }
        if (getenv("WW_FIXTURE_REMOVE_SOURCE") != NULL && remove(handoff.source_name) != 0)
            return 85;
        if (waterwallStartupHandoffReceive(&handoff, options.restricted_config, &content, &length))
            return 82;
    }
    else
        content = waterwallStartupOptionsReadCoreJson(&options, &length);
    if (content == NULL)
        return 83;
    const char *ordinary_hold = getenv("WW_FIXTURE_ORDINARY_HOLD");
    if (ordinary_hold != NULL && (handoff.kill_switch_control != 0 || ! SetEvent((HANDLE) options.ready_event) ||
                                  ! publishFixtureReady(ordinary_hold) ||
                                  WaitForSingleObject((HANDLE) options.stop_event, 60000) != WAIT_OBJECT_0))
        return 87;
    if (handoff.kill_switch_control != 0)
    {
        HANDLE retired = (HANDLE) handoff.kill_switch_retired;
        if (WaitForSingleObject(retired, 0) != WAIT_TIMEOUT)
            return 94;
        if (! exerciseKillSwitch((HANDLE) handoff.kill_switch_control, &options))
        {
            CloseHandle((HANDLE) handoff.kill_switch_control);
            if (WaitForSingleObject(retired, 5000) != WAIT_OBJECT_0 || ! killSwitchTrace("retired"))
                return 95;
            if (getenv("WW_FIXTURE_STOP_AT_REGISTER") != NULL &&
                WaitForSingleObject((HANDLE) options.stop_event, 0) == WAIT_OBJECT_0)
                return 0;
            return 94;
        }
        if (getenv("WW_FIXTURE_DELAY_EXIT_AFTER_CLOSE") != NULL)
        {
            CloseHandle((HANDLE) handoff.kill_switch_control);
            handoff.kill_switch_control = 0;
            if (WaitForSingleObject(retired, 5000) != WAIT_OBJECT_0 || ! killSwitchTrace("retired"))
                return 95;
            /* Model runtime cleanup after confirmed retirement, beyond a policy poll. */
            Sleep(750);
        }
    }
    const char *adapter_state = getenv("WW_FIXTURE_ADAPTER_STATE");
    if (adapter_state != NULL || getenv("WW_FIXTURE_DRIVER_RESIDUE") != NULL)
    {
        windows_session_effects_t *effects =
            MapViewOfFile((HANDLE) handoff.effects_mapping, FILE_MAP_WRITE, 0, 0, sizeof(*effects));
        if (effects == NULL)
            return 92;
        GUID guid = {0xd52902a1, 0x5cbb, 0x4e21, {0x9e, 0x21, 0x40, 0x57, 0xd4, 0xb7, 0x04, 0x26}};
        if (adapter_state != NULL && strcmp(adapter_state, "present") == 0)
        {
            MIB_IF_TABLE2 *interfaces = NULL;
            if (GetIfTable2(&interfaces) != NO_ERROR || interfaces->NumEntries == 0)
                return 92;
            guid = interfaces->Table[0].InterfaceGuid;
            FreeMibTable(interfaces);
        }
        if (adapter_state != NULL)
        {
            effects->adapters[0].guid = guid;
            InterlockedExchange(&effects->adapters[0].state, strcmp(adapter_state, "pending") == 0 ? 1 : 2);
        }
        if (getenv("WW_FIXTURE_DRIVER_RESIDUE") != NULL)
            InterlockedExchange(&effects->driver_residue, 1);
        UnmapViewOfFile(effects);
    }
    const char *image_report = getenv("WW_FIXTURE_IMAGE_REPORT");
    if (image_report != NULL)
    {
        wchar_t image[32768];
        DWORD   count  = GetModuleFileNameW(NULL, image, 32768);
        FILE   *report = fopen(image_report, "wb");
        if (count == 0 || count >= 32768 || report == NULL)
            return 86;
        size_t written = fwrite(image, sizeof(wchar_t), count, report);
        int    closed  = fclose(report);
        if (written != count || closed != 0)
            return 86;
    }
    unsigned long hash = 2166136261u;
    for (size_t i = 0; i < length; ++i)
        hash = (hash ^ (unsigned char) content[i]) * 16777619u;
    printf("snapshot:%zu:%08lx\n", length, hash);
    fprintf(stderr, "fixture-stderr\n");
    free(content);
    waterwallStartupHandoffCleanup(&handoff);
    if (options.stop_event != 0 && getenv("WW_FIXTURE_LIFECYCLE") != NULL)
    {
        HANDLE stop  = (HANDLE) options.stop_event;
        HANDLE ready = (HANDLE) options.ready_event;
        if ((GetConsoleWindow() != NULL) != (getenv("WW_FIXTURE_VISIBLE") != NULL))
            return 87;
        /* The native client fixture supplies least-rights capabilities; the
         * launcher must preserve them across its additional process boundary. */
        if (SetEvent(stop) || GetLastError() != ERROR_ACCESS_DENIED)
            return 87;
        if (ready != NULL && (WaitForSingleObject(ready, 0) != WAIT_FAILED || GetLastError() != ERROR_ACCESS_DENIED))
            return 88;
        DWORD stopped = WaitForSingleObject(stop, 0);
        if (stopped != WAIT_OBJECT_0 && stopped != WAIT_TIMEOUT)
            return 89;
        if (stopped == WAIT_TIMEOUT)
        {
            if (ready != NULL && ! SetEvent(ready))
                return 90;
            printf("lifecycle-fixture-waiting:%lu\n", GetCurrentProcessId());
            fflush(NULL);
            if (WaitForSingleObject(stop, 15000) != WAIT_OBJECT_0)
                return 91;
        }
        wchar_t stopped_name[128];
        if (GetEnvironmentVariableW(L"WW_FIXTURE_STOP_OBSERVED", stopped_name, 128) != 0)
        {
            /* The client kills the public launcher only after recovery has
             * opened its Job and requested stop. No timing-based injection. */
            HANDLE observed = OpenEventW(EVENT_MODIFY_STATE, FALSE, stopped_name);
            if (observed == NULL || ! SetEvent(observed))
                return 93;
            CloseHandle(observed);
            Sleep(INFINITE);
        }
        CloseHandle(stop);
        if (ready != NULL)
            CloseHandle(ready);
    }
    const char *exit_code = getenv("WW_FIXTURE_EXIT");
    if (getenv("WW_FIXTURE_SETTLEMENT_HELPER") != NULL && ! startSettlementHelper())
        return 96;
    fflush(NULL);
    if (getenv("WW_FIXTURE_ABRUPT") != NULL)
        TerminateProcess(GetCurrentProcess(), 0xc0000005U);
    complete();
    if (getenv("WW_FIXTURE_DELAY_EXIT_AFTER_CLOSE") != NULL && ! killSwitchTrace("child-exiting"))
        return 95;
    ExitProcess(exit_code == NULL ? 0 : (DWORD) strtoull(exit_code, NULL, 0));
    return 0;
}
