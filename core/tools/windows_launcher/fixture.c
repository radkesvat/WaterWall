#include "startup_options.h"
#include "windows_session_effects.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(int argc, char **argv)
{
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
    fflush(NULL);
    if (getenv("WW_FIXTURE_ABRUPT") != NULL)
        TerminateProcess(GetCurrentProcess(), 0xc0000005U);
    complete();
    ExitProcess(exit_code == NULL ? 0 : (DWORD) strtoull(exit_code, NULL, 0));
    return 0;
}
