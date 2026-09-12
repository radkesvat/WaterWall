#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

static void require(BOOL value, const char *message)
{
    if (! value)
    {
        DWORD error = GetLastError();
        fflush(stdout);
        fprintf(stderr, "%s (Windows error %lu)\n", message, error);
        ExitProcess(1);
    }
}
static HANDLE inherit(HANDLE handle, DWORD access)
{
    HANDLE copy;
    require(DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &copy, access, TRUE, 0), "duplicate");
    return copy;
}
static HANDLE launch_input;
static HANDLE launch_output;

static PROCESS_INFORMATION launch(wchar_t *command, HANDLE *handles, size_t count)
{
    STARTUPINFOEXW      startup = {0};
    PROCESS_INFORMATION child   = {0};
    SIZE_T              size    = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    startup.lpAttributeList = malloc(size);
    require(startup.lpAttributeList != NULL && InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size),
            "attributes");
    require(
        UpdateProcThreadAttribute(
            startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, count * sizeof(HANDLE), NULL, NULL),
        "handle list");
    startup.StartupInfo.cb         = sizeof(startup);
    startup.StartupInfo.dwFlags    = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput  = launch_input;
    startup.StartupInfo.hStdOutput = launch_output;
    startup.StartupInfo.hStdError  = launch_output;
    require(CreateProcessW(NULL,
                           command,
                           NULL,
                           NULL,
                           TRUE,
                           EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                           NULL,
                           NULL,
                           &startup.StartupInfo,
                           &child),
            "launch");
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    CloseHandle(child.hThread);
    return child;
}
static DWORD await(PROCESS_INFORMATION child)
{
    DWORD code;
    require(WaitForSingleObject(child.hProcess, 30000) == WAIT_OBJECT_0, "bounded public exit");
    require(GetExitCodeProcess(child.hProcess, &code), "exit status");
    CloseHandle(child.hProcess);
    return code;
}
int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--controller") == 0)
    {
        Sleep(60000);
        return 0;
    }
    bool     production  = argc == 4 && strcmp(argv[1], "--production") == 0;
    bool     single_case = argc == 4 && strcmp(argv[1], "--case") == 0;
    unsigned selected    = 0;
    if (single_case)
    {
        char         *end;
        unsigned long value = strtoul(argv[2], &end, 10);
        require(argv[2][0] >= '0' && argv[2][0] <= '9' && *end == 0 && value < 16, "invalid case number");
        selected = (unsigned) value;
    }
    require(production || single_case || argc == 2, "expected launcher path, --case N EXE, or --production EXE CONFIG");
    wchar_t launcher[32768], temporary[MAX_PATH], config[MAX_PATH], journal[MAX_PATH];
    require(MultiByteToWideChar(CP_ACP,
                                0,
                                argv[production    ? 2
                                     : single_case ? 3
                                                   : 1],
                                -1,
                                launcher,
                                32768),
            "launcher path");
    require(GetTempPathW(MAX_PATH, temporary), "temporary path");
    if (production)
    {
        require(MultiByteToWideChar(CP_ACP, 0, argv[3], -1, config, MAX_PATH), "production config path");
    }
    else
    {
        require(GetTempFileNameW(temporary, L"wwc", 0, config), "config path");
        HANDLE file = CreateFileW(config, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        DWORD  written;
        require(file != INVALID_HANDLE_VALUE && WriteFile(file, "{}", 2, &written, NULL) && written == 2, "config");
        CloseHandle(file);
    }
    SetEnvironmentVariableW(L"WW_FIXTURE_LIFECYCLE", L"1");
    HANDLE stop = CreateEventW(NULL, TRUE, FALSE, NULL), ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    require(stop != NULL && ready != NULL, "events");
    HANDLE capabilities[5] = {
        inherit(stop, SYNCHRONIZE), inherit(ready, EVENT_MODIFY_STATE), inherit(GetCurrentProcess(), SYNCHRONIZE)};
    for (unsigned mode = 0; mode < 16; ++mode)
    {
        if (single_case && mode != selected)
            continue;
        if (production && (mode == 1 || mode >= 4))
            continue;
        SetEnvironmentVariableW(L"WW_FIXTURE_EXIT", mode == 7 ? L"0xc0000005" : NULL);
        SetEnvironmentVariableW(L"WW_FIXTURE_ABRUPT", mode == 11 || mode == 13 ? L"1" : NULL);
        SetEnvironmentVariableW(L"WW_FIXTURE_DRIVER_RESIDUE", mode == 14 ? L"1" : NULL);
        SetEnvironmentVariableW(L"WW_FIXTURE_CREATE_FAILURE", mode == 10 ? L"1" : NULL);
        // launch() uses CREATE_NO_WINDOW. Visible startup must replace its
        // windowless console even though GetConsoleWindow() returns NULL.
        bool visible = mode == 8 || mode == 9;
        SetEnvironmentVariableW(L"WW_FIXTURE_VISIBLE", visible ? L"1" : NULL);
        SetEnvironmentVariableW(L"WW_FIXTURE_ADAPTER_STATE",
                                mode == 5 || mode == 15   ? L"absent"
                                : mode == 6 || mode == 12 ? L"present"
                                : mode == 13              ? L"pending"
                                                          : NULL);
        bool    live_recovery = mode == 12 || mode == 15;
        HANDLE  stop_observed = NULL;
        wchar_t stopped_name[128];
        if (mode == 15)
        {
            swprintf(stopped_name,
                     128,
                     L"Local\\Waterwall.RecoveryFixture.%lu.%llu",
                     GetCurrentProcessId(),
                     (unsigned long long) GetTickCount64());
            stop_observed = CreateEventW(NULL, TRUE, FALSE, stopped_name);
            require(stop_observed != NULL && GetLastError() != ERROR_ALREADY_EXISTS, "stop observation event");
        }
        SetEnvironmentVariableW(L"WW_FIXTURE_STOP_OBSERVED", mode == 15 ? stopped_name : NULL);
        if (mode >= 5)
        {
            CloseHandle(capabilities[2]);
            capabilities[2] = inherit(GetCurrentProcess(), SYNCHRONIZE);
        }
        ResetEvent(stop);
        ResetEvent(ready);
        PROCESS_INFORMATION controller = {0};
        if (mode >= 2 && mode <= 4)
        {
            wchar_t self[32768], command[32768];
            require(GetModuleFileNameW(NULL, self, 32768), "controller image");
            swprintf(command, 32768, L"\"%ls\" --controller", self);
            controller = launch(command, capabilities, 3);
            CloseHandle(capabilities[2]);
            capabilities[2] = inherit(controller.hProcess, SYNCHRONIZE);
            if (mode == 3)
            {
                require(TerminateProcess(controller.hProcess, 94), "pre-launch controller loss");
                require(WaitForSingleObject(controller.hProcess, 5000) == WAIT_OBJECT_0, "controller death");
            }
        }
        require(GetTempFileNameW(temporary, L"wws", 0, journal) && DeleteFileW(journal), "journal path");
        wchar_t command[32768];
        swprintf(command,
                 32768,
                 L"\"%ls\" --restricted-config \"-c:%ls\" --stop-event:%llu --ready-event:%llu "
                 L"--controller-process:%llu --console:%ls \"--session-file:%ls\"",
                 launcher,
                 config,
                 (unsigned long long) (uintptr_t) capabilities[0],
                 (unsigned long long) (uintptr_t) capabilities[1],
                 (unsigned long long) (uintptr_t) capabilities[2],
                 visible ? L"visible" : L"hidden",
                 journal);
        HANDLE input_reader = NULL, input_writer = NULL;
        if (mode == 4 || mode == 9)
        {
            SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
            require(CreatePipe(&input_reader, &input_writer, &sa, 0), "stalled configuration pipe");
            require(SetHandleInformation(input_writer, HANDLE_FLAG_INHERIT, 0), "private config writer");
            capabilities[3] = input_reader;
            launch_input    = input_reader;
            swprintf(command,
                     32768,
                     L"\"%ls\" --restricted-config -c:stdin --stop-event:%llu --ready-event:%llu "
                     L"--controller-process:%llu --console:%ls \"--session-file:%ls\"",
                     launcher,
                     (unsigned long long) (uintptr_t) capabilities[0],
                     (unsigned long long) (uintptr_t) capabilities[1],
                     (unsigned long long) (uintptr_t) capabilities[2],
                     visible ? L"visible" : L"hidden",
                     journal);
        }
        HANDLE visible_output = NULL;
        if (mode == 9)
        {
            SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
            visible_output =
                CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
            require(visible_output != INVALID_HANDLE_VALUE, "redirected visible output");
            capabilities[4] = visible_output;
            launch_output   = visible_output;
        }
        PROCESS_INFORMATION child = launch(command, capabilities, mode == 9 ? 5 : input_reader != NULL ? 4 : 3);
        launch_input              = NULL;
        launch_output             = NULL;
        if (visible_output != NULL)
            CloseHandle(visible_output);
        if (mode == 9)
        {
            DWORD written;
            require(WriteFile(input_writer, "{}", 2, &written, NULL) && written == 2, "visible configuration transfer");
            CloseHandle(input_writer);
            input_writer = NULL;
        }
        if (mode == 4)
            require(TerminateProcess(controller.hProcess, 94), "controller loss during config transfer");
        if (mode < 3 || (mode >= 5 && mode != 10))
        {
            DWORD readiness = WaitForSingleObject(ready, 15000);
            if (readiness != WAIT_OBJECT_0)
            {
                DWORD status;
                GetExitCodeProcess(child.hProcess, &status);
                fwprintf(stderr,
                         L"case %u: readiness wait %lu, public status 0x%08lx, journal %ls\n",
                         mode,
                         readiness,
                         status,
                         journal);
            }
            require(readiness == WAIT_OBJECT_0, "runtime readiness");
            if (mode == 1)
                require(TerminateProcess(child.hProcess, 93), "forced public death");
            else if (mode == 2)
                require(TerminateProcess(controller.hProcess, 94), "controller loss");
            else
                require(live_recovery || SetEvent(stop), "stop");
        }
        /* Exercise recovery while mapped effect state is live, before finalization. */
        DWORD public_status   = live_recovery ? STILL_ACTIVE : await(child);
        DWORD expected_status = mode == 1                               ? 93
                                : mode == 3 || mode == 10               ? 1
                                : mode == 7 || mode == 11 || mode == 13 ? 0xc0000005U
                                                                        : 0;
        printf("case %u: public status 0x%08lx\n", mode, (unsigned long) public_status);
        require(live_recovery || (mode == 4 ? (public_status == 1 || public_status == 0xe0570001U)
                                            : public_status == expected_status),
                "public status fidelity");
        if (input_reader != NULL)
            CloseHandle(input_reader);
        if (input_writer != NULL)
            CloseHandle(input_writer);
        if (mode == 3 || mode == 10)
            require(WaitForSingleObject(ready, 0) == WAIT_TIMEOUT, "dead controller emitted readiness");
        if (controller.hProcess != NULL)
            CloseHandle(controller.hProcess);
        swprintf(command, 32768, L"\"%ls\" \"--recover:%ls\"", launcher, journal);
        /* A recovery client controls only the public interface, never a Job. */
        HANDLE              receipt_reader, receipt_writer;
        SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
        require(CreatePipe(&receipt_reader, &receipt_writer, &sa, 4096) &&
                    SetHandleInformation(receipt_reader, HANDLE_FLAG_INHERIT, 0),
                "recovery output pipe");
        launch_output                = receipt_writer;
        capabilities[3]              = receipt_writer;
        PROCESS_INFORMATION recovery = launch(command, capabilities, 4);
        launch_output                = NULL;
        CloseHandle(receipt_writer);
        if (mode == 15)
        {
            require(WaitForSingleObject(stop_observed, 5000) == WAIT_OBJECT_0, "recovery stop observation");
            require(TerminateProcess(child.hProcess, 93), "public death during recovery");
            CloseHandle(stop_observed);
        }
        DWORD recovery_status = await(recovery);
        char  receipt[4096];
        DWORD received;
        require(ReadFile(receipt_reader, receipt, sizeof(receipt) - 1, &received, NULL) && received != 0,
                "recovery receipt missing");
        receipt[received] = 0;
        CloseHandle(receipt_reader);
        DWORD expected_recovery =
            mode == 1 || mode == 6 || mode == 12 || mode == 13 || (mode == 4 && public_status == 0xe0570001U) ? 2 : 0;
        if (recovery_status != expected_recovery)
            fprintf(stderr, "case %u: recovery status %lu, receipt %s\n", mode, recovery_status, receipt);
        require(recovery_status == expected_recovery,
                "recovery must distinguish verified settlement from unresolved effects");
        if (mode == 3 || mode == 10)
            require(strstr(receipt, "\"runtime_status_known\":false") != NULL &&
                        strstr(receipt, "\"cleanup\":\"settled\"") != NULL,
                    "failed startup fabricated a runtime status or failed to settle");
        if (mode == 12)
            require(await(child) == 0 && strstr(receipt, "\"processes_inactive\":true") != NULL,
                    "live recovery failed to settle the public process");
        if (mode == 15)
            require(await(child) == 93 && strstr(receipt, "\"processes_inactive\":true") != NULL &&
                        strstr(receipt, "\"runtime_status_known\":false") != NULL &&
                        strstr(receipt, "\"termination\":\"abrupt\"") != NULL,
                    "missing final receipt lost independent settlement or fabricated runtime status");
        if (mode == 11 || mode == 14 || mode == 15)
            require(strstr(receipt, "\"cleanup\":\"settled\"") != NULL &&
                        strstr(receipt, "\"file_residue\":true") != NULL,
                    "settled recovery must report possible residue separately");
        if (mode == 13)
            require(strstr(receipt, "\"cleanup_detail\":\"adapter_identity_unverified\"") != NULL,
                    "abrupt recovery accepted an unresolved adapter identity");
        if (mode == 6 || mode == 12)
            require(strstr(receipt, "\"cleanup_detail\":\"adapter_present\"") != NULL,
                    "recovery did not identify the remaining adapter");
        if (mode == 7 || mode == 11)
            require(strstr(receipt, "\"runtime_status\":3221225477") != NULL &&
                        strstr(receipt, "\"runtime_status_known\":true") != NULL &&
                        strstr(receipt, mode == 7 ? "\"termination\":\"orderly\"" : "\"termination\":\"abrupt\"") !=
                            NULL,
                    "recovery lost full runtime status or confused orderly and abrupt exit");
        if (mode == 1)
        {
            /* Retain the unverified old journal while a fresh public instance
             * starts. Historical cleanup is not a global restart permission. */
            wchar_t replacement_journal[MAX_PATH];
            require(GetTempFileNameW(temporary, L"wwr", 0, replacement_journal) && DeleteFileW(replacement_journal),
                    "replacement journal path");
            ResetEvent(stop);
            ResetEvent(ready);
            swprintf(command,
                     32768,
                     L"\"%ls\" --restricted-config \"-c:%ls\" --stop-event:%llu --ready-event:%llu "
                     L"--console:hidden \"--session-file:%ls\"",
                     launcher,
                     config,
                     (unsigned long long) (uintptr_t) capabilities[0],
                     (unsigned long long) (uintptr_t) capabilities[1],
                     replacement_journal);
            PROCESS_INFORMATION replacement = launch(command, capabilities, 3);
            require(WaitForSingleObject(ready, 15000) == WAIT_OBJECT_0 && SetEvent(stop) && await(replacement) == 0,
                    "unverified historical cleanup prevented a new session");
            require(GetFileAttributesW(journal) != INVALID_FILE_ATTRIBUTES, "restart discarded old crash evidence");
            require(DeleteFileW(replacement_journal), "replacement journal retirement");
        }
        require(DeleteFileW(journal), "journal retirement");
    }
    for (unsigned i = 0; i < 3; ++i)
        CloseHandle(capabilities[i]);
    CloseHandle(stop);
    CloseHandle(ready);
    if (! production)
        require(DeleteFileW(config), "config retirement");
    puts("lifecycle fixture passed");
    return 0;
}
