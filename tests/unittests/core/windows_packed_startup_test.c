/*
 * Covers: Restricted Windows startup handoff through the real startup parser and receiver.
 * Setup: Creates real pagefile mappings and duplicated child handles; links startup support without the
 * WaterWall runtime.
 * Cases: Valid 65537-byte snapshot, declared-length mismatch, writable child mapping, explicit cleanup,
 * oversized length, uncommitted reserved tail and standalone kill-switch commands with private
 * control and retirement handle handoff. A real closed pipe exercises peer monitoring during stop.
 * Checks: Reserved arguments are removed, restricted selection survives, content and terminating byte
 * are exact, malformed inputs fail and mapping handles close on every outcome.
 * Limits: Requires Windows mapping/handle APIs. This does not execute the packed launcher or qualify
 * deployment behavior.
 * CTest: waterwall.windows_packed_startup_unit
 */
#include "../../../ww/devices/windows_kill_switch_monitor.h"
#include "startup_options.h"
#include "startup_windows.h"
#include <stdio.h>
#include <string.h>

/* Suite-owned return 1 preserves its original failure boundary. */

#include "test_assert.h"

#define CHECK(expression)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! TEST_CHECK(expression, "requirement failed"))                                                            \
        {                                                                                                              \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

static HANDLE snapshot(size_t length, uint64_t declared, int writable_child, int reserve_tail)
{
    HANDLE writable = CreateFileMappingW(INVALID_HANDLE_VALUE,
                                         NULL,
                                         PAGE_READWRITE | (reserve_tail ? SEC_RESERVE : 0),
                                         0,
                                         (DWORD) (sizeof(waterwall_snapshot_header_t) + length),
                                         NULL);
    if (writable == NULL)
        return NULL;
    void *view = MapViewOfFile(writable, FILE_MAP_WRITE, 0, 0, 0);
    if (view == NULL)
    {
        CloseHandle(writable);
        return NULL;
    }
    if (reserve_tail && VirtualAlloc(view, sizeof(waterwall_snapshot_header_t), MEM_COMMIT, PAGE_READWRITE) == NULL)
    {
        UnmapViewOfFile(view);
        CloseHandle(writable);
        return NULL;
    }
    waterwall_snapshot_header_t header = {WW_SNAPSHOT_MAGIC, declared, ~declared};
    memcpy(view, &header, sizeof(header));
    if (! reserve_tail)
        memset((char *) view + sizeof(header), 'x', length);
    UnmapViewOfFile(view);
    HANDLE child = NULL;
    DuplicateHandle(GetCurrentProcess(),
                    writable,
                    GetCurrentProcess(),
                    &child,
                    FILE_MAP_READ | (writable_child ? FILE_MAP_WRITE : 0),
                    TRUE,
                    0);
    CloseHandle(writable);
    return child;
}

static int checkKillSwitchOptions(void)
{
    char                       *status[] = {"fixture", "--kill-switch-status", NULL};
    char                       *unlock[] = {"fixture", "--kill-switch-unlock", NULL};
    waterwall_startup_options_t options  = {.core_json_input = "should be cleared"};
    CHECK(waterwallStartupOptionsParse(2, status, &options) == kWaterwallStartupArgumentsRun);
    CHECK(options.kill_switch_command == kWaterwallKillSwitchCommandStatus && options.core_json_input == NULL);
    CHECK(waterwallStartupOptionsParse(2, unlock, &options) == kWaterwallStartupArgumentsRun);
    CHECK(options.kill_switch_command == kWaterwallKillSwitchCommandUnlock && options.core_json_input == NULL);

    char *mixed[]     = {"fixture", "--config:stdin", "--kill-switch-status", NULL};
    char *duplicate[] = {"fixture", "--kill-switch-unlock", "--kill-switch-unlock", NULL};
    char *recovery[]  = {"fixture", "--kill-switch-unlock", "--recover:session.json", NULL};
    CHECK(waterwallStartupOptionsParse(3, mixed, &options) == kWaterwallStartupArgumentsExitFailure);
    CHECK(waterwallStartupOptionsParse(3, duplicate, &options) == kWaterwallStartupArgumentsExitFailure);
    CHECK(waterwallStartupOptionsParse(3, recovery, &options) == kWaterwallStartupArgumentsExitFailure);
    return 0;
}

static int checkKillSwitchHandoff(void)
{
    HANDLE control, peer;
    CHECK(CreatePipe(&control, &peer, NULL, 0));
    HANDLE mapping = snapshot(1, 1, 0, 0);
    HANDLE retired = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(mapping != NULL && retired != NULL);
    char control_arg[80], retired_arg[80], map_arg[80];
    snprintf(
        control_arg, sizeof(control_arg), "--ww-internal-kill-switch=%llu", (unsigned long long) (uintptr_t) control);
    snprintf(retired_arg,
             sizeof(retired_arg),
             "--ww-internal-kill-switch-retired=%llu",
             (unsigned long long) (uintptr_t) retired);
    snprintf(map_arg, sizeof(map_arg), "--ww-internal-map=%llu", (unsigned long long) (uintptr_t) mapping);
    char               *argv[]  = {"fixture",
                                   control_arg,
                                   retired_arg,
                                   map_arg,
                                   "--ww-internal-len=1",
                                   "--ww-internal-src=stdin",
                                   "--ww-internal-exe=C:\\x",
                                   "--verbose",
                                   NULL};
    int                 argc    = 8;
    waterwall_handoff_t handoff = {0};
    CHECK(waterwallStartupHandoffExtract(&argc, argv, &handoff) == 1);
    CHECK(handoff.kill_switch_control == (uintptr_t) control && handoff.kill_switch_retired == (uintptr_t) retired);
    CHECK(argc == 2 && strcmp(argv[1], "--verbose") == 0);
    waterwallStartupHandoffCleanup(&handoff);
    DWORD flags;
    CHECK(! GetHandleInformation(control, &flags) && ! GetHandleInformation(mapping, &flags) &&
          ! GetHandleInformation(retired, &flags));
    CHECK(CloseHandle(peer));
    return 0;
}

static int checkBadKillSwitchHandoff(void)
{
    char *invalid[][3] = {
        {"--ww-internal-kill-switch=32", NULL, NULL},
        {"--ww-internal-kill-switch-retired=48", NULL, NULL},
        {"--ww-internal-kill-switch=16", "--ww-internal-kill-switch-retired=48", NULL},
        {"--ww-internal-kill-switch=32", "--ww-internal-kill-switch-retired=32", NULL},
        {"--ww-internal-kill-switch=32", "--ww-internal-kill-switch-retired=16", NULL},
        {"--ww-internal-kill-switch=32", "--ww-internal-kill-switch-retired=48", "--ww-internal-complete=48"},
        {"--ww-internal-kill-switch=32", "--ww-internal-kill-switch-retired=48", "--ww-internal-effects=48"},
        {"--ww-internal-kill-switch=32", "--ww-internal-kill-switch-retired=+48", NULL},
        {"--ww-internal-kill-switch=32", "--ww-internal-kill-switch-retired=48", "--ww-internal-kill-switch=64"},
        {"--ww-internal-kill-switch=32",
         "--ww-internal-kill-switch-retired=48",
         "--ww-internal-kill-switch-retired=64"},
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        char *argv[] = {"fixture",
                        "--ww-internal-map=16",
                        "--ww-internal-len=1",
                        "--ww-internal-src=stdin",
                        "--ww-internal-exe=C:\\x",
                        invalid[i][0],
                        invalid[i][1],
                        invalid[i][2],
                        NULL};
        int   argc   = 5;
        while (argv[argc] != NULL)
            ++argc;
        waterwall_handoff_t handoff = {0};
        CHECK(waterwallStartupHandoffExtract(&argc, argv, &handoff) == -1);
        CHECK(handoff.kill_switch_control == 0 && handoff.kill_switch_retired == 0);
        waterwallStartupHandoffCleanup(&handoff);
    }
    return 0;
}

static int checkKillSwitchMonitor(void)
{
    HANDLE pipe, writer;
    CHECK(CreatePipe(&pipe, &writer, NULL, 0));
    CloseHandle(writer);
    HANDLE monitor_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE stop         = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE retired      = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE live         = OpenProcess(SYNCHRONIZE, FALSE, GetCurrentProcessId());
    CHECK(monitor_stop != NULL && stop != NULL && retired != NULL && live != NULL);
    CHECK(wwWindowsKillSwitchWaitForPeerLoss(pipe, live, monitor_stop, stop, retired));
    CHECK(SetEvent(stop));
    CHECK(wwWindowsKillSwitchWaitForPeerLoss(pipe, live, monitor_stop, stop, retired));
    CHECK(SetEvent(retired));
    CHECK(! wwWindowsKillSwitchWaitForPeerLoss(pipe, live, monitor_stop, stop, retired));
    /* A signaled wait handle models launcher exit even if it had signaled retirement. */
    CHECK(wwWindowsKillSwitchWaitForPeerLoss(pipe, retired, monitor_stop, stop, retired));
    CHECK(ResetEvent(stop));
    CHECK(wwWindowsKillSwitchWaitForPeerLoss(pipe, live, monitor_stop, stop, retired));
    CHECK(SetEvent(monitor_stop));
    CHECK(! wwWindowsKillSwitchWaitForPeerLoss(pipe, live, monitor_stop, stop, retired));
    CloseHandle(live);
    CloseHandle(retired);
    CloseHandle(stop);
    CloseHandle(monitor_stop);
    CloseHandle(pipe);
    return 0;
}

int main(void)
{
    testCaseSet("windows_packed_startup_test");
    CHECK(checkKillSwitchOptions() == 0);
    CHECK(checkKillSwitchHandoff() == 0);
    CHECK(checkBadKillSwitchHandoff() == 0);
    CHECK(checkKillSwitchMonitor() == 0);
    for (int mode = 0; mode < 6; ++mode)
    {
        const size_t length  = 65537;
        HANDLE       mapping = snapshot(length, mode == 1 ? length - 1 : length, mode == 2, mode == 5);
        CHECK(mapping != NULL);
        char handle_arg[80];
        snprintf(handle_arg, sizeof(handle_arg), "--ww-internal-map=%llu", (unsigned long long) (uintptr_t) mapping);
        char               *argv[]  = {"fixture",
                                       handle_arg,
                                       "--ww-internal-len=65537",
                                       "--ww-internal-src=stdin",
                                       "--ww-internal-exe=C:\\outer folder\\Waterwall.exe",
                                       "--restricted-config",
                                       NULL};
        int                 argc    = 6;
        waterwall_handoff_t handoff = {0};
        CHECK(waterwallStartupHandoffExtract(&argc, argv, &handoff) == 1);
        CHECK(argc == 2 && strcmp(argv[1], "--restricted-config") == 0);
        if (mode == 3)
        {
            waterwallStartupHandoffCleanup(&handoff);
            DWORD flags;
            CHECK(! GetHandleInformation(mapping, &flags));
            continue;
        }
        if (mode == 4)
            handoff.length = SIZE_MAX;
        char  *content  = NULL;
        size_t received = 0;
        int    result   = waterwallStartupHandoffReceive(&handoff, false, &content, &received);
        CHECK((result == 0) == (mode == 0));
        CHECK(handoff.mapping == 0);
        DWORD flags;
        CHECK(! GetHandleInformation(mapping, &flags));
        if (result == 0)
        {
            CHECK(received == length && content[length] == 0);
            for (size_t i = 0; i < length; ++i)
                CHECK(content[i] == 'x');
            free(content);
        }
        waterwallStartupHandoffCleanup(&handoff);
    }
    char *bad_sets[][7] = {{"fixture",
                            "--ww-internal-map=18446744073709551615",
                            "--ww-internal-len=1",
                            "--ww-internal-src=x",
                            "--ww-internal-exe=C:\\x",
                            NULL},
                           {"fixture", "--ww-internal-kill-switch=32", NULL},
                           {"fixture", "--ww-internal-kill-switch-retired=48", NULL},
                           {"fixture",
                            "--ww-internal-map=16",
                            "--ww-internal-len=1",
                            "--ww-internal-src=x",
                            "--ww-internal-exe=relative",
                            NULL},
                           {"fixture",
                            "--ww-internal-map=16",
                            "--ww-internal-map=16",
                            "--ww-internal-src=x",
                            "--ww-internal-exe=C:\\x",
                            NULL},
                           {"fixture", "--ww-internal-map=16", "--ww-internal-len=1", "--ww-internal-src=x", NULL},
                           {"fixture",
                            "--ww-internal-map=+16",
                            "--ww-internal-len=1",
                            "--ww-internal-src=x",
                            "--ww-internal-exe=C:\\x",
                            NULL}};
    for (size_t i = 0; i < sizeof(bad_sets) / sizeof(bad_sets[0]); ++i)
    {
        int argc = 0;
        while (bad_sets[i][argc] != NULL)
            ++argc;
        waterwall_handoff_t handoff = {0};
        CHECK(waterwallStartupHandoffExtract(&argc, bad_sets[i], &handoff) == -1);
        waterwallStartupHandoffCleanup(&handoff);
    }
    /* Unlike POSIX descriptors, a Windows mapping may have handle value 4
     * when standard handles are absent. Parsing must not reserve that value. */
    char               *low_argv[] = {"fixture",
                                      "--ww-internal-map=4",
                                      "--ww-internal-len=1",
                                      "--ww-internal-src=stdin",
                                      "--ww-internal-exe=C:\\x",
                                      NULL};
    int                 low_argc   = 5;
    waterwall_handoff_t low        = {0};
    CHECK(waterwallStartupHandoffExtract(&low_argc, low_argv, &low) == 1 && low.mapping == 4);
    /* This is a numeric parser case, not an OS handle owned by the test. */
    low.mapping = 0;
    waterwallStartupHandoffCleanup(&low);
    puts("Windows handoff validation and handle ownership passed");
    return 0;
}
