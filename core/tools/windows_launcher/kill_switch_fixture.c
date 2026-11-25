#include "../../launcher/kill_switch_wfp.h"
#include "../../launcher/session_windows.h"
#include "windows_kill_switch_control.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static const GUID uplink_guid = {0xe29ab127, 0x332a, 0x42b8, {0x97, 0x43, 0x17, 0xfa, 0xf2, 0x19, 0x74, 0x10}};
static const GUID tun_guid    = {0xe29ab127, 0x332a, 0x42b8, {0x97, 0x43, 0x17, 0xfa, 0xf2, 0x19, 0x74, 0x11}};
static struct
{
    HANDLE lease;
    bool   image;
    bool   tun;
} grants;

static bool baseInstalled(void)
{
    const char *path = getenv("WW_FIXTURE_KILL_SWITCH_STATE");
    return path != NULL && GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

static void traceTransition(const char *event)
{
    const char *path = getenv("WW_FIXTURE_KILL_SWITCH_TRANSITIONS");
    if (path == NULL)
        return;
    const char *run = getenv("WW_FIXTURE_KILL_SWITCH_RUN");
    char        line[128];
    int         size = snprintf(
        line, sizeof(line), "%s %s %s\n", run == NULL ? "-" : run, event, baseInstalled() ? "locked" : "unlocked");
    if (size <= 0 || (size_t) size >= sizeof(line))
        return;
    HANDLE file = CreateFileA(path,
                              FILE_APPEND_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL,
                              OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
    if (file != INVALID_HANDLE_VALUE)
    {
        DWORD written;
        WriteFile(file, line, (DWORD) size, &written, NULL);
        CloseHandle(file);
    }
}

static void trace(const char *event)
{
    traceTransition(event);
    const char *path = getenv("WW_FIXTURE_KILL_SWITCH_TRACE");
    if (path != NULL)
    {
        FILE *file = fopen(path, "ab");
        if (file != NULL)
        {
            fprintf(file, "%s\n", event);
            fclose(file);
        }
    }
}

static bool failAt(const char *event)
{
    const char *failure = getenv("WW_FIXTURE_KILL_SWITCH_FAIL");
    return failure != NULL && strcmp(failure, event) == 0;
}

DWORD launcherKillSwitchQuery(bool *locked, bool *active)
{
    bool foreign_filter = failAt("foreign-filter");
    bool base_rules     = baseInstalled();
    *locked             = base_rules || foreign_filter;
    *active             = base_rules && ! foreign_filter;
    traceTransition("query");
    return ERROR_SUCCESS;
}

DWORD launcherKillSwitchArm(void)
{
    const char *path = getenv("WW_FIXTURE_KILL_SWITCH_STATE");
    if (path == NULL || failAt("arm"))
        return ERROR_ACCESS_DENIED;
    if (failAt("foreign-filter"))
        return ERROR_INVALID_DATA;
    HANDLE file = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return GetLastError();
    CloseHandle(file);
    trace("arm");
    return failAt("arm-after-commit") ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
}

DWORD launcherKillSwitchUnlock(bool *sublayer_retained)
{
    *sublayer_retained = failAt("foreign-filter") || failAt("foreign-at-cleanup");
    if (failAt("unlock"))
        return ERROR_ACCESS_DENIED;
    const char *path = getenv("WW_FIXTURE_KILL_SWITCH_STATE");
    if (path != NULL && ! DeleteFileA(path) && GetLastError() != ERROR_FILE_NOT_FOUND)
        return GetLastError();
    trace("unlock");
    return ERROR_SUCCESS;
}

DWORD launcherKillSwitchFixtureUplink(ww_kill_switch_message_t *identity)
{
    *identity = (ww_kill_switch_message_t) {.magic = WW_KILL_SWITCH_MESSAGE_MAGIC,
                                            .type  = WW_KILL_SWITCH_UPLINK,
                                            .luid  = 11,
                                            .guid  = uplink_guid,
                                            .index = 12};
    return ERROR_SUCCESS;
}

bool launcherKillSwitchFixtureInterface(const ww_kill_switch_message_t *identity, bool physical)
{
    const GUID *guid = physical ? &uplink_guid : &tun_guid;
    return identity->luid == (physical ? 11 : 21) && identity->index == (physical ? 12 : 22) &&
           memcmp(&identity->guid, guid, sizeof(*guid)) == 0;
}

DWORD launcherKillSwitchOpenSession(HANDLE *session)
{
    /* A dynamic grants session lasts until the launcher closes it or exits.
     * Model that process lifetime across fixture invocations. */
    const char *path = getenv("WW_FIXTURE_KILL_SWITCH_STATE");
    char        lease[MAX_PATH];
    if (path == NULL || ! baseInstalled())
        return ERROR_INVALID_DATA;
    int size = snprintf(lease, sizeof(lease), "%s.grants", path);
    if (size <= 0 || (size_t) size >= sizeof(lease))
        return ERROR_FILENAME_EXCED_RANGE;
    HANDLE file = CreateFileA(lease, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return GetLastError();
    grants.lease = file;
    *session     = &grants;
    return ERROR_SUCCESS;
}

DWORD launcherKillSwitchGrantImage(HANDLE session, const wchar_t *image, NET_LUID uplink)
{
    if (session != &grants || uplink.Value != 11 || GetFileAttributesW(image) == INVALID_FILE_ATTRIBUTES ||
        failAt("image"))
        return ERROR_ACCESS_DENIED;
    const char *path   = getenv("WW_FIXTURE_KILL_SWITCH_IMAGE");
    FILE       *report = path == NULL ? NULL : fopen(path, "wb");
    if (report == NULL)
        return ERROR_INVALID_DATA;
    size_t length  = wcslen(image) + 1;
    size_t written = fwrite(image, sizeof(*image), length, report);
    if (fclose(report) != 0 || written != length)
        return ERROR_WRITE_FAULT;
    grants.image = true;
    trace("image");
    return ERROR_SUCCESS;
}

DWORD launcherKillSwitchGrantTun(HANDLE session, NET_LUID tun)
{
    if (session != &grants || ! grants.image || grants.tun || tun.Value != 21 || failAt("tun"))
        return ERROR_ACCESS_DENIED;
    grants.tun = true;
    trace("grant-tun");
    return ERROR_SUCCESS;
}

DWORD launcherKillSwitchRevokeTun(HANDLE session)
{
    if (session != &grants || ! grants.tun || failAt("revoke"))
        return ERROR_ACCESS_DENIED;
    grants.tun = false;
    trace("revoke-tun");
    return ERROR_SUCCESS;
}

DWORD launcherKillSwitchVerifySession(HANDLE session, bool tun_granted)
{
    if (session != &grants || ! grants.image || grants.tun != tun_granted)
        return ERROR_ACCESS_DENIED;
    if (tun_granted && failAt("health"))
    {
        /* The child publishes this file after readiness, just before waiting for stop. */
        const char *ready = getenv("WW_FIXTURE_KILL_SWITCH_HOLD");
        if (ready != NULL && GetFileAttributesA(ready) != INVALID_FILE_ATTRIBUTES)
            return ERROR_ACCESS_DENIED;
    }
    return ERROR_SUCCESS;
}

/* Make the child and the pipe signal together while the read is pending.
 * Waiting for termination here makes the child-first wait branch deterministic. */
DWORD launcherKillSwitchFixtureAfterPoll(HANDLE child)
{
    if (failAt("crash-launcher-after-poll"))
    {
        const char *ready = getenv("WW_FIXTURE_KILL_SWITCH_HOLD");
        if (ready != NULL && GetFileAttributesA(ready) != INVALID_FILE_ATTRIBUTES)
        {
            trace("crash-launcher");
            if (! TerminateProcess(GetCurrentProcess(), 0xc0000005U))
                return GetLastError();
        }
        return ERROR_SUCCESS;
    }
    if (! failAt("crash-after-poll"))
        return ERROR_SUCCESS;
    trace("poll");
    if (! TerminateProcess(child, 0xc0000005U))
        return GetLastError();
    DWORD wait = WaitForSingleObject(child, 5000);
    return wait == WAIT_OBJECT_0 ? ERROR_SUCCESS : (wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError());
}

void launcherKillSwitchCloseSession(HANDLE session)
{
    if (session == &grants)
    {
        CloseHandle(grants.lease);
        grants.lease = NULL;
        grants.image = grants.tun = false;
        trace("close");
    }
}

void launcherKillSwitchFixtureHandoff(bool stop_requested)
{
    const char *cancel = getenv("WW_FIXTURE_HANDOFF_CANCEL");
    if (cancel != NULL && strcmp(cancel, stop_requested ? "after" : "before") == 0)
        launcherSessionCancel();
    if (! stop_requested)
        return;
    const char *paused  = getenv("WW_FIXTURE_HANDOFF_PAUSED");
    const char *proceed = getenv("WW_FIXTURE_HANDOFF_CONTINUE");
    if (paused == NULL || proceed == NULL)
        return;
    HANDLE marker = CreateFileA(paused, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (marker == INVALID_HANDLE_VALUE)
        return;
    CloseHandle(marker);
    ULONGLONG deadline = GetTickCount64() + 10000;
    while (GetFileAttributesA(proceed) == INVALID_FILE_ATTRIBUTES && GetTickCount64() < deadline)
        Sleep(10);
    if (getenv("WW_FIXTURE_HANDOFF_CRASH") != NULL)
        TerminateProcess(GetCurrentProcess(), 0xc0000005U);
}
