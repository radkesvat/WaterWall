#include "kill_switch_windows.h"
#include "../../ww/devices/tun/tun_windows_route.h"
#include "kill_switch_wfp.h"
#include "session_windows.h"

#include <rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifdef WATERWALL_LAUNCHER_TEST_HOOKS
DWORD launcherKillSwitchFixtureUplink(ww_kill_switch_message_t *identity);
bool  launcherKillSwitchFixtureInterface(const ww_kill_switch_message_t *identity, bool physical);
DWORD launcherKillSwitchFixtureAfterPoll(HANDLE child);
#endif

enum
{
    kPolicyCheckMs     = 250,
    kChannelWriteMs    = 1000,
    kGrantRetirementMs = 2000,
    kGrantRetryMs      = 25,
};

int launcherKillSwitchCommand(waterwall_kill_switch_command_e command)
{
    bool  locked, active;
    DWORD error;
    if (command == kWaterwallKillSwitchCommandUnlock)
    {
        bool   sublayer_retained = false;
        HANDLE ownership = NULL, coordination = NULL;
        error = launcherKillSwitchBeginUnlock(&coordination, &ownership);
        if (error == ERROR_SUCCESS)
        {
            error                    = launcherKillSwitchUnlock(&sublayer_retained);
            DWORD coordination_error = launcherKillSwitchEndUnlock(coordination, ownership, error == ERROR_SUCCESS);
            if (error == ERROR_SUCCESS)
                error = coordination_error;
        }
        if (error == ERROR_SUCCESS && sublayer_retained)
        {
            puts("incomplete");
            fputs("Windows kill switch: conflicting WFP policy remains at or references the WaterWall sublayer.\n",
                  stderr);
            return 1;
        }
        if (error == ERROR_BUSY)
            fputs("Windows kill switch: stop the active protected run before unlocking.\n", stderr);
    }
    else
    {
        error = launcherKillSwitchQuery(&locked, &active);
        if (error == ERROR_SUCCESS)
        {
            puts(active ? "locked" : locked ? "incomplete" : "unlocked");
            return locked && ! active ? 1 : 0;
        }
    }
    if (error != ERROR_SUCCESS)
    {
        fprintf(stderr, "Windows kill switch: command failed (0x%08lx).\n", (unsigned long) error);
        return 1;
    }
    puts("unlocked");
    return 0;
}

static DWORD createChannel(launcher_kill_switch_t *state, PSECURITY_DESCRIPTOR security)
{
    UUID nonce;
    if (UuidCreate(&nonce) != RPC_S_OK)
        return ERROR_GEN_FAILURE;
    RPC_WSTR   suffix = NULL;
    RPC_STATUS result = UuidToStringW(&nonce, &suffix);
    if (result != RPC_S_OK)
        return (DWORD) result;
    wchar_t name[96];
    int     length = swprintf(
        name, sizeof(name) / sizeof(*name), L"\\\\.\\pipe\\WaterWall-kill-switch-%ls", (const wchar_t *) suffix);
    RpcStringFreeW(&suffix);
    if (length < 0)
        return ERROR_INSUFFICIENT_BUFFER;

    SECURITY_ATTRIBUTES server_security = {sizeof(server_security), security, FALSE};
    HANDLE              pipe            = CreateNamedPipeW(name,
                                   PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                   PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
                                   1,
                                   4 * sizeof(ww_kill_switch_message_t),
                                   4 * sizeof(ww_kill_switch_message_t),
                                   0,
                                   &server_security);
    if (pipe == INVALID_HANDLE_VALUE)
        return GetLastError();
    state->pipe                         = pipe;
    SECURITY_ATTRIBUTES client_security = {sizeof(client_security), NULL, TRUE};
    HANDLE              client          = CreateFileW(name,
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                &client_security,
                                OPEN_EXISTING,
                                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                                NULL);
    if (client == INVALID_HANDLE_VALUE)
        return GetLastError();
    state->child_pipe = client;
    DWORD mode        = PIPE_READMODE_MESSAGE;
    ULONG client_pid  = 0;
    if (! SetNamedPipeHandleState(client, &mode, NULL, NULL) || ! GetNamedPipeClientProcessId(pipe, &client_pid))
        return GetLastError();
    if (client_pid != GetCurrentProcessId())
        return ERROR_ACCESS_DENIED;
    state->event = CreateEventW(NULL, TRUE, FALSE, NULL);
    return state->event == NULL ? GetLastError() : ERROR_SUCCESS;
}

static DWORD createChildCapabilities(launcher_kill_switch_t *state)
{
    state->retired = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (state->retired == NULL)
        return GetLastError();
    HANDLE self = GetCurrentProcess();
    if (! DuplicateHandle(self, state->ownership, self, &state->child_ownership, SYNCHRONIZE, TRUE, 0) ||
        ! DuplicateHandle(self, state->retired, self, &state->child_retired, SYNCHRONIZE, TRUE, 0))
        return GetLastError();
    return ERROR_SUCCESS;
}

static DWORD reconcilePolicy(HANDLE stop, ULONGLONG startup_deadline)
{
    ULONGLONG deadline = GetTickCount64() + kGrantRetirementMs;
    if (startup_deadline < deadline)
        deadline = startup_deadline;
    for (;;)
    {
        /* A cancelled successor still owns cleanup of the inherited baseline. */
        if (launcherSessionStopRequested())
            return ERROR_CANCELLED;
        if (GetTickCount64() >= deadline)
            return ERROR_TIMEOUT;
        DWORD error = launcherKillSwitchArm();
        if (error != ERROR_RETRY)
            return error;
        ULONGLONG now = GetTickCount64();
        if (now >= deadline)
            return ERROR_TIMEOUT;
        DWORD slice = deadline - now < kGrantRetryMs ? (DWORD) (deadline - now) : kGrantRetryMs;
        DWORD wait  = WaitForSingleObject(stop, slice);
        if (wait != WAIT_TIMEOUT)
            return wait == WAIT_OBJECT_0 ? ERROR_CANCELLED : GetLastError();
    }
}

DWORD launcherKillSwitchPrepare(launcher_kill_switch_t *state, PSECURITY_DESCRIPTOR security, HANDLE stop)
{
    if (launcherSessionStopRequested())
        return ERROR_CANCELLED;
    DWORD error = launcherSessionIdentity(&state->identity);
    if (error != ERROR_SUCCESS)
        return error;
    ULONGLONG deadline = launcherSessionStartupDeadline();
    error              = launcherKillSwitchTakeOwnership(
        &state->ownership, &state->identity, launcherSessionEffectsMapping(), stop, deadline);
    if (error != ERROR_SUCCESS)
        return error;
    error = reconcilePolicy(stop, deadline);
    if (error != ERROR_SUCCESS)
        return error;
#ifdef WATERWALL_LAUNCHER_TEST_HOOKS
    error = launcherKillSwitchFixtureUplink(&state->uplink);
    if (error != ERROR_SUCCESS)
        return error;
#else
    if (! wwWindowsKillSwitchGetUplink(&state->uplink))
        return ERROR_NETWORK_UNREACHABLE;
#endif
    error = createChildCapabilities(state);
    return error == ERROR_SUCCESS ? createChannel(state, security) : error;
}

static void cancelTransfer(HANDLE pipe, OVERLAPPED *transfer)
{
    DWORD transferred;
    CancelIoEx(pipe, transfer);
    GetOverlappedResult(pipe, transfer, &transferred, TRUE);
}

static DWORD sendMessage(launcher_kill_switch_t *state, const ww_kill_switch_message_t *message)
{
    OVERLAPPED transfer = {0};
    transfer.hEvent     = state->event;
    ResetEvent(state->event);
    DWORD size = 0;
    if (! WriteFile(state->pipe, message, sizeof(*message), &size, &transfer))
    {
        DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING)
            return error;
        DWORD wait = WaitForSingleObject(state->event, kChannelWriteMs);
        if (wait != WAIT_OBJECT_0)
        {
            error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
            cancelTransfer(state->pipe, &transfer);
            return error;
        }
        if (! GetOverlappedResult(state->pipe, &transfer, &size, FALSE))
            return GetLastError();
    }
    return size == sizeof(*message) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

DWORD launcherKillSwitchAuthorize(launcher_kill_switch_t *state, const wchar_t *image)
{
    DWORD error = launcherKillSwitchOpenSession(&state->session);
    if (error != ERROR_SUCCESS)
        return error;
    NET_LUID uplink = {.Value = state->uplink.luid};
    error           = launcherKillSwitchGrantImage(state->session, image, uplink);
    if (error == ERROR_SUCCESS)
        error = launcherKillSwitchVerifySession(state->session, false);
    return error == ERROR_SUCCESS ? sendMessage(state, &state->uplink) : error;
}

static bool sameInterface(const ww_kill_switch_message_t *a, const ww_kill_switch_message_t *b)
{
    return a->luid == b->luid && a->index == b->index && memcmp(&a->guid, &b->guid, sizeof(a->guid)) == 0;
}

static bool liveInterface(const ww_kill_switch_message_t *message, bool physical)
{
#ifdef WATERWALL_LAUNCHER_TEST_HOOKS
    return launcherKillSwitchFixtureInterface(message, physical);
#else
    if (message->luid == 0 || message->index == 0)
        return false;
    MIB_IF_ROW2 row         = {0};
    row.InterfaceLuid.Value = message->luid;
    return GetIfEntry2(&row) == NO_ERROR && row.InterfaceLuid.Value == message->luid &&
           row.InterfaceIndex == message->index &&
           memcmp(&row.InterfaceGuid, &message->guid, sizeof(message->guid)) == 0 &&
           (physical ? row.InterfaceAndOperStatusFlags.HardwareInterface && row.OperStatus == IfOperStatusUp
                     : ! row.InterfaceAndOperStatusFlags.HardwareInterface);
#endif
}

typedef enum tun_grant_state_e
{
    kAwaitingTun,
    kTunGranted,
    kTunRevoked,
} tun_grant_state_e;

static DWORD checkRun(launcher_kill_switch_t *state, const ww_kill_switch_message_t *tun, tun_grant_state_e phase)
{
    if (! liveInterface(&state->uplink, true) || (phase == kTunGranted && ! liveInterface(tun, false)))
        return ERROR_DEVICE_NOT_CONNECTED;
    return launcherKillSwitchVerifySession(state->session, phase == kTunGranted);
}

static DWORD handleMessage(launcher_kill_switch_t *state, ww_kill_switch_message_t *message,
                           ww_kill_switch_message_t *tun, tun_grant_state_e *phase)
{
    DWORD error;
    if (message->type == WW_KILL_SWITCH_REGISTER && *phase == kAwaitingTun)
    {
        if (message->luid == state->uplink.luid || ! liveInterface(message, false))
            return ERROR_INVALID_DATA;
        NET_LUID luid = {.Value = message->luid};
        error         = launcherKillSwitchGrantTun(state->session, luid);
        if (error != ERROR_SUCCESS)
            return error;
        *tun   = *message;
        *phase = kTunGranted;
    }
    else if (message->type == WW_KILL_SWITCH_REVOKE && *phase == kTunGranted && sameInterface(message, tun))
    {
        error = launcherKillSwitchRevokeTun(state->session);
        if (error != ERROR_SUCCESS)
            return error;
        *phase = kTunRevoked;
    }
    else
        return ERROR_INVALID_DATA;

    error = checkRun(state, tun, *phase);
    if (error != ERROR_SUCCESS)
        return error;
    message->type = WW_KILL_SWITCH_ACK;
    return sendMessage(state, message);
}

static DWORD checkChildExit(HANDLE child, HANDLE stop, tun_grant_state_e phase, bool stopping)
{
    DWORD status;
    if (! GetExitCodeProcess(child, &status))
        return GetLastError();
    if (status == 0 && phase != kTunRevoked && ! stopping && WaitForSingleObject(stop, 0) != WAIT_OBJECT_0)
        return ERROR_INVALID_DATA;
    return ERROR_SUCCESS;
}

/* The session watchdog owns the startup and stop deadlines while the main
 * thread services messages. Keep revocation available after cancellation. */
DWORD launcherKillSwitchWait(launcher_kill_switch_t *state, HANDLE child, HANDLE stop)
{
    ww_kill_switch_message_t tun      = {0};
    tun_grant_state_e        phase    = kAwaitingTun;
    bool                     stopping = false;
    for (;;)
    {
        ww_kill_switch_message_t message;
        OVERLAPPED               transfer = {0};
        transfer.hEvent                   = state->event;
        ResetEvent(state->event);
        DWORD size  = 0;
        DWORD error = ERROR_SUCCESS;
        if (! ReadFile(state->pipe, &message, sizeof(message), &size, &transfer))
            error = GetLastError();
        if (error == ERROR_IO_PENDING)
        {
            HANDLE waits[] = {child, state->event, stop};
            for (;;)
            {
                DWORD wait = WaitForMultipleObjects(stopping ? 2 : 3, waits, FALSE, kPolicyCheckMs);
                if (wait == WAIT_OBJECT_0 + 1)
                {
                    error = GetOverlappedResult(state->pipe, &transfer, &size, FALSE) ? ERROR_SUCCESS : GetLastError();
                    break;
                }
                if (wait == WAIT_OBJECT_0 + 2)
                {
                    stopping = true;
                    continue;
                }
                if (wait == WAIT_OBJECT_0)
                {
                    cancelTransfer(state->pipe, &transfer);
                    return checkChildExit(child, stop, phase, stopping);
                }
                DWORD wait_error = wait == WAIT_TIMEOUT ? checkRun(state, &tun, phase) : GetLastError();
#ifdef WATERWALL_LAUNCHER_TEST_HOOKS
                if (wait_error == ERROR_SUCCESS && phase == kTunGranted)
                    wait_error = launcherKillSwitchFixtureAfterPoll(child);
#endif
                if (wait_error != ERROR_SUCCESS)
                {
                    cancelTransfer(state->pipe, &transfer);
                    return wait_error;
                }
            }
        }
        if (error == ERROR_SUCCESS)
        {
            if (size != sizeof(message) || message.magic != WW_KILL_SWITCH_MESSAGE_MAGIC || message.reserved != 0)
                return ERROR_INVALID_DATA;
#ifdef WATERWALL_LAUNCHER_TEST_HOOKS
            /* Deliver stop after the child's REGISTER is queued, just before dispatch. */
            if (message.type == WW_KILL_SWITCH_REGISTER && getenv("WW_FIXTURE_STOP_AT_REGISTER") != NULL)
                launcherSessionCancel();
#endif
            stopping = stopping || WaitForSingleObject(stop, 0) == WAIT_OBJECT_0;
            if (stopping && phase == kAwaitingTun && message.type == WW_KILL_SWITCH_REGISTER)
                break;
            error = handleMessage(state, &message, &tun, &phase);
            if (error == ERROR_SUCCESS)
                continue;
        }
        if (error != ERROR_BROKEN_PIPE && error != ERROR_PIPE_NOT_CONNECTED && error != ERROR_NO_DATA)
            return error;
        break;
    }
    /* A cancelled registration or a closed pipe ends admission. Retire all
     * grants now and let the existing settlement watchdog bound the child wait. */
    launcherSessionSettleChild();
    launcherKillSwitchCloseRun(state);
    if (WaitForSingleObject(child, INFINITE) != WAIT_OBJECT_0)
        return GetLastError();
    return checkChildExit(child, stop, phase, stopping);
}

void launcherKillSwitchCloseRun(launcher_kill_switch_t *state)
{
    if (state->session != NULL)
        launcherKillSwitchCloseSession(state->session);
    if (state->retired != NULL)
    {
        if (! SetEvent(state->retired))
        {
            TerminateProcess(GetCurrentProcess(), 0xe0570001U);
        }
        CloseHandle(state->retired);
    }
    if (state->child_retired != NULL)
        CloseHandle(state->child_retired);
    if (state->child_ownership != NULL)
        CloseHandle(state->child_ownership);
    if (state->child_pipe != NULL)
        CloseHandle(state->child_pipe);
    if (state->pipe != NULL)
        CloseHandle(state->pipe);
    if (state->event != NULL)
        CloseHandle(state->event);
    state->session = state->child_pipe = state->pipe = state->event = NULL;
    state->retired = state->child_retired = state->child_ownership = NULL;
}

DWORD launcherKillSwitchFinish(launcher_kill_switch_t *state, bool *sublayer_retained)
{
    *sublayer_retained = false;
    if (state->ownership == NULL)
        return ERROR_SUCCESS;
    DWORD error = launcherSessionWaitForMembers();
    if (error != ERROR_SUCCESS)
        return error;

    HANDLE coordination    = NULL;
    bool   remove_baseline = false;
    error = launcherKillSwitchBeginCleanup(state->ownership, &state->identity, &coordination, &remove_baseline);
    if (error != ERROR_SUCCESS)
        return error;
    /* A reserved successor holds our adapter inventory and verifies it after
     * Job exit. Otherwise wait for our adapters outside the coordination lock. */
    error = launcherKillSwitchEndCleanup(&state->ownership, &state->identity, coordination, false);
    if (error != ERROR_SUCCESS || ! remove_baseline)
        return error;
    error = launcherSessionWaitForOwnerAdapters(
        launcherSessionEffectsMapping(), &state->identity, launcherSessionSettlementDeadline());
    if (error != ERROR_SUCCESS)
        return error;

    /* A handoff can be reserved during adapter settlement. Serialize the final
     * decision and WFP commit with that successor. */
    error = launcherKillSwitchBeginCleanup(state->ownership, &state->identity, &coordination, &remove_baseline);
    if (error != ERROR_SUCCESS)
        return error;
    if (remove_baseline)
        error = launcherKillSwitchUnlock(sublayer_retained);
    DWORD coordination_error = launcherKillSwitchEndCleanup(
        &state->ownership, &state->identity, coordination, remove_baseline && error == ERROR_SUCCESS);
    return error == ERROR_SUCCESS ? coordination_error : error;
}
