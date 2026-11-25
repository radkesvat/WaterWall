#include "windows_kill_switch_control.h"

#include "tun/tun_windows_route.h"
#include "windows_kill_switch_monitor.h"
#include "windows_kill_switch_owner.h"
#include "wlibc.h"
#include <objbase.h>

enum
{
    kKillSwitchStartupMs  = 60000,
    kKillSwitchStopMs     = 15000,
    kKillSwitchCancelIoMs = 1000
};

/* Startup and teardown exchange messages on the coordinator. The monitor
 * only observes the peer and is joined before its handles are released.
 * Socket creators read only the uplink identity, published before workers. */
static struct
{
    HANDLE                   pipe;
    HANDLE                   launcher;
    HANDLE                   retirement;
    HANDLE                   stop_event;
    HANDLE                   monitor_stop;
    HANDLE                   monitor;
    ULONGLONG                startup_deadline;
    ww_kill_switch_message_t uplink;
    ww_kill_switch_message_t adapter;
    ww_kill_switch_owner_t   owner;
    size_t                   selected_tun;
} kill_switch;

static bool killSwitchSameInterface(const ww_kill_switch_message_t *left, const ww_kill_switch_message_t *right)
{
    return left->luid == right->luid && left->index == right->index &&
           memcmp(&left->guid, &right->guid, sizeof(left->guid)) == 0;
}

static bool killSwitchReadInterface(const ww_kill_switch_message_t *identity, MIB_IF_ROW2 *out)
{
    NET_LUID luid = {.Value = identity->luid};
    *out          = (MIB_IF_ROW2) {.InterfaceLuid = luid};
    return identity->luid != 0 && identity->index != 0 && GetIfEntry2(out) == NO_ERROR &&
           out->InterfaceIndex == identity->index &&
           memcmp(&out->InterfaceGuid, &identity->guid, sizeof(identity->guid)) == 0;
}

static bool killSwitchTransfer(ww_kill_switch_message_t *message, bool write, ULONGLONG deadline, HANDLE cancel)
{
    if (kill_switch.pipe == NULL)
        return false;
    if (cancel != NULL && WaitForSingleObject(cancel, 0) != WAIT_TIMEOUT)
        return false;

    const ULONGLONG now = GetTickCount64();
    if (now >= deadline)
        return false;

    OVERLAPPED operation = {0};
    operation.hEvent     = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (operation.hEvent == NULL)
        return false;

    DWORD transferred = 0;
    BOOL  ok          = write ? WriteFile(kill_switch.pipe, message, sizeof(*message), &transferred, &operation)
                              : ReadFile(kill_switch.pipe, message, sizeof(*message), &transferred, &operation);
    if (! ok && GetLastError() == ERROR_IO_PENDING)
    {
        HANDLE      events[]  = {operation.hEvent, kill_switch.launcher, cancel};
        const DWORD remaining = (DWORD) (deadline - now);
        if (WaitForMultipleObjects(cancel != NULL ? 3 : 2, events, FALSE, remaining) == WAIT_OBJECT_0)
        {
            ok = GetOverlappedResult(kill_switch.pipe, &operation, &transferred, FALSE);
        }
        else
        {
            CancelIoEx(kill_switch.pipe, &operation);
            if (WaitForSingleObject(operation.hEvent, kKillSwitchCancelIoMs) != WAIT_OBJECT_0)
            {
                /* A pending kernel operation still owns both stack objects. */
                abortProgramNow(1);
            }
        }
    }
    CloseHandle(operation.hEvent);
    return ok && transferred == sizeof(*message);
}

static DWORD WINAPI killSwitchMonitor(void *unused)
{
    (void) unused;
    if (wwWindowsKillSwitchWaitForPeerLoss(kill_switch.pipe,
                                           kill_switch.launcher,
                                           kill_switch.monitor_stop,
                                           kill_switch.stop_event,
                                           kill_switch.retirement))
    {
        if (! requestProgramShutdown(1))
            abortProgramNow(1);
    }
    return 0;
}

bool wwWindowsKillSwitchAttach(uintptr_t pipe_handle, uintptr_t retirement_event)
{
    assert(kill_switch.pipe == NULL && kill_switch.retirement == NULL && retirement_event != 0);
    DWORD flags            = 0;
    DWORD mode             = PIPE_READMODE_MESSAGE;
    ULONG launcher_pid     = 0;
    kill_switch.pipe       = (HANDLE) pipe_handle;
    kill_switch.retirement = (HANDLE) retirement_event;
    if (kill_switch.pipe == NULL || kill_switch.pipe == INVALID_HANDLE_VALUE)
    {
        kill_switch.pipe = NULL;
        return false;
    }
    if (! SetHandleInformation(kill_switch.retirement, HANDLE_FLAG_INHERIT, 0) ||
        WaitForSingleObject(kill_switch.retirement, 0) != WAIT_TIMEOUT ||
        ! SetHandleInformation(kill_switch.pipe, HANDLE_FLAG_INHERIT, 0) ||
        ! GetNamedPipeInfo(kill_switch.pipe, &flags, NULL, NULL, NULL) || (flags & PIPE_SERVER_END) != 0 ||
        (flags & PIPE_TYPE_MESSAGE) == 0 || ! SetNamedPipeHandleState(kill_switch.pipe, &mode, NULL, NULL) ||
        ! GetNamedPipeServerProcessId(kill_switch.pipe, &launcher_pid) || launcher_pid == GetCurrentProcessId())
    {
        wwWindowsKillSwitchClose();
        return false;
    }

    kill_switch.launcher = OpenProcess(SYNCHRONIZE, FALSE, launcher_pid);
    if (kill_switch.launcher == NULL || WaitForSingleObject(kill_switch.launcher, 0) != WAIT_TIMEOUT)
    {
        wwWindowsKillSwitchClose();
        return false;
    }

    kill_switch.startup_deadline = GetTickCount64() + kKillSwitchStartupMs;
    return true;
}

bool wwWindowsKillSwitchBegin(HANDLE stop_event)
{
    assert(kill_switch.pipe != NULL && kill_switch.uplink.luid == 0);
    ww_kill_switch_message_t uplink;
    MIB_IF_ROW2              row;
    if (stop_event == NULL || ! killSwitchTransfer(&uplink, false, kill_switch.startup_deadline, stop_event) ||
        uplink.magic != WW_KILL_SWITCH_MESSAGE_MAGIC || uplink.type != WW_KILL_SWITCH_UPLINK || uplink.reserved != 0 ||
        ! killSwitchReadInterface(&uplink, &row) || ! tunWindowsPhysicalInterfaceUp(&row))
    {
        return false;
    }

    kill_switch.stop_event   = stop_event;
    kill_switch.monitor_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (kill_switch.monitor_stop == NULL)
        return false;

    kill_switch.monitor = CreateThread(NULL, 0, killSwitchMonitor, NULL, 0, NULL);
    if (kill_switch.monitor == NULL)
        return false;

    kill_switch.uplink = uplink;
    return true;
}

static void killSwitchDisconnect(void)
{
    if (kill_switch.monitor != NULL)
    {
        if (! SetEvent(kill_switch.monitor_stop) ||
            WaitForSingleObject(kill_switch.monitor, kKillSwitchCancelIoMs) != WAIT_OBJECT_0)
            abortProgramNow(1);
        CloseHandle(kill_switch.monitor);
        kill_switch.monitor = NULL;
    }
    if (kill_switch.monitor_stop != NULL)
    {
        CloseHandle(kill_switch.monitor_stop);
        kill_switch.monitor_stop = NULL;
    }
    if (kill_switch.pipe != NULL)
    {
        CloseHandle(kill_switch.pipe);
        kill_switch.pipe = NULL;
    }
}

void wwWindowsKillSwitchClose(void)
{
    killSwitchDisconnect();
    if (kill_switch.retirement != NULL)
    {
        CloseHandle(kill_switch.retirement);
        kill_switch.retirement = NULL;
    }
    if (kill_switch.launcher != NULL)
    {
        CloseHandle(kill_switch.launcher);
        kill_switch.launcher = NULL;
    }
}

bool wwWindowsKillSwitchActive(void)
{
    return kill_switch.uplink.luid != 0;
}

bool wwWindowsKillSwitchConsiderTun(bool eligible, bool marked, size_t *candidate)
{
    assert(wwWindowsKillSwitchActive() && kill_switch.selected_tun == 0);
    return wwKillSwitchConsiderTun(&kill_switch.owner, eligible, marked, candidate);
}

bool wwWindowsKillSwitchFinishSelection(void)
{
    assert(wwWindowsKillSwitchActive() && kill_switch.selected_tun == 0);
    kill_switch.selected_tun = wwKillSwitchSelectedTun(&kill_switch.owner);
    return kill_switch.selected_tun != 0;
}

size_t wwWindowsKillSwitchSelectedTun(void)
{
    assert(wwWindowsKillSwitchActive() && kill_switch.selected_tun != 0);
    return kill_switch.selected_tun;
}

static bool killSwitchExchange(ww_kill_switch_message_t *message, ULONGLONG deadline, HANDLE cancel)
{
    ww_kill_switch_message_t reply;
    if (killSwitchTransfer(message, true, deadline, cancel) && killSwitchTransfer(&reply, false, deadline, cancel) &&
        reply.magic == WW_KILL_SWITCH_MESSAGE_MAGIC && reply.type == WW_KILL_SWITCH_ACK && reply.reserved == 0 &&
        killSwitchSameInterface(&reply, message))
    {
        return true;
    }
    /* The launcher may have committed before losing the reply. Disconnect to
     * force session closure and hold the Wintun handle until it is confirmed. */
    const ULONGLONG now                 = GetTickCount64();
    const ULONGLONG retirement_deadline = message->type == WW_KILL_SWITCH_REVOKE ? deadline : now + kKillSwitchStopMs;
    killSwitchDisconnect();
    ULONGLONG after_disconnect = GetTickCount64();
    DWORD     remaining = after_disconnect < retirement_deadline ? (DWORD) (retirement_deadline - after_disconnect) : 0;
    HANDLE    events[]  = {kill_switch.retirement, kill_switch.launcher};
    if (WaitForMultipleObjects(2, events, FALSE, remaining) != WAIT_OBJECT_0)
        abortProgramNow(1);
    return false;
}

bool wwWindowsKillSwitchRegisterTun(const NET_LUID *luid)
{
    assert(wwWindowsKillSwitchActive() && kill_switch.selected_tun != 0 && kill_switch.adapter.luid == 0);
    NET_IFINDEX              index;
    ww_kill_switch_message_t request = {
        .magic = WW_KILL_SWITCH_MESSAGE_MAGIC, .type = WW_KILL_SWITCH_REGISTER, .luid = luid->Value};
    if (luid->Value == 0 || luid->Value == kill_switch.uplink.luid ||
        ConvertInterfaceLuidToGuid(luid, &request.guid) != NO_ERROR ||
        ConvertInterfaceLuidToIndex(luid, &index) != NO_ERROR || index == 0)
    {
        return false;
    }
    request.index = index;
    if (! killSwitchExchange(&request, kill_switch.startup_deadline, kill_switch.stop_event))
        return false;
    kill_switch.adapter = request;
    return true;
}

bool wwWindowsKillSwitchRevokeTun(void)
{
    assert(kill_switch.adapter.luid != 0);
    ww_kill_switch_message_t request = kill_switch.adapter;
    request.type                     = WW_KILL_SWITCH_REVOKE;
    kill_switch.adapter              = (ww_kill_switch_message_t) {0};
    return killSwitchExchange(&request, GetTickCount64() + kKillSwitchStopMs, NULL);
}

bool wwWindowsKillSwitchTunRegistered(void)
{
    return kill_switch.adapter.luid != 0;
}

bool wwWindowsKillSwitchStartupWasStopped(void)
{
    return kill_switch.stop_event != NULL && WaitForSingleObject(kill_switch.stop_event, 0) == WAIT_OBJECT_0;
}

bool wwWindowsKillSwitchGetApprovedIndex(const char *explicit_ifname, uint32_t *index)
{
    assert(wwWindowsKillSwitchActive());
    MIB_IF_ROW2 row;
    if (! killSwitchReadInterface(&kill_switch.uplink, &row) || ! tunWindowsPhysicalInterfaceUp(&row))
        return false;

    if (explicit_ifname != NULL && explicit_ifname[0] != '\0')
    {
        wchar_t configured[IF_MAX_STRING_SIZE + 1];
        wchar_t adapter_id[39]; /* Canonical GUID, with braces and terminator. */
        if (MultiByteToWideChar(
                CP_UTF8, MB_ERR_INVALID_CHARS, explicit_ifname, -1, configured, IF_MAX_STRING_SIZE + 1) == 0 ||
            (CompareStringOrdinal(row.Alias, -1, configured, -1, TRUE) != CSTR_EQUAL &&
             (StringFromGUID2(&row.InterfaceGuid, adapter_id, 39) == 0 ||
              CompareStringOrdinal(adapter_id, -1, configured, -1, TRUE) != CSTR_EQUAL)))
        {
            return false;
        }
    }
    *index = kill_switch.uplink.index;
    return true;
}
