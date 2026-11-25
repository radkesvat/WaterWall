#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* NetIO declarations depend on the Winsock address types. */
// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
// clang-format on

#define WW_KILL_SWITCH_MESSAGE_MAGIC UINT32_C(0x574b5331)

enum
{
    WW_KILL_SWITCH_UPLINK   = 1,
    WW_KILL_SWITCH_REGISTER = 2,
    WW_KILL_SWITCH_REVOKE   = 3,
    WW_KILL_SWITCH_ACK      = 4
};

/* The launcher and its embedded child have the same Windows ABI. The channel
 * is message-mode. Each ACK echoes all identity fields of one request. */
typedef struct ww_kill_switch_message_s
{
    uint32_t magic;
    uint32_t type;
    uint64_t luid;
    GUID     guid;
    uint32_t index;
    uint32_t reserved;
} ww_kill_switch_message_t;

_Static_assert(sizeof(ww_kill_switch_message_t) == 40, "Windows kill-switch message layout");

/* Runtime coordinator only. Attach consumes the supplied capabilities on
 * every result. The caller validates the retirement handle as a synchronizable
 * Event. A successful Begin publishes immutable uplink state before workers. */
bool wwWindowsKillSwitchAttach(uintptr_t pipe_handle, uintptr_t retirement_event);
bool wwWindowsKillSwitchBegin(HANDLE stop_event);
void wwWindowsKillSwitchClose(void);
bool wwWindowsKillSwitchActive(void);

/* The coordinator collects declared TunDevices across all configurations,
 * then finalizes the owner before any prepare or start hook. */
bool   wwWindowsKillSwitchConsiderTun(bool eligible, bool marked, size_t *candidate);
bool   wwWindowsKillSwitchFinishSelection(void);
size_t wwWindowsKillSwitchSelectedTun(void);

bool wwWindowsKillSwitchRegisterTun(const NET_LUID *luid);
bool wwWindowsKillSwitchRevokeTun(void);
bool wwWindowsKillSwitchTunRegistered(void);
bool wwWindowsKillSwitchStartupWasStopped(void);

/* Concurrent socket creators only read the uplink snapshot. Validate the live
 * identity again before returning an index that Windows can reuse. */
bool wwWindowsKillSwitchGetApprovedIndex(const char *explicit_ifname, uint32_t *index);
