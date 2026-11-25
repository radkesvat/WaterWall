#pragma once

#include "../../ww/devices/windows_kill_switch_control.h"
#include "kill_switch_ownership.h"
#include "startup_options.h"

typedef struct launcher_kill_switch_s
{
    HANDLE                          ownership;
    HANDLE                          child_ownership;
    HANDLE                          session;
    HANDLE                          pipe;
    HANDLE                          child_pipe;
    HANDLE                          event;
    HANDLE                          retired;
    HANDLE                          child_retired;
    launcher_kill_switch_identity_t identity;
    ww_kill_switch_message_t        uplink;
} launcher_kill_switch_t;

int   launcherKillSwitchCommand(waterwall_kill_switch_command_e command);
DWORD launcherKillSwitchPrepare(launcher_kill_switch_t *state, PSECURITY_DESCRIPTOR security, HANDLE stop);
DWORD launcherKillSwitchAuthorize(launcher_kill_switch_t *state, const wchar_t *image);
DWORD launcherKillSwitchWait(launcher_kill_switch_t *state, HANDLE child, HANDLE stop);
void  launcherKillSwitchCloseRun(launcher_kill_switch_t *state);
DWORD launcherKillSwitchFinish(launcher_kill_switch_t *state, bool *sublayer_retained);
