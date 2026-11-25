#pragma once

#include "startup_windows.h"
#include <stdbool.h>

/* Fixed-width identity shared by elevated x86 and x64 launchers. The handles
 * belong to this process and can be duplicated only after verifying it. */
typedef struct launcher_kill_switch_identity_s
{
    DWORD    pid;
    DWORD    stop_handle;
    DWORD    job_handle;
    FILETIME created;
    wchar_t  job_name[80];
} launcher_kill_switch_identity_t;

PSECURITY_DESCRIPTOR launcherKillSwitchMachineSecurity(void);
DWORD                launcherKillSwitchAcquire(HANDLE *lease);

/* Once stop has been signaled, acquire the lease after settlement even if our
 * own stop event has fired. A returned lease assigns baseline cleanup even
 * when ownership publication or the startup deadline failed. */
DWORD launcherKillSwitchTakeOwnership(HANDLE *lease, const launcher_kill_switch_identity_t *self, HANDLE effects,
                                      HANDLE stop, ULONGLONG startup_deadline);

/* The guard spans the decision and WFP commit. End must always release it. */
DWORD launcherKillSwitchBeginCleanup(HANDLE lease, const launcher_kill_switch_identity_t *self, HANDLE *coordination,
                                     bool *remove_baseline);
DWORD launcherKillSwitchEndCleanup(HANDLE *lease, const launcher_kill_switch_identity_t *self, HANDLE coordination,
                                   bool removed);
DWORD launcherKillSwitchBeginUnlock(HANDLE *coordination, HANDLE *lease);
DWORD launcherKillSwitchEndUnlock(HANDLE coordination, HANDLE lease, bool removed);
