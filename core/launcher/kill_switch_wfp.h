#ifndef WW_LAUNCHER_KILL_SWITCH_WFP_H
#define WW_LAUNCHER_KILL_SWITCH_WFP_H

#include <stdbool.h>
#include <winsock2.h>

#include <windows.h>

#include <ifdef.h>

/* An incomplete policy is present but inactive. */
DWORD launcherKillSwitchQuery(bool *locked, bool *active);
/* Reconciles the baseline under exclusive ownership and verifies the commit.
 * ERROR_RETRY reports identified grants still present without a policy commit.
 * Failure can leave committed rules that the owning launcher must remove. */
DWORD launcherKillSwitchArm(void);
/* Removes the known baseline under exclusive ownership. On success, reports
 * whether a foreign object prevented removal of the sublayer. */
DWORD launcherKillSwitchUnlock(bool *sublayer_retained);

/* The session handle is private to this backend. */
DWORD launcherKillSwitchOpenSession(HANDLE *session);
DWORD launcherKillSwitchGrantImage(HANDLE session, const wchar_t *image, NET_LUID uplink);
DWORD launcherKillSwitchGrantTun(HANDLE session, NET_LUID tun);
DWORD launcherKillSwitchRevokeTun(HANDLE session);
DWORD launcherKillSwitchVerifySession(HANDLE session, bool tun_granted);
void  launcherKillSwitchCloseSession(HANDLE session);

#endif
