#pragma once
#include "kill_switch_ownership.h"
#include "startup_options.h"
#include "startup_windows.h"

enum
{
    kLauncherSessionStopMs     = 15000,
    kLauncherSessionRecoveryMs = 20000
};

/* All APIs are launcher-owned; the runtime never receives a Job handle. */
bool launcherSessionStart(waterwall_startup_options_t *options);
void launcherSessionCancel(void);
bool launcherSessionStopRequested(void);
void launcherSessionProtectionFailed(void);
/* A runtime disposing its control channel is settling under the stop deadline. */
void launcherSessionSettleChild(void);
void launcherSessionChildStarted(void);
/* Creation failed, or a never-resumed child has been terminated and waited for. */
void launcherSessionChildAborted(void);
/* Publishes a collected runtime status independently of later cleanup. */
void                 launcherSessionChildExited(DWORD status, bool status_known);
DWORD                launcherSessionWaitForMembers(void);
bool                 launcherSessionDiagnosticsAvailable(void);
void                 launcherSessionFinish(DWORD status, bool residue);
HANDLE               launcherSessionCompletionEvent(void);
HANDLE               launcherSessionEffectsMapping(void);
int                  launcherSessionRecover(const char *path);
PSECURITY_DESCRIPTOR waterwallLauncherPrivateSecurity(void);

DWORD     launcherSessionIdentity(launcher_kill_switch_identity_t *identity);
bool      launcherSessionIdentityValid(const launcher_kill_switch_identity_t *identity);
void      launcherSessionStopName(const wchar_t *job_name, wchar_t stop_name[96]);
bool      launcherSessionJobNameMatches(HANDLE job, const launcher_kill_switch_identity_t *identity);
bool      launcherSessionStopNameMatches(HANDLE stop, const launcher_kill_switch_identity_t *identity);
ULONGLONG launcherSessionStartupDeadline(void);
ULONGLONG launcherSessionSettlementDeadline(void);
DWORD     launcherSessionWaitForJob(HANDLE job, HANDLE process, ULONGLONG graceful_deadline, ULONGLONG deadline);
DWORD     launcherSessionWaitForOwnerAdapters(HANDLE mapping, const launcher_kill_switch_identity_t *owner,
                                              ULONGLONG deadline);
