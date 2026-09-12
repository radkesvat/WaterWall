#pragma once
#include "startup_options.h"
#include "startup_windows.h"

/* All APIs are launcher-owned; the runtime never receives a Job handle. */
bool launcherSessionStart(waterwall_startup_options_t *options);
void launcherSessionCancel(void);
void launcherSessionChildStarted(void);
/* Creation failed, or a never-resumed child has been terminated and waited for. */
void launcherSessionChildAborted(void);
/* Also arms the cleanup deadline when launch failed without a runtime status. */
void                 launcherSessionChildExited(DWORD status, bool status_known);
void                 launcherSessionFinish(DWORD status, bool residue);
HANDLE               launcherSessionCompletionEvent(void);
HANDLE               launcherSessionEffectsMapping(void);
int                  launcherSessionRecover(const char *path);
PSECURITY_DESCRIPTOR waterwallLauncherPrivateSecurity(void);
