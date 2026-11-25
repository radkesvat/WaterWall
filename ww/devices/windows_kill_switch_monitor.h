#pragma once

#include "windows_kill_switch_control.h"

/* Wait for a lost peer or for orderly settlement. The launcher signals
 * retirement after closing its WFP session and before closing its pipe. */
static inline bool wwWindowsKillSwitchWaitForPeerLoss(HANDLE pipe, HANDLE launcher, HANDLE monitor_stop,
                                                      HANDLE stop_event, HANDLE retirement)
{
    enum
    {
        kMonitorPollMs = 250
    };
    const HANDLE events[] = {monitor_stop, launcher};
    for (;;)
    {
        DWORD wait = WaitForMultipleObjects(2, events, FALSE, kMonitorPollMs);
        if (wait != WAIT_TIMEOUT)
            return wait != WAIT_OBJECT_0;
        if (! PeekNamedPipe(pipe, NULL, 0, NULL, NULL, NULL))
        {
            const HANDLE settling[] = {stop_event, retirement};
            return WaitForMultipleObjects(2, settling, TRUE, 0) != WAIT_OBJECT_0 ||
                   WaitForSingleObject(launcher, 0) != WAIT_TIMEOUT;
        }
    }
}
