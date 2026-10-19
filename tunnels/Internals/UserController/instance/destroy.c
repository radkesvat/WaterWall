#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                  context;
    usercontroller_tstate_t *ts = tunnelGetState(t);
    for (wid_t wid = 0; wid < ts->worker_count; ++wid)
    {
        if (ts->worker_states[wid].line_count != 0 || ts->worker_states[wid].sweep_timer != NULL)
        {
            LOGF("UserController: live line registry or timer at final destruction");
            abortProgramNow(1);
        }
    }
    usercontrollerTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
