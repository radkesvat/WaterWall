#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    usercontroller_lstate_t *ls = lineGetState(l, t);

    // Forward origin: the line was initiated from the prev side (this upstream Init), so upstream
    // payload is the user's upload.
    usercontrollerLinestateInitialize(ls, false);

    // Admit the line at start if it already carries an authenticated user. Anonymous/no-auth lines
    // return kUserAdmissionOk and simply pass through unmanaged; nodes that authenticate later promote
    // the line on demand with usercontrollerTunnelTryManageLine().
    user_admission_result_t result = usercontrollerTunnelTryManageLine(t, l);

    if (result != kUserAdmissionOk)
    {
        usercontrollerLogAdmissionRejected(t, l, ls, result);

        // The upstream side was never opened, so we only finish the prev/downstream side that
        // initiated us. This is the natural "upstream is unavailable" close (close prev only).
        usercontrollerLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tunnelNextUpStreamInit(t, l);
}
