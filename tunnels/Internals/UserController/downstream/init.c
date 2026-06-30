#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    usercontroller_lstate_t *ls = lineGetState(l, t);

    // Reverse origin: the line was initiated from the next side (this downstream Init), as in
    // TunDevice -> WireGuardDevice -> UserController -> UdpStatelessSocket. This flips the
    // upload/download mapping (downstream payload becomes the user's upload).
    usercontrollerLinestateInitialize(ls, true);

    // Admit the line at start if it already carries an authenticated user. Lines with no user (the
    // usual reverse case, where a node like WireGuardDevice authenticates later) pass through
    // unmanaged and are promoted on demand via usercontrollerTunnelTryManageLine().
    user_admission_result_t result = usercontrollerTunnelTryManageLine(t, l);

    if (result != kUserAdmissionOk)
    {
        usercontrollerLogAdmissionRejected(t, l, ls, result);

        // The downstream side was never opened, so we only finish the next/upstream side that
        // initiated us (mirror of the upstream-Init rejection, opposite direction).
        usercontrollerLinestateDestroy(ls);
        tunnelNextUpStreamFinish(t, l);
        return;
    }

    tunnelPrevDownStreamInit(t, l);
}



