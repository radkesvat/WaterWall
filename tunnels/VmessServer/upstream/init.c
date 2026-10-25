#include "auth.h"
#include "internal.h"

void vmessserverTunnelUpStreamInit(tunnel_t *t, line_t *line)
{
    vmessserver_lstate_t *ls = lineGetState(line, t);
    vmessserverLinestateInitialize(ls, t, line, kVmessServerLineKindClient);
    if (! vmessserverAuthLineInit(ls))
    {
        vmessserverReason(ls, kVmessServerReasonAdmission);
        vmessserverCloseLineBidirectional(t, line);
    }
}
