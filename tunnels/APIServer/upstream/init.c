#include "APIServer/structure.h"

void apiserverUpStreamInit(tunnel_t *t, line_t *line)
{
    if (! apiserverLinestateInitialize(t, line))
    {
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    apiserver_lstate_t *ls = lineGetState(line, t);
    if (! apiserverArmTimer(ls))
    {
        apiserverCloseSession(t, line);
        return;
    }
    tunnelPrevDownStreamEst(t, line);
}
