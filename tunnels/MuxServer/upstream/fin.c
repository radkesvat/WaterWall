#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelUpStreamFinish(tunnel_t *t, line_t *parent_l)
{
    // The previous side sent Finish, so parent teardown must not call back toward it.
    muxserverHandleParentLoss(t, parent_l, false);
}
