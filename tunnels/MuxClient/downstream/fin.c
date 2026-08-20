#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelDownStreamFinish(tunnel_t *t, line_t *parent_l)
{
    // The next side sent Finish, so parent teardown must not call back toward it.
    muxclientHandleParentLoss(t, parent_l, false);
}
