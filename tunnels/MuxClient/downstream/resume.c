#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelDownStreamResume(tunnel_t *t, line_t *parent_l)
{
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);

    muxclient_lstate_t *child_ls = parent_ls->child_next;
    while (child_ls)
    {
        muxclient_lstate_t *temp = child_ls->child_next;
        tunnelPrevDownStreamResume(t, child_ls->l);
        child_ls = temp;
    }
}
