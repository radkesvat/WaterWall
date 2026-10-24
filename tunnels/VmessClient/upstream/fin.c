#include "internal.h"

#include "loggers/network_logger.h"

void vmessclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    vmessclientCloseLine(t, l, kVmessClientCloseFromPrev);
}
