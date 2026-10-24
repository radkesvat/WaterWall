#include "internal.h"

#include "loggers/network_logger.h"

void vmessclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    vmessclientCloseLine(t, l, kVmessClientCloseFromNext);
}
