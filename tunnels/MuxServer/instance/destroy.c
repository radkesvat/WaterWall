#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

