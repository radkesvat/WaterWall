#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("MuxServer: DownStreamInit is disabled");
    abortProgramNow(1);
}
