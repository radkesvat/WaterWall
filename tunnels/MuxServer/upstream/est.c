#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("MuxServer: UpStreamEst is disabled");
    terminateProgram(1);
}
