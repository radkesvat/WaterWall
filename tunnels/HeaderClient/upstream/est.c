#include "structure.h"

#include "loggers/network_logger.h"

void headerclientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("HeaderClient: UpStreamEst is disabled");
    terminateProgram(1);
}
