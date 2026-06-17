#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TrojanClient: UpStreamEst is disabled");
    terminateProgram(1);
}
