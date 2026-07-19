#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    LOGF("TunDevice: unexpected upstream Finish on worker packet line %u", (unsigned int) lineGetWID(l));
    terminateProgram(1);
}
