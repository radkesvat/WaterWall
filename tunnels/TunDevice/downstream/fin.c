#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    LOGF("TunDevice: unexpected downstream Finish on worker packet line %u", (unsigned int) lineGetWID(l));
    terminateProgram(1);
}
