#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("This Function is not supposed to be called for a down chain tunnel (TunDevice)");
    terminateProgram(1);
}
