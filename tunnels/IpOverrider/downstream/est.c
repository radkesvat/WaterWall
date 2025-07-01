#include "structure.h"

#include "loggers/network_logger.h"

void ipoverriderDownStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("This Function is not supported to be called for a down chain tunnel (IpOverrider)");
    terminateProgram(1);
}
