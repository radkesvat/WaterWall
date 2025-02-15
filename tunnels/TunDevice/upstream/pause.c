#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
    LOGF("This Function is not supported to be called for a down chain tunnel (TunDevice)");
    exit(1);
}
