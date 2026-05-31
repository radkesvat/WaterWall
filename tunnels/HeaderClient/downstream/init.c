#include "structure.h"

#include "loggers/network_logger.h"

void headerclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("HeaderClient: DownStreamInit is disabled");
    terminateProgram(1);
}
