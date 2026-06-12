#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("AuthenticationClient: DownStreamInit is disabled");
    terminateProgram(1);
}
