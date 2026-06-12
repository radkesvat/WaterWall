#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("AuthenticationClient: UpStreamInit is disabled; this node owns its control line");
    terminateProgram(1);
}
