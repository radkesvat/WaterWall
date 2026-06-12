#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("AuthenticationClient: UpStreamPause is disabled");
    terminateProgram(1);
}
