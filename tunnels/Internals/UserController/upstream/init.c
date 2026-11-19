#include "structure.h"

void usercontrollerTunnelUpStreamInit(tunnel_t *tunnel, line_t *line)
{
    usercontrollerOpenLine(tunnel, line, false);
}
