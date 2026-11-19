#include "structure.h"

void usercontrollerTunnelDownStreamInit(tunnel_t *tunnel, line_t *line)
{
    usercontrollerOpenLine(tunnel, line, true);
}
