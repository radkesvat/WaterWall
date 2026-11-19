#include "RtmpServer/structure.h"

void rtmpserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    /* The shared pump admits the backend after it receives a valid publication. */
    discard rtmpInitLine(t, l);
}
