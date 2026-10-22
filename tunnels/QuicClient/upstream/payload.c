#include "structure.h"

void quicclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    quicSubmitApplication(t, l, buf);
}
