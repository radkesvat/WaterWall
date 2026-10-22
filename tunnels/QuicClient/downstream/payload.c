#include "structure.h"

void quicclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    quicSubmitCarrier(t, l, buf);
}
