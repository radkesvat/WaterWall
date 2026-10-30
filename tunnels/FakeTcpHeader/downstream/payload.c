#include "structure.h"

void faketcpheaderDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    faketcpheaderProcessPayload(t, l, buf, false);
}
