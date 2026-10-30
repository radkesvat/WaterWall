#include "structure.h"

void faketcpheaderUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    faketcpheaderProcessPayload(t, l, buf, true);
}
