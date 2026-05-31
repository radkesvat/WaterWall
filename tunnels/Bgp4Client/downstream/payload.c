#include "structure.h"

#include "loggers/network_logger.h"

void bgp4clientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    bgp4client_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kBgp4ClientPhaseNone)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    bufferstreamPush(&ls->read_stream, buf);

    while (true)
    {
        sbuf_t *payload = NULL;
        if (! bgp4clientReadFrame(t, l, &ls->read_stream, &payload))
        {
            bgp4clientCloseLine(t, l);
            return;
        }

        if (payload == NULL)
        {
            break;
        }

        if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, payload))
        {
            return;
        }
    }
}
