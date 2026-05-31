#include "structure.h"

#include "loggers/network_logger.h"

static bool headerserverReadHeaderPort(headerserver_lstate_t *ls, line_t *l, uint16_t *port_out)
{
    if (bufferstreamGetBufLen(&ls->read_stream) < kHeaderServerHeaderSize)
    {
        return false;
    }

    sbuf_t  *header = bufferstreamReadExact(&ls->read_stream, kHeaderServerHeaderSize);
    uint16_t port_network;

    sbufReadUnAlignedUI16(header, &port_network);
    lineReuseBuffer(l, header);

    *port_out = ntohs(port_network);
    return true;
}

static void headerserverForwardBufferedPayload(tunnel_t *t, line_t *l)
{
    headerserver_lstate_t *ls = lineGetState(l, t);
    sbuf_t                *buf = bufferstreamFullRead(&ls->read_stream);

    if (buf != NULL)
    {
        discard withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf);
    }
}

void headerserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    headerserver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kHeaderServerPhaseNone)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase == kHeaderServerPhaseEstablished)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    bufferstreamPush(&ls->read_stream, buf);

    uint16_t port = 0;
    if (! headerserverReadHeaderPort(ls, l, &port))
    {
        return;
    }

    if (port < kHeaderServerMinAllowedPort)
    {
        LOGW("HeaderServer: received invalid header port %u, closing line", (unsigned int) port);
        headerserverCloseLineFromProtocolError(t, l);
        return;
    }

    addresscontextSetPort(lineGetDestinationAddressContext(l), port);
    ls->phase = kHeaderServerPhaseEstablished;

    if (! withLineLocked(l, tunnelNextUpStreamInit, t))
    {
        return;
    }

    headerserverForwardBufferedPayload(t, l);
}
