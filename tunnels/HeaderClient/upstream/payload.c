#include "structure.h"

#include "loggers/network_logger.h"

static uint16_t headerclientGetHeaderPort(headerclient_tstate_t *ts, line_t *l)
{
    switch (ts->data_mode)
    {
    case kHeaderClientDataModeSourcePort:
        return lineGetSourceAddressContext(l)->port;

    case kHeaderClientDataModeConstant:
        return ts->constant_port;

    default:
        return 0;
    }
}

void headerclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    headerclient_tstate_t *ts = tunnelGetState(t);
    headerclient_lstate_t *ls = lineGetState(l, t);

    if (! ls->header_sent)
    {
        uint16_t port = headerclientGetHeaderPort(ts, l);
        uint16_t port_network = htons(port);

        ls->header_sent = true;
        sbufShiftLeft(buf, kHeaderClientHeaderSize);
        sbufWriteUnAlignedUI16(buf, port_network);
    }

    tunnelNextUpStreamPayload(t, l, buf);
}
