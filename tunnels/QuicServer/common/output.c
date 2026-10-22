#include "structure.h"

static void quicserverSendWire(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnelPrevDownStreamPayload(t, l, buf);
}

static void quicserverSendApplication(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnelNextUpStreamPayload(t, l, buf);
}

static void quicserverPauseApplication(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamPause(t, l);
}

static void quicserverResumeApplication(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamResume(t, l);
}

const quic_output_t quicserverOutput = {
    .wire_payload        = quicserverSendWire,
    .application_payload = quicserverSendApplication,
    .application_pause   = quicserverPauseApplication,
    .application_resume  = quicserverResumeApplication,
};
