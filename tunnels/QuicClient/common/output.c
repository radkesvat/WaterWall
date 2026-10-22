#include "structure.h"

static void quicclientSendWire(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnelNextUpStreamPayload(t, l, buf);
}

static void quicclientSendApplication(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnelPrevDownStreamPayload(t, l, buf);
}

static void quicclientPauseApplication(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamPause(t, l);
}

static void quicclientResumeApplication(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamResume(t, l);
}

const quic_output_t quicclientOutput = {
    .wire_payload        = quicclientSendWire,
    .application_payload = quicclientSendApplication,
    .application_pause   = quicclientPauseApplication,
    .application_resume  = quicclientResumeApplication,
};
