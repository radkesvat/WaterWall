#include "EnetClient/structure.h"

static void enetclientInitCarrier(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamInit(t, line);
}

static void enetclientEstablishApplication(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamEst(t, line);
}

static void enetclientSendApplication(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    tunnelPrevDownStreamPayload(t, line, buf);
}

static void enetclientPauseApplication(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamPause(t, line);
}

static void enetclientResumeApplication(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamResume(t, line);
}

static void enetclientFinishApplication(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamFinish(t, line);
}

static void enetclientSendCarrier(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    tunnelNextUpStreamPayload(t, line, buf);
}

static void enetclientPauseCarrier(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamPause(t, line);
}

static void enetclientResumeCarrier(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamResume(t, line);
}

static void enetclientFinishCarrier(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamFinish(t, line);
}

/* The application is borrowed from the previous node; this node creates the carrier toward the next one. */
const enet_output_t enetclientOutput = {
    .init_owned          = enetclientInitCarrier,
    .application_est     = enetclientEstablishApplication,
    .application_payload = enetclientSendApplication,
    .application_pause   = enetclientPauseApplication,
    .application_resume  = enetclientResumeApplication,
    .application_finish  = enetclientFinishApplication,
    .carrier_payload     = enetclientSendCarrier,
    .carrier_pause       = enetclientPauseCarrier,
    .carrier_resume      = enetclientResumeCarrier,
    .carrier_finish      = enetclientFinishCarrier,
};
