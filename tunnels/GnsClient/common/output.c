#include "GnsClient/structure.h"

static void gnsclientInitCarrier(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamInit(t, line);
}

static void gnsclientEstablishApplication(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamEst(t, line);
}

static void gnsclientSendApplication(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    tunnelPrevDownStreamPayload(t, line, buf);
}

static void gnsclientPauseApplication(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamPause(t, line);
}

static void gnsclientResumeApplication(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamResume(t, line);
}

static void gnsclientFinishApplication(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamFinish(t, line);
}

static void gnsclientSendCarrier(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    tunnelNextUpStreamPayload(t, line, buf);
}

static void gnsclientPauseCarrier(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamPause(t, line);
}

static void gnsclientResumeCarrier(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamResume(t, line);
}

static void gnsclientFinishCarrier(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamFinish(t, line);
}

/* The application is borrowed from the previous node; this node creates the carrier toward the next one. */
const gns_output_t gnsclientOutput = {
    .init_owned          = gnsclientInitCarrier,
    .application_est     = gnsclientEstablishApplication,
    .application_payload = gnsclientSendApplication,
    .application_pause   = gnsclientPauseApplication,
    .application_resume  = gnsclientResumeApplication,
    .application_finish  = gnsclientFinishApplication,
    .carrier_payload     = gnsclientSendCarrier,
    .carrier_pause       = gnsclientPauseCarrier,
    .carrier_resume      = gnsclientResumeCarrier,
    .carrier_finish      = gnsclientFinishCarrier,
};
