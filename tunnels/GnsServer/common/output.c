#include "GnsServer/structure.h"

static void gnsserverInitService(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamInit(t, line);
}

static void gnsserverEstablishApplication(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamEst(t, line);
}

static void gnsserverSendApplication(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    tunnelNextUpStreamPayload(t, line, buf);
}

static void gnsserverPauseApplication(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamPause(t, line);
}

static void gnsserverResumeApplication(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamResume(t, line);
}

static void gnsserverFinishApplication(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamFinish(t, line);
}

static void gnsserverEstablishCarrier(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamEst(t, line);
}

static void gnsserverSendCarrier(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    tunnelPrevDownStreamPayload(t, line, buf);
}

static void gnsserverPauseCarrier(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamPause(t, line);
}

static void gnsserverResumeCarrier(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamResume(t, line);
}

static void gnsserverFinishCarrier(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamFinish(t, line);
}

/* The carrier is borrowed from the previous node; this node creates the service line toward the next one. */
const gns_output_t gnsserverOutput = {
    .init_owned          = gnsserverInitService,
    .application_est     = gnsserverEstablishApplication,
    .application_payload = gnsserverSendApplication,
    .application_pause   = gnsserverPauseApplication,
    .application_resume  = gnsserverResumeApplication,
    .application_finish  = gnsserverFinishApplication,
    .carrier_est         = gnsserverEstablishCarrier,
    .carrier_payload     = gnsserverSendCarrier,
    .carrier_pause       = gnsserverPauseCarrier,
    .carrier_resume      = gnsserverResumeCarrier,
    .carrier_finish      = gnsserverFinishCarrier,
};
