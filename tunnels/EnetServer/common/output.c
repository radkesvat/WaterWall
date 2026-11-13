#include "EnetServer/structure.h"

static void enetserverInitService(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamInit(t, line);
}

static void enetserverEstablishApplication(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamEst(t, line);
}

static void enetserverSendApplication(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    tunnelNextUpStreamPayload(t, line, buf);
}

static void enetserverPauseApplication(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamPause(t, line);
}

static void enetserverResumeApplication(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamResume(t, line);
}

static void enetserverFinishApplication(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamFinish(t, line);
}

static void enetserverEstablishCarrier(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamEst(t, line);
}

static void enetserverSendCarrier(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    tunnelPrevDownStreamPayload(t, line, buf);
}

static void enetserverPauseCarrier(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamPause(t, line);
}

static void enetserverResumeCarrier(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamResume(t, line);
}

static void enetserverFinishCarrier(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamFinish(t, line);
}

/* The carrier is borrowed from the previous node; this node creates the service line toward the next one. */
const enet_output_t enetserverOutput = {
    .init_owned          = enetserverInitService,
    .application_est     = enetserverEstablishApplication,
    .application_payload = enetserverSendApplication,
    .application_pause   = enetserverPauseApplication,
    .application_resume  = enetserverResumeApplication,
    .application_finish  = enetserverFinishApplication,
    .carrier_est         = enetserverEstablishCarrier,
    .carrier_payload     = enetserverSendCarrier,
    .carrier_pause       = enetserverPauseCarrier,
    .carrier_resume      = enetserverResumeCarrier,
    .carrier_finish      = enetserverFinishCarrier,
};
