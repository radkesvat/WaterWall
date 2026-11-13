#include "ConnectionStripeServer/structure.h"

static void connectionstripeserverInitOwned(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamInit(t, line);
}

static void connectionstripeserverEstablishBorrowed(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamEst(t, line);
}

static void connectionstripeserverSendTransport(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    tunnelPrevDownStreamPayload(t, line, buf);
}

static void connectionstripeserverSendApplication(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    tunnelNextUpStreamPayload(t, line, buf);
}

static void connectionstripeserverPauseApplication(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamPause(t, line);
}

static void connectionstripeserverResumeApplication(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamResume(t, line);
}

static void connectionstripeserverFinishTransport(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamFinish(t, line);
}

static void connectionstripeserverFinishApplication(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamFinish(t, line);
}

/* Incoming transports are borrowed; this node creates the application. */
const stripe_output_t connectionstripeserverOutput = {
    .owned_line_role     = kStripeApplicationLine,
    .init_owned          = connectionstripeserverInitOwned,
    .est_borrowed        = connectionstripeserverEstablishBorrowed,
    .transport_payload   = connectionstripeserverSendTransport,
    .application_payload = connectionstripeserverSendApplication,
    .application_pause   = connectionstripeserverPauseApplication,
    .application_resume  = connectionstripeserverResumeApplication,
    .transport_finish    = connectionstripeserverFinishTransport,
    .application_finish  = connectionstripeserverFinishApplication,
};
