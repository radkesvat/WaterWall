#include "ConnectionStripeClient/structure.h"

static void connectionstripeclientInitOwned(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamInit(t, line);
}

static void connectionstripeclientEstablishBorrowed(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamEst(t, line);
}

static void connectionstripeclientSendTransport(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    tunnelNextUpStreamPayload(t, line, buf);
}

static void connectionstripeclientSendApplication(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    tunnelPrevDownStreamPayload(t, line, buf);
}

static void connectionstripeclientPauseApplication(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamPause(t, line);
}

static void connectionstripeclientResumeApplication(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamResume(t, line);
}

static void connectionstripeclientFinishTransport(tunnel_t *t, line_t *line)
{
    tunnelNextUpStreamFinish(t, line);
}

static void connectionstripeclientFinishApplication(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamFinish(t, line);
}

/* The application is borrowed; this node creates every transport. */
const stripe_output_t connectionstripeclientOutput = {
    .owned_line_role     = kStripeTransportLine,
    .init_owned          = connectionstripeclientInitOwned,
    .est_borrowed        = connectionstripeclientEstablishBorrowed,
    .transport_payload   = connectionstripeclientSendTransport,
    .application_payload = connectionstripeclientSendApplication,
    .application_pause   = connectionstripeclientPauseApplication,
    .application_resume  = connectionstripeclientResumeApplication,
    .transport_finish    = connectionstripeclientFinishTransport,
    .application_finish  = connectionstripeclientFinishApplication,
};
