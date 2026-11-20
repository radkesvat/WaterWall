#include "RtmpClient/structure.h"

static void rtmpclientSetApplicationPressure(tunnel_t *t, line_t *l, bool paused)
{
    if (paused)
    {
        tunnelPrevDownStreamPause(t, l);
    }
    else
    {
        tunnelPrevDownStreamResume(t, l);
    }
}

static void rtmpclientSetCarrierPressure(tunnel_t *t, line_t *l, bool paused)
{
    if (paused)
    {
        tunnelNextUpStreamPause(t, l);
    }
    else
    {
        tunnelNextUpStreamResume(t, l);
    }
}

const rtmp_output_t rtmpclientOutput = {
    .wire_payload         = tunnelNextUpStreamPayload,
    .application_payload  = tunnelPrevDownStreamPayload,
    .carrier_pressure     = rtmpclientSetCarrierPressure,
    .application_pressure = rtmpclientSetApplicationPressure,
};
