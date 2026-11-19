#include "RtmpServer/structure.h"

static void rtmpserverSetApplicationPressure(tunnel_t *t, line_t *l, bool paused)
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

static void rtmpserverSetCarrierPressure(tunnel_t *t, line_t *l, bool paused)
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

const rtmp_output_t rtmpserverOutput = {
    .wire_payload         = tunnelPrevDownStreamPayload,
    .application_payload  = tunnelNextUpStreamPayload,
    .carrier_pressure     = rtmpserverSetCarrierPressure,
    .application_pressure = rtmpserverSetApplicationPressure,
};
