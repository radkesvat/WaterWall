#include "structure.h"

#include "loggers/network_logger.h"

static void rawsocketStopDevices(rawsocket_tstate_t *state)
{
    if (state->capture_device && state->capture_device->up)
    {
        if (! caputredeviceBringDown(state->capture_device))
        {
            LOGW("RawSocket: capture device bring down completed with cleanup errors");
        }
    }
    if (state->raw_device && state->raw_device->up)
    {
        rawdeviceBringDown(state->raw_device);
    }
}

void rawsocketOnStop(tunnel_t *t)
{
    rawsocketStopDevices(tunnelGetState(t));
}
