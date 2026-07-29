#include "structure.h"

#include "loggers/network_logger.h"

static void rawsocketStopDevices(rawsocket_tstate_t *state)
{
    if (state->capture_device)
    {
        if (! caputredeviceBringDown(state->capture_device))
        {
            LOGW("RawSocket: capture device bring down completed with cleanup errors");
        }
    }
    if (state->raw_device && ! rawdeviceBringDown(state->raw_device))
    {
        LOGW("RawSocket: raw device bring down completed with cleanup errors");
    }
}

void rawsocketOnStop(tunnel_t *t)
{
    rawsocketStopDevices(tunnelGetState(t));
}
