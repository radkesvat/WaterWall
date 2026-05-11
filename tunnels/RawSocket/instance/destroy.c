#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketDestroy(tunnel_t *t)
{
    rawsocket_tstate_t *state = tunnelGetState(t);

    if (state->capture_ranges)
    {
        memoryFree(state->capture_ranges);
    }
    if (state->capture_device_name)
    {
        memoryFree(state->capture_device_name);
    }

    if (state->raw_device_name)
    {
        memoryFree(state->raw_device_name);
    }

    if (state->capture_device)
    {
        capturedeviceDestroy(state->capture_device);
    }
    if (state->raw_device)
    {
        rawdeviceDestroy(state->raw_device);
    }
    tunnelDestroy(t);
}
