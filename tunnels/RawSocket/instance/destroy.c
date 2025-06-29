#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketDestroy(tunnel_t *t)
{
    rawsocket_tstate_t *state = tunnelGetState(t);
    if (state->capture_device != NULL)
    {
        if (state->capture_ip)
        {
            memoryFree(state->capture_ip);
        }
        if (state->capture_device_name)
        {
            memoryFree(state->capture_device_name);
        }

        if (state->raw_device_name)
        {
            memoryFree(state->raw_device_name);
        }
        execCmd(state->onexit_command);

        capturedeviceDestroy(state->capture_device);
        rawdeviceDestroy(state->raw_device);
    }
    tunnelDestroy(t);
}
