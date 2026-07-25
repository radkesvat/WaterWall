#include "structure.h"

#include "loggers/network_logger.h"

static void rawsocketStopStartupCapture(rawsocket_tstate_t *state)
{
    if (state->capture_device != NULL)
    {
        if (state->capture_device->up && ! caputredeviceBringDown(state->capture_device))
        {
            LOGW("RawSocket: capture device bring down completed with cleanup errors");
        }
    }
}

static void rawsocketDestroyStartupDevicesBeforeCaptureStart(rawsocket_tstate_t *state)
{
    if (state->raw_device != NULL)
    {
        rawdeviceDestroy(state->raw_device);
        state->raw_device = NULL;
    }

    if (state->capture_device != NULL)
    {
        capturedeviceDestroy(state->capture_device);
        state->capture_device = NULL;
    }
}

void rawsocketOnStart(tunnel_t *t)
{
    rawsocket_tstate_t *state = tunnelGetState(t);

    if (nodeIsLastInChain(t->node))
    {
        state->WriteReceivedPacket = t->prev->fnPayloadD;
        state->write_tunnel        = t->prev;
    }
    else
    {
        state->WriteReceivedPacket = t->next->fnPayloadU;
        state->write_tunnel        = t->next;
    }

    state->capture_device = caputredeviceCreate(
        state->capture_device_name, state->capture_ranges, state->capture_range_count, t, rawsocketOnIPPacketReceived);

    if (state->capture_device == NULL)
    {
        LOGF("CaptureDevice: could not create device");
        terminateProgram(1);
    }

    // we are not going to read, so pass read call back as null therfore no buffers for read will be allocated
    state->raw_device = rawdeviceCreate(state->raw_device_name, state->firewall_mark, t);
    if (state->raw_device == NULL)
    {
        rawsocketDestroyStartupDevicesBeforeCaptureStart(state);
        LOGF("RawDevice: could not create device");
        terminateProgram(1);
    }

    if (! caputredeviceBringUp(state->capture_device))
    {
        rawsocketDestroyStartupDevicesBeforeCaptureStart(state);
        LOGF("CaptureDevice: could not bring device up");
        terminateProgram(1);
    }
    if (! rawdeviceBringUp(state->raw_device))
    {
        rawsocketStopStartupCapture(state);
        LOGF("RawDevice: could not bring device up");
        terminateProgram(1);
    }
}
