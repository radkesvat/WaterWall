#include "structure.h"

#include "loggers/network_logger.h"

static void rawsocketStopStartupDevices(rawsocket_tstate_t *state)
{
    if (state->capture_device != NULL && ! caputredeviceBringDown(state->capture_device))
    {
        LOGW("RawSocket: capture device bring down completed with cleanup errors");
    }
    if (state->raw_device != NULL && ! rawdeviceBringDown(state->raw_device))
    {
        LOGW("RawSocket: raw device bring down completed with cleanup errors");
    }
}

static void rawsocketDestroyStartupDevices(rawsocket_tstate_t *state)
{
    if (state->capture_device != NULL)
    {
        capturedeviceDestroy(state->capture_device);
        state->capture_device = NULL;
    }

    if (state->raw_device != NULL)
    {
        rawdeviceDestroy(state->raw_device);
        state->raw_device = NULL;
    }
}

void rawsocketOnStart(tunnel_t *t)
{
    rawsocket_tstate_t *state = tunnelGetState(t);

    if (state->capture_range_count > 0 && ! packettunnelLifecycleAnchorBind(t))
    {
        LOGF("RawSocket: packet publication side is not chained");
        startupFailureRecord(1);
        return;
    }

    if (state->capture_range_count > 0)
    {
        state->capture_device = caputredeviceCreate(state->capture_device_name,
                                                    state->capture_ranges,
                                                    state->capture_range_count,
                                                    state->skip_sysctl,
                                                    t,
                                                    rawsocketOnIPPacketReceived);

        if (state->capture_device == NULL)
        {
            LOGF("CaptureDevice: could not create device");
            startupFailureRecord(1);
            return;
        }
    }

    // we are not going to read, so pass read call back as null therfore no buffers for read will be allocated
    state->raw_device = rawdeviceCreate(state->raw_device_name, state->firewall_mark, t);
    if (state->raw_device == NULL)
    {
        rawsocketDestroyStartupDevices(state);
        LOGF("RawDevice: could not create device");
        startupFailureRecord(1);
        return;
    }

    // The writer must be operational before any NFQUEUE rule can become active.
    // Capture's reader accepts packets during rule installation and switches to
    // drop-and-dispatch only after this raw device is ready.
    if (! rawdeviceBringUp(state->raw_device))
    {
        rawsocketDestroyStartupDevices(state);
        LOGF("RawDevice: could not bring device up");
        startupFailureRecord(1);
        return;
    }
    if (state->capture_device != NULL && ! caputredeviceBringUp(state->capture_device))
    {
        rawsocketStopStartupDevices(state);
        rawsocketDestroyStartupDevices(state);
        LOGF("CaptureDevice: could not bring device up");
        startupFailureRecord(1);
        return;
    }
}
