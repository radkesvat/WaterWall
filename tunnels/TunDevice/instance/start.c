#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelOnStart(tunnel_t *t)
{
    tundevice_tstate_t *state = tunnelGetState(t);
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

    state->tdev = tundeviceCreate(state->name, false, state->mtu, t, tundeviceOnIPPacketReceived);

    if (state->tdev == NULL)
    {
        LOGF("TunDevice: could not create device");
        terminateProgram(1);
    }

    if (! tundeviceAssignIP(state->tdev, state->ip_present, (unsigned int) state->subnet_mask))
    {
        tundeviceDestroy(state->tdev);
        state->tdev = NULL;
        LOGF("TunDevice: could not assign device IP");
        terminateProgram(1);
    }

    if (! tundeviceBringUp(state->tdev))
    {
        tundeviceDestroy(state->tdev);
        state->tdev = NULL;
        LOGF("TunDevice: could not bring device up");
        terminateProgram(1);
    }

#ifdef OS_LINUX
    if (state->system_route_enabled && ! tundeviceDisableReversePathFiltering(state->name))
    {
        LOGW("TunDevice: could not disable Linux reverse path filtering for %s; continuing", state->name);
    }
#endif

    if (! tundeviceApplySystemRoutes(state))
    {
        tundeviceClearEgressPinIfPublished(state);
        tundeviceDestroy(state->tdev);
        state->tdev = NULL;
        LOGF("TunDevice: could not install system routes");
        terminateProgram(1);
    }

    if (! tundeviceApplyDnsSettings(state))
    {
        tundeviceCleanupSystemRoutes(state);
        tundeviceClearEgressPinIfPublished(state);
        tundeviceDestroy(state->tdev);
        state->tdev = NULL;
        LOGF("TunDevice: could not configure DNS servers");
        terminateProgram(1);
    }

    if (state->post_up_script != NULL && execCmd(state->post_up_script).exit_code != 0)
    {
        tundeviceCleanupDnsSettings(state);
        tundeviceCleanupSystemRoutes(state);
        tundeviceClearEgressPinIfPublished(state);
        tundeviceDestroy(state->tdev);
        state->tdev = NULL;
        LOGF("TunDevice: post-up-script failed");
        terminateProgram(1);
    }
}
