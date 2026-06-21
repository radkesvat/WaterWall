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

    // Self-traffic loop protection must capture the original default gateway
    // before the TUN system routes are installed. It is a best-effort feature:
    // failure to start it is non-fatal (it returns NULL and stays inactive).
    if (state->loop_protection_enabled)
    {
        uint64_t tun_luid = 0;
        tundeviceGetLuid(state->tdev, &tun_luid);
        state->loop_guard = tunLoopGuardStart(tun_luid);
    }

    if (! tundeviceApplySystemRoutes(state))
    {
        tunLoopGuardStop(state->loop_guard);
        state->loop_guard = NULL;
        tundeviceDestroy(state->tdev);
        state->tdev = NULL;
        LOGF("TunDevice: could not install system routes");
        terminateProgram(1);
    }

    if (state->post_up_script != NULL && execCmd(state->post_up_script).exit_code != 0)
    {
        tundeviceCleanupSystemRoutes(state);
        tunLoopGuardStop(state->loop_guard);
        state->loop_guard = NULL;
        tundeviceDestroy(state->tdev);
        state->tdev = NULL;
        LOGF("TunDevice: post-up-script failed");
        terminateProgram(1);
    }
}
