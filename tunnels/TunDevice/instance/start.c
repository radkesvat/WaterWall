#include "structure.h"

#include "loggers/network_logger.h"
#ifdef OS_WIN
#include "devices/tun/tun_windows_dns.h"
#endif

void tundeviceTunnelOnStart(tunnel_t *t)
{
    tundevice_tstate_t *state     = tunnelGetState(t);
    bool                device_up = false;
    bool                cancelled = false;
    const char         *failure   = NULL;

    if (! packettunnelLifecycleAnchorBind(t))
    {
        LOGF("TunDevice: packet publication side is not chained");
        startupFailureRecord(1);
        return;
    }

    state->tdev = tundeviceCreate(state->name, false, state->mtu, t, tundeviceOnIPPacketReceived);

    if (state->tdev == NULL)
    {
        failure = "TunDevice: could not create device";
        goto rollback;
    }

    if (! tundeviceAssignIP(state->tdev, state->ip_present, (unsigned int) state->subnet_mask))
    {
        failure = "TunDevice: could not assign device IP";
        goto rollback;
    }

    if (! tundeviceBringUp(state->tdev))
    {
        failure = "TunDevice: could not bring device up";
        goto rollback;
    }
    device_up = true;

#ifdef OS_LINUX
    /*
     * Reverse path filtering drops packets whose source address does not route
     * back out of the interface they arrived on. Traffic injected into the TUN
     * regularly trips that check, and it does so whether or not this instance
     * installs the system routes itself, so disable it for every Linux TUN
     * rather than only for the native-system-route configuration.
     */
    if (! tundeviceDisableReversePathFiltering(state->name))
    {
        LOGW("TunDevice: could not disable Linux reverse path filtering for %s; continuing", state->name);
    }
#endif

    if (! tundeviceApplySystemRoutes(state))
    {
        failure = "TunDevice: could not install system routes";
        goto rollback;
    }
    if (! tundeviceApplyDnsSettings(state))
    {
#ifdef OS_WIN
        cancelled = tundeviceWindowsDnsWasCancelled(state->tdev);
#endif
        failure = "TunDevice: could not configure DNS servers";
        goto rollback;
    }

    if (state->post_up_script != NULL && execCmd(state->post_up_script).exit_code != 0)
    {
        failure = "TunDevice: post-up-script failed";
        goto rollback;
    }
    state->pre_down_pending = state->pre_down_script != NULL;
    return;

rollback:
    /* Attempt partial installations too. Failed entries stay owned until a
     * later cleanup succeeds or the
     * exclusively owned adapter is destroyed. */
    tundeviceCleanupDnsSettings(state);
    tundeviceCleanupSystemRoutes(state);
    tundeviceClearEgressPinIfPublished(state);
    if (device_up && ! tundeviceBringDown(state->tdev))
    {
        LOGW("TunDevice: bring-down during startup rollback completed with cleanup errors");
        state->policy_cleanup_failed = true;
    }
    /* Keep the device for the normal owner teardown, including another bounded
     * cleanup pass for unresolved
     * policy. A stop is not a startup failure. */
    if (! cancelled || state->policy_cleanup_failed)
    {
        if (! cancelled)
        {
            LOGF("%s", failure);
        }
        startupFailureRecord(1);
    }
    return;
}
