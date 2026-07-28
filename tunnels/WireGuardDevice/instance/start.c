#include "structure.h"

#include "loggers/network_logger.h"

static void loopHandle(wtimer_t *timer)
{
    wgd_tstate_t *state = weventGetUserdata(timer);
    if (state == NULL)
    {
        return;
    }

    wireguarddeviceStateLock(state);
    const bool active = state->wg_device.loop_timer == timer && ! isApplicationTerminating();
    wireguarddeviceStateUnlock(state);

    if (! active)
    {
        return;
    }

    wireguarddeviceLoop((wireguard_device_t *) state);
}

static void wireguarddeviceQueueWorkerPacketInit(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;
    discard arg3;

    tunnel_t *t = arg1;
    line_t   *l = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), getWID());

    tunnelNextUpStreamInit(t, l);
    if (! lineIsAlive(l))
    {
        LOGF("WireGuardDevice: worker packet line died during packet-side init");
        abortProgramNow(1);
    }
}

static void wireguarddeviceQueueWorkerTransportLineInit(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;
    discard arg3;

    tunnel_t     *t     = arg1;
    wgd_tstate_t *state = tunnelGetState(t);

    /*
     * Not a process-wide failure: this is an ordinary transport line, and a
     * neighbouring connector may reject this one line for an operational
     * reason. The slot stays NULL, the output paths treat that as ERR_CONN, and
     * wireguarddeviceEnsureTransportLine() retries on a later output.
     */
    if (wireguarddeviceEnsureTransportLine(state, getWID()) == NULL)
    {
        LOGW("WireGuardDevice: worker transport line was rejected at startup; it will be retried on demand");
        return;
    }
}

static void wireguarddeviceEnsureTransportLineStorage(tunnel_t *t, wgd_tstate_t *state)
{
    tunnel_chain_t *tc = tunnelGetChain(t);

    if (state->transport_lines != NULL)
    {
        return;
    }

    if (tc == NULL || tc->workers_count == 0)
    {
        LOGF("WireGuardDevice: transport line storage requires a finalized tunnel chain");
        terminateProgram(1);
    }

    state->transport_lines = memoryAllocateZero(sizeof(*state->transport_lines) * tc->workers_count);
}

static void wireguarddeviceEnsureTransportLineInit(tunnel_t *t, wgd_tstate_t *state)
{
    tunnel_chain_t *tc = tunnelGetChain(t);

    wireguarddeviceEnsureTransportLineStorage(t, state);
    for (wid_t wi = 0; wi < tc->workers_count; ++wi)
    {
        sendWorkerMessageForceQueue(wi, wireguarddeviceQueueWorkerTransportLineInit, t, NULL, NULL);
    }
}

static void wireguarddeviceEnsureInnerPacketInit(tunnel_t *t, wgd_tstate_t *state)
{
    tunnel_chain_t *tc = tunnelGetChain(t);

    if (wireguarddeviceTransportSideIsNext(state) || tc == NULL || tc->packet_lines == NULL ||
        tc->packet_chain_init_sent)
    {
        return;
    }

    if (t->next == NULL)
    {
        LOGF("WireGuardDevice: transport-direction=prev requires a next packet-side tunnel");
        terminateProgram(1);
    }

    tc->packet_chain_init_sent = true;
    for (wid_t wi = 0; wi < tc->workers_count; ++wi)
    {
        sendWorkerMessageForceQueue(wi, wireguarddeviceQueueWorkerPacketInit, t, NULL, NULL);
    }
}

void wireguarddeviceTunnelOnStart(tunnel_t *t)
{
    wgd_tstate_t *state = tunnelGetState(t);

    wireguarddeviceEnsureTransportLineInit(t, state);

    wireguard_device_t *device = (wireguard_device_t *) state;
    for (uint8_t i = 0; i < WIREGUARD_MAX_PEERS; i++)
    {
        wireguard_peer_t *peer = &device->peers[i];
        if (peer->valid)
        {
            if (wireguardifConnect(device, i) != ERR_OK)
            {
                LOGF("Error: wireguardifConnect failed");
                terminateProgram(1);
            }
        }
    }

    wireguarddeviceEnsureInnerPacketInit(t, state);

    state->wg_device.loop_timer = wtimerAdd(getWorkerLoop(0), loopHandle, WIREGUARDIF_TIMER_MSECS, INFINITE);
    if (state->wg_device.loop_timer == NULL)
    {
        LOGF("WireGuardDevice: failed to create periodic timer");
        terminateProgram(1);
    }
    weventSetUserData(state->wg_device.loop_timer, state);

    discard t;
}
