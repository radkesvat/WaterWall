#include "structure.h"

#include "loggers/network_logger.h"

static void loopHandle(wtimer_t *timer)
{
    wgd_tstate_t *state = weventGetUserdata(timer);
    assert(state != NULL);

    wireguarddeviceStateLock(state);
    assert(state->wg_device.loop_timer == timer);
    wireguarddeviceStateUnlock(state);

    wireguarddeviceLoop((wireguard_device_t *) state);
}

void wireguarddeviceQueueWorkerPacketInit(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    // The message was delivered to exactly one worker; that worker owns the
    // packet line this callback must initialize.
    const wid_t wid = ((worker_t *) worker)->wid;
    assert(currentThreadIsEventWorkerWID(wid));

    tunnel_t *t = arg1;
    line_t   *l = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), wid);

    if (UNLIKELY(! lineCallWithRef(l, tunnelNextUpStreamInit, t)))
    {
        LOGF("WireGuardDevice: worker packet line died during packet-side init");
        abortProgramNow(1);
    }
}

static void wireguarddeviceQueueWorkerTransportLineInit(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    const wid_t wid = ((worker_t *) worker)->wid;
    assert(currentThreadIsEventWorkerWID(wid));

    tunnel_t     *t     = arg1;
    wgd_tstate_t *state = tunnelGetState(t);

    /*
     * Not a process-wide failure: this is an ordinary transport line, and a
     * neighbouring connector may reject this one line for an operational
     * reason. The slot stays NULL, the output paths treat that as ERR_CONN, and
     * wireguarddeviceEnsureTransportLine() retries on a later output.
     */
    if (wireguarddeviceEnsureTransportLine(state, wid) == NULL)
    {
        LOGW("WireGuardDevice: worker transport line was rejected at startup; it will be retried on demand");
        return;
    }
}

static bool wireguarddeviceEnsureTransportLineStorage(tunnel_t *t, wgd_tstate_t *state)
{
    tunnel_chain_t *tc = tunnelGetChain(t);

    if (state->transport_lines != NULL)
    {
        return true;
    }

    if (tc == NULL || tc->workers_count == 0)
    {
        LOGF("WireGuardDevice: transport line storage requires a finalized tunnel chain");
        startupFailureRecord(1);
        return false;
    }

    size_t storage_bytes;
    if (! memoryTryComputeArraySize(tc->workers_count, sizeof(*state->transport_lines), &storage_bytes))
    {
        LOGF("WireGuardDevice: transport line storage geometry overflows size_t");
        startupFailureRecord(1);
        return false;
    }

    line_t **storage = memoryAllocateZero(storage_bytes);
    if (UNLIKELY(storage == NULL))
    {
        LOGF("WireGuardDevice: failed to allocate mandatory transport line storage");
        startupFailureRecord(1);
        return false;
    }
    state->transport_lines = storage;
    return true;
}

static bool wireguarddeviceEnsureTransportLineInit(tunnel_t *t, wgd_tstate_t *state)
{
    tunnel_chain_t *tc = tunnelGetChain(t);

    if (! wireguarddeviceEnsureTransportLineStorage(t, state))
    {
        return false;
    }
    for (wid_t wi = 0; wi < tc->workers_count; ++wi)
    {
        if (UNLIKELY(sendWorkerMessageForceQueueWithCleanup(
                         wi, wireguarddeviceQueueWorkerTransportLineInit, NULL, t, NULL, NULL) !=
                     kWorkerMessageSubmitAccepted))
        {
            LOGF("WireGuardDevice: failed to admit required transport-line startup on worker %u", (unsigned int) wi);
            startupFailureRecord(1);
            return false;
        }
    }
    return true;
}

static bool wireguarddeviceEnsureInnerPacketInit(tunnel_t *t, wgd_tstate_t *state)
{
    tunnel_chain_t *tc = tunnelGetChain(t);

    if (wireguarddeviceTransportSideIsNext(state) || tc == NULL || tc->packet_lines == NULL ||
        tc->packet_chain_init_sent)
    {
        return true;
    }

    if (t->next == NULL)
    {
        LOGF("WireGuardDevice: a previous transport side requires a next packet-side tunnel");
        startupFailureRecord(1);
        return false;
    }

    for (wid_t wi = 0; wi < tc->workers_count; ++wi)
    {
        if (UNLIKELY(
                sendWorkerMessageForceQueueWithCleanup(wi, wireguarddeviceQueueWorkerPacketInit, NULL, t, NULL, NULL) !=
                kWorkerMessageSubmitAccepted))
        {
            LOGF("WireGuardDevice: failed to admit required packet-side Init on worker %u", (unsigned int) wi);
            startupFailureRecord(1);
            return false;
        }
    }
    tc->packet_chain_init_sent = true;
    return true;
}

void wireguarddeviceTunnelOnStart(tunnel_t *t)
{
    wgd_tstate_t *state = tunnelGetState(t);

    if (! wireguarddeviceEnsureTransportLineInit(t, state))
    {
        return;
    }

    wireguard_device_t *device = (wireguard_device_t *) state;
    for (uint8_t i = 0; i < WIREGUARD_MAX_PEERS; i++)
    {
        wireguard_peer_t *peer = &device->peers[i];
        if (peer->valid)
        {
            if (wireguardifConnect(device, i) != ERR_OK)
            {
                LOGF("Error: wireguardifConnect failed");
                startupFailureRecord(1);
                return;
            }
        }
    }

    if (! wireguarddeviceEnsureInnerPacketInit(t, state))
    {
        return;
    }

    state->wg_device.loop_timer = wtimerAdd(getWorkerLoop(0), loopHandle, WIREGUARDIF_TIMER_MSECS, INFINITE);
    if (state->wg_device.loop_timer == NULL)
    {
        LOGF("WireGuardDevice: failed to create periodic timer");
        startupFailureRecord(1);
        return;
    }
    weventSetUserData(state->wg_device.loop_timer, state);

    discard t;
}
