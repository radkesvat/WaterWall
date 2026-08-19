#include "structure.h"

#include "loggers/network_logger.h"

void packetsenderTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    packetsender_tstate_t *state = tunnelGetState(t);
    tunnel_chain_t        *chain = tunnelGetChain(t);
    const wid_t            wid   = lineGetWID(l);

    if (! tunnelchainIsWorkerPacketLine(chain, l) || state->workers == NULL || wid >= state->workers_count)
    {
        LOGF("PacketSender: downstream Finish did not target a configured worker packet line");
        abortProgramNow(1);
    }

    packetsender_worker_state_t *slot = &state->workers[wid];
    if (slot->line != NULL && slot->line != l)
    {
        LOGF("PacketSender: downstream Finish targeted the wrong packet line for worker %u", (unsigned int) wid);
        abortProgramNow(1);
    }

    /*
     * UdpConnector legitimately finishes its borrowed packet-line side when
     * its socket expires or closes. Mark this producer stopped before deleting
     * its timer: Finish permanently closes the upstream direction, including
     * when it is emitted re-entrantly from a payload send.
     *
     * PacketSender has no prev to notify and does not own the packet line, so
     * the Finish is absorbed after local producer teardown.
     */
    packetsenderStopWorker(slot);
}
