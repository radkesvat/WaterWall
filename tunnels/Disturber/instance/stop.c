#include "structure.h"

#include "loggers/network_logger.h"

void disturberTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard         context;
    tunnel_chain_t *chain = tunnelGetChain(t);

    /* Worker-stop runs on this exact worker while its line and buffer pools are
     * still alive. Packet lines remain chain-owned; only Disturber's retained
     * per-worker payload state is settled here. */
    /* Startup rollback may have no chain or an unfinalized chain. Once the
     * chain is finalized, its packet-line slot array and the worker index are
     * runtime geometry invariants; hiding either would skip owner cleanup in
     * Release. */
    if (chain == NULL || ! chain->finalized)
    {
        return;
    }

    if (UNLIKELY(chain->packet_lines == NULL || wid >= chain->workers_count))
    {
        LOGF("Disturber: finalized packet chain has invalid worker packet-line geometry for worker %d",
             workerWIDForLog(wid));
        abortProgramNow(1);
    }

    line_t *packet_line = tunnelchainGetWorkerPacketLine(chain, wid);
    if (UNLIKELY(chain->contains_packet_node != (packet_line != NULL)))
    {
        LOGF("Disturber: finalized packet-line topology disagrees with worker slot %d", workerWIDForLog(wid));
        abortProgramNow(1);
    }

    /* A finalized stream-only chain has a packet-line slot array, but every
     * individual slot is intentionally NULL. */
    if (packet_line == NULL)
    {
        return;
    }

    if (UNLIKELY(! currentThreadIsEventWorkerWID(wid) || lineGetWID(packet_line) != wid ||
                 ! tunnelchainIsWorkerPacketLine(chain, packet_line)))
    {
        LOGF("Disturber: worker Stop did not run on the exact owner packet line for worker %d", workerWIDForLog(wid));
        abortProgramNow(1);
    }

    assert(currentThreadIsEventWorkerWID(wid));
    assert(lineGetWID(packet_line) == wid);
    assert(tunnelchainIsWorkerPacketLine(chain, packet_line));

    disturberLinestateDestroy(packet_line, lineGetState(packet_line, t));
}

void disturberTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}
