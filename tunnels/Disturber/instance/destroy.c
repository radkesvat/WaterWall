#include "structure.h"

#include "loggers/network_logger.h"

static void disturberVerifyPacketStateDrained(tunnel_t *t)
{
    tunnel_chain_t *chain = tunnelGetChain(t);
    if (chain == NULL || ! chain->finalized)
    {
        return;
    }

    if (UNLIKELY(chain->packet_lines == NULL))
    {
        LOGF("Disturber: finalized packet chain is missing its packet-line slots during Destroy");
        abortProgramNow(1);
    }

    for (wid_t wid = 0; wid < chain->workers_count; ++wid)
    {
        line_t *packet_line = tunnelchainGetWorkerPacketLine(chain, wid);
        if (UNLIKELY(chain->contains_packet_node != (packet_line != NULL)))
        {
            LOGF("Disturber: finalized packet-line topology disagrees with worker slot %d during Destroy",
                 workerWIDForLog(wid));
            abortProgramNow(1);
        }

        if (packet_line == NULL)
        {
            continue;
        }

        if (UNLIKELY(lineGetWID(packet_line) != wid || ! tunnelchainIsWorkerPacketLine(chain, packet_line)))
        {
            LOGF("Disturber: finalized chain has a non-owner packet line in worker %d slot during Destroy",
                 workerWIDForLog(wid));
            abortProgramNow(1);
        }

        disturber_lstate_t *ls = lineGetState(packet_line, t);
        if (ls->upstream.held_payload != NULL || ls->downstream.held_payload != NULL || ls->upstream.is_deadhang ||
            ls->downstream.is_deadhang || ls->upstream.finished || ls->downstream.finished)
        {
            LOGF("Disturber: finalized packet line on worker %d retained undrained line state", workerWIDForLog(wid));
            abortProgramNow(1);
        }
    }
}

void disturberTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;

    /* Normal teardown already settled every packet line through onWorkerStop
     * while its owner pool was alive. Startup rollback before owner callbacks
     * cannot have accepted payload into this state, so Destroy must not touch a
     * post-worker packet buffer pool. Packet-line destruction remains solely
     * tunnelchainDestroy()'s responsibility. */
    disturberVerifyPacketStateDrained(t);

    tunnelDestroy(t);
}
