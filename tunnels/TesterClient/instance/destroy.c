#include "structure.h"

#include "loggers/network_logger.h"

static bool testerclientLinestateIsZeroed(const testerclient_lstate_t *ls)
{
    const uint8_t *state = (const uint8_t *) ls;
    const size_t   size  = tunnelGetCorrectAlignedLineStateSize(sizeof(*ls));

    for (size_t offset = 0; offset < size; ++offset)
    {
        if (state[offset] != 0)
        {
            return false;
        }
    }

    return true;
}

static void testerclientVerifyPacketStateDrained(tunnel_t *t)
{
    testerclient_tstate_t *ts    = tunnelGetState(t);
    tunnel_chain_t        *chain = tunnelGetChain(t);
    if (! ts->packet_mode || chain == NULL || ! chain->finalized)
    {
        return;
    }

    if (UNLIKELY(! chain->contains_packet_node))
    {
        LOGF("TesterClient: packet mode finalized chain has no packet-node topology during Destroy");
        abortProgramNow(1);
    }

    if (UNLIKELY(chain->packet_lines == NULL))
    {
        LOGF("TesterClient: finalized packet chain is missing packet-line slots during Destroy");
        abortProgramNow(1);
    }

    for (wid_t wid = 0; wid < chain->workers_count; ++wid)
    {
        line_t *packet_line = tunnelchainGetWorkerPacketLine(chain, wid);
        if (packet_line == NULL)
        {
            LOGF("TesterClient: finalized packet chain is missing worker packet line %d during Destroy",
                 workerWIDForLog(wid));
            abortProgramNow(1);
        }

        if (UNLIKELY(lineGetWID(packet_line) != wid || ! tunnelchainIsWorkerPacketLine(chain, packet_line)))
        {
            LOGF("TesterClient: finalized chain has a non-owner packet line in worker %d slot during Destroy",
                 workerWIDForLog(wid));
            abortProgramNow(1);
        }

        testerclient_lstate_t *ls = lineGetState(packet_line, t);
        if (UNLIKELY(! testerclientLinestateIsZeroed(ls)))
        {
            LOGF("TesterClient: finalized packet line on worker %d retained undrained line state",
                 workerWIDForLog(wid));
            abortProgramNow(1);
        }
    }
}

void testerclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                context;
    testerclient_tstate_t *ts = tunnelGetState(t);

    /* Packet line state is initialized and settled only by owner-worker
     * callbacks. By Destroy, worker pools are gone; startup rollback before
     * those callbacks has no packet payload state to reclaim here. */
    testerclientVerifyPacketStateDrained(t);

    addresscontextReset(&ts->initial_dest_context);
    tunnelDestroy(t);
}
