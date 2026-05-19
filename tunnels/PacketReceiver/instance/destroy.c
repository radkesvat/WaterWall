#include "structure.h"

#include "loggers/network_logger.h"

void packetreceiverTunnelDestroy(tunnel_t *t)
{
    packetreceiver_tstate_t *state = tunnelGetState(t);

    if (! state->report_written)
    {
        packetreceiverFinalizeReport(t, false);
    }

    if (state->source_ranges != NULL)
    {
        memoryFree(state->source_ranges);
        state->source_ranges = NULL;
    }

    if (state->received_counts != NULL)
    {
        memoryFree(state->received_counts);
        state->received_counts = NULL;
    }

    if (state->output_file != NULL)
    {
        memoryFree(state->output_file);
        state->output_file = NULL;
    }

    mutexDestroy(&state->state_mutex);
    tunnelDestroy(t);
}
