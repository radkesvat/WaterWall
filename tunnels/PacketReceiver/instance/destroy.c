#include "structure.h"

#include "loggers/network_logger.h"

void packetreceiverTunnelDestroy(tunnel_t *t)
{
    packetreceiver_tstate_t *state = tunnelGetState(t);
    bool                     should_finalize;

    mutexLock(&state->state_mutex);
    should_finalize = ! state->report_written;
    mutexUnlock(&state->state_mutex);

    if (should_finalize)
    {
        packetreceiverFinalizeReport(t, false);
    }

    while (true)
    {
        mutexLock(&state->state_mutex);
        const bool report_in_progress = state->report_in_progress;
        mutexUnlock(&state->state_mutex);

        if (! report_in_progress)
        {
            break;
        }

        wwSleepMS(1);
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
