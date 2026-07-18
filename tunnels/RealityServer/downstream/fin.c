#include "structure.h"

void realityserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    realityserver_lstate_t *ls = lineGetState(l, t);
    if (ls->closing_destination_for_authorized)
    {
        return;
    }

    bool cutoff_complete = ls->mode == kRealityServerModeHandoffAwaitConfirm &&
                           ls->destination_downstream_cutoff;
    bool final_record_in_flight = ls->mode == kRealityServerModeHandoffAwaitBoundary &&
                                  ls->destination_downstream_forward_depth != 0 &&
                                  realityserverTlsRecordBoundaryTrackerIsAtBoundary(
                                      &ls->destination_record_boundary);
    if (cutoff_complete || final_record_in_flight)
    {
        /* Receiving Finish closes the destination direction permanently. */
        ls->destination_up_finished = true;
        return;
    }

    realityserverHandleDownstreamFinish(t, l);
}
