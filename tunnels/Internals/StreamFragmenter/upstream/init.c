#include "structure.h"

void streamfragmenterTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    const streamfragmenter_tstate_t *ts = tunnelGetState(t);
    streamfragmenter_lstate_t       *ls = lineGetState(l, t);
    *ls                                 = (streamfragmenter_lstate_t) {
                                        .tunnel          = t,
                                        .line            = l,
                                        .remaining       = ts->scope,
                                        .deadline_us     = ts->timed && ! ts->wait_for_est ? getHRTimeUs() + (uint64_t) ts->scope * 1000 : 0,
                                        .exhausted       = ts->scope == 0 || ts->cut_count == 0,
                                        .waiting_for_est = ts->wait_for_est,
    };
    bufferbudgetInit(
        &ls->budget,
        (buffer_budget_cost_t) {kStreamFragmenterHardCharge, kStreamFragmenterHardCharge, kStreamFragmenterHardJobs});
    tunnelNextUpStreamInit(t, l);
}
