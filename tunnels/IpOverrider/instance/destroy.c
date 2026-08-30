#include "structure.h"

#include "loggers/network_logger.h"

void ipoverriderDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard               context;
    ipoverrider_tstate_t *state = tunnelGetState(t);

    for (uint8_t direction_index = 0; direction_index < kIpOverriderDirectionCount; ++direction_index)
    {
        for (uint8_t mode_index = 0; mode_index < kIpOverriderModeCount; ++mode_index)
        {
            ipoverrider_rule_t *rule = &(state->rules[direction_index][mode_index]);
            if (rule->ov_4_list != NULL)
            {
                memoryFree(rule->ov_4_list);
                rule->ov_4_list  = NULL;
                rule->ov_4_count = 0;
            }
        }
    }

    if (state->worker_gates != NULL)
    {
        memoryFreeAligned(state->worker_gates);
        state->worker_gates      = NULL;
        state->worker_gate_count = 0;
    }

    tunnelDestroy(t);
}
