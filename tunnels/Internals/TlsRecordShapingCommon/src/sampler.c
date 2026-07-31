#include "TlsRecordShapingCommon/record_shaping.h"

static uint32_t boundedDraw(uint32_t supplied, const tlsrecordshaping_range_t *range)
{
    if (supplied < range->minimum)
    {
        return range->minimum;
    }
    if (supplied > range->maximum)
    {
        return range->maximum;
    }
    return supplied;
}

bool tlsrecordshapingSelectDeterministic(const tlsrecordshaping_config_t *config, tlsrecordshaping_state_t *state,
                                         uint32_t outcome_roll, uint32_t padding_draw, uint32_t delay_roll,
                                         uint32_t delay_draw, tlsrecordshaping_decision_t *decision)
{
    if (decision == NULL)
    {
        return false;
    }
    *decision = (tlsrecordshaping_decision_t) {0};

    if (config == NULL || state == NULL || ! config->enabled || outcome_roll < 1 || outcome_roll > 100 ||
        delay_roll < 1 || delay_roll > 100)
    {
        return false;
    }
    if (state->application_records_seen >= config->first_application_records)
    {
        return true;
    }

    state->application_records_seen += 1;
    decision->considered = true;

    unsigned int cumulative = 0;
    for (uint8_t i = 0; i < config->outcome_count; ++i)
    {
        const tlsrecordshaping_outcome_t *outcome = &config->outcomes[i];
        cumulative += outcome->probability;
        if (outcome_roll > cumulative)
        {
            continue;
        }

        decision->outcome_selected = true;
        decision->selected_outcome = i;
        if (outcome->has_padding)
        {
            decision->requested_padding_bytes = boundedDraw(padding_draw, &outcome->padding_bytes);
        }
        if (outcome->has_delay && delay_roll <= outcome->delay_probability)
        {
            decision->delay_ms = boundedDraw(delay_draw, &outcome->delay_ms);
        }
        if (decision->delay_ms > 0)
        {
            state->records_delayed += 1;
        }
        return true;
    }

    return true;
}

bool tlsrecordshapingSample(const tlsrecordshaping_config_t *config, tlsrecordshaping_state_t *state,
                            tlsrecordshaping_decision_t *decision)
{
    if (config == NULL || ! config->enabled)
    {
        if (decision != NULL)
        {
            *decision = (tlsrecordshaping_decision_t) {0};
        }
        return false;
    }

    uint32_t outcome_roll = fastRandRange32(1, 100);
    uint32_t delay_roll   = fastRandRange32(1, 100);
    uint32_t padding_draw = 0;
    uint32_t delay_draw   = 0;

    unsigned int cumulative = 0;
    for (uint8_t i = 0; i < config->outcome_count; ++i)
    {
        cumulative += config->outcomes[i].probability;
        if (outcome_roll <= cumulative)
        {
            if (config->outcomes[i].has_padding)
            {
                padding_draw = fastRandRange32(config->outcomes[i].padding_bytes.minimum,
                                               config->outcomes[i].padding_bytes.maximum);
            }
            if (config->outcomes[i].has_delay)
            {
                delay_draw =
                    fastRandRange32(config->outcomes[i].delay_ms.minimum, config->outcomes[i].delay_ms.maximum);
            }
            break;
        }
    }

    return tlsrecordshapingSelectDeterministic(
        config, state, outcome_roll, padding_draw, delay_roll, delay_draw, decision);
}

void tlsrecordshapingRecordEffectivePadding(tlsrecordshaping_state_t          *state,
                                            const tlsrecordshaping_decision_t *decision,
                                            uint32_t                           effective_padding_bytes)
{
    if (state == NULL || decision == NULL || decision->requested_padding_bytes == 0)
    {
        return;
    }

    state->records_padded += effective_padding_bytes > 0 ? 1U : 0U;
    state->requested_padding_bytes += decision->requested_padding_bytes;
    state->effective_padding_bytes += effective_padding_bytes;
}
