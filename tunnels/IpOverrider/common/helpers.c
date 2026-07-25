#include "structure.h"

#include "loggers/network_logger.h"

static bool ipoverriderShouldApply(const ipoverrider_tstate_t *state, const sbuf_t *buf)
{
    const struct ip_hdr *ipheader = (const struct ip_hdr *) sbufGetRawPtr(buf);
    if (state->only120 && (IPH_V(ipheader) != 4 || lwip_ntohs(IPH_LEN(ipheader)) > 120))
    {
        return false;
    }

    return state->chance >= 100 || (state->chance > 0 && (fastRand32() % 100) < (uint32_t) state->chance);
}

static uint32_t ipoverriderSelectIpv4(ipoverrider_rule_t *rule)
{
    if (rule->ov_4_count == 0)
    {
        return rule->ov_4;
    }

    const uint32_t index = (uint32_t) atomicIncRelaxed(&(rule->ov_4_rr_cursor)) % rule->ov_4_count;
    return rule->ov_4_list[index];
}

static void ipoverriderApplyRule(ipoverrider_rule_t *rule, line_t *l, sbuf_t *buf, bool replace_source)
{
    if (! rule->enabled)
    {
        return;
    }

    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (rule->support4 && IPH_V(ipheader) == 4)
    {
        const uint32_t selected_ipv4 = ipoverriderSelectIpv4(rule);

        if (replace_source)
        {
            memoryCopy(&(ipheader->src.addr), &(selected_ipv4), sizeof(selected_ipv4));
        }
        else
        {
            memoryCopy(&(ipheader->dest.addr), &(selected_ipv4), sizeof(selected_ipv4));
        }

        l->recalculate_checksum = true;
    }
    // else if (rule->support6 && IPH_V(ipheader) == 6)
    // {
    //     struct ip6_hdr *ip6header = (struct ip6_hdr *) sbufGetMutablePtr(buf);
    //     // alignment assumed to be correct
    //     if (replace_source)
    //     {
    //         memoryCopy(&(ip6header->src.addr), &(rule->ov_6), sizeof(rule->ov_6));
    //     }
    //     else
    //     {
    //         memoryCopy(&(ip6header->dest.addr), &(rule->ov_6), sizeof(rule->ov_6));
    //     }
    // }
}

void ipoverriderApplyUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipoverrider_tstate_t *state = tunnelGetState(t);

    if (ipoverriderShouldApply(state, buf))
    {
        ipoverriderApplyRule(&(state->rules[kIpOverriderDirectionUp][kIpOverriderModeSource]), l, buf, true);
        ipoverriderApplyRule(&(state->rules[kIpOverriderDirectionUp][kIpOverriderModeDest]), l, buf, false);
    }

    tunnelNextUpStreamPayload(t, l, buf);
}

void ipoverriderApplyDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipoverrider_tstate_t *state = tunnelGetState(t);

    if (ipoverriderShouldApply(state, buf))
    {
        ipoverriderApplyRule(&(state->rules[kIpOverriderDirectionDown][kIpOverriderModeSource]), l, buf, true);
        ipoverriderApplyRule(&(state->rules[kIpOverriderDirectionDown][kIpOverriderModeDest]), l, buf, false);
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
