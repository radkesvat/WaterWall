#include "structure.h"

#include "loggers/network_logger.h"

static bool ipoverriderShouldApply(const ipoverrider_tstate_t *state, const sbuf_t *buf)
{
    if (UNLIKELY(sbufGetLength(buf) < sizeof(struct ip_hdr)))
    {
        return false;
    }

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

static bool ipoverriderApplyRule(ipoverrider_rule_t *rule, sbuf_t *buf, ipv4_checksum_address_field_e field)
{
    if (! rule->enabled)
    {
        return true;
    }

    if (UNLIKELY(sbufGetLength(buf) < sizeof(struct ip_hdr)))
    {
        return false;
    }

    const struct ip_hdr *ipheader = (const struct ip_hdr *) sbufGetRawPtr(buf);

    if (rule->support4 && IPH_V(ipheader) == 4)
    {
        const uint32_t selected_ipv4 = ipoverriderSelectIpv4(rule);

        return setIpv4AddressWithChecksumUpdate(sbufGetMutablePtr(buf), sbufGetLength(buf), field, selected_ipv4);
    }

    return true;
}

void ipoverriderApplyUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipoverrider_tstate_t *state = tunnelGetState(t);

    if (ipoverriderShouldApply(state, buf))
    {
        if (ipoverriderApplyRule(
                &(state->rules[kIpOverriderDirectionUp][kIpOverriderModeSource]), buf, kIpv4ChecksumAddressSource))
        {
            ipoverriderApplyRule(
                &(state->rules[kIpOverriderDirectionUp][kIpOverriderModeDest]), buf, kIpv4ChecksumAddressDestination);
        }
    }

    tunnelNextUpStreamPayload(t, l, buf);
}

void ipoverriderApplyDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipoverrider_tstate_t *state = tunnelGetState(t);

    if (ipoverriderShouldApply(state, buf))
    {
        if (ipoverriderApplyRule(
                &(state->rules[kIpOverriderDirectionDown][kIpOverriderModeSource]), buf, kIpv4ChecksumAddressSource))
        {
            ipoverriderApplyRule(
                &(state->rules[kIpOverriderDirectionDown][kIpOverriderModeDest]), buf, kIpv4ChecksumAddressDestination);
        }
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
