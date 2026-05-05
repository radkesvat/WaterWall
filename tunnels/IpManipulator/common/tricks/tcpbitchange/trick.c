#include "trick.h"

#include "loggers/network_logger.h"

enum
{
    kIpv4FragmentMask = 0x3FFF
};

// processes each bit and it can return 1 or 0 based on the action
static uint8_t processTcpBitAction(enum tcp_bit_action_dynamic_value action, uint8_t current_bit, uint8_t all_flags)
{
    switch (action)
    {
    case kDvsOff:
        return 0;
    case kDvsOn:
        return 1;
    case kDvsToggle:
        return current_bit ? 0 : 1;
    case kDvsPacketCwr:
        return (all_flags & 0x80) ? 1 : 0; // packet CWR bit
    case kDvsPacketEce:
        return (all_flags & 0x40) ? 1 : 0; // packet ECE bit
    case kDvsPacketUrg:
        return (all_flags & 0x20) ? 1 : 0; // packet URG bit
    case kDvsPacketAck:
        return (all_flags & 0x10) ? 1 : 0; // packet ACK bit
    case kDvsPacketPsh:
        return (all_flags & 0x08) ? 1 : 0; // packet PSH bit
    case kDvsPacketRst:
        return (all_flags & 0x04) ? 1 : 0; // packet RST bit
    case kDvsPacketSyn:
        return (all_flags & 0x02) ? 1 : 0; // packet SYN bit
    case kDvsPacketFin:
        return (all_flags & 0x01) ? 1 : 0; // packet FIN bit
    case kDvsNoAction:
    default:
        return current_bit; // Not changed, will not change the bit
    }
}

typedef struct
{
    uint8_t                           mask;
    enum tcp_bit_action_dynamic_value action;
} tcp_flag_config_t;

static bool hasTcpFlagActionsConfigured(const ipmanipulator_tstate_t *state, bool is_upstream)
{
    if (is_upstream)
    {
        return state->up_tcp_bit_cwr_action != kDvsNoAction || state->up_tcp_bit_ece_action != kDvsNoAction ||
               state->up_tcp_bit_urg_action != kDvsNoAction || state->up_tcp_bit_ack_action != kDvsNoAction ||
               state->up_tcp_bit_psh_action != kDvsNoAction || state->up_tcp_bit_rst_action != kDvsNoAction ||
               state->up_tcp_bit_syn_action != kDvsNoAction || state->up_tcp_bit_fin_action != kDvsNoAction;
    }

    return state->down_tcp_bit_cwr_action != kDvsNoAction || state->down_tcp_bit_ece_action != kDvsNoAction ||
           state->down_tcp_bit_urg_action != kDvsNoAction || state->down_tcp_bit_ack_action != kDvsNoAction ||
           state->down_tcp_bit_psh_action != kDvsNoAction || state->down_tcp_bit_rst_action != kDvsNoAction ||
           state->down_tcp_bit_syn_action != kDvsNoAction || state->down_tcp_bit_fin_action != kDvsNoAction;
}

static bool appendFlagsToTransportPayload(sbuf_t **buf_ptr, struct ip_hdr **ipheader_ptr, uint16_t iphdr_len,
                                          uint16_t tcphdr_len, uint8_t flags)
{
    sbuf_t  *buf          = *buf_ptr;
    uint16_t ip_total_len = lwip_ntohs(IPH_LEN(*ipheader_ptr));

    if (ip_total_len >= UINT16_MAX)
    {
        LOGW("tcpbitchangetrick: cannot append transported flags because IPv4 total length is already full");
        return false;
    }

    if (ip_total_len < iphdr_len + tcphdr_len)
    {
        LOGE("tcpbitchangetrick: invalid packet lengths while appending transported flags");
        return false;
    }

    uint32_t new_len = (uint32_t) ip_total_len + 1U;
    if (sbufGetMaximumWriteableSize(buf) < new_len)
    {
        LOGW("tcpbitchangetrick: dropping packet because bit-transport needs one extra byte but the buffer has no room");
        return false;
    }

    sbufSetLength(buf, new_len);
    uint8_t *packet = sbufGetMutablePtr(buf);
    packet[ip_total_len] = flags;

    *buf_ptr      = buf;
    *ipheader_ptr = (struct ip_hdr *) packet;
    IPH_LEN_SET(*ipheader_ptr, lwip_htons((uint16_t) new_len));
    return true;
}

static bool restoreFlagsFromTransportPayload(sbuf_t *buf, struct ip_hdr *ipheader, struct tcp_hdr *tcp_header,
                                             uint16_t iphdr_len, uint16_t tcphdr_len)
{
    uint16_t ip_total_len = lwip_ntohs(IPH_LEN(ipheader));

    if (ip_total_len <= iphdr_len + tcphdr_len)
    {
        return false;
    }

    uint8_t *packet            = sbufGetMutablePtr(buf);
    uint32_t flags_offset      = (uint32_t) ip_total_len - 1U;
    uint8_t  restored_flags    = packet[flags_offset];
    uint16_t restored_len      = (uint16_t) (ip_total_len - 1U);

    TCPH_FLAGS_SET(tcp_header, restored_flags);
    IPH_LEN_SET(ipheader, lwip_htons(restored_len));
    sbufSetLength(buf, restored_len);
    return true;
}

static uint8_t processAllTcpFlags(uint8_t original_flags, const ipmanipulator_tstate_t *state, bool is_upstream)
{
    uint8_t new_flags = original_flags;

    // Define flag positions and corresponding actions
    tcp_flag_config_t flag_configs[8];

    if (is_upstream)
    {
        flag_configs[0] = (tcp_flag_config_t){0x80, state->up_tcp_bit_cwr_action}; // CWR
        flag_configs[1] = (tcp_flag_config_t){0x40, state->up_tcp_bit_ece_action}; // ECE
        flag_configs[2] = (tcp_flag_config_t){0x20, state->up_tcp_bit_urg_action}; // URG
        flag_configs[3] = (tcp_flag_config_t){0x10, state->up_tcp_bit_ack_action}; // ACK
        flag_configs[4] = (tcp_flag_config_t){0x08, state->up_tcp_bit_psh_action}; // PSH
        flag_configs[5] = (tcp_flag_config_t){0x04, state->up_tcp_bit_rst_action}; // RST
        flag_configs[6] = (tcp_flag_config_t){0x02, state->up_tcp_bit_syn_action}; // SYN
        flag_configs[7] = (tcp_flag_config_t){0x01, state->up_tcp_bit_fin_action}; // FIN
    }
    else
    {
        flag_configs[0] = (tcp_flag_config_t){0x80, state->down_tcp_bit_cwr_action}; // CWR
        flag_configs[1] = (tcp_flag_config_t){0x40, state->down_tcp_bit_ece_action}; // ECE
        flag_configs[2] = (tcp_flag_config_t){0x20, state->down_tcp_bit_urg_action}; // URG
        flag_configs[3] = (tcp_flag_config_t){0x10, state->down_tcp_bit_ack_action}; // ACK
        flag_configs[4] = (tcp_flag_config_t){0x08, state->down_tcp_bit_psh_action}; // PSH
        flag_configs[5] = (tcp_flag_config_t){0x04, state->down_tcp_bit_rst_action}; // RST
        flag_configs[6] = (tcp_flag_config_t){0x02, state->down_tcp_bit_syn_action}; // SYN
        flag_configs[7] = (tcp_flag_config_t){0x01, state->down_tcp_bit_fin_action}; // FIN
    }

    for (int i = 0; i < 8; i++)
    {
        if (flag_configs[i].action != kDvsNoAction)
        {
            uint8_t current_bit = (original_flags & flag_configs[i].mask) ? 1 : 0;
            uint8_t new_bit     = processTcpBitAction(flag_configs[i].action, current_bit, original_flags);
            if (new_bit != current_bit)
            {
                new_flags = (new_flags & ~flag_configs[i].mask) | (new_bit ? flag_configs[i].mask : 0);
            }
        }
    }

    return new_flags;
}

static void tcpbitchangetrickPayload(tunnel_t *t, line_t *l, sbuf_t **buf_ptr, bool is_upstream)
{
    ipmanipulator_tstate_t *state       = tunnelGetState(t);
    sbuf_t                 *buf         = *buf_ptr;
    struct ip_hdr          *ipheader    = (struct ip_hdr *) sbufGetMutablePtr(buf);
    bool                    has_actions = hasTcpFlagActionsConfigured(state, is_upstream);
    bool                    opposite_has_actions = hasTcpFlagActionsConfigured(state, ! is_upstream);

    if (IPH_V(ipheader) == 4 && IPH_PROTO(ipheader) == IPPROTO_TCP)
    {
        // Validate IP header length field first
        uint8_t ip_hdr_len_words = IPH_HL(ipheader);
        if (ip_hdr_len_words < 5 || ip_hdr_len_words > 15)
        {
            LOGE("tcpbitchangetrick: invalid IP header length: %d", ip_hdr_len_words);
            return;
        }

        uint16_t iphdr_len = ip_hdr_len_words * 4;
        uint16_t off_f      = lwip_ntohs(IPH_OFFSET(ipheader));
        if ((off_f & (IP_MF | kIpv4FragmentMask)) != 0)
        {
            return;
        }

        // Check if buffer has enough space for IP header
        if (sbufGetLength(buf) < iphdr_len + sizeof(struct tcp_hdr))
        {
            LOGE("tcpbitchangetrick: buffer too small for IP + minimum TCP header");
            return;
        }

        struct tcp_hdr *tcp_header = (struct tcp_hdr *) (((uint8_t *) sbufGetMutablePtr(buf)) + iphdr_len);
        uint8_t         tcp_hdr_len_words = TCPH_HDRLEN(tcp_header);

        // Validate TCP header length
        if (tcp_hdr_len_words < 5 || tcp_hdr_len_words > 15)
        {
            LOGE("tcpbitchangetrick: invalid TCP header length: %d", tcp_hdr_len_words);
            return;
        }

        uint16_t tcphdr_len = tcp_hdr_len_words * 4;

        if (sbufGetLength(buf) < iphdr_len + tcphdr_len)
        {
            LOGE("tcpbitchangetrick: buffer length is less than ip header + tcp header length");
            return;
        }

        if (state->trick_bit_transport && ! has_actions && opposite_has_actions)
        {
            if (restoreFlagsFromTransportPayload(buf, ipheader, tcp_header, iphdr_len, tcphdr_len))
            {
                l->recalculate_checksum = true;
            }
            return;
        }

        uint8_t original_flags = TCPH_FLAGS(tcp_header);
        uint8_t new_flags      = processAllTcpFlags(original_flags, state, is_upstream);

        if (state->trick_bit_transport && has_actions)
        {
            if (! appendFlagsToTransportPayload(buf_ptr, &ipheader, iphdr_len, tcphdr_len, original_flags))
            {
                lineReuseBuffer(l, *buf_ptr);
                *buf_ptr = NULL;
                return;
            }

            buf        = *buf_ptr;
            tcp_header = (struct tcp_hdr *) (((uint8_t *) sbufGetMutablePtr(buf)) + iphdr_len);
        }

        if (new_flags != original_flags)
        {
            TCPH_FLAGS_SET(tcp_header, new_flags);
        }

        if ((state->trick_bit_transport && has_actions) || new_flags != original_flags)
        {
            l->recalculate_checksum = true;
        }
    }

    discard t;
}

void tcpbitchangetrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t **buf)
{
    tcpbitchangetrickPayload(t, l, buf, true);
}

void tcpbitchangetrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t **buf)
{
    tcpbitchangetrickPayload(t, l, buf, false);
}
