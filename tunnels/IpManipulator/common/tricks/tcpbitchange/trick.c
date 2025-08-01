#include "trick.h"

#include "loggers/network_logger.h"

// processes each bit and it can return 1 or 0 based on the action
static uint8_t processTcpBitAction(enum tcp_bit_action_dynamic_value action, uint8_t current_bit, uint8_t all_flags)
{
    switch (action)
    {
    case kDvsOff:
        return 0;
    case kDvsOn:
        return 1;
    case kDvsSwapCwr:
        return (all_flags & 0x80) ? 1 : 0; // Swap with CWR bit
    case kDvsSwapEce:
        return (all_flags & 0x40) ? 1 : 0; // Swap with ECE bit
    case kDvsSwapUrg:
        return (all_flags & 0x20) ? 1 : 0; // Swap with URG bit
    case kDvsSwapAck:
        return (all_flags & 0x10) ? 1 : 0; // Swap with ACK bit
    case kDvsSwapPsh:
        return (all_flags & 0x08) ? 1 : 0; // Swap with PSH bit
    case kDvsSwapRst:
        return (all_flags & 0x04) ? 1 : 0; // Swap with RST bit
    case kDvsSwapSyn:
        return (all_flags & 0x02) ? 1 : 0; // Swap with SYN bit
    case kDvsSwapFin:
        return (all_flags & 0x01) ? 1 : 0; // Swap with FIN bit
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

void tcpbitchangetrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state    = tunnelGetState(t);
    struct ip_hdr          *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (IPH_V(ipheader) == 4 && IPH_PROTO(ipheader) == IPPROTO_TCP)
    {
        // Validate IP header length field first
        uint8_t ip_hdr_len_words = IPH_HL(ipheader);
        if (ip_hdr_len_words < 5 || ip_hdr_len_words > 15)
        {
            LOGE("tcpbitchangetrick: invalid IP header length: %d", ip_hdr_len_words);
            tunnelNextUpStreamPayload(t, l, buf);
            return;
        }
        
        uint16_t iphdr_len = ip_hdr_len_words * 4;
        
        // Check if buffer has enough space for IP header
        if (sbufGetLength(buf) < iphdr_len + sizeof(struct tcp_hdr))
        {
            LOGE("tcpbitchangetrick: buffer too small for IP + minimum TCP header");
            tunnelNextUpStreamPayload(t, l, buf);
            return;
        }
        
        struct tcp_hdr *tcp_header = (struct tcp_hdr *) (((uint8_t *) sbufGetMutablePtr(buf)) + iphdr_len);
        uint8_t tcp_hdr_len_words = TCPH_HDRLEN(tcp_header);
        
        // Validate TCP header length
        if (tcp_hdr_len_words < 5 || tcp_hdr_len_words > 15)
        {
            LOGE("tcpbitchangetrick: invalid TCP header length: %d", tcp_hdr_len_words);
            tunnelNextUpStreamPayload(t, l, buf);
            return;
        }
        
        uint16_t tcphdr_len = tcp_hdr_len_words * 4;

        if (sbufGetLength(buf) < iphdr_len + tcphdr_len)
        {
            LOGE("tcpbitchangetrick: buffer length is less than ip header + tcp header length");
            tunnelNextUpStreamPayload(t, l, buf);
            return;
        }

        uint8_t original_flags = TCPH_FLAGS(tcp_header);
        uint8_t new_flags      = processAllTcpFlags(original_flags, state, true);

        if (new_flags != original_flags)
        {
            TCPH_FLAGS_SET(tcp_header, new_flags);

            l->recalculate_checksum = true;
        }
    }

    tunnelNextUpStreamPayload(t, l, buf);
}

void tcpbitchangetrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state    = tunnelGetState(t);
    struct ip_hdr          *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (IPH_V(ipheader) == 4 && IPH_PROTO(ipheader) == IPPROTO_TCP)
    {
        // Validate IP header length field first
        uint8_t ip_hdr_len_words = IPH_HL(ipheader);
        if (ip_hdr_len_words < 5 || ip_hdr_len_words > 15)
        {
            LOGE("tcpbitchangetrick: invalid IP header length: %d", ip_hdr_len_words);
            tunnelPrevDownStreamPayload(t, l, buf);
            return;
        }
        
        uint16_t iphdr_len = ip_hdr_len_words * 4;
        
        // Check if buffer has enough space for IP header
        if (sbufGetLength(buf) < iphdr_len + sizeof(struct tcp_hdr))
        {
            LOGE("tcpbitchangetrick: buffer too small for IP + minimum TCP header");
            tunnelPrevDownStreamPayload(t, l, buf);
            return;
        }
        
        struct tcp_hdr *tcp_header = (struct tcp_hdr *) (((uint8_t *) sbufGetMutablePtr(buf)) + iphdr_len);
        uint8_t tcp_hdr_len_words = TCPH_HDRLEN(tcp_header);
        
        // Validate TCP header length
        if (tcp_hdr_len_words < 5 || tcp_hdr_len_words > 15)
        {
            LOGE("tcpbitchangetrick: invalid TCP header length: %d", tcp_hdr_len_words);
            tunnelPrevDownStreamPayload(t, l, buf);
            return;
        }
        
        uint16_t tcphdr_len = tcp_hdr_len_words * 4;

        if (sbufGetLength(buf) < iphdr_len + tcphdr_len)
        {
            LOGE("tcpbitchangetrick: buffer length is less than ip header + tcp header length");
            tunnelPrevDownStreamPayload(t, l, buf);
            return;
        }

        uint8_t original_flags = TCPH_FLAGS(tcp_header);
        uint8_t new_flags      = processAllTcpFlags(original_flags, state, false);

        if (new_flags != original_flags)
        {
            TCPH_FLAGS_SET(tcp_header, new_flags);

            l->recalculate_checksum = true;
        }
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
