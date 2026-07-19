#include "trick.h"

#include "loggers/network_logger.h"

static bool isTlsClientHello(const uint8_t *packet, uint16_t iphdr_hlen, uint16_t tcphdr_hlen, uint16_t ip_total_len)
{
    if (ip_total_len < iphdr_hlen + tcphdr_hlen + 6)
    {
        return false;
    }

    const uint8_t *tls = packet + iphdr_hlen + tcphdr_hlen;

    if (tls[0] == 0x16 && tls[1] == 0x03 && (tls[2] <= 0x03) && tls[5] == 0x01)
    {
        return true;
    }
    return false;
}

bool sniblendertrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state    = tunnelGetState(t);
    struct ip_hdr          *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    uint16_t                fragment_offsets[kSniBlenderTrickMaxPacketsCount] = {0};
    uint16_t                fragment_lengths[kSniBlenderTrickMaxPacketsCount] = {0};

    if (IPH_V(ipheader) != 4 || IPH_PROTO(ipheader) != IPPROTO_TCP)
    {
        return false;
    }

    uint32_t packet_length = sbufGetLength(buf);
    uint8_t  ip_hdr_len_words = IPH_HL(ipheader);
    if (ip_hdr_len_words < 5 || ip_hdr_len_words > 15)
    {
        LOGE("sniblendertrick: invalid IP header words length: %u", ip_hdr_len_words);
        return false;
    }

    uint16_t iphdr_len = ip_hdr_len_words * 4;
    if (packet_length < iphdr_len + sizeof(struct tcp_hdr))
    {
        return false;
    }

    uint16_t ip_total_len = lwip_ntohs(IPH_LEN(ipheader));
    if (ip_total_len < iphdr_len + sizeof(struct tcp_hdr) || packet_length < ip_total_len)
    {
        return false;
    }

    // Do not touch packets that are already fragmented, including the first fragment (MF set, offset 0).
    uint16_t off_f = lwip_ntohs(IPH_OFFSET(ipheader));
    if ((off_f & (IP_MF | IP_OFFMASK)) != 0)
    {
        return false;
    }

    struct tcp_hdr *tcp_header = (struct tcp_hdr *) (((uint8_t *) sbufGetMutablePtr(buf)) + iphdr_len);
    uint8_t         tcp_hdr_len_words = TCPH_HDRLEN(tcp_header);
    if (tcp_hdr_len_words < 5 || tcp_hdr_len_words > 15)
    {
        LOGE("sniblendertrick: invalid TCP header length: %u", tcp_hdr_len_words);
        return false;
    }
    uint16_t tcphdr_len = tcp_hdr_len_words * 4;
    if (ip_total_len < iphdr_len + tcphdr_len)
    {
        return false;
    }

    uint16_t total_payload = ip_total_len - iphdr_len;
    int      payload_len   = total_payload - tcphdr_len;
    if (payload_len <= 0)
    {
        return false;
    }

    if (! isTlsClientHello((uint8_t *) sbufGetMutablePtr(buf), iphdr_len, tcphdr_len, ip_total_len))
    {
        return false;
    }

    if (state->trick_sni_blender_packets_count <= 0)
    {
        return false;
    }

    uint16_t min_first_fragment_payload = (uint16_t) ((tcphdr_len + 7U) & ~0x7U);
    if (min_first_fragment_payload >= total_payload)
    {
        LOGW("sniblendertrick: packet is too small to fragment without splitting the TCP header, bypassing");
        return false;
    }

    uint16_t identification = lwip_ntohs(IPH_ID(ipheader));

    // Before crafting, satisfy any pending checksum request on the source packet.
    if (UNLIKELY(l->recalculate_checksum && IPH_V(ipheader) == 4))
    {
        calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf));
        l->recalculate_checksum = false;
    }

    sbuf_t *crafted_packets[kSniBlenderTrickMaxPacketsCount] = {0};
    int     crafted_count = 0;
    buffer_pool_t *bp = lineGetBufferPool(l);

    fragment_offsets[0] = 0;
    fragment_lengths[0] = min_first_fragment_payload;

    uint16_t offset_bytes = min_first_fragment_payload;
    uint16_t remaining_payload = (uint16_t) (total_payload - min_first_fragment_payload);
    int      planned_count = 1;

    while (remaining_payload > 0 && planned_count < state->trick_sni_blender_packets_count)
    {
        int      fragments_left = state->trick_sni_blender_packets_count - planned_count;
        uint16_t this_len       = remaining_payload;

        if (fragments_left > 1)
        {
            this_len = (remaining_payload / fragments_left) & ~0x7U;
            if (this_len == 0)
            {
                this_len = remaining_payload;
            }
        }

        fragment_offsets[planned_count] = offset_bytes;
        fragment_lengths[planned_count] = this_len;
        offset_bytes                    = (uint16_t) (offset_bytes + this_len);
        remaining_payload               = (uint16_t) (remaining_payload - this_len);
        planned_count++;
    }

    if (planned_count <= 1)
    {
        LOGW("sniblendertrick: packet is too small for configured fragment count (%d) after preserving the TCP header,"
             " bypassing",
             state->trick_sni_blender_packets_count);
        return false;
    }

    for (int i = 0; i < planned_count; i++)
    {
        uint16_t this_offset = fragment_offsets[i];
        uint16_t this_len    = fragment_lengths[i];

        if (this_len == 0)
        {
            break;
        }

        sbuf_t *craft_buf = ((iphdr_len + this_len) <= bufferpoolGetSmallBufferSize(bp)) ? bufferpoolGetSmallBuffer(bp)
                                                                                           : bufferpoolGetLargeBuffer(bp);
        crafted_packets[i] = craft_buf;
        crafted_count++;

        sbufSetLength(craft_buf, iphdr_len + this_len);
        struct ip_hdr *fhdr = (struct ip_hdr *) sbufGetMutablePtr(craft_buf);
        memoryCopy(fhdr, ipheader, iphdr_len);

        IPH_LEN_SET(fhdr, lwip_htons(iphdr_len + this_len));
        IPH_VHL_SET(fhdr, 4, iphdr_len / 4);
        IPH_ID_SET(fhdr, lwip_htons(identification));

        uint16_t flags_offset = (this_offset >> 3);
        if (i < planned_count - 1)
        {
            flags_offset |= IP_MF;
        }
        IPH_OFFSET_SET(fhdr, lwip_htons(flags_offset));

        uint8_t *data_src = sbufGetMutablePtr(buf) + iphdr_len + this_offset;
        uint8_t *data_dst = (uint8_t *) sbufGetMutablePtr(craft_buf) + iphdr_len;
        memoryCopy(data_dst, data_src, this_len);
    }

    if (crafted_count <= 0)
    {
        return false;
    }

    LOGD("IpManipolator: sending %d crafted packets of a Tls Hello", crafted_count);

    int shuffled_indices[kSniBlenderTrickMaxPacketsCount] = {0};
    for (int ti = 0; ti < crafted_count; ti++)
    {
        shuffled_indices[ti] = ti;
    }

    for (int idx = crafted_count - 1; idx > 1; idx--)
    {
        int j                 = 1 + ((int) fastRand() % idx);
        int temp              = shuffled_indices[idx];
        shuffled_indices[idx] = shuffled_indices[j];
        shuffled_indices[j]   = temp;
    }

    for (int idx = 0; idx < crafted_count; idx++)
    {
        int packet_i                = shuffled_indices[idx];
        l->recalculate_checksum     = true;
        ipmanipulatorSendUpstreamFinal(t, l, crafted_packets[packet_i]);
        crafted_packets[packet_i] = NULL;
    }

    lineReuseBuffer(l, buf);
    return true;
}

void sniblendertrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    discard l;
    discard buf;
}
