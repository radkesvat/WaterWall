#include "trick.h"

#include "loggers/network_logger.h"

static bool isTlsClientHello(const struct ip_hdr *iphdr, const struct tcp_hdr *tcphdr)
{
    uint16_t iphdr_hlen  = IPH_HL(iphdr) * 4;
    uint16_t tcphdr_hlen = TCPH_HDRLEN(tcphdr) * 4; // corrected

    uint8_t *tls     = (uint8_t *) iphdr + iphdr_hlen + tcphdr_hlen;
    uint16_t tls_len = lwip_ntohs(IPH_LEN(iphdr)) - iphdr_hlen - tcphdr_hlen;

    if (tls_len < 6)
    {
        return false;
    }

    if (tls[0] == 0x16 && tls[1] == 0x03 && (tls[2] <= 0x03) && tls[5] == 0x01)
    {
        return true;
    }
    return false;
}

void sniblendertrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state    = tunnelGetState(t);
    struct ip_hdr          *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (IPH_V(ipheader) == 4 && IPH_PROTO(ipheader) == IPPROTO_TCP)
    {
        // skip non-zero-offset fragments (means we dont fragment already fragmented packets)
        uint16_t off_f = lwip_ntohs(IPH_OFFSET(ipheader));
        if ((off_f & IP_OFFMASK) != 0)
        {
            tunnelNextUpStreamPayload(t, l, buf);
            return;
        }

        struct tcp_hdr *tcp_header =
            (struct tcp_hdr *) (((uint8_t *) sbufGetMutablePtr(buf)) + (uintptr_t) (IPH_HL(ipheader) * 4));

        uint16_t tcphdr_len = TCPH_HDRLEN(tcp_header) * 4;
        // alloc the full IP payload length (tcp hdr + tls data)
        uint16_t iphdr_len     = IPH_HL(ipheader) * 4;
        uint16_t total_payload = lwip_ntohs(IPH_LEN(ipheader)) - iphdr_len;

        // round down per-fragment size to 8‑byte multiple because offset in ip layer works with mult 8 
        uint16_t frag_unit      = (total_payload / state->trick_sni_blender_packets_count) & ~0x7;
        uint16_t identification = lwip_ntohs(IPH_ID(ipheader));

        int payload_len = total_payload - tcphdr_len;

        if (payload_len <= 0)
        {
            // No TCP data, pure ACK / SYN / FIN etc, bypass ...
            tunnelNextUpStreamPayload(t, l, buf);
            return;
        }
        if (! isTlsClientHello(ipheader, tcp_header))
        {
            // just break the client hello (should we add option for all types?)
            tunnelNextUpStreamPayload(t, l, buf);
            return;
        }

        // before crafting we recalculate any checksum request
        if (l->recalculate_checksum && IPH_V(ipheader) == 4)
        {
            if (UNLIKELY(l->do_not_recalculate_transport_checksum == true))
            {
                IPH_CHKSUM_SET(ipheader, 0);
                IPH_CHKSUM_SET(ipheader, inet_chksum(ipheader, IPH_HL_BYTES(ipheader)));
            }
            else
            {
                recalculatePacketChecksum(sbufGetMutablePtr(buf));
            }
            l->recalculate_checksum                  = false;
            l->do_not_recalculate_transport_checksum = false;
        }

        sbuf_t *crafted_packets[kSniBlenderTrickMaxPacketsCount] = {0};

        int i = 0;

        for (; i < state->trick_sni_blender_packets_count; i++)
        {
            uint16_t offset_bytes = i * frag_unit;
            uint16_t this_len =
                (i == state->trick_sni_blender_packets_count - 1) ? total_payload - offset_bytes : frag_unit;

            if (this_len == 0)
            {
                break;
            }

            sbuf_t *craft_buf  = bufferpoolGetSmallBuffer(lineGetBufferPool(l));
            crafted_packets[i] = craft_buf;

            sbufSetLength(craft_buf, iphdr_len + this_len);
            // copy and tweak IP header (got DF flag copied from this original source)
            struct ip_hdr *fhdr = (struct ip_hdr *) sbufGetMutablePtr(craft_buf);
            memoryCopy(fhdr, ipheader, iphdr_len);

            // recompute length
            IPH_LEN_SET(fhdr, lwip_htons(iphdr_len + this_len));
            IPH_VHL_SET(fhdr, 4, iphdr_len / 4);
            IPH_ID_SET(fhdr, lwip_htons(identification));

            // set flags+offset
            uint16_t flags_offset = (offset_bytes >> 3);
            if (i < state->trick_sni_blender_packets_count - 1)
            {
                flags_offset |= IP_MF; // More Fragments for all but last
            }
            // Do NOT set IP_DF on last fragment; just leave flags_offset as is , copied already from main packet
            IPH_OFFSET_SET(fhdr, lwip_htons(flags_offset));

            // Copy the payload slice
            uint8_t *data_src = sbufGetMutablePtr(buf) + iphdr_len + offset_bytes;
            uint8_t *data_dst = (uint8_t *) sbufGetMutablePtr(craft_buf) + iphdr_len;
            memoryCopy(data_dst, data_src, this_len);
        }
        int crafted_count = i;

        LOGD("IpManipolator: sending  %d crafted packets of a Tls Hello", crafted_count);
        lineLock(l);

        int shuffled_indices[kSniBlenderTrickMaxPacketsCount] = {0};

        for (int ti = 0; ti < crafted_count; ti++)
        {
            shuffled_indices[ti] = ti;
        }

        // shuffle
        for (int idx = crafted_count - 1; idx > 0; idx--)
        {
            int j                 = (int) fastRand() % (idx + 1);
            int temp              = shuffled_indices[idx];
            shuffled_indices[idx] = shuffled_indices[j];
            shuffled_indices[j]   = temp;
        }

        for (int idx = 0; idx < crafted_count; idx++)
        {
            int packet_i                             = shuffled_indices[idx];
            l->recalculate_checksum                  = true;
            l->do_not_recalculate_transport_checksum = true;
            tunnelNextUpStreamPayload(t, l, crafted_packets[packet_i]);
            crafted_packets[packet_i] = NULL;
            // wwSleepMS(fastRand()%200);
            if (! lineIsAlive(l))
            {
                for (int j = 0; j < crafted_count; j++)
                {
                    if (crafted_packets[j] != NULL)
                    {
                        bufferpoolReuseBuffer(lineGetBufferPool(l), crafted_packets[j]);
                        crafted_packets[j] = NULL;
                    }
                }
                bufferpoolReuseBuffer(lineGetBufferPool(l), buf);

                lineUnlock(l);

                return;
            }
        }

        lineUnlock(l);
        bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
        return;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}

void sniblendertrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{

    tunnelPrevDownStreamPayload(t, l, buf);
}
