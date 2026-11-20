#include "interface.h"
#include "structure.h"

#include "devices/device_packet_checksum.h"
#include "loggers/network_logger.h"

enum
{
    kSynReplyPacketLength = IP_HLEN + TCP_HLEN,
    kSynReplyWindow       = UINT16_MAX,
    kSynReplyTcpOptionMss = 2,
    kSynReplyTcpMssLength = 4,
};

static bool synreplyOptionsValid(const uint8_t *options, size_t length, bool tcp_options)
{
    while (length > 0)
    {
        /* IPv4 and TCP both use kind 0 for End of List and 1 for No Operation. */
        if (options[0] == 0)
        {
            for (size_t i = 1; i < length; ++i)
            {
                if (options[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }
        size_t option_length = 1;
        if (options[0] != 1)
        {
            if (length < 2 || options[1] < 2 || options[1] > length)
            {
                return false;
            }
            option_length = options[1];
            if (tcp_options && options[0] == kSynReplyTcpOptionMss && option_length != kSynReplyTcpMssLength)
            {
                return false;
            }
        }
        options += option_length;
        length -= option_length;
    }
    return true;
}

static bool synreplyReadSyn(const sbuf_t *payload, ipv4_packet_view_t *syn)
{
    const uint8_t *packet = sbufGetRawPtr(payload);
    const size_t   length = sbufGetLength(payload);
    if (! ipv4packetviewParseTcp(packet, length, syn) || syn->ip_total_length != length ||
        ! ipv4packetviewIsOpeningTcpSyn(syn) || ! synreplyAddressAllowsReply(syn->source_address) ||
        ! synreplyAddressAllowsReply(syn->destination_address) ||
        ! synreplyOptionsValid(packet + IP_HLEN, syn->ip_header_length - IP_HLEN, false) ||
        ! synreplyOptionsValid(
            packet + syn->transport_offset + TCP_HLEN, syn->transport_header_length - TCP_HLEN, true))
    {
        return false;
    }

    const device_packet_checksum_validity_t checksums = deviceIpv4ChecksumValidity(packet, syn->ip_total_length);
    return checksums.ipv4 && checksums.tcp;
}

static sbuf_t *synreplyBuildReply(line_t *line, const ipv4_packet_view_t *syn, const synreply_tstate_t *state)
{
    sbuf_t  *reply  = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    uint8_t *packet = sbufGetMutablePtr(reply);
    sbufSetLength(reply, kSynReplyPacketLength);
    memoryZero(packet, kSynReplyPacketLength);

    struct ip_hdr *ip = (struct ip_hdr *) packet;
    IPH_VHL_SET(ip, 4, IP_HLEN / 4U);
    IPH_LEN_SET(ip, lwip_htons(kSynReplyPacketLength));
    IPH_OFFSET_SET(ip, lwip_htons(IP_DF));
    IPH_TTL_SET(ip, state->ttl);
    IPH_PROTO_SET(ip, IP_PROTO_TCP);
    ip->src.addr  = state->has_reply_source_ip ? state->reply_source_ip : syn->destination_address;
    ip->dest.addr = syn->source_address;

    struct tcp_hdr *tcp = (struct tcp_hdr *) (packet + IP_HLEN);
    tcp->src            = lwip_htons(syn->destination_port);
    tcp->dest           = lwip_htons(syn->source_port);
    tcp->seqno          = lwip_htonl(fastRand32());
    tcp->ackno          = lwip_htonl(syn->tcp_sequence + UINT32_C(1));
    TCPH_HDRLEN_FLAGS_SET(tcp, TCP_HLEN / 4U, TCP_SYN | TCP_ACK);
    tcp->wnd = lwip_htons(kSynReplyWindow);

    if (! calcFullPacketChecksum(packet, kSynReplyPacketLength))
    {
        LOGF("SynReply: generated an invalid IPv4 SYN-ACK");
        abortProgramNow(1);
    }
    if (state->fake_checksum)
    {
        /* Skip zero on wrap since 0xffff and 0 are equivalent in one's-complement arithmetic. */
        const uint16_t valid_checksum = lwip_ntohs(tcp->chksum);
        tcp->chksum                   = lwip_htons(valid_checksum == UINT16_MAX ? 1 : (uint16_t) (valid_checksum + 1));
    }
    sbufSetRecalculateChecksum(reply, false);
    return reply;
}

void synreplyTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    assert(! sbufIsSplice(payload));
    assert(tunnelchainIsWorkerPacketLine(tunnelGetChain(t), line));
    assert(lineIsOnCurrentWorker(line));
    ipv4_packet_view_t syn;
    if (! synreplyReadSyn(payload, &syn))
    {
        tunnelNextUpStreamPayload(t, line, payload);
        return;
    }

    /* The scalar view survives the handoff. A reentrant Finish bypasses SynReply on the live packet line. */
    if (! lineCallWithRefWithBuf(line, tunnelNextUpStreamPayload, t, payload) || ! tunnelIsActiveForLine(t, line))
    {
        return;
    }

    sbuf_t *reply = synreplyBuildReply(line, &syn, tunnelGetState(t));
    tunnelPrevDownStreamPayload(t, line, reply);
}
