#include "ww_lwip.h"

#include "loggers/network_logger.h"

#define IP_PROTO_STR(proto)                                                                                            \
    (((proto) == IP_PROTO_TCP)    ? "TCP"                                                                              \
     : ((proto) == IP_PROTO_UDP)  ? "UDP"                                                                              \
     : ((proto) == IP_PROTO_ICMP) ? "ICMP"                                                                             \
     : ((proto) == 58)            ? "ICMPv6"                                                                           \
     : ((proto) == 0)             ? "Hop-by-Hop"                                                                       \
     : ((proto) == IP_PROTO_IGMP) ? "IGMP"                                                                             \
                                  : "UNKNOWN")

void printIPPacketInfo(const char *prefix, const unsigned char *buffer)
{
    char  logbuf[256];
    int   rem = sizeof(logbuf);
    char *ptr = logbuf;
    int   ret;

    uint8_t version = buffer[0] >> 4;

    if (version == 4)
    {
        struct ip_hdr *ip_header = (struct ip_hdr *) buffer;
        ip4_addr_t     src_addr, dst_addr;
        memoryCopy(&src_addr, &ip_header->src.addr, sizeof(ip4_addr_t));
        memoryCopy(&dst_addr, &ip_header->dest.addr, sizeof(ip4_addr_t));

        char src_ip[40];
        char dst_ip[40];

        stringCopyN(src_ip, ip4addr_ntoa(&src_addr), 40);
        stringCopyN(dst_ip, ip4addr_ntoa(&dst_addr), 40);
        ret = snprintf(ptr, (size_t) rem, "%s : Packet v4 %s From %s to %s, Data: ", prefix,
                       IP_PROTO_STR(ip_header->_proto), src_ip, dst_ip);
    }
    else if (version == 6)
    {
        struct ip6_hdr *ip6_header = (struct ip6_hdr *) buffer;
        ip6_addr_t      src_addr, dst_addr;
        memoryCopy(&src_addr, &ip6_header->src, sizeof(ip6_addr_t));
        memoryCopy(&dst_addr, &ip6_header->dest, sizeof(ip6_addr_t));
        char src_ip[40];
        char dst_ip[40];

        stringCopyN(src_ip, ip6addr_ntoa(&src_addr), 40);
        stringCopyN(dst_ip, ip6addr_ntoa(&dst_addr), 40);
        ret = snprintf(ptr, (size_t) rem, "%s : Packet v6 %s From %s to %s, Data: ", prefix,
                       IP_PROTO_STR(ip6_header->_nexth), src_ip, dst_ip);
    }
    else
    {
        ret = snprintf(ptr, (size_t) rem, "%s : Unknown IP version, Data: ", prefix);
    }

    ptr += ret;
    rem -= ret;

    for (int i = 0; i < 16; i++)
    {
        ret = snprintf(ptr, (size_t) rem, "%02x ", buffer[i]);
        ptr += ret;
        rem -= ret;
    }
    *ptr = '\0';

    LOGD(logbuf);
}

static void printTcpPacketFlagsInfoNoNewLIne(u8_t flags)
{
    if (flags & TCP_FIN)
    {
        printDebug("FIN ");
    }
    if (flags & TCP_SYN)
    {
        printDebug("SYN ");
    }
    if (flags & TCP_RST)
    {
        printDebug("RST ");
    }
    if (flags & TCP_PSH)
    {
        printDebug("PSH ");
    }
    if (flags & TCP_ACK)
    {
        printDebug("ACK ");
    }
    if (flags & TCP_URG)
    {
        printDebug("URG ");
    }
    if (flags & TCP_ECE)
    {
        printDebug("ECE ");
    }
    if (flags & TCP_CWR)
    {
        printDebug("CWR ");
    }
}

void printTcpPacketInfo(struct tcp_hdr *tcphdr)
{
    printDebug("TCP header:\n");
    printDebug("+-------------------------------+\n");
    printDebug("|    %5" U16_F "      |    %5" U16_F "      | (src port, dest port)\n", lwip_ntohs(tcphdr->src),
               lwip_ntohs(tcphdr->dest));
    printDebug("+-------------------------------+\n");
    printDebug("|           %010" U32_F "          | (seq no)\n", lwip_ntohl(tcphdr->seqno));
    printDebug("+-------------------------------+\n");
    printDebug("|           %010" U32_F "          | (ack no)\n", lwip_ntohl(tcphdr->ackno));
    printDebug("+-------------------------------+\n");
    printDebug("| %2" U16_F " |   |%" U16_F "%" U16_F "%" U16_F "%" U16_F "%" U16_F "%" U16_F "|     %5" U16_F
               "     | (hdrlen, flags ( ",
               TCPH_HDRLEN(tcphdr), (u16_t) (TCPH_FLAGS(tcphdr) >> 5 & 1), (u16_t) (TCPH_FLAGS(tcphdr) >> 4 & 1),
               (u16_t) (TCPH_FLAGS(tcphdr) >> 3 & 1), (u16_t) (TCPH_FLAGS(tcphdr) >> 2 & 1),
               (u16_t) (TCPH_FLAGS(tcphdr) >> 1 & 1), (u16_t) (TCPH_FLAGS(tcphdr) & 1), lwip_ntohs(tcphdr->wnd));
    printTcpPacketFlagsInfoNoNewLIne(TCPH_FLAGS(tcphdr));
    printDebug("), win)\n");
    printDebug("+-------------------------------+\n");
    printDebug("|    0x%04" X16_F "     |     %5" U16_F "     | (chksum, urgp)\n", lwip_ntohs(tcphdr->chksum),
               lwip_ntohs(tcphdr->urgp));
    printDebug("+-------------------------------+\n");
}

void printTcpPacketFlagsInfo(u8_t flags)
{
    printTcpPacketFlagsInfoNoNewLIne(flags);
    printDebug("\n");
}

/**
 * @ingroup pbuf
 * Copy (part of) the contents of a packet buffer
 * to an application supplied buffer.
 *
 * @param buf the pbuf from which to copy data
 * @param dataptr the application supplied buffer
 * @return the number of bytes copied, or 0 on failure
 */
u16_t pbufLargeCopyToPtr(const struct pbuf *buf, void *dataptr)
{
    const struct pbuf *p;
    u16_t              left = 0;
    u16_t              buf_copy_len;
    u16_t              copied_total = 0;

    LWIP_ERROR("pbuf_copy_partial: invalid buf", (buf != NULL), return 0;);
    LWIP_ERROR("pbuf_copy_partial: invalid dataptr", (dataptr != NULL), return 0;);

    /* Note some systems use byte copy if dataptr or one of the pbuf payload pointers are unaligned. */
    for (p = buf; p != NULL; p = p->next)
    {

        buf_copy_len = (p->len);
        if (buf_copy_len < 64)
        {
            memoryCopy(&((char *) dataptr)[left], &((char *) p->payload)[0], buf_copy_len);
        }
        else
        {
            /* copy the necessary parts of the buffer */
            memoryCopyLarge(&((char *) dataptr)[left], &((char *) p->payload)[0], buf_copy_len);
        }
        copied_total = (u16_t) (copied_total + buf_copy_len);
        left         = (u16_t) (left + buf_copy_len);
    }
    return copied_total;
}
