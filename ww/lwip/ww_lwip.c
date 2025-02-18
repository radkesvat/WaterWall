#include "ww_lwip.h"

#include "loggers/network_logger.h"

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
        memoryCopy(&src_addr, &ip_header->src, sizeof(ip4_addr_t));
        memoryCopy(&dst_addr, &ip_header->dest, sizeof(ip4_addr_t));
        const char *src_ip = ip4addr_ntoa(&src_addr);
        const char *dst_ip = ip4addr_ntoa(&dst_addr);
        ret = snprintf(ptr, (size_t) rem, "%s : Packet v4 From %s to %s, Data: ", prefix, src_ip, dst_ip);
    }
    else if (version == 6)
    {
        struct ip6_hdr *ip6_header = (struct ip6_hdr *) buffer;
        ip6_addr_t      src_addr, dst_addr;
        memoryCopy(&src_addr, &ip6_header->src, sizeof(ip6_addr_t));
        memoryCopy(&dst_addr, &ip6_header->dest, sizeof(ip6_addr_t));
        const char *src_ip = ip6addr_ntoa(&src_addr);
        const char *dst_ip = ip6addr_ntoa(&dst_addr);
        ret = snprintf(ptr, (size_t) rem, "%s : Packet v6 From %s to %s, Data: ", prefix, src_ip, dst_ip);
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
