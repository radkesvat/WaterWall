#include "ww_lwip.h"

#include "loggers/network_logger.h"
#include "lwip/memp.h"
#include "lwip/priv/tcp_priv.h"
#include "wcrypto.h"
#include "wfrand.h"

/*
 * The pooled heap's hot class must actually be able to hold a full-MSS segment
 * copy. lwippools.h computes what such an allocation costs; this is where that
 * arithmetic is checked, because an x-macro list cannot assert. If a change to
 * transport headroom or MEM_ALIGNMENT pushes the request past the class, every
 * normal TCP write silently skips it and falls forward into the far smaller
 * classes above - which is exactly how the previous 1536-byte class went unused.
 */
_Static_assert(WW_LWIP_FULL_MSS_ALLOC <= WW_LWIP_FULL_MSS_BLOCK,
               "the lwIP heap's full-MSS class is smaller than a full-MSS PBUF_RAM allocation");

enum
{
    kWwLwipTcpIsnDigestSize       = 4,
    kWwLwipTcpIsnFamilyV4         = 4,
    kWwLwipTcpIsnFamilyV6         = 6,
    kWwLwipTcpIsnAddressSize      = 16,
    kWwLwipTcpIsnFamilyOffset     = 0,
    kWwLwipTcpIsnLocalAddrOffset  = 1,
    kWwLwipTcpIsnRemoteAddrOffset = kWwLwipTcpIsnLocalAddrOffset + kWwLwipTcpIsnAddressSize,
    kWwLwipTcpIsnLocalPortOffset  = kWwLwipTcpIsnRemoteAddrOffset + kWwLwipTcpIsnAddressSize,
    kWwLwipTcpIsnRemotePortOffset = kWwLwipTcpIsnLocalPortOffset + sizeof(uint16_t)
};

_Static_assert(kWwLwipTcpIsnRemotePortOffset + sizeof(uint16_t) == kWwLwipTcpIsnTupleSize,
               "TCP ISN tuple offsets must cover the canonical encoding exactly");

static uint8_t g_ww_lwip_tcp_isn_secret[kWwLwipTcpIsnSecretSize];
static bool    g_ww_lwip_tcp_isn_secret_initialized;

unsigned int lwip_port_rand(void)
{
    return fastRand32();
}

static void wwLwipTcpIsnEncodeAddress(uint8_t output[kWwLwipTcpIsnAddressSize], const ip_addr_t *address, bool is_ipv6)
{
    if (is_ipv6)
    {
        const ip6_addr_t *address_v6 = ip_2_ip6(address);
        for (size_t word_index = 0; word_index < 4; ++word_index)
        {
            PUT_BE32(output + (word_index * sizeof(uint32_t)), lwip_ntohl(address_v6->addr[word_index]));
        }
        return;
    }

    memoryZero(output, 10);
    output[10] = 0xFF;
    output[11] = 0xFF;
    PUT_BE32(output + 12, lwip_ntohl(ip4_addr_get_u32(ip_2_ip4(address))));
}

static void wwLwipTcpIsnSerializeTuple(uint8_t output[kWwLwipTcpIsnTupleSize], const ip_addr_t *local_ip,
                                       uint16_t local_port, const ip_addr_t *remote_ip, uint16_t remote_port)
{
    assert(local_ip != NULL);
    assert(remote_ip != NULL);
    assert(IP_GET_TYPE(local_ip) == IP_GET_TYPE(remote_ip));

    const bool is_ipv6                = IP_IS_V6(local_ip);
    output[kWwLwipTcpIsnFamilyOffset] = is_ipv6 ? kWwLwipTcpIsnFamilyV6 : kWwLwipTcpIsnFamilyV4;
    wwLwipTcpIsnEncodeAddress(output + kWwLwipTcpIsnLocalAddrOffset, local_ip, is_ipv6);
    wwLwipTcpIsnEncodeAddress(output + kWwLwipTcpIsnRemoteAddrOffset, remote_ip, is_ipv6);
    PUT_BE16(output + kWwLwipTcpIsnLocalPortOffset, local_port);
    PUT_BE16(output + kWwLwipTcpIsnRemotePortOffset, remote_port);
}

static uint32_t wwLwipTcpIsnAt(const ip_addr_t *local_ip, uint16_t local_port, const ip_addr_t *remote_ip,
                               uint16_t remote_port, uint32_t now_ms)
{
    if (UNLIKELY(! g_ww_lwip_tcp_isn_secret_initialized))
    {
        LOGF("wwLwipTcpIsn: TCP ISN secret is unavailable");
        abortProgramNow(1);
    }

    uint8_t tuple[kWwLwipTcpIsnTupleSize];
    uint8_t digest[kWwLwipTcpIsnDigestSize];
    wwLwipTcpIsnSerializeTuple(tuple, local_ip, local_port, remote_ip, remote_port);

    const wcrypto_status_t status = wCryptoBlake2s(
        digest, sizeof(digest), g_ww_lwip_tcp_isn_secret, sizeof(g_ww_lwip_tcp_isn_secret), tuple, sizeof(tuple));
    if (UNLIKELY(status != kWCryptoOk))
    {
        LOGF("wwLwipTcpIsn: keyed BLAKE2s failed: %s", wCryptoStatusString(status));
        abortProgramNow(1);
    }

    const uint32_t tuple_value = GET_BE32(digest);
    memorySecureZero(digest, sizeof(digest));
    return (now_ms * UINT32_C(250)) + tuple_value;
}

u32_t wwLwipTcpIsn(const ip_addr_t *local_ip, u16_t local_port, const ip_addr_t *remote_ip, u16_t remote_port)
{
    return wwLwipTcpIsnAt(local_ip, local_port, remote_ip, remote_port, sys_now());
}

void wwLwipInitializeProtocolState(void)
{
    if (UNLIKELY(g_ww_lwip_tcp_isn_secret_initialized))
    {
        LOGF("wwLwipInitializeProtocolState: TCP ISN secret was initialized twice");
        abortProgramNow(1);
    }

    getRandomBytes(g_ww_lwip_tcp_isn_secret, sizeof(g_ww_lwip_tcp_isn_secret));
    g_ww_lwip_tcp_isn_secret_initialized = true;
}

static void wwLwipEraseProtocolState(void)
{
    memorySecureZero(g_ww_lwip_tcp_isn_secret, sizeof(g_ww_lwip_tcp_isn_secret));
    g_ww_lwip_tcp_isn_secret_initialized = false;
}

#if defined(WW_LWIP_TEST_SEAM)
void wwLwipTestSetTcpIsnSecret(const uint8_t secret[kWwLwipTcpIsnSecretSize])
{
    assert(secret != NULL);
    memoryCopy(g_ww_lwip_tcp_isn_secret, secret, sizeof(g_ww_lwip_tcp_isn_secret));
    g_ww_lwip_tcp_isn_secret_initialized = true;
}

void wwLwipTestEraseTcpIsnSecret(void)
{
    wwLwipEraseProtocolState();
}

bool wwLwipTestTcpIsnSecretIsInitialized(void)
{
    return g_ww_lwip_tcp_isn_secret_initialized;
}

uint32_t wwLwipTestTcpIsnAt(const ip_addr_t *local_ip, uint16_t local_port, const ip_addr_t *remote_ip,
                            uint16_t remote_port, uint32_t now_ms)
{
    return wwLwipTcpIsnAt(local_ip, local_port, remote_ip, remote_port, now_ms);
}

void wwLwipTestSerializeTcpIsnTuple(uint8_t output[kWwLwipTcpIsnTupleSize], const ip_addr_t *local_ip,
                                    uint16_t local_port, const ip_addr_t *remote_ip, uint16_t remote_port)
{
    assert(output != NULL);
    wwLwipTcpIsnSerializeTuple(output, local_ip, local_port, remote_ip, remote_port);
}
#endif

#define IP_PROTO_STR(proto)                                                                                            \
    (((proto) == IP_PROTO_TCP)    ? "TCP"                                                                              \
     : ((proto) == IP_PROTO_UDP)  ? "UDP"                                                                              \
     : ((proto) == IP_PROTO_ICMP) ? "ICMP"                                                                             \
     : ((proto) == 58)            ? "ICMPv6"                                                                           \
     : ((proto) == 0)             ? "Hop-by-Hop"                                                                       \
     : ((proto) == IP_PROTO_IGMP) ? "IGMP"                                                                             \
                                  : "UNKNOWN")

static void wwLwipAbandonTcpPcb(struct tcp_pcb *pcb)
{
    /*
     * tcp_abandon() releases segment queues but not data retained after an
     * application receive callback returned ERR_MEM.
     */
    if (pcb->refused_data != NULL)
    {
        pbuf_free(pcb->refused_data);
        pcb->refused_data = NULL;
    }
    tcp_abandon(pcb, 0);
}

static void wwLwipReleaseProtocolState(void *userdata)
{
    discard userdata;
    LWIP_ASSERT_CORE_LOCKED();
    assert(tcp_input_pcb == NULL);
    if (tcp_input_pcb != NULL)
    {
        LOGF("wwLwipReleaseProtocolState: active TCP input PCB (tcp_input_pcb != NULL) during protocol release");
        abortProgramNow(1);
    }

    /*
     * tcp_abandon(reset=0) releases queued segments, including custom pbufs in
     * TCP out-of-order queues, without trying to emit reset packets through
     * netifs that node Stop has already detached.
     */
    while (tcp_active_pcbs != NULL)
    {
        wwLwipAbandonTcpPcb(tcp_active_pcbs);
    }
    while (tcp_tw_pcbs != NULL)
    {
        wwLwipAbandonTcpPcb(tcp_tw_pcbs);
    }
    while (tcp_bound_pcbs != NULL)
    {
        wwLwipAbandonTcpPcb(tcp_bound_pcbs);
    }
    while (tcp_listen_pcbs.pcbs != NULL)
    {
        err_t close_result = tcp_close(tcp_listen_pcbs.pcbs);
        assert(close_result == ERR_OK);
        if (close_result != ERR_OK)
        {
            LOGF("wwLwipReleaseProtocolState: failed to close listen PCB (close_result != ERR_OK, result=%d)",
                 (int) close_result);
            abortProgramNow(1);
        }
    }
    while (udp_pcbs != NULL)
    {
        udp_remove(udp_pcbs);
    }
    while (netif_list != NULL)
    {
        netif_remove(netif_list);
    }
    frandThreadCleanup();
}

bool wwLwipShutdown(void)
{
    /*
     * Cleanup runs from the shutdown callback after all previously queued work.
     * That closes the last window in which packet input could recreate retained
     * protocol state after it had already been released.
     */
    if (tcpip_shutdown(wwLwipReleaseProtocolState, NULL) != ERR_OK)
    {
        return false;
    }

    /* tcpip_shutdown() has joined the thread here, and the release callback
     * has already removed every TCP PCB. The process-lifetime ISN key is no
     * longer reachable by lwIP and can now be erased. */
    wwLwipEraseProtocolState();
    return true;
}

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
        ret = snprintf(ptr,
                       (size_t) rem,
                       "%s : Packet v4 %s From %s to %s, Data: ",
                       prefix,
                       IP_PROTO_STR(ip_header->_proto),
                       src_ip,
                       dst_ip);
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
        ret = snprintf(ptr,
                       (size_t) rem,
                       "%s : Packet v6 %s From %s to %s, Data: ",
                       prefix,
                       IP_PROTO_STR(ip6_header->_nexth),
                       src_ip,
                       dst_ip);
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
    printDebug("|    %5" U16_F "      |    %5" U16_F "      | (src port, dest port)\n",
               lwip_ntohs(tcphdr->src),
               lwip_ntohs(tcphdr->dest));
    printDebug("+-------------------------------+\n");
    printDebug("|           %010" U32_F "          | (seq no)\n", lwip_ntohl(tcphdr->seqno));
    printDebug("+-------------------------------+\n");
    printDebug("|           %010" U32_F "          | (ack no)\n", lwip_ntohl(tcphdr->ackno));
    printDebug("+-------------------------------+\n");
    printDebug("| %2" U16_F " |   |%" U16_F "%" U16_F "%" U16_F "%" U16_F "%" U16_F "%" U16_F "|     %5" U16_F
               "     | (hdrlen, flags ( ",
               TCPH_HDRLEN(tcphdr),
               (u16_t) (TCPH_FLAGS(tcphdr) >> 5 & 1),
               (u16_t) (TCPH_FLAGS(tcphdr) >> 4 & 1),
               (u16_t) (TCPH_FLAGS(tcphdr) >> 3 & 1),
               (u16_t) (TCPH_FLAGS(tcphdr) >> 2 & 1),
               (u16_t) (TCPH_FLAGS(tcphdr) >> 1 & 1),
               (u16_t) (TCPH_FLAGS(tcphdr) & 1),
               lwip_ntohs(tcphdr->wnd));
    printTcpPacketFlagsInfoNoNewLIne(TCPH_FLAGS(tcphdr));
    printDebug("), win)\n");
    printDebug("+-------------------------------+\n");
    printDebug("|    0x%04" X16_F "     |     %5" U16_F "     | (chksum, urgp)\n",
               lwip_ntohs(tcphdr->chksum),
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
