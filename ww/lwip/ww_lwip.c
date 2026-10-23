#include "ww_lwip.h"
#include "engine_runtime.h"

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

bool wwLwipShutdown(void)
{
    /* The controller has joined every event worker. No engine or callback may
     * still reach shared storage or the process ISN secret. */
    wwLwipRuntimeFinalize();
    wwLwipEraseProtocolState();
    return true;
}

/* snprintf/vsnprintf report the desired length even after truncation. Keep
 * only bytes actually present so the next append never advances out of bounds. */
static void packetInfoAppend(char *output, size_t capacity, size_t *used, const char *format, ...)
{
    if (*used >= capacity - 1)
        return;

    va_list arguments;
    va_start(arguments, format);
    const int result = vsnprintf(output + *used, capacity - *used, format, arguments);
    va_end(arguments);
    if (result > 0)
        *used += min((size_t) result, capacity - *used - 1);
    output[*used] = '\0';
}

void printIPPacketInfo(const char *prefix, const unsigned char *buffer, size_t length)
{
    assert(prefix != NULL && (buffer != NULL || length == 0));
    char          logbuf[256] = {0};
    size_t        used        = 0;
    const uint8_t version     = length != 0 ? buffer[0] >> 4 : 0;

    if (length == 0)
        packetInfoAppend(logbuf, sizeof(logbuf), &used, "%s : Empty packet, Data: ", prefix);
    else if (version == 4 && length < IP_HLEN)
        packetInfoAppend(logbuf, sizeof(logbuf), &used, "%s : Truncated IPv4 header, Data: ", prefix);
    else if (version == 4)
    {
        const size_t header_length = (buffer[0] & 15U) * 4U;
        if (header_length < IP_HLEN)
            packetInfoAppend(logbuf, sizeof(logbuf), &used, "%s : Invalid IPv4 header, Data: ", prefix);
        else if (header_length > length)
            packetInfoAppend(logbuf, sizeof(logbuf), &used, "%s : Truncated IPv4 header, Data: ", prefix);
        else
        {
            ip4_addr_t source, destination;
            memoryCopy(&source.addr, buffer + 12, sizeof(source.addr));
            memoryCopy(&destination.addr, buffer + 16, sizeof(destination.addr));
            char source_text[IP4ADDR_STRLEN_MAX], destination_text[IP4ADDR_STRLEN_MAX];
            ip4addr_ntoa_r(&source, source_text, sizeof(source_text));
            ip4addr_ntoa_r(&destination, destination_text, sizeof(destination_text));
            packetInfoAppend(logbuf,
                             sizeof(logbuf),
                             &used,
                             "%s : Packet v4 %s From %s to %s, Data: ",
                             prefix,
                             IP_PROTO_STR(buffer[9]),
                             source_text,
                             destination_text);
        }
    }
    else if (version == 6 && length < IP6_HLEN)
        packetInfoAppend(logbuf, sizeof(logbuf), &used, "%s : Truncated IPv6 header, Data: ", prefix);
    else if (version == 6)
    {
        ip6_addr_t source = {0}, destination = {0};
        memoryCopy(source.addr, buffer + 8, sizeof(source.addr));
        memoryCopy(destination.addr, buffer + 24, sizeof(destination.addr));
        char source_text[IP6ADDR_STRLEN_MAX], destination_text[IP6ADDR_STRLEN_MAX];
        ip6addr_ntoa_r(&source, source_text, sizeof(source_text));
        ip6addr_ntoa_r(&destination, destination_text, sizeof(destination_text));
        packetInfoAppend(logbuf,
                         sizeof(logbuf),
                         &used,
                         "%s : Packet v6 %s From %s to %s, Data: ",
                         prefix,
                         IP_PROTO_STR(buffer[6]),
                         source_text,
                         destination_text);
    }
    else
        packetInfoAppend(logbuf, sizeof(logbuf), &used, "%s : Unknown IP version, Data: ", prefix);

    for (size_t i = 0; i < min(length, (size_t) 16); ++i)
        packetInfoAppend(logbuf, sizeof(logbuf), &used, "%02x ", buffer[i]);
    LOGD("%s", logbuf);
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

u16_t pbufLargeCopyToPtr(const struct pbuf *buf, void *dataptr)
{
    LWIP_ERROR("pbufLargeCopyToPtr: invalid buf", (buf != NULL), return 0;);
    LWIP_ERROR("pbufLargeCopyToPtr: invalid dataptr", (dataptr != NULL), return 0;);

    const uint32_t length = buf->tot_len;
    uint32_t       copied = 0;
    for (const struct pbuf *p = buf; p != NULL && copied < length; p = p->next)
    {
        const uint32_t count = min((uint32_t) p->len, length - copied);
        if (count != 0)
        {
            uint8_t *destination = (uint8_t *) dataptr + copied;
            if (count < 64)
                memoryCopy(destination, p->payload, count);
            else
                memoryCopyLarge(destination, p->payload, count);
            copied += count;
        }
        /* The final span may link to another packet in a pbuf queue. */
        if (p->tot_len == p->len)
            break;
    }
    return (u16_t) copied;
}
