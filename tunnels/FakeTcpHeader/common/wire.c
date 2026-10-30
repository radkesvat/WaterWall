#include "structure.h"

#include "ipv4_packet_view.h"
#include "wchecksum.h"

static uint16_t faketcpheaderRead16(const uint8_t *bytes)
{
    return (uint16_t) (((uint16_t) bytes[0] << 8) | bytes[1]);
}

static void faketcpheaderWrite16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t) (value >> 8);
    bytes[1] = (uint8_t) value;
}

static void faketcpheaderWrite32(uint8_t *bytes, uint32_t value)
{
    faketcpheaderWrite16(bytes, (uint16_t) (value >> 16));
    faketcpheaderWrite16(bytes + 2, (uint16_t) value);
}

static uint32_t faketcpheaderPseudoSum(const uint8_t *bytes, uint8_t protocol, uint16_t length)
{
    uint32_t sum = protocol + (uint32_t) length;
    for (unsigned int i = 12; i < 20; i += 2)
        sum += faketcpheaderRead16(bytes + i);
    return sum;
}

/* Validate complete packet geometry and transport geometry before honoring an
 * internal repair request. Inner fragments are preserved as IP packets; a TUN
 * peer can deliver them to the kernel's ordinary fragment reassembly. */
static bool faketcpheaderInnerValid(const uint8_t *bytes, uint32_t length, bool repair_requested)
{
    ipv4_packet_view_t view;
    if (! ipv4packetviewParse(bytes, length, &view) || view.ip_total_length != length)
        return false;
    if (! view.fragmented)
    {
        if (view.protocol == IPPROTO_TCP && ! ipv4packetviewParseTcp(bytes, length, &view))
            return false;
        if (view.protocol == IPPROTO_UDP &&
            (! ipv4packetviewParseUdp(bytes, length, &view) || view.udp_datagram_length != view.transport_length))
            return false;
    }
    if (repair_requested)
        return true;
    if (calcGenericChecksum(bytes, view.ip_header_length, 0) != 0)
        return false;
    if (view.fragmented || (view.protocol != IPPROTO_TCP && view.protocol != IPPROTO_UDP))
        return true;
    const uint8_t *transport = bytes + view.transport_offset;
    if (view.protocol == IPPROTO_UDP && faketcpheaderRead16(transport + 6) == 0)
        return true;
    return calcGenericChecksum(transport,
                               view.transport_length,
                               faketcpheaderPseudoSum(bytes, view.protocol, view.transport_length)) == 0;
}

bool faketcpheaderEncode(const faketcpheader_tstate_t *config, sbuf_t *buf)
{
    assert(! sbufIsSplice(buf));
    assert(config->options_length <= kFakeTcpHeaderMaxOptions && config->options_length % 4 == 0);
    const uint16_t overhead     = faketcpheaderOverhead(config);
    const uint32_t inner_length = sbufGetLength(buf);
    const bool     repair       = sbufGetRecalculateChecksum(buf);
    if (inner_length > faketcpheaderInnerMtu(config) || sbufGetLeftCapacity(buf) < overhead ||
        ! faketcpheaderInnerValid(sbufGetRawPtr(buf), inner_length, repair))
        return false;
    if (repair && ! calcFullPacketChecksum(sbufGetMutablePtr(buf), inner_length))
        return false;

    /* The complete original packet remains in place, including its addresses,
     * ports, transport header, IP options and application datagram boundary. */
    const uint8_t tos = sbufGetMutablePtr(buf)[1];
    sbufShiftLeft(buf, overhead);
    uint8_t *ip = sbufGetMutablePtr(buf);
    memoryZero(ip, overhead);
    ip[0] = 0x45;
    ip[1] = tos;
    faketcpheaderWrite16(ip + 2, (uint16_t) sbufGetLength(buf));
    ip[6] = 0x40; /* DF: configured carrier MTU is the wire admission boundary. */
    ip[8] = 64;
    ip[9] = config->protocol;
    memoryCopy(ip + 12, &config->local_ipv4, 4);
    memoryCopy(ip + 16, &config->peer_ipv4, 4);
    uint8_t *tcp = ip + IP_HLEN;
    faketcpheaderWrite16(tcp, config->local_port);
    faketcpheaderWrite16(tcp + 2, config->peer_port);
    faketcpheaderWrite32(tcp + 4, config->sequence);
    faketcpheaderWrite32(tcp + 8, config->acknowledgment);
    tcp[12] = (uint8_t) (((TCP_HLEN + config->options_length) / 4U) << 4);
    tcp[13] = config->flags;
    faketcpheaderWrite16(tcp + 14, config->window);
    faketcpheaderWrite16(tcp + 18, config->urgent_pointer);
    memoryCopy(tcp + TCP_HLEN, config->options, config->options_length);
    uint16_t checksum = calcGenericChecksum(ip, IP_HLEN, 0);
    memoryCopy(ip + 10, &checksum, sizeof(checksum));
    const uint16_t transport_length = (uint16_t) (TCP_HLEN + config->options_length + inner_length);
    checksum =
        calcGenericChecksum(tcp, transport_length, faketcpheaderPseudoSum(ip, config->protocol, transport_length));
    memoryCopy(tcp + 16, &checksum, sizeof(checksum));
    sbufSetRecalculateChecksum(buf, false);
    return true;
}

bool faketcpheaderDecode(const faketcpheader_tstate_t *config, sbuf_t *buf)
{
    assert(! sbufIsSplice(buf));
    ipv4_packet_view_t view;
    const uint8_t     *ip = sbufGetRawPtr(buf);
    if (! ipv4packetviewParse(ip, sbufGetLength(buf), &view) || view.ip_total_length != sbufGetLength(buf) ||
        view.fragmented || view.protocol != config->protocol || sbufGetLength(buf) > config->mtu ||
        view.transport_length < TCP_HLEN || view.source_address != config->peer_ipv4 ||
        view.destination_address != config->local_ipv4)
        return false;
    const uint8_t *tcp        = ip + view.transport_offset;
    const uint16_t tcp_length = (uint16_t) ((tcp[12] >> 4) * 4U);
    if (tcp_length < TCP_HLEN || tcp_length > view.transport_length || faketcpheaderRead16(tcp) != config->peer_port ||
        faketcpheaderRead16(tcp + 2) != config->local_port)
        return false;
    if (! sbufGetRecalculateChecksum(buf) &&
        (calcGenericChecksum(ip, view.ip_header_length, 0) != 0 ||
         calcGenericChecksum(
             tcp, view.transport_length, faketcpheaderPseudoSum(ip, view.protocol, view.transport_length)) != 0))
        return false;
    const uint16_t overhead = (uint16_t) (view.ip_header_length + tcp_length);
    if (! faketcpheaderInnerValid(ip + overhead, sbufGetLength(buf) - overhead, false))
        return false;
    sbufShiftRight(buf, overhead);
    sbufSetRecalculateChecksum(buf, false);
    return true;
}
