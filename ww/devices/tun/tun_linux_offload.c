#include "devices/tun/tun_linux_offload.h"

#include "ipv4_packet_view.h"
#include "wchecksum.h"
#include "wlibc.h"

#include <linux/virtio_net.h>

_Static_assert(sizeof(struct virtio_net_hdr) == kTunVirtioHeaderSize, "unexpected Linux virtio header size");

enum
{
    kIpv4TotalLengthOffset    = 2,
    kIpv4IdentificationOffset = 4,
    kIpv4ChecksumOffset       = 10,
    kIpv4SourceOffset         = 12,
    kIpv4DestinationOffset    = 16,
    kTcpSequenceOffset        = 4,
    kTcpFlagsOffset           = 13,
    kTcpChecksumOffset        = 16,
    kTcpFin                   = 0x01,
    kTcpPsh                   = 0x08,
    kTcpCwr                   = 0x80
};

static uint16_t readLittle16(const uint8_t *bytes)
{
    return (uint16_t) ((uint16_t) bytes[0] | ((uint16_t) bytes[1] << 8U));
}

static void writeNetwork16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t) (value >> 8U);
    bytes[1] = (uint8_t) value;
}

static void writeNetwork32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t) (value >> 24U);
    bytes[1] = (uint8_t) (value >> 16U);
    bytes[2] = (uint8_t) (value >> 8U);
    bytes[3] = (uint8_t) value;
}

static uint16_t readNetwork16(const uint8_t *bytes)
{
    return (uint16_t) (((uint16_t) bytes[0] << 8U) | bytes[1]);
}

/* The current destination in an IPv4 source-routed packet can be the next hop,
 * while TCP's pseudoheader covers the final destination. For a fully checksummed
 * GSO input, recover that destination from a well-formed route option. Unknown
 * options are opaque and may be copied without interpreting their contents. */
static bool selectPseudoheaderDestination(const uint8_t *ip, uint32_t ip_header_length, uint8_t destination[4])
{
    memoryCopy(destination, ip + kIpv4DestinationOffset, 4);
    for (uint32_t offset = 20; offset < ip_header_length;)
    {
        const uint8_t kind = ip[offset];
        if (kind == 0)
        {
            break;
        }
        if (kind == 1)
        {
            offset++;
            continue;
        }
        if (ip_header_length - offset < 2)
        {
            return false;
        }
        const uint32_t option_length = ip[offset + 1];
        if (option_length < 2 || option_length > ip_header_length - offset)
        {
            return false;
        }
        if (kind == 131 || kind == 137) /* LSRR and SSRR. */
        {
            if (option_length < 7 || (option_length - 3U) % 4U != 0)
            {
                return false;
            }
            const uint8_t pointer = ip[offset + 2];
            if (pointer < 4 || (pointer - 4U) % 4U != 0 || (uint32_t) pointer > option_length + 1U ||
                ((uint32_t) pointer <= option_length && (uint32_t) pointer + 3U > option_length))
            {
                return false;
            }
            if (pointer <= option_length)
            {
                memoryCopy(destination, ip + offset + option_length - 4U, 4);
            }
        }
        offset += option_length;
    }
    return true;
}

static uint32_t tcpPseudoheaderSum(const uint8_t *ip, const uint8_t destination[4], uint16_t tcp_length)
{
    return (uint32_t) readNetwork16(ip + kIpv4SourceOffset) + readNetwork16(ip + kIpv4SourceOffset + 2U) +
           readNetwork16(destination) + readNetwork16(destination + 2U) + 6U + tcp_length;
}

static uint16_t foldChecksumSeed(uint32_t sum)
{
    while (sum > UINT16_MAX)
    {
        sum = (sum & UINT16_MAX) + (sum >> 16U);
    }
    return (uint16_t) sum;
}

tun_linux_offload_reject_t tunLinuxOffloadPreflight(const uint8_t metadata[kTunVirtioHeaderSize], const uint8_t *ip,
                                                    uint32_t ip_length, uint16_t mtu, tun_linux_offload_plan_t *plan)
{
    assert(metadata != NULL && ip != NULL && plan != NULL);

    if (ip_length > UINT16_MAX)
    {
        return kTunLinuxOffloadOversized;
    }

    const uint8_t  flags           = metadata[0];
    const uint8_t  gso_type        = metadata[1];
    const uint16_t hdr_len         = readLittle16(metadata + 2);
    const uint16_t gso_size        = readLittle16(metadata + 4);
    const uint16_t checksum_start  = readLittle16(metadata + 6);
    const uint16_t checksum_offset = readLittle16(metadata + 8);

    if ((flags & ~(VIRTIO_NET_HDR_F_NEEDS_CSUM | VIRTIO_NET_HDR_F_DATA_VALID)) != 0)
    {
        return kTunLinuxOffloadUnsupported;
    }
    /* Linux may add the ECN modifier to its negotiated TCPv4 GSO type. */
    if (gso_type != VIRTIO_NET_HDR_GSO_NONE && gso_type != VIRTIO_NET_HDR_GSO_TCPV4 &&
        gso_type != (VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN))
    {
        return kTunLinuxOffloadUnsupported;
    }

    tun_linux_offload_plan_t candidate = {
        .action    = kTunLinuxOffloadOrdinary,
        .ip_length = ip_length,
    };

    if (gso_type == VIRTIO_NET_HDR_GSO_NONE)
    {
        /* Checksum offload applies to ordinary packets of any IP version.
         * Negotiating only TCPv4 GSO does not make ordinary IPv6 disappear. */
        if (ip_length == 0)
        {
            return kTunLinuxOffloadMalformed;
        }
        if (ip_length > mtu)
        {
            return kTunLinuxOffloadOversized;
        }
        if ((flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) != 0)
        {
            const uint32_t field = (uint32_t) checksum_start + checksum_offset;
            if (checksum_start >= ip_length || field > ip_length || ip_length - field < sizeof(uint16_t))
            {
                return kTunLinuxOffloadMalformed;
            }
            candidate.action         = kTunLinuxOffloadChecksum;
            candidate.checksum_start = checksum_start;
            candidate.checksum_field = (uint16_t) field;
        }
        *plan = candidate;
        return kTunLinuxOffloadAccept;
    }

    ipv4_packet_view_t packet = {0};
    if (! ipv4packetviewParse(ip, ip_length, &packet) || packet.ip_total_length != ip_length)
    {
        return kTunLinuxOffloadMalformed;
    }

    if (hdr_len > ip_length || packet.fragmented || gso_size == 0 || ! ipv4packetviewParseTcp(ip, ip_length, &packet) ||
        packet.payload_length == 0)
    {
        return kTunLinuxOffloadMalformed;
    }
    if ((flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) != 0 &&
        (checksum_start != packet.transport_offset || checksum_offset != kTcpChecksumOffset))
    {
        return kTunLinuxOffloadMalformed;
    }

    const uint32_t header_length        = packet.payload_offset;
    const uint32_t first_payload_length = min((uint32_t) gso_size, (uint32_t) packet.payload_length);
    if (header_length + first_payload_length > mtu)
    {
        return kTunLinuxOffloadOversized;
    }

    candidate.action                  = kTunLinuxOffloadSegment;
    candidate.ip_header_length        = packet.ip_header_length;
    candidate.header_length           = header_length;
    candidate.payload_length          = packet.payload_length;
    candidate.gso_size                = gso_size;
    candidate.tcp_sequence            = packet.tcp_sequence;
    candidate.segment_count           = ((uint32_t) packet.payload_length + gso_size - 1U) / gso_size;
    candidate.ip_identification       = packet.ip_identification;
    candidate.tcp_checksum_is_partial = (flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) != 0;
    if (! selectPseudoheaderDestination(ip, packet.ip_header_length, candidate.pseudoheader_destination))
    {
        return kTunLinuxOffloadMalformed;
    }
    if (candidate.tcp_checksum_is_partial)
    {
        candidate.tcp_checksum_seed = readNetwork16(ip + packet.ip_header_length + kTcpChecksumOffset);
    }
    *plan = candidate;
    return kTunLinuxOffloadAccept;
}

void tunLinuxOffloadCompleteChecksum(uint8_t *ip, const tun_linux_offload_plan_t *plan)
{
    assert(ip != NULL && plan != NULL && plan->action == kTunLinuxOffloadChecksum);
    assert(plan->checksum_start < plan->ip_length && plan->checksum_field + sizeof(uint16_t) <= plan->ip_length);

    uint16_t checksum =
        calcGenericChecksum(ip + plan->checksum_start, (uint16_t) (plan->ip_length - plan->checksum_start), 0);
    if (checksum == 0)
    {
        checksum = UINT16_MAX;
    }
    memoryCopy(ip + plan->checksum_field, &checksum, sizeof(checksum));
}

bool tunLinuxOffloadPrepareSegment(const uint8_t *ip, const tun_linux_offload_plan_t *plan, uint32_t offset,
                                   uint8_t *destination, uint32_t destination_capacity, uint32_t *segment_length)
{
    assert(ip != NULL && plan != NULL && destination != NULL && segment_length != NULL);
    assert(plan->action == kTunLinuxOffloadSegment && plan->gso_size != 0);

    if (offset >= plan->payload_length || offset % plan->gso_size != 0)
    {
        return false;
    }

    const uint32_t payload_length = min(plan->gso_size, plan->payload_length - offset);
    const uint32_t length         = plan->header_length + payload_length;
    if (destination_capacity < length)
    {
        return false;
    }

    memoryCopy(destination, ip, plan->header_length);
    memoryCopy(destination + plan->header_length, ip + plan->header_length + offset, payload_length);

    const uint32_t tcp_offset = plan->ip_header_length;
    writeNetwork16(destination + kIpv4TotalLengthOffset, (uint16_t) length);
    writeNetwork16(destination + kIpv4IdentificationOffset,
                   (uint16_t) (plan->ip_identification + offset / plan->gso_size));
    writeNetwork32(destination + tcp_offset + kTcpSequenceOffset, plan->tcp_sequence + offset);

    uint8_t *tcp_flags = destination + tcp_offset + kTcpFlagsOffset;
    if (offset + payload_length < plan->payload_length)
    {
        *tcp_flags &= (uint8_t) ~(kTcpFin | kTcpPsh);
    }
    if (offset != 0)
    {
        *tcp_flags &= (uint8_t) ~kTcpCwr;
    }

    /* Complete the IPv4 header checksum after changing length and ID. */
    destination[kIpv4ChecksumOffset]      = 0;
    destination[kIpv4ChecksumOffset + 1U] = 0;
    const uint16_t ip_checksum            = calcGenericChecksum(destination, (uint16_t) plan->ip_header_length, 0);
    memoryCopy(destination + kIpv4ChecksumOffset, &ip_checksum, sizeof(ip_checksum));

    /* CHECKSUM_PARTIAL carries a pseudoheader seed for the original aggregate.
     * Replace only its TCP-length contribution before storing the segment's
     * folded seed. Completion can then scan this independent packet on its
     * destination worker, including for source-routed aggregates. */
    const uint16_t tcp_length = (uint16_t) (length - tcp_offset);
    uint32_t       tcp_seed;
    if (plan->tcp_checksum_is_partial)
    {
        const uint16_t old_tcp_length = (uint16_t) (plan->ip_length - plan->ip_header_length);
        tcp_seed                      = (uint32_t) plan->tcp_checksum_seed + ((uint16_t) ~old_tcp_length) + tcp_length;
    }
    else
    {
        tcp_seed = tcpPseudoheaderSum(ip, plan->pseudoheader_destination, tcp_length);
    }
    writeNetwork16(destination + tcp_offset + kTcpChecksumOffset, foldChecksumSeed(tcp_seed));

    *segment_length = length;
    return true;
}

void tunLinuxOffloadCompleteSegment(uint8_t *ip, uint32_t ip_length)
{
    assert(ip != NULL && ip_length <= UINT16_MAX && ip_length >= 40);

    const uint32_t tcp_offset = (uint32_t) (ip[0] & 0x0fU) * 4U;
    assert((ip[0] >> 4U) == 4U && tcp_offset >= 20 && tcp_offset <= 60 && tcp_offset <= ip_length &&
           ip_length - tcp_offset >= 20 && readNetwork16(ip + kIpv4TotalLengthOffset) == ip_length && ip[9] == 6);

    const uint16_t tcp_length   = (uint16_t) (ip_length - tcp_offset);
    const uint16_t tcp_checksum = calcGenericChecksum(ip + tcp_offset, tcp_length, 0);
    memoryCopy(ip + tcp_offset + kTcpChecksumOffset, &tcp_checksum, sizeof(tcp_checksum));
}
