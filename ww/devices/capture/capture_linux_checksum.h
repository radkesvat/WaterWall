#pragma once

#include "ipv4_packet_view.h"
#include "wchecksum.h"

#include <linux/netfilter/nfnetlink_queue.h>

/*
 * Capture treats transport bytes as opaque: altered headers and deliberately
 * invalid checksums belong to the receiving tunnel. Only complete, structurally
 * valid IPv4 is required here. Finish explicitly pending kernel offload when the
 * unfragmented packet can be interpreted safely; a refusal leaves its bytes
 * unchanged and is not grounds to drop it. Fragment admission remains separate.
 */
static inline bool captureLinuxPreparePacket(uint8_t *packet, uint32_t length, bool has_skb_info, uint32_t skb_info)
{
    ipv4_packet_view_t view = {0};
    if (! ipv4packetviewParse(packet, length, &view) || view.ip_total_length != length)
    {
        return false;
    }

    if (has_skb_info && (skb_info & NFQA_SKB_CSUMNOTREADY) != 0 && ! view.fragmented)
    {
        // calcFullPacketChecksum validates all accessed fields before any write.
        discard calcFullPacketChecksum(packet, length);
    }
    return true;
}
