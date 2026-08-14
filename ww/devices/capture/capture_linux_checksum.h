#pragma once

#include "devices/device_frag_affinity.h"

#include <linux/netfilter/nfnetlink_queue.h>

static inline device_packet_checksum_provenance_t captureLinuxChecksumProvenance(bool has_skb_info, uint32_t skb_info)
{
    if (has_skb_info && (skb_info & NFQA_SKB_CSUMNOTREADY) != 0)
    {
        return (device_packet_checksum_provenance_t) {
            .ipv4 = kDeviceIpv4ChecksumOffloadNotReady,
            .tcp  = kDeviceIpv4ChecksumOffloadNotReady,
            .udp  = kDeviceIpv4ChecksumOffloadNotReady,
        };
    }
    return (device_packet_checksum_provenance_t) {
        .ipv4 = kDeviceIpv4ChecksumUntrusted,
        .tcp  = kDeviceIpv4ChecksumUntrusted,
        .udp  = kDeviceIpv4ChecksumUntrusted,
    };
}
