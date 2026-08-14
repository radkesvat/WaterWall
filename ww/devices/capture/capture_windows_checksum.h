#pragma once

#include "devices/device_frag_affinity.h"

static inline device_ipv4_checksum_provenance_t captureWindowsChecksumField(bool checksum_valid, bool trusted_offload)
{
    if (checksum_valid)
    {
        return kDeviceIpv4ChecksumProvenValid;
    }
    return trusted_offload ? kDeviceIpv4ChecksumOffloadNotReady : kDeviceIpv4ChecksumUntrusted;
}

/*
 * `impostor` is WinDivert's marker for a packet another injecting driver put on
 * the stack. An outbound or loopback packet is normally the local stack's own,
 * so a cleared checksum-valid bit on it means offload not yet applied - work the
 * stack was going to finish and this reader can finish for it. An impostor did
 * not come from that stack, so the same cleared bit means nothing was promised;
 * treating it as pending offload materializes a checksum over bytes nobody
 * vouched for. Independently set IPChecksum/TCPChecksum/UDPChecksum bits remain
 * positive evidence whatever the origin.
 */
static inline device_packet_checksum_provenance_t captureWindowsChecksumProvenance(bool ip_checksum_valid,
                                                                                   bool tcp_checksum_valid,
                                                                                   bool udp_checksum_valid,
                                                                                   bool outbound, bool loopback,
                                                                                   bool impostor)
{
    const bool trusted_offload = (outbound || loopback) && ! impostor;
    return (device_packet_checksum_provenance_t) {
        .ipv4 = captureWindowsChecksumField(ip_checksum_valid, trusted_offload),
        .tcp  = captureWindowsChecksumField(tcp_checksum_valid, trusted_offload),
        .udp  = captureWindowsChecksumField(udp_checksum_valid, trusted_offload),
    };
}
