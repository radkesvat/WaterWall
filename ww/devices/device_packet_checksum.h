#pragma once

#include "wplatform.h"

#include <stdbool.h>
#include <stdint.h>

typedef enum device_ipv4_checksum_provenance_e
{
    /* The capture API positively reported that the header checksum is valid. */
    kDeviceIpv4ChecksumProvenValid = 0,
    /* The capture API positively reported checksum work that is not ready yet. */
    kDeviceIpv4ChecksumOffloadNotReady,
    /* No trustworthy positive metadata: verify the bytes before admission. */
    kDeviceIpv4ChecksumUntrusted
} device_ipv4_checksum_provenance_t;

typedef struct device_packet_checksum_provenance_s
{
    device_ipv4_checksum_provenance_t ipv4;
    device_ipv4_checksum_provenance_t tcp;
    device_ipv4_checksum_provenance_t udp;
} device_packet_checksum_provenance_t;

/*
 * Materializes trusted offload results and validates untrusted bytes for the
 * IPv4 header and the applicable TCP/UDP transport checksum. Fragmented L4
 * offload cannot be materialized from one fragment and is rejected.
 */
bool deviceIpv4PreparePacketChecksums(uint8_t *packet, uint32_t length, device_packet_checksum_provenance_t provenance);

typedef struct device_packet_checksum_validity_s
{
    bool ipv4;
    bool tcp;
    bool udp;
} device_packet_checksum_validity_t;

/*
 * Which checksums in this packet are provably correct, field by field.
 *
 * Used where a bit must assert a fact rather than a shape: a non-IPv4 or
 * malformed packet proves nothing, a fragment carries no complete transport
 * checksum, and a protocol without one proves nothing about TCP or UDP.
 */
device_packet_checksum_validity_t deviceIpv4ChecksumValidity(const uint8_t *packet, uint32_t length);
