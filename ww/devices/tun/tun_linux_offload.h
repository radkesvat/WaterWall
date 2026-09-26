#pragma once

/* Linux TUN virtio-header conversion. The caller owns all packet storage. */

#include "devices/tun/tun.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum tun_linux_offload_action_e
{
    kTunLinuxOffloadOrdinary = 0,
    kTunLinuxOffloadChecksum,
    kTunLinuxOffloadSegment
} tun_linux_offload_action_t;

typedef enum tun_linux_offload_reject_e
{
    kTunLinuxOffloadAccept = 0,
    kTunLinuxOffloadMalformed,
    kTunLinuxOffloadUnsupported,
    kTunLinuxOffloadOversized
} tun_linux_offload_reject_t;

typedef struct tun_linux_offload_plan_s
{
    tun_linux_offload_action_t action;
    uint32_t                   ip_length;
    uint32_t                   ip_header_length;
    uint32_t                   header_length;
    uint32_t                   payload_length;
    uint32_t                   gso_size;
    uint32_t                   tcp_sequence;
    uint32_t                   segment_count;
    uint16_t                   ip_identification;
    uint16_t                   checksum_start;
    uint16_t                   checksum_field;
    uint16_t                   tcp_checksum_seed;
    bool                       tcp_checksum_is_partial;
    uint8_t                    pseudoheader_destination[4];
} tun_linux_offload_plan_t;

/* Metadata is the separate, exactly ten-byte virtio header; ip is the record's
 * complete IP bytes. No bytes are changed during preflight. */
tun_linux_offload_reject_t tunLinuxOffloadPreflight(const uint8_t metadata[kTunVirtioHeaderSize], const uint8_t *ip,
                                                    uint32_t ip_length, uint16_t mtu, tun_linux_offload_plan_t *plan);

/* Only a preflighted ordinary NEEDS_CSUM packet may be passed here. */
void tunLinuxOffloadCompleteChecksum(uint8_t *ip, const tun_linux_offload_plan_t *plan);

/* Prepare one segment in caller-owned storage. Offset is a payload offset
 * aligned to gso_size. The IPv4 checksum is complete, but the TCP checksum
 * field holds a folded pseudoheader seed until CompleteSegment runs. Returns
 * false only for caller misuse or a violated preflight invariant; the reader
 * must never queue a failed preparation. */
bool tunLinuxOffloadPrepareSegment(const uint8_t *ip, const tun_linux_offload_plan_t *plan, uint32_t offset,
                                   uint8_t *destination, uint32_t destination_capacity, uint32_t *segment_length);

/* Complete TCP checksum of a prepared segment on its destination worker. The
 * segment is independent of the aggregate and plan after preparation. */
void tunLinuxOffloadCompleteSegment(uint8_t *ip, uint32_t ip_length);
