#pragma once

#include "buffer_stream.h"

typedef enum ipv4stream_validation_level_e
{
    kIpv4StreamValidationNone = 0,
    kIpv4StreamValidationLoose,
    kIpv4StreamValidationHard
} ipv4stream_validation_level_t;

const char *ipv4streamValidationLevelName(ipv4stream_validation_level_t level);

/* Ordinary, exclusively owned packet. Returns NULL on acceptance, otherwise a
 * static diagnostic reason. Inspection restores all checksum bytes before returning;
 * ownership stays with the caller. No logging, callbacks or checksum-request changes.
 * None accepts unchanged; loose checks complete IPv4 geometry; hard additionally
 * checks IPv4 and unfragmented TCP/UDP/ICMP checksums. */
const char *ipv4streamValidatePacket(ipv4stream_validation_level_t level, sbuf_t *packet);

/* Framing is always IPv4-only, independently of optional packet validation.
 * The complete packet must fit kMaxAllowedPacketLength and its declared length. */
bool ipv4streamIsForwardablePacket(const sbuf_t *packet);

/* Consume garbage and extract at most one complete packet from ordinary input.
 * Success transfers one owned buffer through packet_out. Otherwise packet_out is
 * NULL and only an incomplete candidate/header remains. A plausible header waits
 * for its declared length; no checksum or source-authorization policy is implied.
 * Uses the stream's owner-worker pool and exact-read padding, with no callbacks.
 * Delivery admission, retained-storage limits and compaction belong to the caller. */
bool ipv4streamTryReadPacket(buffer_stream_t *stream, sbuf_t **packet_out);
