#pragma once

#include <stdint.h>

enum
{
    kCaptureLinuxSteeringMaxInstructions = 64,
    kCaptureLinuxSteeringFilterSize      = kCaptureLinuxSteeringMaxInstructions * 32 + 8
};

/* Build one iptables bpf --bytecode predicate. queue_count is positive and
 * lane_index is below it. Together all lane predicates select exactly one lane
 * for every IPv4 packet; malformed/unsupported packets select lane zero for
 * ordinary reader validation.
 *
 * Symmetric IPv4 address/protocol and TCP/UDP port steering distributes receive
 * work only. The existing software flow affinity still selects processing workers.
 * Every fragment and every complete protocol other than TCP/UDP uses the
 * address/protocol fallback. A transform can hide the transport identity of such
 * packets (a swapped protocol number, an obfuscated header) until after capture,
 * so the packets of one peer pair keep one lane: one reader posts them to their
 * processing worker in arrival order.
 * Protocol exclusions remain a separate match shared with the NOTRACK rules.
 * Evaluation is linear in the number of queue predicates visited. */
void captureLinuxBuildSteeringFilter(uint16_t queue_count, uint16_t lane_index,
                                     char output[kCaptureLinuxSteeringFilterSize]);
