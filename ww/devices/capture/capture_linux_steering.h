#pragma once

#include <stdint.h>

enum
{
    kCaptureLinuxSteeringMaxInstructions = 64,
    kCaptureLinuxSteeringFilterSize      = kCaptureLinuxSteeringMaxInstructions * 32 + 8
};

/* Build one iptables bpf --bytecode predicate. queue_count is positive and
 * lane_index is below it. Together all lane predicates select exactly one lane
 * for TCP/UDP and fragmented IPv4; complete opaque protocols select no flow lane.
 * malformed/unsupported packets select lane zero for ordinary reader validation.
 *
 * Symmetric IPv4 address/protocol and TCP/UDP port steering distributes receive
 * work only. The existing software flow affinity still selects processing workers.
 * Every fragment uses the address/protocol fallback, including fragment zero.
 * Protocol exclusions remain a separate match shared with the NOTRACK rules.
 * Evaluation is linear in the number of queue predicates visited. */
void captureLinuxBuildSteeringFilter(uint16_t queue_count, uint16_t lane_index,
                                     char output[kCaptureLinuxSteeringFilterSize]);

/* Match complete non-TCP/UDP IPv4 for the independent statistic nth cascade. */
void captureLinuxBuildOpaqueFilter(char output[kCaptureLinuxSteeringFilterSize]);
