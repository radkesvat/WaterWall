#pragma once

#include <stdbool.h>
#include <stdint.h>

enum
{
    kCaptureLinuxSteeringMaxInstructions = 64,
    kCaptureLinuxSteeringFilterSize      = kCaptureLinuxSteeringMaxInstructions * 32 + 8
};

/* Build one iptables bpf --bytecode predicate. queue_count is positive and
 * lane_index is below it. Together all lane predicates select exactly one lane
 * for TCP/UDP and fragmented IPv4; complete opaque protocols select no flow lane
 * unless opaque_lanes is set, when they take the address/protocol lane as
 * fragments do. malformed/unsupported packets select lane zero for ordinary
 * reader validation.
 *
 * Symmetric IPv4 address/protocol and TCP/UDP port steering distributes receive
 * work and initial processing. Stateful consumers independently establish flow
 * ownership after any preceding packet transformations.
 * Every fragment uses the address/protocol fallback, including fragment zero.
 * Protocol exclusions remain a separate match shared with the NOTRACK rules.
 * Evaluation is linear in the number of queue predicates visited. */
void captureLinuxBuildSteeringFilter(uint16_t queue_count, uint16_t lane_index, bool opaque_lanes,
                                     char output[kCaptureLinuxSteeringFilterSize]);

/* Match complete non-TCP/UDP IPv4 for the independent statistic random cascade. */
void captureLinuxBuildOpaqueFilter(char output[kCaptureLinuxSteeringFilterSize]);
