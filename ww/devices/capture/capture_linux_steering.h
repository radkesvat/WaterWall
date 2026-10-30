#pragma once

// <<<<<<< fix/protoswap-inner-flow-steering
// #include "devices/device_flow_hash.h"

// =======
// #include <stdbool.h>
// >>>>>>> packet-steering-integration
// #include <stdint.h>

enum
{
    kCaptureLinuxSteeringMaxInstructions = 64,
    kCaptureLinuxPortedProtocols         = kDeviceFlowPortedProtocolMax,
    kCaptureLinuxSteeringFilterSize      = kCaptureLinuxSteeringMaxInstructions * 32 + 8
};

// /* Build one iptables bpf --bytecode predicate. queue_count is positive and
//  * lane_index is below it. Together all lane predicates select exactly one lane
//  * for TCP/UDP, ported protocols and fragmented IPv4; the remaining complete
//  * opaque protocols select no flow lane. Malformed/unsupported packets select
//  * lane zero for ordinary reader validation.
//  *
//  * A ported protocol (see device_flow_ported_set_t) begins with a
//  * TCP/UDP-style port pair, for example a protocol swap that left the transport
//  * header in place. ported_protocols lists up to kCaptureLinuxPortedProtocols such
//  * numbers; their packets are steered by that port pair like TCP/UDP, so one inner
//  * flow keeps one lane and different flows spread. The hash is symmetric and
//  * only combines the two port words, so a constant byte-wise obfuscation of the
//  * header does not change which packets agree.
//  * for TCP/UDP and fragmented IPv4; complete opaque protocols select no flow lane
//  * unless opaque_lanes is set, when they take the address/protocol lane as
//  * fragments do. malformed/unsupported packets select lane zero for ordinary
//  * reader validation.
//  *
//  * Symmetric IPv4 address/protocol and TCP/UDP port steering distributes receive
//  * work and initial processing. Stateful consumers independently establish flow
//  * ownership after any preceding packet transformations.
//  * Every fragment uses the address/protocol fallback, including fragment zero.
//  * Protocol exclusions remain a separate match shared with the NOTRACK rules.
//  * Evaluation is linear in the number of queue predicates visited. */
// void captureLinuxBuildSteeringFilter(uint16_t queue_count, uint16_t lane_index, const uint8_t *ported_protocols,
//                                      unsigned ported_count, char output[kCaptureLinuxSteeringFilterSize]);
// void captureLinuxBuildSteeringFilter(uint16_t queue_count, uint16_t lane_index, bool opaque_lanes,
//                                      char output[kCaptureLinuxSteeringFilterSize]);

/* Match complete IPv4 that is neither TCP/UDP nor one of the ported protocols,
 * for the independent statistic random cascade. */
void captureLinuxBuildOpaqueFilter(const uint8_t *ported_protocols, unsigned ported_count,
                                   char output[kCaptureLinuxSteeringFilterSize]);
