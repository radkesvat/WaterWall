#pragma once

#include "devices/device_opaque_flow_mode.h"
#include <stdint.h>

enum
{
    kCaptureLinuxSteeringMaxInstructions = 64,
    kCaptureLinuxSteeringFilterSize      = kCaptureLinuxSteeringMaxInstructions * 32 + 8
};

/* Build one complete iptables bpf --bytecode predicate. Positive queue_count
 * and lane_index below it are required. mode is resolved prefix/peer/spread.
 * Every deterministic valid IPv4 packet selects exactly one lane; spread sends
 * ordinary opaque packets to the separate random class. Every fragment uses
 * address/protocol fallback, including fragment zero. Invalid/unsupported input
 * selects lane zero for ordinary reader validation. Protocol exclusions remain
 * a separate match shared with NOTRACK. Stateful consumers establish ownership
 * independently after preceding packet transformations. */
void captureLinuxBuildSteeringFilter(uint16_t queue_count, uint16_t lane_index, device_opaque_flow_mode_t mode,
                                     char output[kCaptureLinuxSteeringFilterSize]);

/* Match complete non-TCP/UDP IPv4 for the independent statistic random cascade. */
void captureLinuxBuildOpaqueFilter(char output[kCaptureLinuxSteeringFilterSize]);
