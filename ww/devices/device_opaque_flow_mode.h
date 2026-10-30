#pragma once

/* Device receive policy for opaque IPv4 packets. Auto is a requested setting
 * only; resolve it at the tunnel layer before constructing/activating a reader. */
typedef enum device_opaque_flow_mode_e
{
    kDeviceOpaqueFlowPrefix = 0,
    kDeviceOpaqueFlowPeer,
    kDeviceOpaqueFlowSpread,
    kDeviceOpaqueFlowAuto
} device_opaque_flow_mode_t;

static inline const char *deviceOpaqueFlowModeName(device_opaque_flow_mode_t mode)
{
    switch (mode)
    {
    case kDeviceOpaqueFlowPrefix:
        return "prefix";
    case kDeviceOpaqueFlowPeer:
        return "peer";
    case kDeviceOpaqueFlowSpread:
        return "spread";
    case kDeviceOpaqueFlowAuto:
        return "auto";
    }
    return "invalid";
}
