#pragma once

typedef enum device_fragment_policy_e
{
    kDeviceFragmentPolicyUnset = 0,
    kDeviceFragmentReassemble,
    kDeviceFragmentPreserve
} device_fragment_policy_t;
