#pragma once

#include "devices/device_lifecycle.h"

typedef device_lifecycle_state_t tun_lifecycle_state_t;

#define kTunLifecycleDown     kDeviceLifecycleDown
#define kTunLifecycleStarting kDeviceLifecycleStarting
#define kTunLifecycleUp       kDeviceLifecycleUp
#define kTunLifecycleStopping kDeviceLifecycleStopping
#define kTunLifecycleFailed   kDeviceLifecycleFailed

#define tunLifecycleIsActive                 deviceLifecycleIsActive
#define tunLifecycleLoad                     deviceLifecycleLoad
#define tunLifecycleTransitionDownToStarting deviceLifecycleTransitionDownToStarting
#define tunLifecycleTransitionStartingToUp   deviceLifecycleTransitionStartingToUp
#define tunLifecycleTransitionToFailed       deviceLifecycleTransitionToFailed
#define tunLifecycleTransitionToStopping     deviceLifecycleTransitionToStopping
#define tunLifecycleTransitionStoppingToDown deviceLifecycleTransitionStoppingToDown
