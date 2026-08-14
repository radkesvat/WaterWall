#pragma once

#include "devices/device_lifecycle.h"

typedef device_lifecycle_state_t raw_lifecycle_state_t;

#define kRawLifecycleDown     kDeviceLifecycleDown
#define kRawLifecycleStarting kDeviceLifecycleStarting
#define kRawLifecycleUp       kDeviceLifecycleUp
#define kRawLifecycleStopping kDeviceLifecycleStopping
#define kRawLifecycleFailed   kDeviceLifecycleFailed

#define rawLifecycleIsActive                 deviceLifecycleIsActive
#define rawLifecycleLoad                     deviceLifecycleLoad
#define rawLifecycleTransitionDownToStarting deviceLifecycleTransitionDownToStarting
#define rawLifecycleTransitionStartingToUp   deviceLifecycleTransitionStartingToUp
#define rawLifecycleTransitionToFailed       deviceLifecycleTransitionToFailed
#define rawLifecycleTransitionToStopping     deviceLifecycleTransitionToStopping
#define rawLifecycleTransitionStoppingToDown deviceLifecycleTransitionStoppingToDown
