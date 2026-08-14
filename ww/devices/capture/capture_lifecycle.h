#pragma once

#include "devices/device_lifecycle.h"

typedef device_lifecycle_state_t capture_lifecycle_state_t;

#define kCaptureLifecycleDown     kDeviceLifecycleDown
#define kCaptureLifecycleStarting kDeviceLifecycleStarting
#define kCaptureLifecycleUp       kDeviceLifecycleUp
#define kCaptureLifecycleStopping kDeviceLifecycleStopping
#define kCaptureLifecycleFailed   kDeviceLifecycleFailed

#define captureLifecycleIsActive                 deviceLifecycleIsActive
#define captureLifecycleLoad                     deviceLifecycleLoad
#define captureLifecycleTransitionDownToStarting deviceLifecycleTransitionDownToStarting
#define captureLifecycleTransitionStartingToUp   deviceLifecycleTransitionStartingToUp
#define captureLifecycleTransitionToFailed       deviceLifecycleTransitionToFailed
#define captureLifecycleTransitionToStopping     deviceLifecycleTransitionToStopping
#define captureLifecycleTransitionStoppingToDown deviceLifecycleTransitionStoppingToDown
