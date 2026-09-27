#pragma once
#include "capture_linux_private.h"

bool     capturedeviceChooseQueueNumber(uint16_t *selected);
uint32_t capturedevicePendingRangeCount(const capture_device_t *cdev);
bool     capturedeviceRemoveInstalledRules(capture_device_t *cdev);
char    *capturedeviceFormatCidrString(const ipmask_t *range);
void     capturedeviceFreeCidrs(char **cidrs, uint32_t count);
bool     capturedeviceInstallRuleKind(capture_device_t *cdev, bool notrack);
