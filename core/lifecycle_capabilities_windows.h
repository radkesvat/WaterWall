#pragma once
#include "startup_windows.h"
#include <stdbool.h>

/* Check object type and existing access without consuming/signaling a capability.
 * DuplicateHandle alone is not validation: it can grant additional access. */
bool waterwallCapabilityValidate(HANDLE handle, const wchar_t *type, ACCESS_MASK access);
