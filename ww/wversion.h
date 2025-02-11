#ifndef WW_VERSION_H_
#define WW_VERSION_H_

#include "wlibc.h"

#include "wconfig.h"

#define WW_VERSION_STRING STRINGIFY(WW_VERSION_MAJOR) "." STRINGIFY(WW_VERSION_MINOR) "." STRINGIFY(WW_VERSION_PATCH)

#define WW_VERSION_NUMBER ((WW_VERSION_MAJOR << 16) | (WW_VERSION_MINOR << 8) | WW_VERSION_PATCH)

static inline const char *wwGetVersion(void)
{
    return WW_VERSION_STRING;
}

static inline const char *wwGetCompileVersion(void);

// 1.2.3.4 => 0x01020304
static inline int versionATOI(const char *str);

// 0x01020304 => 1.2.3.4
static inline void versionITOA(int hex, char *str);

#endif // WW_VERSION_H_
