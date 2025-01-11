#ifndef WW_VERSION_H_
#define WW_VERSION_H_

#include "wexport.h"
#include "wdef.h"



#define WW_VERSION_MAJOR    1
#define WW_VERSION_MINOR    3
#define WW_VERSION_PATCH    2

#define WW_VERSION_STRING   STRINGIFY(WW_VERSION_MAJOR) "." \
                            STRINGIFY(WW_VERSION_MINOR) "." \
                            STRINGIFY(WW_VERSION_PATCH)

#define WW_VERSION_NUMBER   ((WW_VERSION_MAJOR << 16) | (WW_VERSION_MINOR << 8) | WW_VERSION_PATCH)


WW_INLINE const char* wwVersion(void) {
    return WW_VERSION_STRING;
}

WW_EXPORT const char* wwCompileVersion(void);

// 1.2.3.4 => 0x01020304
WW_EXPORT int versionATOI(const char* str);

// 0x01020304 => 1.2.3.4
WW_EXPORT void versionITOA(int hex, char* str);


#endif // WW_VERSION_H_
