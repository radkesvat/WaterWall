#ifndef HV_VERSION_H_
#define HV_VERSION_H_

#include "hexport.h"
#include "hdef.h"

BEGIN_EXTERN_C

#define HV_VERSION_MAJOR    1
#define HV_VERSION_MINOR    3
#define HV_VERSION_PATCH    2

#define HV_VERSION_STRING   STRINGIFY(HV_VERSION_MAJOR) "." \
                            STRINGIFY(HV_VERSION_MINOR) "." \
                            STRINGIFY(HV_VERSION_PATCH)

#define HV_VERSION_NUMBER   ((HV_VERSION_MAJOR << 16) | (HV_VERSION_MINOR << 8) | HV_VERSION_PATCH)


HV_INLINE const char* wwVersion(void) {
    return HV_VERSION_STRING;
}

HV_EXPORT const char* wwCompileVersion(void);

// 1.2.3.4 => 0x01020304
HV_EXPORT int versionATOI(const char* str);

// 0x01020304 => 1.2.3.4
HV_EXPORT void versionITOA(int hex, char* str);

END_EXTERN_C

#endif // HV_VERSION_H_
