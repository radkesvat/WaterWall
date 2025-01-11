#include "werr.h"
#include "wplatform.h"
#include <string.h> // for strerror

// errcode => errmsg
const char* errorCodeToString(int err) {
    if (err > 0 && err <= SYS_NERR) {
#if defined(OS_UNIX)
        return strerror(err);
#else
        static _Thread_local char errmsg[100];
        strerror_s(errmsg, sizeof(errmsg), err);
        return errmsg;
#endif
    }

    switch (err) {
#define F(errcode, name, errmsg) \
    case errcode: return errmsg;
        FOREACH_ERR(F)
#undef F
    default: return "Undefined error";
    }
}
