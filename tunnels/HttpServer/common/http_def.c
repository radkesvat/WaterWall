#include "http_def.h"

#include <string.h>

static int strstartswith(const char* str, const char* start) {
    while (*str && *start && *str == *start) {
        ++str;
        ++start;
    }
    return *start == '\0';
}

const char* httpStatusStr(enum http_status status) {
    switch (status) {
#define XX(num, name, string) case kHttpStatus##name: return #string;
    HTTP_STATUS_MAP(XX)
#undef XX
    default: return "<unknown>";
    }
}


const char* httpMethodStr(enum http_method method) {
    switch (method) {
#define XX(num, name, string) case kHttp##name: return #string;
    HTTP_METHOD_MAP(XX)
#undef XX
    default: return "<unknown>";
    }
}

const char* httpContentTypeStr(enum http_content_type type) {
    switch (type) {
#define XX(name, string, suffix) case k##name: return #string;
    HTTP_CONTENT_TYPE_MAP(XX)
#undef XX
    default: return "<unknown>";
    }
}

//NOLINTBEGIN
enum http_status httpStatusEnum(const char* str) {
#define XX(num, name, string) \
    if (strcmp(str, #string) == 0) { \
        return kHttpStatus##name; \
    }
    HTTP_STATUS_MAP(XX)
#undef XX
    return kHttpCustomStatus;
}

enum http_method httpMethodEnum(const char* str) {
#define XX(num, name, string) \
    if (strcmp(str, #string) == 0) { \
        return kHttp##name; \
    }
    HTTP_METHOD_MAP(XX)
#undef XX
    return kHttpCustomMethod;
}

enum http_content_type httpContentTypeEnum(const char* str) {
    if (!str || !*str) {
        return kContentTypeNone;
    }
#define XX(name, string, suffix) \
    if (strstartswith(str, #string)) { \
        return k##name; \
    }
    HTTP_CONTENT_TYPE_MAP(XX)
#undef XX
    return kContentTypeUndefined;
}

const char* httpContentTypeSuffix(enum http_content_type type) {
    switch (type) {
#define XX(name, string, suffix) case k##name: return #suffix;
    HTTP_CONTENT_TYPE_MAP(XX)
#undef XX
    default: return "<unknown>";
    }
}

const char* httpContentTypeStrBySuffix(const char* str) {
    if (!str || !*str) {
        return "";
    }
#define XX(name, string, suffix) \
    if (strcmp(str, #suffix) == 0) { \
        return #string; \
    }
    HTTP_CONTENT_TYPE_MAP(XX)
#undef XX
    return "";
}

enum http_content_type httpContentTypeEnumBySuffix(const char* str) {
    if (!str || !*str) {
        return kContentTypeNone;
    }
#define XX(name, string, suffix) \
    if (strcmp(str, #suffix) == 0) { \
        return k##name; \
    }
    HTTP_CONTENT_TYPE_MAP(XX)
#undef XX
    return kContentTypeUndefined;
}
//NOLINTEND
