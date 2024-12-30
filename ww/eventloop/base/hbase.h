#ifndef HV_BASE_H_
#define HV_BASE_H_

#include "hexport.h"
#include "hplatform.h" // for bool
#include "hdef.h" // for printd

BEGIN_EXTERN_C

//--------------------alloc/free---------------------------
HV_EXPORT void* hv_malloc(size_t size);
HV_EXPORT void* hv_realloc(void* oldptr, size_t newsize, size_t oldsize);
HV_EXPORT void* hv_calloc(size_t nmemb, size_t size);
HV_EXPORT void* hv_zalloc(size_t size);
HV_EXPORT void  hv_free(void* ptr);

#define HV_ALLOC(ptr, size)\
    do {\
        *(void**)&(ptr) = hv_zalloc(size);\
        printd("alloc(%p, size=%llu)\tat [%s:%d:%s]\n", ptr, (unsigned long long)size, __FILE__, __LINE__, __FUNCTION__);\
    } while(0)

#define HV_ALLOC_SIZEOF(ptr)  HV_ALLOC(ptr, sizeof(*(ptr)))

#define HV_FREE(ptr)\
    do {\
        if (ptr) {\
            hv_free(ptr);\
            printd("memoryFree( %p )\tat [%s:%d:%s]\n", ptr, __FILE__, __LINE__, __FUNCTION__);\
            ptr = NULL;\
        }\
    } while(0)

#define STACK_OR_HEAP_ALLOC(ptr, size, stack_size)\
    unsigned char _stackbuf_[stack_size] = { 0 };\
    if ((size) > (stack_size)) {\
        HV_ALLOC(ptr, size);\
    } else {\
        *(unsigned char**)&(ptr) = _stackbuf_;\
    }

#define STACK_OR_HEAP_FREE(ptr)\
    if ((unsigned char*)(ptr) != _stackbuf_) {\
        HV_FREE(ptr);\
    }

#define HV_DEFAULT_STACKBUF_SIZE    1024
#define HV_STACK_ALLOC(ptr, size)   STACK_OR_HEAP_ALLOC(ptr, size, HV_DEFAULT_STACKBUF_SIZE)
#define HV_STACK_FREE(ptr)          STACK_OR_HEAP_FREE(ptr)

HV_EXPORT long hv_alloc_cnt(void);
HV_EXPORT long hv_free_cnt(void);
HV_INLINE void hv_memcheck(void) {
    printf("Memcheck => alloc:%ld free:%ld\n", hv_alloc_cnt(), hv_free_cnt());
}
#define HV_MEMCHECK    atexit(hv_memcheck);

//--------------------string-------------------------------
HV_EXPORT char* stringUpperCase(char* str);
HV_EXPORT char* stringLowerCase(char* str);
HV_EXPORT char* stringReverse(char* str);

HV_EXPORT bool stringStartsWith(const char* str, const char* start);
HV_EXPORT bool stringEndsWith(const char* str, const char* end);
HV_EXPORT bool stringContains(const char* str, const char* sub);
HV_EXPORT bool stringWildCardMatch(const char* str, const char* pattern);

// strncpy n = sizeof(dest_buf)-1
// stringCopyN n = sizeof(dest_buf)
HV_EXPORT char* stringCopyN(char* dest, const char* src, size_t n);

// strncat n = sizeof(dest_buf)-1-strlen(dest)
// stringCopyN n = sizeof(dest_buf)
HV_EXPORT char* stringCat(char* dest, const char* src, size_t n);

#if !HAVE_STRLCPY
#define strlcpy stringCopyN
#endif

#if !HAVE_STRLCAT
#define strlcat stringCat
#endif

HV_EXPORT char* stringChr(const char* s, char c, size_t n);

#define stringChrDot(str) strrchr(str, '.')
HV_EXPORT char* stringChrDir(const char* filepath);

// basename
HV_EXPORT const char* filePathBaseName(const char* filepath);
HV_EXPORT const char* filePathSuffixName(const char* filename);
// mkdir -p
HV_EXPORT int createDirIfNotExists(const char* dir);
// rmdir -p
HV_EXPORT int removeDirIfExists(const char* dir);
// path
HV_EXPORT bool dirExists(const char* path);
HV_EXPORT bool isDir(const char* path);
HV_EXPORT bool isFile(const char* path);
HV_EXPORT bool isLink(const char* path);
HV_EXPORT size_t getFileSize(const char* filepath);

HV_EXPORT char* getExecuteablePath(char* buf, int size);
HV_EXPORT char* getExecuteableDir(char* buf, int size);
HV_EXPORT char* getExecuteableFile(char* buf, int size);
HV_EXPORT char* getRunDir(char* buf, int size);

// random
HV_EXPORT int   randomRange(int min, int max);
HV_EXPORT char* randomString(char *buf, int len);

// 1 y on yes true enable => true
HV_EXPORT bool   stringRepresenstsTrue(const char* str);
// 1T2G3M4K5B => ?B
HV_EXPORT size_t stringToSize(const char* str);
// 1w2d3h4m5s => ?s
HV_EXPORT time_t stringToTime(const char* str);

// scheme:[//[user[:password]@]host[:port]][/path][?query][#fragment]
typedef enum {
    HV_URL_SCHEME,
    HV_URL_USERNAME,
    HV_URL_PASSWORD,
    HV_URL_HOST,
    HV_URL_PORT,
    HV_URL_PATH,
    HV_URL_QUERY,
    HV_URL_FRAGMENT,
    HV_URL_FIELD_NUM,
} hurl_field_e;

typedef struct hurl_s {
    struct {
        unsigned short off;
        unsigned short len;
    } fields[HV_URL_FIELD_NUM];
    unsigned short port;
} hurl_t;

HV_EXPORT int stringToUrl(hurl_t* stURL, const char* strURL);

END_EXTERN_C

#endif // HV_BASE_H_
