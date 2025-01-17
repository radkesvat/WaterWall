#pragma once

#include "wplatform.h"
#include "wtime.h"

#include "watomic.h"
#include "wdef.h"
#include "wendian.h"
#include "werr.h"
#include "wexport.h"
#include "wfrand.h"
#include "whash.h"
#include "wmath.h"

void initWLibc(void);

//--------------------Memory-------------------------------

struct dedicated_memory_s;
typedef struct dedicated_memory_s dedicated_memory_t;

void *memoryAllocate(size_t size);
void *memoryReAllocate(void *ptr, size_t size);
void  memoryFree(void *ptr);

void *memoryDedicatedAllocate(dedicated_memory_t *dm, size_t size);
void *memoryDedicatedReallocate(dedicated_memory_t *dm, void *ptr, size_t size);
void  memoryDedicatedFree(dedicated_memory_t *dm, void *ptr);



void memoryCopy128(uint8_t *__restrict _dest, const uint8_t *__restrict _src, intmax_t n);

//--------------------string-------------------------------

#ifndef STRINGIFY
#define STRINGIFY(x) #x
#endif
#define TOSTRING(x) STRINGIFY(x)

WW_EXPORT char *stringUpperCase(char *str);
WW_EXPORT char *stringLowerCase(char *str);
WW_EXPORT char *stringReverse(char *str);
char           *stringDuplicate(const char *src);
char           *stringConcat(const char *s1, const char *s2);

WW_EXPORT bool stringStartsWith(const char *str, const char *start);
WW_EXPORT bool stringEndsWith(const char *str, const char *end);
WW_EXPORT bool stringContains(const char *str, const char *sub);
WW_EXPORT bool stringWildCardMatch(const char *str, const char *pattern);

// strncpy n = sizeof(dest_buf)-1
// stringCopyN n = sizeof(dest_buf)
WW_EXPORT char *stringCopyN(char *dest, const char *src, size_t n);

// strncat n = sizeof(dest_buf)-1-strlen(dest)
// stringCopyN n = sizeof(dest_buf)
WW_EXPORT char *stringCat(char *dest, const char *src, size_t n);

#if ! HAVE_STRLCPY
#define stringCopyN strlcpy
#endif

#if ! HAVE_STRLCAT
#define stringCat strlcat
#endif

WW_EXPORT char *stringChr(const char *s, char c, size_t n);

#define stringChrDot(str) strrchr(str, '.')
WW_EXPORT char *stringChrDir(const char *filepath);

//--------------------file-------------------------------

char *readFile(const char *path);
bool  writeFile(const char *path, const char *data, size_t len);

// basename
WW_EXPORT const char *filePathBaseName(const char *filepath);
WW_EXPORT const char *filePathSuffixName(const char *filename);
// mkdir -p
WW_EXPORT int createDirIfNotExists(const char *dir);
// rmdir -p
WW_EXPORT int removeDirIfExists(const char *dir);
// path
WW_EXPORT bool   dirExists(const char *path);
WW_EXPORT bool   isDir(const char *path);
WW_EXPORT bool   isFile(const char *path);
WW_EXPORT bool   isLink(const char *path);
WW_EXPORT size_t getFileSize(const char *filepath);

WW_EXPORT char *getExecuteablePath(char *buf, int size);
WW_EXPORT char *getExecuteableDir(char *buf, int size);
WW_EXPORT char *getExecuteableFile(char *buf, int size);
WW_EXPORT char *getRunDir(char *buf, int size);

// random
WW_EXPORT int   randomRange(int min, int max);
WW_EXPORT char *randomString(char *buf, int len);

// 1 y on yes true enable => true
WW_EXPORT bool stringRepresenstsTrue(const char *str);
// 1T2G3M4K5B => ?B
WW_EXPORT size_t stringToSize(const char *str);
// 1w2d3h4m5s => ?s
WW_EXPORT time_t stringToTime(const char *str);

// scheme:[//[user[:password]@]host[:port]][/path][?query][#fragment]
typedef enum
{
    WW_URL_SCHEME,
    WW_URL_USERNAME,
    WW_URL_PASSWORD,
    WW_URL_HOST,
    WW_URL_PORT,
    WW_URL_PATH,
    WW_URL_QUERY,
    WW_URL_FRAGMENT,
    WW_URL_FIELD_NUM,
} hurl_field_e;

typedef struct hurl_s
{
    struct
    {
        unsigned short off;
        unsigned short len;
    } fields[WW_URL_FIELD_NUM];
    unsigned short port;
} hurl_t;

WW_EXPORT int stringToUrl(hurl_t *stURL, const char *strURL);

//-------------------------prints----------------------------------
#define printError perror
