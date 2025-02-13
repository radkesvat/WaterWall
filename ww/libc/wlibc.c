#include "wlibc.h"

#include "managers/memory_manager.h"

void initWLibc(void)
{
    memorymanagerInit();
}

//--------------------string-------------------------------

char *stringUpperCase(char *str)
{
    char *p = str;
    while (*p != '\0')
    {
        if (*p >= 'a' && *p <= 'z')
        {
            *p &= ~0x20;
        }
        ++p;
    }
    return str;
}

char *stringLowerCase(char *str)
{
    char *p = str;
    while (*p != '\0')
    {
        if (*p >= 'A' && *p <= 'Z')
        {
            *p |= 0x20;
        }
        ++p;
    }
    return str;
}

char *stringReverse(char *str)
{
    if (str == NULL)
        return NULL;
    char *b = str;
    char *e = str;
    while (*e)
    {
        ++e;
    }
    --e;
    char tmp;
    while (e > b)
    {
        tmp = *e;
        *e  = *b;
        *b  = tmp;
        --e;
        ++b;
    }
    return str;
}

char *stringConcat(const char *s1, const char *s2)
{
    char *result = memoryAllocate(stringLength(s1) + stringLength(s2) + 1); // +1 for the null-terminator
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

char *stringDuplicate(const char *src)
{
    if (src == NULL)
    {
        return NULL;
    }

    size_t length = stringLength(src) + 1;
    char  *dup    = (char *) memoryAllocate(length);
    if (dup == NULL)
    {
        return NULL;
    }
    memoryCopy(dup, src, length);
    return dup;
}
// n = sizeof(dest_buf)
#if ! HAVE_STRLCPY
char *stringCopyN(char *dest, const char *src, size_t n)
{
    assert(dest != NULL && src != NULL);
    char *ret = dest;
    while (*src != '\0' && --n > 0)
    {
        *dest++ = *src++;
    }
    *dest = '\0';
    return ret;
}
#endif

#if ! HAVE_STRLCAT

// n = sizeof(dest_buf)
char *stringCat(char *dest, const char *src, size_t n)
{
    assert(dest != NULL && src != NULL);
    char *ret = dest;
    while (*dest)
    {
        ++dest;
        --n;
    }
    while (*src != '\0' && --n > 0)
    {
        *dest++ = *src++;
    }
    *dest = '\0';
    return ret;
}

#endif

bool stringStartsWith(const char *str, const char *start)
{
    assert(str != NULL && start != NULL);
    while (*str && *start && *str == *start)
    {
        ++str;
        ++start;
    }
    return *start == '\0';
}

bool stringEndsWith(const char *str, const char *end)
{
    assert(str != NULL && end != NULL);
    int len1 = 0;
    int len2 = 0;
    while (*str)
    {
        ++str;
        ++len1;
    }
    while (*end)
    {
        ++end;
        ++len2;
    }
    if (len1 < len2)
        return false;
    while (len2-- > 0)
    {
        --str;
        --end;
        if (*str != *end)
        {
            return false;
        }
    }
    return true;
}

bool stringContains(const char *str, const char *sub)
{
    assert(str != NULL && sub != NULL);
    return strstr(str, sub) != NULL;
}

bool stringWildCardMatch(const char *str, const char *pattern)
{
    assert(str != NULL && pattern != NULL);
    bool match = false;
    while (*str && *pattern)
    {
        if (*pattern == '*')
        {
            match = stringEndsWith(str, pattern + 1);
            break;
        }
        else if (*str != *pattern)
        {
            match = false;
            break;
        }
        else
        {
            ++str;
            ++pattern;
        }
    }
    return match ? match : (*str == '\0' && *pattern == '\0');
}

char *stringNewWithoutSpace(const char *str)
{
    if (str == NULL)
    {
        return NULL;
    }

    int len = (int) stringLength(str);

    int new_len = 0;
    for (int i = 0; i < len; i++)
    {
        if (str[i] != ' ')
        {
            new_len++;
        }
    }

    char *result = (char *) memoryAllocate((size_t)(new_len + 1) * sizeof(char));
    if (result == NULL)
    {
        return NULL;
    }

    int j = 0;
    for (int i = 0; i < len; i++)
    {
        if (str[i] != ' ')
        {
            result[j++] = str[i];
        }
    }

    result[new_len] = '\0';

    return result;
}

char *stringChrLen(const char *s, char c, size_t n)
{
    assert(s != NULL);
    const char *p = s;
    while (*p != '\0' && n-- > 0)
    {
        if (*p == c)
            return (char *) p;
        ++p;
    }
    return NULL;
}

//--------------------file-------------------------------

char *readFile(const char *const path)
{
    FILE *f = fopen(path, "rb");

    if (! f)
    {
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET); /* same as rewind(f); */

    char  *string = memoryAllocate((size_t) (fsize + 1));
    size_t count  = fread(string, (size_t) fsize, 1, f);
    if (count == 0)
    {
        memoryFree(string);
        return NULL;
    }
    fclose(f);

    string[fsize] = 0;
    return string;
}

bool writeFile(const char *const path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");

    if (! f)
    {
        return false;
    }

    fseek(f, 0, SEEK_SET);

    if (fwrite(data, len, 1, f) != len)
    {
        fclose(f);
        return false;
    }
    fclose(f);
    return true;
}

char *stringChrDir(const char *filepath)
{
    char *p = (char *) filepath;
    while (*p)
        ++p;
    while (--p >= filepath)
    {
#ifdef OS_WIN
        if (*p == '/' || *p == '\\')
#else
        if (*p == '/')
#endif
            return p;
    }
    return NULL;
}

const char *filePathBaseName(const char *filepath)
{
    const char *pos = stringChrDir(filepath);
    return pos ? pos + 1 : filepath;
}

const char *filePathSuffixName(const char *filename)
{
    const char *pos = stringChrDot(filename);
    return pos ? pos + 1 : "";
}

int createDirIfNotExists(const char *dir)
{
    if (access(dir, 0) == 0)
    {
        return EEXIST;
    }
    char tmp[MAX_PATH] = {0};
    stringCopyN(tmp, dir, sizeof(tmp));
    char *p     = tmp;
    char  delim = '/';
    while (*p)
    {
#ifdef OS_WIN
        if (*p == '/' || *p == '\\')
        {
            delim = *p;
#else
        if (*p == '/')
        {
#endif
            *p = '\0';
            hv_mkdir(tmp);
            *p = delim;
        }
        ++p;
    }
    if (hv_mkdir(tmp) != 0)
    {
        return EPERM;
    }
    return 0;
}

int removeDirIfExists(const char *dir)
{
    if (access(dir, 0) != 0)
    {
        return ENOENT;
    }
    if (rmdir(dir) != 0)
    {
        return EPERM;
    }
    char tmp[MAX_PATH] = {0};
    stringCopyN(tmp, dir, sizeof(tmp));
    char *p = tmp;
    while (*p)
        ++p;
    while (--p >= tmp)
    {
#ifdef OS_WIN
        if (*p == '/' || *p == '\\')
        {
#else
        if (*p == '/')
        {
#endif
            *p = '\0';
            if (rmdir(tmp) != 0)
            {
                return 0;
            }
        }
    }
    return 0;
}

bool dirExists(const char *path)
{
    return access(path, 0) == 0;
}

bool isDir(const char *path)
{
    if (access(path, 0) != 0)
        return false;
    struct stat st;
    memorySet(&st, 0, sizeof(st));
    stat(path, &st);
    return S_ISDIR(st.st_mode);
}

bool isFile(const char *path)
{
    if (access(path, 0) != 0)
        return false;
    struct stat st;
    memorySet(&st, 0, sizeof(st));
    stat(path, &st);
    return S_ISREG(st.st_mode);
}

bool isLink(const char *path)
{
#ifdef OS_WIN
    return isDir(path) && (GetFileAttributes(path) & FILE_ATTRIBUTE_REPARSE_POINT);
#else
    if (access(path, 0) != 0)
        return false;
    struct stat st;
    memorySet(&st, 0, sizeof(st));
    lstat(path, &st);
    return S_ISLNK(st.st_mode);
#endif
}

size_t getFileSize(const char *filepath)
{
    struct stat st;
    memorySet(&st, 0, sizeof(st));
    stat(filepath, &st);
    return (size_t) st.st_size;
}
#if defined(OS_DARWIN) // i cant believe mac has no header for this, afaik
int _NSGetExecutablePath(char *buf, uint32_t *bufsize);
#endif

char *getExecuteablePath(char *buf, int size)
{
#ifdef OS_WIN
    GetModuleFileName(NULL, buf, size);
#elif defined(OS_DARWIN)
    _NSGetExecutablePath(buf, (uint32_t *) &size);
#elif defined(OS_UNIX)
    if (readlink("/proc/self/exe", buf, (size_t) size) == -1)
    {
        return NULL;
    }

#endif
    return buf;
}

char *getExecuteableDir(char *buf, int size)
{
    char filepath[MAX_PATH] = {0};
    getExecuteablePath(filepath, sizeof(filepath));
    char *pos = stringChrDir(filepath);
    if (pos)
    {
        *pos = '\0';

#if defined(OS_UNIX)
        strncpy(buf, filepath, (long unsigned int) size);
#else
        strncpy_s(buf, ((size_t)size) + 1, filepath, (size_t)size);
#endif
    }
    return buf;
}

char *getExecuteableFile(char *buf, int size)
{
    char filepath[MAX_PATH] = {0};
    getExecuteablePath(filepath, sizeof(filepath));
    char *pos = stringChrDir(filepath);
    if (pos)
    {

#if defined(OS_UNIX)
        strncpy(buf, pos + 1, (unsigned long) size);
#else
        strncpy_s(buf, ((size_t)size) + 1, pos + 1, (size_t)size);
#endif
    }
    return buf;
}

char *getRunDir(char *buf, int size)
{
    return getcwd(buf, (size_t)size); // Or, if getcwd expects an int, use: (int)size
}

int randomRange(int min, int max)
{
    static int s_seed = 0;
    assert(max > min);

    if (s_seed == 0)
    {
        s_seed = (int) time(NULL);
        srand((unsigned int) s_seed);
    }

    int _rand = rand();
    _rand     = min + (int) ((double) ((double) (max) - (min) + 1.0) * ((_rand) / ((RAND_MAX) + 1.0)));
    return _rand;
}

char *randomString(char *buf, int len)
{
    static char s_characters[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
        'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
        'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    };
    int i = 0;
    for (; i < len; i++)
    {
        buf[i] = s_characters[randomRange(0, sizeof(s_characters) - 1)];
    }
    buf[i] = '\0';
    return buf;
}

bool stringRepresenstsTrue(const char *str)
{
    if (str == NULL)
        return false;
    int len = (int) stringLength(str);
    if (len == 0)
        return false;
    switch (len)
    {
    case 1:
        return *str == '1' || *str == 'y' || *str == 'Y';
    case 2:
        return stricmp(str, "on") == 0;
    case 3:
        return stricmp(str, "yes") == 0;
    case 4:
        return stricmp(str, "true") == 0;
    case 6:
        return stricmp(str, "enable") == 0;
    default:
        return false;
    }
}

size_t stringToSize(const char *str)
{
    size_t      size = 0;
    uint64_t    n    = 0;
    const char *p    = str;
    char        c;
    while ((c = *p) != '\0')
    {
        if (c >= '0' && c <= '9')
        {
            n = n * 10 + (uint64_t) (c - '0');
        }
        else
        {
            switch (c)
            {
            case 'K':
            case 'k':
                n <<= 10;
                break;
            case 'M':
            case 'm':
                n <<= 20;
                break;
            case 'G':
            case 'g':
                n <<= 30;
                break;
            case 'T':
            case 't':
                n <<= 40;
                break;
            default:
                break;
            }
            size += n;
            n = 0;
        }
        ++p;
    }
    return (size_t)(size + n);
}

time_t stringToTime(const char *str)
{
    time_t      time = 0, n = 0;
    const char *p = str;
    char        c;
    while ((c = *p) != '\0')
    {
        if (c >= '0' && c <= '9')
        {
            n = n * 10 + c - '0';
        }
        else
        {
            switch (c)
            {
            case 's':
                break;
            case 'm':
                n *= 60;
                break;
            case 'h':
                n *= 60 * 60;
                break;
            case 'd':
                n *= 24 * 60 * 60;
                break;
            case 'w':
                n *= 7 * 24 * 60 * 60;
                break;
            default:
                break;
            }
            time += n;
            n = 0;
        }
        ++p;
    }
    return time + n;
}

int stringToUrl(hurl_t *stURL, const char *strURL)
{
    if (stURL == NULL || strURL == NULL)
        return -1;
    memorySet(stURL, 0, sizeof(hurl_t));
    const char *begin = strURL;
    const char *end   = strURL;
    while (*end != '\0')
        ++end;
    if (end - begin > 65535)
        return -2;
    // scheme://
    const char *sp = strURL;
    const char *ep = strstr(sp, "://");
    if (ep)
    {
        // stURL->fields[WW_URL_SCHEME].off = sp - begin;
        stURL->fields[WW_URL_SCHEME].len = (unsigned short) (ep - sp);
        sp                               = ep + 3;
    }
    // user:pswd@host:port
    ep = strchr(sp, '/');
    if (ep == NULL)
        ep = end;
    const char *user = sp;
    const char *host = sp;
    const char *pos  = stringChrLen(sp, '@', (size_t) (ep - sp));
    if (pos)
    {
        // user:pswd
        const char *pswd = stringChrLen(user, ':', (size_t) (pos - user));
        if (pswd)
        {
            stURL->fields[WW_URL_PASSWORD].off = (unsigned short) (pswd + 1 - begin);
            stURL->fields[WW_URL_PASSWORD].len = (unsigned short) (pos - pswd - 1);
        }
        else
        {
            pswd = pos;
        }
        stURL->fields[WW_URL_USERNAME].off = (unsigned short) (user - begin);
        stURL->fields[WW_URL_USERNAME].len = (unsigned short) (pswd - user);
        // @
        host = pos + 1;
    }
    // port
    const char *port = stringChrLen(host, ':', (size_t) (ep - host));
    if (port)
    {
        stURL->fields[WW_URL_PORT].off = (unsigned short) (port + 1 - begin);
        stURL->fields[WW_URL_PORT].len = (unsigned short) (ep - port - 1);
        // atoi
        for (unsigned short i = 1; i <= stURL->fields[WW_URL_PORT].len; ++i)
        {
            stURL->port = (unsigned short) ((stURL->port * 10) + (port[i] - '0'));
        }
    }
    else
    {
        port = ep;
        // set default port
        stURL->port = 80;
        if (stURL->fields[WW_URL_SCHEME].len > 0)
        {
            if (strncmp(strURL, "https://", 8) == 0)
            {
                stURL->port = 443;
            }
        }
    }
    // host
    stURL->fields[WW_URL_HOST].off = (unsigned short) (host - begin);
    stURL->fields[WW_URL_HOST].len = (unsigned short) (port - host);
    if (ep == end)
        return 0;
    // /path
    sp = ep;
    ep = strchr(sp, '?');
    if (ep == NULL)
        ep = end;
    stURL->fields[WW_URL_PATH].off = (unsigned short) (sp - begin);
    stURL->fields[WW_URL_PATH].len = (unsigned short) (ep - sp);
    if (ep == end)
        return 0;
    // ?query
    sp = ep + 1;
    ep = strchr(sp, '#');
    if (ep == NULL)
        ep = end;
    stURL->fields[WW_URL_QUERY].off = (unsigned short) (sp - begin);
    stURL->fields[WW_URL_QUERY].len = (unsigned short) (ep - sp);
    if (ep == end)
        return 0;
    // #fragment
    sp                                 = ep + 1;
    ep                                 = end;
    stURL->fields[WW_URL_FRAGMENT].off = (unsigned short) (sp - begin);
    stURL->fields[WW_URL_FRAGMENT].len = (unsigned short) (ep - sp);
    return 0;
}

/* This function is only required to prevent arch.h including stdio.h
 * (which it does if LWIP_PLATFORM_ASSERT is undefined)
 */
void lwip_example_app_platform_assert(const char *msg, int line, const char *file)
{
    printf("LWIP: Assertion \"%s\" failed at line %d in %s\n", msg, line, file);
    fflush(NULL);
    abort();
}
