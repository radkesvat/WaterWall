/* Linux-only implementation included by wsysinfo.c. */

#include <sys/personality.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>

enum
{
    kSystemMemoryLinuxCgroupTextCapacity    = 64U * 1024U,
    kSystemMemoryLinuxMountinfoCapacity     = 1024U * 1024U,
    kSystemMemoryLinuxMountinfoLineCapacity = (2U * kSystemMemoryLinuxPathCapacity) + 512U,
};

typedef struct linux_memory_provider_state_s
{
    char                             *leaf_path;
    char                             *boundary_path;
    uint64_t                          last_discovery_ms;
    bool                              discovery_attempted;
    system_memory_linux_cgroup_kind_t kind;
    system_memory_linux_resolution_t  metadata;
    system_memory_linux_io_t          io;
} linux_memory_provider_state_t;

typedef int (*system_memory_linux_personality_fn)(void *userdata, unsigned long personality_value);
typedef int (*system_memory_linux_uname_machine_fn)(void *userdata, char *machine, size_t capacity);

typedef struct system_memory_linux_kernel_ops_s
{
    system_memory_linux_personality_fn   personality;
    system_memory_linux_uname_machine_fn uname_machine;
    void                                *userdata;
} system_memory_linux_kernel_ops_t;

static system_memory_linux_kernel_long_width_t systemMemoryLinuxClassifyNativeMachine(const char *machine)
{
    static const char *const kernel_64_names[] = {"x86_64", "aarch64"};
    static const char *const kernel_32_names[] = {
        "i386",
        "i486",
        "i586",
        "i686",
        "arm",
        "armv6l",
        "armv7l",
        "armv8l",
    };

    if (machine == NULL || *machine == '\0')
    {
        return kSystemMemoryLinuxKernelLongUnknown;
    }
    for (size_t index = 0; index < ARRAY_SIZE(kernel_64_names); ++index)
    {
        if (strcmp(machine, kernel_64_names[index]) == 0)
        {
            return kSystemMemoryLinuxKernelLong64;
        }
    }
    for (size_t index = 0; index < ARRAY_SIZE(kernel_32_names); ++index)
    {
        if (strcmp(machine, kernel_32_names[index]) == 0)
        {
            return kSystemMemoryLinuxKernelLong32;
        }
    }
    return kSystemMemoryLinuxKernelLongUnknown;
}

static system_memory_linux_kernel_long_width_t systemMemoryLinuxDetectKernelLongWidth(
    size_t userspace_long_size, const system_memory_linux_kernel_ops_t *ops)
{
    if (userspace_long_size == 8U)
    {
        return kSystemMemoryLinuxKernelLong64;
    }
    if (userspace_long_size != 4U || ops == NULL || ops->personality == NULL || ops->uname_machine == NULL)
    {
        return kSystemMemoryLinuxKernelLongUnknown;
    }

    const int original_result = ops->personality(ops->userdata, UINT32_MAX);
    if (original_result < 0)
    {
        return kSystemMemoryLinuxKernelLongUnknown;
    }
    const unsigned long original_personality = (unsigned int) original_result;
    const unsigned long native_personality =
        (original_personality & ~((unsigned long) PER_MASK)) | (unsigned long) PER_LINUX;
    const int switch_previous = ops->personality(ops->userdata, native_personality);
    if (switch_previous < 0)
    {
        return kSystemMemoryLinuxKernelLongUnknown;
    }

    system_memory_linux_kernel_long_width_t detected = kSystemMemoryLinuxKernelLongUnknown;
    if ((unsigned long) (unsigned int) switch_previous == original_personality)
    {
        char machine[256];
        if (ops->uname_machine(ops->userdata, machine, sizeof(machine)) == 0)
        {
            detected = systemMemoryLinuxClassifyNativeMachine(machine);
        }
    }

    const int restore_previous = ops->personality(ops->userdata, original_personality);
    if (restore_previous < 0 || (unsigned long) (unsigned int) restore_previous != native_personality)
    {
        return kSystemMemoryLinuxKernelLongUnknown;
    }
    return detected;
}

static bool systemMemoryLinuxV1Sentinels(uint64_t base_page_size_bytes, uint64_t *sentinel_32, uint64_t *sentinel_64)
{
    if (base_page_size_bytes == 0 || (base_page_size_bytes & (base_page_size_bytes - 1U)) != 0 ||
        base_page_size_bytes > UINT64_MAX / (uint64_t) INT32_MAX || sentinel_32 == NULL || sentinel_64 == NULL)
    {
        return false;
    }

    *sentinel_32            = (uint64_t) INT32_MAX * base_page_size_bytes;
    const uint64_t pages_64 = (uint64_t) INT64_MAX / base_page_size_bytes;
    if (pages_64 == 0 || pages_64 > UINT64_MAX / base_page_size_bytes)
    {
        return false;
    }
    *sentinel_64 = pages_64 * base_page_size_bytes;
    return true;
}

static system_memory_linux_v1_limit_class_t systemMemoryLinuxClassifyV1Limit(
    uint64_t limit_bytes, system_memory_linux_kernel_long_width_t kernel_long_width, uint64_t base_page_size_bytes)
{
    uint64_t sentinel_32 = 0;
    uint64_t sentinel_64 = 0;
    if (! systemMemoryLinuxV1Sentinels(base_page_size_bytes, &sentinel_32, &sentinel_64))
    {
        return kSystemMemoryLinuxV1LimitUnavailable;
    }

    switch (kernel_long_width)
    {
    case kSystemMemoryLinuxKernelLong32:
        if (limit_bytes == sentinel_32)
        {
            return kSystemMemoryLinuxV1LimitUnbounded;
        }
        return limit_bytes < sentinel_32 ? kSystemMemoryLinuxV1LimitFinite : kSystemMemoryLinuxV1LimitUnavailable;
    case kSystemMemoryLinuxKernelLong64:
        if (limit_bytes == sentinel_64)
        {
            return kSystemMemoryLinuxV1LimitUnbounded;
        }
        return limit_bytes < sentinel_64 ? kSystemMemoryLinuxV1LimitFinite : kSystemMemoryLinuxV1LimitUnavailable;
    case kSystemMemoryLinuxKernelLongUnknown:
        if (limit_bytes == sentinel_32 || limit_bytes == sentinel_64 || limit_bytes > sentinel_64)
        {
            return kSystemMemoryLinuxV1LimitUnavailable;
        }
        return kSystemMemoryLinuxV1LimitFinite;
    default:
        return kSystemMemoryLinuxV1LimitUnavailable;
    }
}

#ifdef WW_SYSINFO_TEST_SEAM
system_memory_linux_kernel_long_width_t systemMemoryLinuxTestDetectKernelLongWidth(
    size_t userspace_long_size, const system_memory_linux_kernel_test_ops_t *test_ops)
{
    if (test_ops == NULL)
    {
        return systemMemoryLinuxDetectKernelLongWidth(userspace_long_size, NULL);
    }
    const system_memory_linux_kernel_ops_t ops = {
        .personality   = test_ops->personality,
        .uname_machine = test_ops->uname_machine,
        .userdata      = test_ops->userdata,
    };
    return systemMemoryLinuxDetectKernelLongWidth(userspace_long_size, &ops);
}

system_memory_linux_v1_limit_class_t systemMemoryLinuxTestClassifyV1Limit(
    uint64_t limit_bytes, system_memory_linux_kernel_long_width_t kernel_long_width, uint64_t base_page_size_bytes)
{
    return systemMemoryLinuxClassifyV1Limit(limit_bytes, kernel_long_width, base_page_size_bytes);
}
#endif

typedef struct system_memory_linux_membership_s
{
    char                              path[kSystemMemoryLinuxPathCapacity];
    system_memory_linux_cgroup_kind_t kind;
} system_memory_linux_membership_t;

typedef struct system_memory_linux_mount_s
{
    char     root[kSystemMemoryLinuxPathCapacity];
    char     mount_point[kSystemMemoryLinuxPathCapacity];
    uint32_t device_major;
    uint32_t device_minor;
    bool     cgroup_v2;
    bool     cgroup_v1_memory;
} system_memory_linux_mount_t;

typedef struct system_memory_linux_candidate_s
{
    char                              leaf[kSystemMemoryLinuxPathCapacity];
    char                              boundary[kSystemMemoryLinuxPathCapacity];
    char                              root[kSystemMemoryLinuxPathCapacity];
    system_memory_linux_fs_identity_t leaf_identity;
    system_memory_linux_fs_identity_t boundary_identity;
    uint32_t                          device_major;
    uint32_t                          device_minor;
    uint8_t                           depth;
    bool                              present;
} system_memory_linux_candidate_t;

static bool systemMemoryLinuxParseU32(const char *value, uint32_t *parsed)
{
    if (value == NULL || parsed == NULL || *value == '\0')
    {
        return false;
    }
    uint64_t result = 0;
    for (const unsigned char *cursor = (const unsigned char *) value; *cursor != '\0'; ++cursor)
    {
        if (! isdigit(*cursor))
        {
            return false;
        }
        result = (result * 10U) + (uint32_t) (*cursor - '0');
        if (result > UINT32_MAX)
        {
            return false;
        }
    }
    *parsed = (uint32_t) result;
    return true;
}

static bool systemMemoryLinuxTokenIsUnsigned(const char *token)
{
    uint32_t ignored = 0;
    return systemMemoryLinuxParseU32(token, &ignored);
}

static bool systemMemoryLinuxParseDevice(char *token, uint32_t *device_major, uint32_t *device_minor)
{
    if (token == NULL)
    {
        return false;
    }
    char *colon = strchr(token, ':');
    if (colon == NULL || colon == token || colon[1] == '\0' || strchr(colon + 1U, ':') != NULL)
    {
        return false;
    }
    *colon = '\0';
    return systemMemoryLinuxParseU32(token, device_major) && systemMemoryLinuxParseU32(colon + 1U, device_minor);
}

static bool systemMemoryLinuxCsvContains(const char *csv, const char *name)
{
    const size_t name_len = strlen(name);
    const char  *cursor   = csv;
    while (cursor != NULL && *cursor != '\0')
    {
        const char  *comma  = strchr(cursor, ',');
        const size_t length = comma == NULL ? strlen(cursor) : (size_t) (comma - cursor);
        if (length == name_len && strncmp(cursor, name, name_len) == 0)
        {
            return true;
        }
        cursor = comma == NULL ? NULL : comma + 1U;
    }
    return false;
}

static bool systemMemoryLinuxControllersAreValid(const char *controllers)
{
    if (controllers == NULL || *controllers == '\0')
    {
        return true;
    }

    const char *cursor = controllers;
    while (*cursor != '\0')
    {
        const char *comma = strchr(cursor, ',');
        const char *end   = comma == NULL ? cursor + strlen(cursor) : comma;
        if (end == cursor)
        {
            return false;
        }
        for (const unsigned char *value = (const unsigned char *) cursor; value < (const unsigned char *) end; ++value)
        {
            if (! (isalnum(*value) || *value == '_' || *value == '-' || *value == '.' || *value == '='))
            {
                return false;
            }
        }
        if (comma == NULL)
        {
            return true;
        }
        if (comma[1] == '\0')
        {
            return false;
        }
        cursor = comma + 1U;
    }
    return true;
}

static bool systemMemoryLinuxPathIsCanonical(const char *path)
{
    if (path == NULL || path[0] != '/')
    {
        return false;
    }
    if (path[1] == '\0')
    {
        return true;
    }

    const char *component = path + 1U;
    while (*component != '\0')
    {
        const char  *separator = strchr(component, '/');
        const size_t length    = separator == NULL ? strlen(component) : (size_t) (separator - component);
        if (length == 0 || (length == 1U && component[0] == '.') ||
            (length == 2U && component[0] == '.' && component[1] == '.'))
        {
            return false;
        }
        if (separator == NULL)
        {
            return true;
        }
        component = separator + 1U;
    }
    return false;
}

static bool systemMemoryLinuxPathComponentPrefixes(const char *prefix, const char *path)
{
    if (! systemMemoryLinuxPathIsCanonical(prefix) || ! systemMemoryLinuxPathIsCanonical(path))
    {
        return false;
    }
    if (strcmp(prefix, "/") == 0)
    {
        return true;
    }
    const size_t prefix_length = strlen(prefix);
    return strncmp(prefix, path, prefix_length) == 0 && (path[prefix_length] == '\0' || path[prefix_length] == '/');
}

static bool systemMemoryLinuxPathsComparable(const char *left, const char *right)
{
    return systemMemoryLinuxPathComponentPrefixes(left, right) || systemMemoryLinuxPathComponentPrefixes(right, left);
}

static bool systemMemoryLinuxCopyCanonicalPath(char *destination, size_t capacity, const char *path)
{
    const size_t length = path == NULL ? 0 : strlen(path);
    if (length == 0 || length >= capacity || ! systemMemoryLinuxPathIsCanonical(path))
    {
        return false;
    }
    memoryCopy(destination, path, length + 1U);
    return true;
}

static bool systemMemoryLinuxCopyMembership(char *destination, size_t capacity, const char *path, bool *present)
{
    if (! systemMemoryLinuxPathIsCanonical(path) || strlen(path) >= capacity)
    {
        return false;
    }
    if (*present)
    {
        return strcmp(destination, path) == 0;
    }
    strcpy(destination, path);
    *present = true;
    return true;
}

static bool systemMemoryLinuxParseMembership(const char *contents, system_memory_linux_membership_t *membership,
                                             bool *confirmed_absent)
{
    if (contents == NULL || membership == NULL || confirmed_absent == NULL || *contents == '\0')
    {
        return false;
    }
    const size_t content_length = strlen(contents);
    if (contents[content_length - 1U] != '\n')
    {
        return false;
    }

    char        v1_path[kSystemMemoryLinuxPathCapacity]      = {0};
    char        unified_path[kSystemMemoryLinuxPathCapacity] = {0};
    bool        have_v1                                      = false;
    bool        have_unified                                 = false;
    const char *cursor                                       = contents;
    while (*cursor != '\0')
    {
        const char *newline = strchr(cursor, '\n');
        if (newline == NULL)
        {
            return false;
        }
        const size_t length = (size_t) (newline - cursor);
        if (length == 0 || length >= kSystemMemoryLinuxMountinfoLineCapacity)
        {
            return false;
        }

        char line[kSystemMemoryLinuxMountinfoLineCapacity];
        memoryCopy(line, cursor, length);
        line[length] = '\0';
        char *first  = strchr(line, ':');
        char *second = first == NULL ? NULL : strchr(first + 1U, ':');
        if (first == NULL || second == NULL || strchr(second + 1U, ':') != NULL)
        {
            return false;
        }
        *first            = '\0';
        *second           = '\0';
        char *controllers = first + 1U;
        char *path        = second + 1U;
        if (! systemMemoryLinuxTokenIsUnsigned(line) || ! systemMemoryLinuxControllersAreValid(controllers) ||
            ! systemMemoryLinuxPathIsCanonical(path))
        {
            return false;
        }

        uint64_t hierarchy = 0;
        bool     unbounded = false;
        if (! systemMemoryParseUnsignedValue(line, false, &hierarchy, &unbounded) || unbounded ||
            (hierarchy == 0) != (*controllers == '\0'))
        {
            return false;
        }
        if (hierarchy == 0)
        {
            if (! systemMemoryLinuxCopyMembership(unified_path, sizeof(unified_path), path, &have_unified))
            {
                return false;
            }
        }
        else if (systemMemoryLinuxCsvContains(controllers, "memory"))
        {
            if (! systemMemoryLinuxCopyMembership(v1_path, sizeof(v1_path), path, &have_v1))
            {
                return false;
            }
        }
        cursor = newline + 1U;
    }

    *membership = (system_memory_linux_membership_t) {0};
    if (have_v1)
    {
        membership->kind = kSystemMemoryLinuxCgroupV1;
        strcpy(membership->path, v1_path);
        *confirmed_absent = false;
        return true;
    }
    if (have_unified)
    {
        membership->kind = kSystemMemoryLinuxCgroupV2;
        strcpy(membership->path, unified_path);
        *confirmed_absent = false;
        return true;
    }

    membership->kind  = kSystemMemoryLinuxCgroupAbsent;
    *confirmed_absent = true;
    return true;
}

static bool systemMemoryLinuxDecodeMountPath(const char *encoded, char *decoded, size_t capacity)
{
    if (encoded == NULL || decoded == NULL || capacity == 0)
    {
        return false;
    }
    size_t output = 0;
    for (size_t input = 0; encoded[input] != '\0'; ++input)
    {
        unsigned int value = (unsigned char) encoded[input];
        if (value == '\\')
        {
            if (encoded[input + 1U] < '0' || encoded[input + 1U] > '7' || encoded[input + 2U] < '0' ||
                encoded[input + 2U] > '7' || encoded[input + 3U] < '0' || encoded[input + 3U] > '7')
            {
                return false;
            }
            value = ((unsigned int) (encoded[input + 1U] - '0') << 6U) |
                    ((unsigned int) (encoded[input + 2U] - '0') << 3U) | (unsigned int) (encoded[input + 3U] - '0');
            if (value != 040U && value != 011U && value != 012U && value != 0134U)
            {
                return false;
            }
            input += 3U;
        }
        if (value == 0 || value > UCHAR_MAX || output + 1U >= capacity)
        {
            return false;
        }
        decoded[output++] = (char) value;
    }
    decoded[output] = '\0';
    return output > 0 && systemMemoryLinuxPathIsCanonical(decoded);
}

#ifdef WW_SYSINFO_TEST_SEAM
bool systemMemoryLinuxTestDecodeMountPath(const char *encoded, char *decoded, size_t capacity)
{
    return systemMemoryLinuxDecodeMountPath(encoded, decoded, capacity);
}
#endif

static bool systemMemoryLinuxParseMountLine(const char *source, size_t length, system_memory_linux_mount_t *mount)
{
    if (source == NULL || mount == NULL || length == 0 || length >= kSystemMemoryLinuxMountinfoLineCapacity)
    {
        return false;
    }

    char line[kSystemMemoryLinuxMountinfoLineCapacity];
    memoryCopy(line, source, length);
    line[length] = '\0';

    char    *save          = NULL;
    char    *mount_id      = strtok_r(line, " ", &save);
    char    *parent_id     = strtok_r(NULL, " ", &save);
    char    *device        = strtok_r(NULL, " ", &save);
    char    *root          = strtok_r(NULL, " ", &save);
    char    *mount_point   = strtok_r(NULL, " ", &save);
    char    *mount_options = strtok_r(NULL, " ", &save);
    uint32_t device_major  = 0;
    uint32_t device_minor  = 0;
    if (! systemMemoryLinuxTokenIsUnsigned(mount_id) || ! systemMemoryLinuxTokenIsUnsigned(parent_id) ||
        ! systemMemoryLinuxParseDevice(device, &device_major, &device_minor) || root == NULL || mount_point == NULL ||
        mount_options == NULL)
    {
        return false;
    }

    char *token = strtok_r(NULL, " ", &save);
    while (token != NULL && strcmp(token, "-") != 0)
    {
        token = strtok_r(NULL, " ", &save);
    }
    char *fstype        = token == NULL ? NULL : strtok_r(NULL, " ", &save);
    char *mount_source  = fstype == NULL ? NULL : strtok_r(NULL, " ", &save);
    char *super_options = mount_source == NULL ? NULL : strtok_r(NULL, " ", &save);
    if (fstype == NULL || mount_source == NULL || super_options == NULL || strtok_r(NULL, " ", &save) != NULL)
    {
        return false;
    }

    *mount = (system_memory_linux_mount_t) {0};
    if (! systemMemoryLinuxDecodeMountPath(root, mount->root, sizeof(mount->root)) ||
        ! systemMemoryLinuxDecodeMountPath(mount_point, mount->mount_point, sizeof(mount->mount_point)))
    {
        return false;
    }
    mount->device_major     = device_major;
    mount->device_minor     = device_minor;
    mount->cgroup_v2        = strcmp(fstype, "cgroup2") == 0;
    mount->cgroup_v1_memory = strcmp(fstype, "cgroup") == 0 && (systemMemoryLinuxCsvContains(mount_options, "memory") ||
                                                                systemMemoryLinuxCsvContains(super_options, "memory"));
    return true;
}

static bool systemMemoryLinuxMountinfoIsComplete(const char *contents)
{
    if (contents == NULL || *contents == '\0')
    {
        return false;
    }
    const size_t length = strlen(contents);
    if (contents[length - 1U] != '\n')
    {
        return false;
    }
    const char *cursor = contents;
    while (*cursor != '\0')
    {
        const char *newline = strchr(cursor, '\n');
        if (newline == NULL)
        {
            return false;
        }
        system_memory_linux_mount_t ignored;
        if (! systemMemoryLinuxParseMountLine(cursor, (size_t) (newline - cursor), &ignored))
        {
            return false;
        }
        cursor = newline + 1U;
    }
    return true;
}

static bool systemMemoryLinuxJoinPath(const char *base, const char *suffix, char *result, size_t capacity)
{
    if (! systemMemoryLinuxPathIsCanonical(base) || ! systemMemoryLinuxPathIsCanonical(suffix) || result == NULL ||
        capacity == 0)
    {
        return false;
    }

    const bool   suffix_is_root = strcmp(suffix, "/") == 0;
    const bool   base_is_root   = strcmp(base, "/") == 0;
    const size_t base_length    = strlen(base);
    const size_t suffix_length  = suffix_is_root ? 0 : strlen(suffix);
    const size_t skipped_slash  = base_is_root && suffix_length != 0 ? 1U : 0U;
    if (base_length > SIZE_MAX - suffix_length || base_length + suffix_length < skipped_slash)
    {
        return false;
    }
    const size_t length = base_length + suffix_length - skipped_slash;
    if (length + 1U > capacity)
    {
        return false;
    }
    memoryCopy(result, base, base_length);
    if (suffix_length != 0)
    {
        memoryCopy(result + base_length, suffix + skipped_slash, suffix_length - skipped_slash);
    }
    result[length] = '\0';
    return systemMemoryLinuxPathIsCanonical(result);
}

static bool systemMemoryLinuxAppendName(const char *base, const char *name, char *path, size_t capacity)
{
    if (! systemMemoryLinuxPathIsCanonical(base) || name == NULL || *name == '\0' || strchr(name, '/') != NULL)
    {
        return false;
    }
    const size_t base_length = strlen(base);
    const size_t name_length = strlen(name);
    const bool   base_root   = strcmp(base, "/") == 0;
    const size_t separator   = base_root ? 0U : 1U;
    if (base_length > SIZE_MAX - separator || base_length + separator > SIZE_MAX - name_length ||
        base_length + separator + name_length + 1U > capacity)
    {
        return false;
    }
    memoryCopy(path, base, base_length);
    size_t offset = base_length;
    if (! base_root)
    {
        path[offset++] = '/';
    }
    memoryCopy(path + offset, name, name_length + 1U);
    return true;
}

static bool systemMemoryLinuxBuildDirectCandidate(const system_memory_linux_mount_t *mount, const char *membership_path,
                                                  char *leaf, size_t capacity)
{
    if (! systemMemoryLinuxPathComponentPrefixes(mount->root, membership_path))
    {
        return false;
    }
    const char *suffix = strcmp(mount->root, "/") == 0 ? membership_path : membership_path + strlen(mount->root);
    if (*suffix == '\0')
    {
        suffix = "/";
    }
    return systemMemoryLinuxJoinPath(mount->mount_point, suffix, leaf, capacity);
}

static bool systemMemoryLinuxBuildRelativeCandidate(const system_memory_linux_mount_t *mount,
                                                    const char *membership_path, char *leaf, size_t capacity)
{
    return systemMemoryLinuxJoinPath(mount->mount_point, membership_path, leaf, capacity);
}

static bool systemMemoryLinuxIdentityEqual(const system_memory_linux_fs_identity_t *left,
                                           const system_memory_linux_fs_identity_t *right)
{
    return left->device_major == right->device_major && left->device_minor == right->device_minor &&
           left->inode == right->inode && left->type == right->type;
}

static bool systemMemoryLinuxIdentityIsDirectoryOnDevice(const system_memory_linux_fs_identity_t *identity,
                                                         uint32_t device_major, uint32_t device_minor)
{
    return identity->type == kSystemMemoryLinuxFsTypeDirectory && identity->device_major == device_major &&
           identity->device_minor == device_minor;
}

static bool systemMemoryLinuxIdentityIsRegularOnDevice(const system_memory_linux_fs_identity_t *identity,
                                                       uint32_t device_major, uint32_t device_minor)
{
    return identity->type == kSystemMemoryLinuxFsTypeRegular && identity->device_major == device_major &&
           identity->device_minor == device_minor;
}

static bool systemMemoryLinuxCalculateDepth(const char *leaf, const char *boundary, uint8_t *depth)
{
    if (! systemMemoryLinuxPathComponentPrefixes(boundary, leaf) || depth == NULL)
    {
        return false;
    }
    size_t      levels = 1U;
    const char *cursor = leaf + strlen(boundary);
    if (strcmp(boundary, "/") == 0 && *cursor != '\0')
    {
        cursor--;
    }
    while (*cursor != '\0')
    {
        if (*cursor == '/')
        {
            levels++;
            if (levels > kSystemMemoryLinuxMaxCgroupLevels)
            {
                return false;
            }
        }
        ++cursor;
    }
    *depth = (uint8_t) levels;
    return true;
}

static bool systemMemoryLinuxMountMatches(const system_memory_linux_mount_t *mount,
                                          system_memory_linux_cgroup_kind_t  kind)
{
    return kind == kSystemMemoryLinuxCgroupV1 ? mount->cgroup_v1_memory : mount->cgroup_v2;
}

typedef enum system_memory_linux_candidate_result_e
{
    kSystemMemoryLinuxCandidateMissing,
    kSystemMemoryLinuxCandidateReadable,
    kSystemMemoryLinuxCandidateInvalid,
} system_memory_linux_candidate_result_t;

static system_memory_linux_candidate_result_t systemMemoryLinuxIdentifyCandidate(
    const system_memory_linux_mount_t *mount, const char *leaf, const system_memory_linux_io_t *io,
    system_memory_linux_candidate_t *candidate)
{
    system_memory_linux_fs_identity_t     leaf_identity     = {0};
    system_memory_linux_fs_identity_t     boundary_identity = {0};
    const system_memory_linux_fs_status_t leaf_status       = io->identity(io->userdata, leaf, &leaf_identity);
    const system_memory_linux_fs_status_t boundary_status =
        io->identity(io->userdata, mount->mount_point, &boundary_identity);
    if (leaf_status == kSystemMemoryLinuxFsMissing || boundary_status == kSystemMemoryLinuxFsMissing)
    {
        return kSystemMemoryLinuxCandidateMissing;
    }
    if (leaf_status != kSystemMemoryLinuxFsOk || boundary_status != kSystemMemoryLinuxFsOk ||
        ! systemMemoryLinuxIdentityIsDirectoryOnDevice(&leaf_identity, mount->device_major, mount->device_minor) ||
        ! systemMemoryLinuxIdentityIsDirectoryOnDevice(&boundary_identity, mount->device_major, mount->device_minor))
    {
        return kSystemMemoryLinuxCandidateInvalid;
    }

    uint8_t depth = 0;
    if (! systemMemoryLinuxCalculateDepth(leaf, mount->mount_point, &depth))
    {
        return kSystemMemoryLinuxCandidateInvalid;
    }
    *candidate = (system_memory_linux_candidate_t) {
        .leaf_identity     = leaf_identity,
        .boundary_identity = boundary_identity,
        .device_major      = mount->device_major,
        .device_minor      = mount->device_minor,
        .depth             = depth,
        .present           = true,
    };
    strcpy(candidate->leaf, leaf);
    strcpy(candidate->boundary, mount->mount_point);
    strcpy(candidate->root, mount->root);
    return kSystemMemoryLinuxCandidateReadable;
}

static bool systemMemoryLinuxCandidatePreferred(const system_memory_linux_candidate_t *candidate,
                                                const system_memory_linux_candidate_t *selected)
{
    if (candidate->depth != selected->depth)
    {
        return candidate->depth > selected->depth;
    }
    const size_t candidate_length = strlen(candidate->leaf);
    const size_t selected_length  = strlen(selected->leaf);
    if (candidate_length != selected_length)
    {
        return candidate_length < selected_length;
    }
    return strcmp(candidate->leaf, selected->leaf) < 0;
}

static bool systemMemoryLinuxMergeCandidate(system_memory_linux_candidate_t       *selected,
                                            const system_memory_linux_candidate_t *candidate)
{
    if (! selected->present)
    {
        *selected = *candidate;
        return true;
    }
    if (! systemMemoryLinuxIdentityEqual(&selected->leaf_identity, &candidate->leaf_identity) ||
        ! systemMemoryLinuxPathsComparable(selected->root, candidate->root))
    {
        return false;
    }
    if (systemMemoryLinuxCandidatePreferred(candidate, selected))
    {
        *selected = *candidate;
    }
    return true;
}

static bool systemMemoryLinuxScanCandidates(const char                             *mountinfo_text,
                                            const system_memory_linux_membership_t *membership,
                                            const system_memory_linux_io_t *io, bool relative_pass,
                                            system_memory_linux_candidate_t *selected)
{
    const char *cursor = mountinfo_text;
    while (*cursor != '\0')
    {
        const char *newline = strchr(cursor, '\n');
        assert(newline != NULL);
        system_memory_linux_mount_t mount;
        if (! systemMemoryLinuxParseMountLine(cursor, (size_t) (newline - cursor), &mount))
        {
            return false;
        }
        cursor = newline + 1U;
        if (! systemMemoryLinuxMountMatches(&mount, membership->kind))
        {
            continue;
        }

        char       leaf[kSystemMemoryLinuxPathCapacity];
        const bool direct = systemMemoryLinuxBuildDirectCandidate(&mount, membership->path, leaf, sizeof(leaf));
        if (! relative_pass && ! direct)
        {
            continue;
        }
        if (relative_pass && ! systemMemoryLinuxBuildRelativeCandidate(&mount, membership->path, leaf, sizeof(leaf)))
        {
            return false;
        }

        system_memory_linux_candidate_t              candidate = {0};
        const system_memory_linux_candidate_result_t result =
            systemMemoryLinuxIdentifyCandidate(&mount, leaf, io, &candidate);
        if (result == kSystemMemoryLinuxCandidateInvalid)
        {
            return false;
        }
        if (result == kSystemMemoryLinuxCandidateReadable && ! systemMemoryLinuxMergeCandidate(selected, &candidate))
        {
            return false;
        }
    }
    return true;
}

system_memory_provider_result_t systemMemoryLinuxResolveCgroup(const char *cgroup_text, const char *mountinfo_text,
                                                               const system_memory_linux_io_t   *io,
                                                               system_memory_linux_resolution_t *resolution)
{
    if (io == NULL || io->identity == NULL || resolution == NULL)
    {
        return kSystemMemoryProviderUnavailable;
    }
    *resolution = (system_memory_linux_resolution_t) {0};

    system_memory_linux_membership_t membership;
    bool                             confirmed_absent = false;
    if (! systemMemoryLinuxParseMembership(cgroup_text, &membership, &confirmed_absent))
    {
        return kSystemMemoryProviderUnavailable;
    }
    if (confirmed_absent)
    {
        resolution->kind = kSystemMemoryLinuxCgroupAbsent;
        return kSystemMemoryProviderOk;
    }
    if (! systemMemoryLinuxMountinfoIsComplete(mountinfo_text))
    {
        return kSystemMemoryProviderUnavailable;
    }

    system_memory_linux_candidate_t selected = {0};
    if (! systemMemoryLinuxScanCandidates(mountinfo_text, &membership, io, false, &selected))
    {
        return kSystemMemoryProviderUnavailable;
    }
    if (! selected.present)
    {
        if (! systemMemoryLinuxScanCandidates(mountinfo_text, &membership, io, true, &selected) || ! selected.present)
        {
            return kSystemMemoryProviderUnavailable;
        }
    }

    resolution->kind               = membership.kind;
    resolution->leaf_identity      = selected.leaf_identity;
    resolution->boundary_identity  = selected.boundary_identity;
    resolution->mount_device_major = selected.device_major;
    resolution->mount_device_minor = selected.device_minor;
    resolution->depth              = selected.depth;
    strcpy(resolution->leaf_path, selected.leaf);
    strcpy(resolution->boundary_path, selected.boundary);
    return kSystemMemoryProviderOk;
}

static bool systemMemoryLinuxMoveToParent(char *path, const char *boundary)
{
    if (strcmp(path, boundary) == 0 || ! systemMemoryLinuxPathComponentPrefixes(boundary, path))
    {
        return false;
    }
    char *separator = strrchr(path, '/');
    if (separator == NULL)
    {
        return false;
    }
    if (separator == path)
    {
        path[1] = '\0';
    }
    else
    {
        *separator = '\0';
    }
    return systemMemoryLinuxPathComponentPrefixes(boundary, path);
}

static system_memory_linux_sample_result_t systemMemoryLinuxValidateSampleDirectory(
    const system_memory_linux_resolution_t *resolution, const system_memory_linux_io_t *io, const char *path,
    uint8_t level)
{
    system_memory_linux_fs_identity_t     identity = {0};
    const system_memory_linux_fs_status_t status   = io->identity(io->userdata, path, &identity);
    if (status != kSystemMemoryLinuxFsOk ||
        ! systemMemoryLinuxIdentityIsDirectoryOnDevice(
            &identity, resolution->mount_device_major, resolution->mount_device_minor))
    {
        return kSystemMemoryLinuxSampleResolutionInvalid;
    }
    if ((level == 0 && ! systemMemoryLinuxIdentityEqual(&identity, &resolution->leaf_identity)) ||
        (level + 1U == resolution->depth &&
         ! systemMemoryLinuxIdentityEqual(&identity, &resolution->boundary_identity)))
    {
        return kSystemMemoryLinuxSampleResolutionInvalid;
    }
    return kSystemMemoryLinuxSampleValid;
}

static system_memory_linux_sample_result_t systemMemoryLinuxValidateOpenedAccounting(
    const system_memory_linux_resolution_t *resolution, system_memory_linux_fs_status_t status,
    const system_memory_linux_fs_identity_t *identity)
{
    if (status == kSystemMemoryLinuxFsIdentityMismatch)
    {
        return kSystemMemoryLinuxSampleResolutionInvalid;
    }
    if (status != kSystemMemoryLinuxFsOk)
    {
        return kSystemMemoryLinuxSampleUnavailable;
    }
    return systemMemoryLinuxIdentityIsRegularOnDevice(
               identity, resolution->mount_device_major, resolution->mount_device_minor)
               ? kSystemMemoryLinuxSampleValid
               : kSystemMemoryLinuxSampleResolutionInvalid;
}

static bool systemMemoryLinuxSelectDiagnostic(uint32_t basis_points, uint64_t remaining, uint8_t level,
                                              bool have_diagnostic, uint32_t diagnostic_basis_points,
                                              uint64_t diagnostic_remaining, uint8_t diagnostic_level)
{
    if (! have_diagnostic || basis_points != diagnostic_basis_points)
    {
        return ! have_diagnostic || basis_points > diagnostic_basis_points;
    }
    if (remaining != diagnostic_remaining)
    {
        return remaining < diagnostic_remaining;
    }
    return level < diagnostic_level;
}

system_memory_linux_sample_result_t systemMemoryLinuxSampleResolvedCgroup(system_memory_linux_resolution_t *resolution,
                                                                          const system_memory_linux_io_t   *io,
                                                                          system_memory_snapshot_t         *snapshot)
{
    if (resolution == NULL || io == NULL || io->identity == NULL || io->read_accounting == NULL || snapshot == NULL)
    {
        return kSystemMemoryLinuxSampleUnavailable;
    }
    if (resolution->kind == kSystemMemoryLinuxCgroupAbsent)
    {
        snapshot->cgroup_limited = false;
        return kSystemMemoryLinuxSampleValid;
    }
    if ((resolution->kind != kSystemMemoryLinuxCgroupV1 && resolution->kind != kSystemMemoryLinuxCgroupV2) ||
        ! systemMemoryLinuxPathIsCanonical(resolution->leaf_path) ||
        ! systemMemoryLinuxPathIsCanonical(resolution->boundary_path) || resolution->depth == 0 ||
        resolution->depth > kSystemMemoryLinuxMaxCgroupLevels ||
        ! systemMemoryLinuxPathComponentPrefixes(resolution->boundary_path, resolution->leaf_path))
    {
        return kSystemMemoryLinuxSampleResolutionInvalid;
    }

    char path[kSystemMemoryLinuxPathCapacity];
    strcpy(path, resolution->leaf_path);
    bool     have_finite          = false;
    bool     have_diagnostic      = false;
    uint64_t minimum_remaining    = UINT64_MAX;
    uint64_t diagnostic_current   = 0;
    uint64_t diagnostic_limit     = 0;
    uint64_t diagnostic_remaining = UINT64_MAX;
    uint32_t diagnostic_pressure  = 0;
    uint8_t  diagnostic_level     = UINT8_MAX;

    for (uint8_t level = 0; level < resolution->depth; ++level)
    {
        const system_memory_linux_sample_result_t directory_result =
            systemMemoryLinuxValidateSampleDirectory(resolution, io, path, level);
        if (directory_result != kSystemMemoryLinuxSampleValid)
        {
            return directory_result;
        }

        const char *current_name =
            resolution->kind == kSystemMemoryLinuxCgroupV1 ? "memory.usage_in_bytes" : "memory.current";
        const char *limit_name =
            resolution->kind == kSystemMemoryLinuxCgroupV1 ? "memory.limit_in_bytes" : "memory.max";
        char current_path[kSystemMemoryLinuxPathCapacity];
        char limit_path[kSystemMemoryLinuxPathCapacity];
        if (! systemMemoryLinuxAppendName(path, current_name, current_path, sizeof(current_path)) ||
            ! systemMemoryLinuxAppendName(path, limit_name, limit_path, sizeof(limit_path)))
        {
            return kSystemMemoryLinuxSampleResolutionInvalid;
        }

        char                                  current_text[128];
        char                                  limit_text[128];
        system_memory_linux_fs_identity_t     current_identity = {0};
        system_memory_linux_fs_identity_t     limit_identity   = {0};
        const system_memory_linux_fs_status_t current_status   = io->read_accounting(io->userdata,
                                                                                   current_path,
                                                                                   resolution->mount_device_major,
                                                                                   resolution->mount_device_minor,
                                                                                   current_text,
                                                                                   sizeof(current_text),
                                                                                   &current_identity);
        const system_memory_linux_fs_status_t limit_status     = io->read_accounting(io->userdata,
                                                                                 limit_path,
                                                                                 resolution->mount_device_major,
                                                                                 resolution->mount_device_minor,
                                                                                 limit_text,
                                                                                 sizeof(limit_text),
                                                                                 &limit_identity);
        const uint64_t                        level_bit        = UINT64_C(1) << level;

        const system_memory_linux_sample_result_t current_identity_result =
            systemMemoryLinuxValidateOpenedAccounting(resolution, current_status, &current_identity);
        const system_memory_linux_sample_result_t limit_identity_result =
            systemMemoryLinuxValidateOpenedAccounting(resolution, limit_status, &limit_identity);
        if (current_identity_result == kSystemMemoryLinuxSampleResolutionInvalid ||
            limit_identity_result == kSystemMemoryLinuxSampleResolutionInvalid)
        {
            return kSystemMemoryLinuxSampleResolutionInvalid;
        }

        const bool current_missing = current_status == kSystemMemoryLinuxFsMissing;
        const bool limit_missing   = limit_status == kSystemMemoryLinuxFsMissing;
        if (current_missing || limit_missing)
        {
            if ((resolution->readable_pair_levels & level_bit) != 0)
            {
                return kSystemMemoryLinuxSampleResolutionInvalid;
            }
            if (resolution->kind == kSystemMemoryLinuxCgroupV2 && current_missing && limit_missing)
            {
                if (level + 1U < resolution->depth && ! systemMemoryLinuxMoveToParent(path, resolution->boundary_path))
                {
                    return kSystemMemoryLinuxSampleResolutionInvalid;
                }
                continue;
            }
            return kSystemMemoryLinuxSampleUnavailable;
        }
        if (current_status != kSystemMemoryLinuxFsOk || limit_status != kSystemMemoryLinuxFsOk)
        {
            return kSystemMemoryLinuxSampleUnavailable;
        }

        if ((resolution->readable_pair_levels & level_bit) != 0)
        {
            if (! systemMemoryLinuxIdentityEqual(&current_identity, &resolution->current_identities[level]) ||
                ! systemMemoryLinuxIdentityEqual(&limit_identity, &resolution->limit_identities[level]))
            {
                return kSystemMemoryLinuxSampleResolutionInvalid;
            }
        }
        else
        {
            resolution->current_identities[level] = current_identity;
            resolution->limit_identities[level]   = limit_identity;
            resolution->readable_pair_levels |= level_bit;
        }

        if (resolution->kind == kSystemMemoryLinuxCgroupV1)
        {
            char                              hierarchy_path[kSystemMemoryLinuxPathCapacity];
            char                              hierarchy_text[128];
            system_memory_linux_fs_identity_t hierarchy_identity = {0};
            if (! systemMemoryLinuxAppendName(path, "memory.use_hierarchy", hierarchy_path, sizeof(hierarchy_path)))
            {
                return kSystemMemoryLinuxSampleResolutionInvalid;
            }
            const system_memory_linux_fs_status_t     hierarchy_status = io->read_accounting(io->userdata,
                                                                                         hierarchy_path,
                                                                                         resolution->mount_device_major,
                                                                                         resolution->mount_device_minor,
                                                                                         hierarchy_text,
                                                                                         sizeof(hierarchy_text),
                                                                                         &hierarchy_identity);
            const system_memory_linux_sample_result_t hierarchy_identity_result =
                systemMemoryLinuxValidateOpenedAccounting(resolution, hierarchy_status, &hierarchy_identity);
            if (hierarchy_identity_result != kSystemMemoryLinuxSampleValid)
            {
                return hierarchy_identity_result;
            }
            if ((resolution->readable_hierarchy_levels & level_bit) != 0)
            {
                if (! systemMemoryLinuxIdentityEqual(&hierarchy_identity, &resolution->hierarchy_identities[level]))
                {
                    return kSystemMemoryLinuxSampleResolutionInvalid;
                }
            }
            else
            {
                resolution->hierarchy_identities[level] = hierarchy_identity;
                resolution->readable_hierarchy_levels |= level_bit;
            }

            uint64_t hierarchy_value = 0;
            bool     hierarchy_max   = false;
            if (! systemMemoryParseUnsignedValue(hierarchy_text, false, &hierarchy_value, &hierarchy_max) ||
                hierarchy_max || hierarchy_value != 1U)
            {
                return kSystemMemoryLinuxSampleUnavailable;
            }
        }

        uint64_t current           = 0;
        uint64_t limit             = 0;
        bool     current_unbounded = false;
        bool     limit_unbounded   = false;
        if (! systemMemoryParseUnsignedValue(current_text, false, &current, &current_unbounded) || current_unbounded ||
            ! systemMemoryParseUnsignedValue(
                limit_text, resolution->kind == kSystemMemoryLinuxCgroupV2, &limit, &limit_unbounded))
        {
            return kSystemMemoryLinuxSampleUnavailable;
        }
        if (resolution->kind == kSystemMemoryLinuxCgroupV1)
        {
            const system_memory_linux_v1_limit_class_t limit_class =
                systemMemoryLinuxClassifyV1Limit(limit, io->kernel_long_width, io->base_page_size_bytes);
            if (limit_class == kSystemMemoryLinuxV1LimitUnavailable)
            {
                return kSystemMemoryLinuxSampleUnavailable;
            }
            limit_unbounded = limit_class == kSystemMemoryLinuxV1LimitUnbounded;
        }
        if (! limit_unbounded)
        {
            if (limit == 0)
            {
                return kSystemMemoryLinuxSampleUnavailable;
            }
            const uint64_t remaining = current >= limit ? 0 : limit - current;
            const uint64_t bounded   = min(current, limit);
            uint32_t       pressure  = 0;
            if (! systemMemoryBasisPoints(bounded, limit, &pressure))
            {
                return kSystemMemoryLinuxSampleUnavailable;
            }
            have_finite       = true;
            minimum_remaining = min(minimum_remaining, remaining);
            if (systemMemoryLinuxSelectDiagnostic(pressure,
                                                  remaining,
                                                  level,
                                                  have_diagnostic,
                                                  diagnostic_pressure,
                                                  diagnostic_remaining,
                                                  diagnostic_level))
            {
                have_diagnostic      = true;
                diagnostic_current   = current;
                diagnostic_limit     = limit;
                diagnostic_remaining = remaining;
                diagnostic_pressure  = pressure;
                diagnostic_level     = level;
            }
        }

        if (level + 1U < resolution->depth && ! systemMemoryLinuxMoveToParent(path, resolution->boundary_path))
        {
            return kSystemMemoryLinuxSampleResolutionInvalid;
        }
    }

    if (strcmp(path, resolution->boundary_path) != 0)
    {
        return kSystemMemoryLinuxSampleResolutionInvalid;
    }
    if (! have_finite || ! have_diagnostic)
    {
        return kSystemMemoryLinuxSampleUnavailable;
    }

    snapshot->cgroup_limited         = true;
    snapshot->cgroup_current_bytes   = diagnostic_current;
    snapshot->cgroup_limit_bytes     = diagnostic_limit;
    snapshot->cgroup_available_bytes = minimum_remaining;
    return kSystemMemoryLinuxSampleValid;
}

system_memory_provider_result_t systemMemoryLinuxReadResolvedCgroup(system_memory_linux_resolution_t *resolution,
                                                                    const system_memory_linux_io_t   *io,
                                                                    system_memory_snapshot_t         *snapshot)
{
    return systemMemoryLinuxSampleResolvedCgroup(resolution, io, snapshot) == kSystemMemoryLinuxSampleValid
               ? kSystemMemoryProviderOk
               : kSystemMemoryProviderUnavailable;
}

static system_memory_linux_fs_status_t systemMemoryLinuxErrnoStatus(int error_number)
{
    if (error_number == ENOENT || error_number == ENOTDIR)
    {
        return kSystemMemoryLinuxFsMissing;
    }
    if (error_number == EACCES || error_number == EPERM)
    {
        return kSystemMemoryLinuxFsInaccessible;
    }
    return kSystemMemoryLinuxFsError;
}

static system_memory_linux_fs_status_t systemMemoryLinuxClassifyBoundedRead(size_t capacity, size_t read_length,
                                                                            bool read_failed, int read_error,
                                                                            int probe_value, bool probe_failed,
                                                                            int probe_error, bool close_failed,
                                                                            int close_error)
{
    discard read_error;
    discard probe_error;
    discard close_error;
    if (capacity < 2U || read_length > capacity - 1U)
    {
        return kSystemMemoryLinuxFsError;
    }
    if (read_failed)
    {
        return kSystemMemoryLinuxFsError;
    }
    if (read_length == capacity - 1U)
    {
        if (probe_value != EOF)
        {
            return kSystemMemoryLinuxFsTruncated;
        }
        if (probe_failed)
        {
            return kSystemMemoryLinuxFsError;
        }
    }
    return close_failed ? kSystemMemoryLinuxFsError : kSystemMemoryLinuxFsOk;
}

#ifdef WW_SYSINFO_TEST_SEAM
system_memory_linux_fs_status_t systemMemoryLinuxTestClassifyBoundedRead(size_t capacity, size_t read_length,
                                                                         bool read_failed, int read_error,
                                                                         int probe_value, bool probe_failed,
                                                                         int probe_error, bool close_failed,
                                                                         int close_error)
{
    return systemMemoryLinuxClassifyBoundedRead(capacity,
                                                read_length,
                                                read_failed,
                                                read_error,
                                                probe_value,
                                                probe_failed,
                                                probe_error,
                                                close_failed,
                                                close_error);
}
#endif

static system_memory_linux_fs_status_t systemMemoryLinuxReadOpenedText(FILE *file, char *buffer, size_t capacity)
{
    errno                     = 0;
    const size_t length       = fread(buffer, 1U, capacity - 1U, file);
    bool         read_failed  = false;
    int          read_error   = 0;
    int          probe_value  = EOF;
    bool         probe_failed = false;
    int          probe_error  = 0;
    if (length < capacity - 1U && ferror(file) != 0)
    {
        read_failed = true;
        read_error  = errno;
    }
    else if (length == capacity - 1U)
    {
        errno       = 0;
        probe_value = fgetc(file);
        if (probe_value == EOF && ferror(file) != 0)
        {
            probe_failed = true;
            probe_error  = errno;
        }
    }

    errno                                              = 0;
    const bool                            close_failed = fclose(file) != 0;
    const int                             close_error  = errno;
    const system_memory_linux_fs_status_t result       = systemMemoryLinuxClassifyBoundedRead(
        capacity, length, read_failed, read_error, probe_value, probe_failed, probe_error, close_failed, close_error);
    if (result == kSystemMemoryLinuxFsOk)
    {
        buffer[length] = '\0';
    }
    return result;
}

static system_memory_linux_fs_status_t systemMemoryLinuxReadText(void *userdata, const char *path, char *buffer,
                                                                 size_t capacity)
{
    discard userdata;
    if (path == NULL || buffer == NULL || capacity < 2U)
    {
        return kSystemMemoryLinuxFsError;
    }
    errno      = 0;
    FILE *file = fopen(path, "r");
    if (file == NULL)
    {
        return systemMemoryLinuxErrnoStatus(errno);
    }
    return systemMemoryLinuxReadOpenedText(file, buffer, capacity);
}

static system_memory_linux_fs_type_t systemMemoryLinuxModeType(mode_t mode)
{
    if (S_ISDIR(mode))
    {
        return kSystemMemoryLinuxFsTypeDirectory;
    }
    if (S_ISREG(mode))
    {
        return kSystemMemoryLinuxFsTypeRegular;
    }
    return kSystemMemoryLinuxFsTypeOther;
}

static void systemMemoryLinuxIdentityFromStat(const struct stat *status, system_memory_linux_fs_identity_t *identity)
{
    *identity = (system_memory_linux_fs_identity_t) {
        .device_major = (uint32_t) major(status->st_dev),
        .device_minor = (uint32_t) minor(status->st_dev),
        .inode        = (uint64_t) status->st_ino,
        .type         = systemMemoryLinuxModeType(status->st_mode),
    };
}

static system_memory_linux_fs_status_t systemMemoryLinuxIdentity(void *userdata, const char *path,
                                                                 system_memory_linux_fs_identity_t *identity)
{
    discard userdata;
    if (path == NULL || identity == NULL)
    {
        return kSystemMemoryLinuxFsError;
    }
    struct stat status;
    errno = 0;
    if (stat(path, &status) != 0)
    {
        return systemMemoryLinuxErrnoStatus(errno);
    }
    systemMemoryLinuxIdentityFromStat(&status, identity);
    return kSystemMemoryLinuxFsOk;
}

static system_memory_linux_fs_status_t systemMemoryLinuxReadAccounting(void *userdata, const char *path,
                                                                       uint32_t expected_device_major,
                                                                       uint32_t expected_device_minor, char *buffer,
                                                                       size_t                             capacity,
                                                                       system_memory_linux_fs_identity_t *identity)
{
    discard userdata;
    if (path == NULL || buffer == NULL || capacity < 2U || identity == NULL)
    {
        return kSystemMemoryLinuxFsError;
    }
    errno      = 0;
    FILE *file = fopen(path, "r");
    if (file == NULL)
    {
        return systemMemoryLinuxErrnoStatus(errno);
    }

    struct stat status;
    errno = 0;
    if (fstat(fileno(file), &status) != 0)
    {
        const int operation_error = errno;
        discard   fclose(file);
        return systemMemoryLinuxErrnoStatus(operation_error);
    }
    systemMemoryLinuxIdentityFromStat(&status, identity);
    if (! systemMemoryLinuxIdentityIsRegularOnDevice(identity, expected_device_major, expected_device_minor))
    {
        const bool close_failed = fclose(file) != 0;
        return close_failed ? kSystemMemoryLinuxFsError : kSystemMemoryLinuxFsIdentityMismatch;
    }
    return systemMemoryLinuxReadOpenedText(file, buffer, capacity);
}

static int systemMemoryLinuxProductionPersonality(void *userdata, unsigned long personality_value)
{
    discard userdata;
    return personality(personality_value);
}

static int systemMemoryLinuxProductionUnameMachine(void *userdata, char *machine, size_t capacity)
{
    discard userdata;
    if (machine == NULL || capacity == 0)
    {
        return -1;
    }
    struct utsname name;
    if (uname(&name) != 0)
    {
        return -1;
    }
    const size_t length = strlen(name.machine);
    if (length >= capacity)
    {
        return -1;
    }
    memoryCopy(machine, name.machine, length + 1U);
    return 0;
}

static uint64_t systemMemoryLinuxBasePageSize(void)
{
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
    {
        return 0;
    }
    const uint64_t page_size_bytes = (uint64_t) page_size;
    return (page_size_bytes & (page_size_bytes - 1U)) == 0 ? page_size_bytes : 0;
}

static void systemMemoryLinuxClearResolution(linux_memory_provider_state_t *provider)
{
    memoryFree(provider->leaf_path);
    memoryFree(provider->boundary_path);
    provider->leaf_path     = NULL;
    provider->boundary_path = NULL;
    provider->kind          = kSystemMemoryLinuxCgroupUnknown;
    provider->metadata      = (system_memory_linux_resolution_t) {0};
}

static system_memory_provider_result_t systemMemoryLinuxCacheResolution(
    linux_memory_provider_state_t *provider, const system_memory_linux_resolution_t *resolution)
{
    char *new_leaf     = NULL;
    char *new_boundary = NULL;
    if (resolution->kind == kSystemMemoryLinuxCgroupV1 || resolution->kind == kSystemMemoryLinuxCgroupV2)
    {
        new_leaf     = stringDuplicate(resolution->leaf_path);
        new_boundary = stringDuplicate(resolution->boundary_path);
        if (new_leaf == NULL || new_boundary == NULL)
        {
            memoryFree(new_leaf);
            memoryFree(new_boundary);
            return kSystemMemoryProviderUnavailable;
        }
    }

    systemMemoryLinuxClearResolution(provider);
    provider->leaf_path     = new_leaf;
    provider->boundary_path = new_boundary;
    provider->kind          = resolution->kind;
    provider->metadata      = *resolution;
    memoryZero(provider->metadata.leaf_path, sizeof(provider->metadata.leaf_path));
    memoryZero(provider->metadata.boundary_path, sizeof(provider->metadata.boundary_path));
    return kSystemMemoryProviderOk;
}

static void systemMemoryLinuxMakeResolution(const linux_memory_provider_state_t *provider,
                                            system_memory_linux_resolution_t    *resolution)
{
    *resolution      = provider->metadata;
    resolution->kind = provider->kind;
    if (provider->leaf_path != NULL)
    {
        strcpy(resolution->leaf_path, provider->leaf_path);
    }
    if (provider->boundary_path != NULL)
    {
        strcpy(resolution->boundary_path, provider->boundary_path);
    }
}

static void systemMemoryLinuxSaveSampleMetadata(linux_memory_provider_state_t          *provider,
                                                const system_memory_linux_resolution_t *resolution)
{
    provider->metadata.readable_pair_levels      = resolution->readable_pair_levels;
    provider->metadata.readable_hierarchy_levels = resolution->readable_hierarchy_levels;
    memoryCopy(provider->metadata.current_identities,
               resolution->current_identities,
               sizeof(provider->metadata.current_identities));
    memoryCopy(
        provider->metadata.limit_identities, resolution->limit_identities, sizeof(provider->metadata.limit_identities));
    memoryCopy(provider->metadata.hierarchy_identities,
               resolution->hierarchy_identities,
               sizeof(provider->metadata.hierarchy_identities));
}

static system_memory_provider_result_t systemMemoryLinuxDiscoverCgroup(linux_memory_provider_state_t *provider,
                                                                       uint64_t                       now_ms)
{
    provider->last_discovery_ms   = now_ms;
    provider->discovery_attempted = true;
    char *cgroup_text             = memoryAllocate(kSystemMemoryLinuxCgroupTextCapacity);
    if (cgroup_text == NULL)
    {
        return kSystemMemoryProviderUnavailable;
    }
    if (provider->io.read_text(
            provider->io.userdata, "/proc/self/cgroup", cgroup_text, kSystemMemoryLinuxCgroupTextCapacity) !=
        kSystemMemoryLinuxFsOk)
    {
        memoryFree(cgroup_text);
        return kSystemMemoryProviderUnavailable;
    }

    system_memory_linux_resolution_t resolution;
    if (systemMemoryLinuxResolveCgroup(cgroup_text, NULL, &provider->io, &resolution) == kSystemMemoryProviderOk &&
        resolution.kind == kSystemMemoryLinuxCgroupAbsent)
    {
        memoryFree(cgroup_text);
        return systemMemoryLinuxCacheResolution(provider, &resolution);
    }

    char *mountinfo_text = memoryAllocate(kSystemMemoryLinuxMountinfoCapacity);
    if (mountinfo_text == NULL)
    {
        memoryFree(cgroup_text);
        return kSystemMemoryProviderUnavailable;
    }
    const system_memory_linux_fs_status_t mountinfo_status = provider->io.read_text(
        provider->io.userdata, "/proc/self/mountinfo", mountinfo_text, kSystemMemoryLinuxMountinfoCapacity);
    const system_memory_provider_result_t result =
        mountinfo_status == kSystemMemoryLinuxFsOk
            ? systemMemoryLinuxResolveCgroup(cgroup_text, mountinfo_text, &provider->io, &resolution)
            : kSystemMemoryProviderUnavailable;
    memoryFree(mountinfo_text);
    memoryFree(cgroup_text);
    return result == kSystemMemoryProviderOk ? systemMemoryLinuxCacheResolution(provider, &resolution) : result;
}

static bool systemMemoryLinuxRediscoveryDue(const linux_memory_provider_state_t *provider, uint64_t now_ms)
{
    return ! provider->discovery_attempted || now_ms < provider->last_discovery_ms ||
           now_ms - provider->last_discovery_ms >= SYSTEM_LOAD_SAMPLER_INTERVAL_MS;
}

static system_memory_provider_result_t systemMemoryLinuxRead(void *userdata, system_memory_snapshot_t *snapshot)
{
    system_load_state_t           *state    = userdata;
    linux_memory_provider_state_t *provider = state->memory_provider_state;
    if (provider == NULL || provider->io.read_text == NULL || provider->io.identity == NULL ||
        provider->io.read_accounting == NULL)
    {
        return kSystemMemoryProviderUnavailable;
    }
    const uint64_t now_ms = state->memory_now_ms(state->memory_now_userdata);

    char meminfo[32768];
    if (provider->io.read_text(provider->io.userdata, "/proc/meminfo", meminfo, sizeof(meminfo)) !=
            kSystemMemoryLinuxFsOk ||
        ! systemMemoryParseLinuxMeminfo(meminfo, &snapshot->host_total_bytes, &snapshot->host_available_bytes))
    {
        return kSystemMemoryProviderUnavailable;
    }

    if (provider->kind == kSystemMemoryLinuxCgroupUnknown)
    {
        if (! systemMemoryLinuxRediscoveryDue(provider, now_ms) ||
            systemMemoryLinuxDiscoverCgroup(provider, now_ms) != kSystemMemoryProviderOk)
        {
            return kSystemMemoryProviderUnavailable;
        }
    }
    if (provider->kind == kSystemMemoryLinuxCgroupAbsent)
    {
        snapshot->cgroup_limited = false;
        return kSystemMemoryProviderOk;
    }

    system_memory_linux_resolution_t resolution;
    systemMemoryLinuxMakeResolution(provider, &resolution);
    system_memory_linux_sample_result_t sample_result =
        systemMemoryLinuxSampleResolvedCgroup(&resolution, &provider->io, snapshot);
    systemMemoryLinuxSaveSampleMetadata(provider, &resolution);
    if (sample_result == kSystemMemoryLinuxSampleValid)
    {
        return kSystemMemoryProviderOk;
    }
    if (sample_result == kSystemMemoryLinuxSampleUnavailable)
    {
        return kSystemMemoryProviderUnavailable;
    }

    if (! systemMemoryLinuxRediscoveryDue(provider, now_ms))
    {
        return kSystemMemoryProviderUnavailable;
    }
    const system_memory_linux_cgroup_kind_t previous_kind = provider->kind;
    systemMemoryLinuxClearResolution(provider);
    if (systemMemoryLinuxDiscoverCgroup(provider, now_ms) != kSystemMemoryProviderOk)
    {
        return kSystemMemoryProviderUnavailable;
    }
    if ((previous_kind == kSystemMemoryLinuxCgroupV1 || previous_kind == kSystemMemoryLinuxCgroupV2) &&
        provider->kind == kSystemMemoryLinuxCgroupAbsent)
    {
        systemMemoryLinuxClearResolution(provider);
        return kSystemMemoryProviderUnavailable;
    }
    if (provider->kind == kSystemMemoryLinuxCgroupAbsent)
    {
        snapshot->cgroup_limited = false;
        return kSystemMemoryProviderOk;
    }

    systemMemoryLinuxMakeResolution(provider, &resolution);
    sample_result = systemMemoryLinuxSampleResolvedCgroup(&resolution, &provider->io, snapshot);
    systemMemoryLinuxSaveSampleMetadata(provider, &resolution);
    return sample_result == kSystemMemoryLinuxSampleValid ? kSystemMemoryProviderOk : kSystemMemoryProviderUnavailable;
}

static bool systemMemoryLinuxProviderInit(system_load_state_t *state, const system_memory_linux_io_t *io)
{
    linux_memory_provider_state_t *provider = memoryAllocateZero(sizeof(*provider));
    if (provider == NULL)
    {
        return false;
    }
    provider->io                    = *io;
    state->memory_provider_state    = provider;
    state->memory_provider          = systemMemoryLinuxRead;
    state->memory_provider_userdata = state;
    discard systemMemoryLinuxDiscoverCgroup(provider, state->memory_now_ms(state->memory_now_userdata));
    return true;
}

static bool systemMemoryDefaultProviderInit(system_load_state_t *state)
{
    const system_memory_linux_kernel_ops_t kernel_ops = {
        .personality   = systemMemoryLinuxProductionPersonality,
        .uname_machine = systemMemoryLinuxProductionUnameMachine,
        .userdata      = NULL,
    };
    const system_memory_linux_io_t io = {
        .read_text            = systemMemoryLinuxReadText,
        .identity             = systemMemoryLinuxIdentity,
        .read_accounting      = systemMemoryLinuxReadAccounting,
        .userdata             = NULL,
        .kernel_long_width    = systemMemoryLinuxDetectKernelLongWidth(sizeof(long), &kernel_ops),
        .base_page_size_bytes = systemMemoryLinuxBasePageSize(),
    };
    return systemMemoryLinuxProviderInit(state, &io);
}

static void systemMemoryDefaultProviderDestroy(system_load_state_t *state)
{
    linux_memory_provider_state_t *provider = state->memory_provider_state;
    if (provider != NULL)
    {
        systemMemoryLinuxClearResolution(provider);
        memoryFree(provider);
    }
    state->memory_provider_state = NULL;
}

#ifdef WW_SYSINFO_TEST_SEAM
void systemLoadSamplerSetLinuxMemoryTestHooks(system_load_state_t *state, const system_memory_linux_io_t *io,
                                              SystemMemoryNowMsFn now_ms, void *now_userdata)
{
    assert(state != NULL && state->initialized && io != NULL && io->read_text != NULL && io->identity != NULL &&
           io->read_accounting != NULL);
    systemMemoryDefaultProviderDestroy(state);
    state->memory_now_ms       = now_ms != NULL ? now_ms : systemMemoryDefaultNowMS;
    state->memory_now_userdata = now_userdata;
    if (! systemMemoryLinuxProviderInit(state, io))
    {
        printError("System memory Linux test provider allocation failed");
        abortProgramNow(1);
    }
    atomicStoreU64Relaxed(&state->memory_generation, 0);
    atomicStoreRelaxed(&state->memory_provider_supported, true);
    atomicStoreRelaxed(&state->memory_provider_unavailable, true);
    state->memory_sample_valid = false;
}
#endif
