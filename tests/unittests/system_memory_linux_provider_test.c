#include "global_state.h"
#include "wsysinfo_linux.h"

#include <sys/personality.h>

enum
{
    kFixtureFiles = 512,
};

typedef struct fixture_file_s
{
    const char                       *path;
    const char                       *contents;
    system_memory_linux_fs_status_t   read_status;
    system_memory_linux_fs_status_t   identity_status;
    system_memory_linux_fs_identity_t identity;
} fixture_file_t;

typedef struct linux_fixture_s
{
    fixture_file_t                          files[kFixtureFiles];
    size_t                                  file_count;
    uint64_t                                now_ms;
    unsigned int                            read_calls;
    unsigned int                            identity_calls;
    unsigned int                            accounting_calls;
    unsigned int                            cgroup_reads;
    unsigned int                            mountinfo_reads;
    system_memory_linux_kernel_long_width_t kernel_long_width;
    uint64_t                                base_page_size_bytes;
    bool                                    have_kernel_environment;
} linux_fixture_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static system_memory_linux_fs_identity_t identity(uint32_t major_value, uint32_t minor_value, uint64_t inode,
                                                  system_memory_linux_fs_type_t type)
{
    return (system_memory_linux_fs_identity_t) {
        .device_major = major_value,
        .device_minor = minor_value,
        .inode        = inode,
        .type         = type,
    };
}

static fixture_file_t *fixtureFind(linux_fixture_t *fixture, const char *path)
{
    for (size_t index = 0; index < fixture->file_count; ++index)
    {
        if (strcmp(fixture->files[index].path, path) == 0)
        {
            return &fixture->files[index];
        }
    }
    return NULL;
}

static fixture_file_t *fixtureAdd(linux_fixture_t *fixture, const char *path, const char *contents,
                                  system_memory_linux_fs_status_t   read_status,
                                  system_memory_linux_fs_status_t   identity_status,
                                  system_memory_linux_fs_identity_t file_identity)
{
    require(fixture->file_count < ARRAY_SIZE(fixture->files), "Linux memory fixture file table overflow");
    fixture_file_t *file = &fixture->files[fixture->file_count++];
    *file                = (fixture_file_t) {
                       .path            = path,
                       .contents        = contents,
                       .read_status     = read_status,
                       .identity_status = identity_status,
                       .identity        = file_identity,
    };
    return file;
}

static fixture_file_t *fixtureAddDirectory(linux_fixture_t *fixture, const char *path, uint32_t major_value,
                                           uint32_t minor_value, uint64_t inode)
{
    return fixtureAdd(fixture,
                      path,
                      NULL,
                      kSystemMemoryLinuxFsError,
                      kSystemMemoryLinuxFsOk,
                      identity(major_value, minor_value, inode, kSystemMemoryLinuxFsTypeDirectory));
}

static fixture_file_t *fixtureAddAccounting(linux_fixture_t *fixture, const char *path, const char *contents,
                                            uint32_t major_value, uint32_t minor_value, uint64_t inode)
{
    return fixtureAdd(fixture,
                      path,
                      contents,
                      kSystemMemoryLinuxFsOk,
                      kSystemMemoryLinuxFsOk,
                      identity(major_value, minor_value, inode, kSystemMemoryLinuxFsTypeRegular));
}

static system_memory_linux_fs_status_t fixtureCopyFile(fixture_file_t *file, char *buffer, size_t capacity)
{
    if (file->read_status != kSystemMemoryLinuxFsOk)
    {
        return file->read_status;
    }
    if (file->contents == NULL || strlen(file->contents) >= capacity)
    {
        return kSystemMemoryLinuxFsTruncated;
    }
    strcpy(buffer, file->contents);
    return kSystemMemoryLinuxFsOk;
}

static system_memory_linux_fs_status_t fixtureRead(void *userdata, const char *path, char *buffer, size_t capacity)
{
    linux_fixture_t *fixture = userdata;
    fixture->read_calls++;
    if (strcmp(path, "/proc/self/cgroup") == 0)
    {
        fixture->cgroup_reads++;
    }
    else if (strcmp(path, "/proc/self/mountinfo") == 0)
    {
        fixture->mountinfo_reads++;
    }
    fixture_file_t *file = fixtureFind(fixture, path);
    return file == NULL ? kSystemMemoryLinuxFsMissing : fixtureCopyFile(file, buffer, capacity);
}

static system_memory_linux_fs_status_t fixtureIdentity(void *userdata, const char *path,
                                                       system_memory_linux_fs_identity_t *file_identity)
{
    linux_fixture_t *fixture = userdata;
    fixture->identity_calls++;
    fixture_file_t *file = fixtureFind(fixture, path);
    if (file == NULL)
    {
        return kSystemMemoryLinuxFsMissing;
    }
    if (file->identity_status == kSystemMemoryLinuxFsOk)
    {
        *file_identity = file->identity;
    }
    return file->identity_status;
}

static system_memory_linux_fs_status_t fixtureReadAccounting(void *userdata, const char *path,
                                                             uint32_t expected_device_major,
                                                             uint32_t expected_device_minor, char *buffer,
                                                             size_t                             capacity,
                                                             system_memory_linux_fs_identity_t *file_identity)
{
    linux_fixture_t *fixture = userdata;
    fixture->accounting_calls++;
    fixture_file_t *file = fixtureFind(fixture, path);
    if (file == NULL)
    {
        return kSystemMemoryLinuxFsMissing;
    }
    if (file->identity_status != kSystemMemoryLinuxFsOk)
    {
        return file->identity_status;
    }
    *file_identity = file->identity;
    if (file->identity.type != kSystemMemoryLinuxFsTypeRegular ||
        file->identity.device_major != expected_device_major || file->identity.device_minor != expected_device_minor)
    {
        return kSystemMemoryLinuxFsIdentityMismatch;
    }
    return fixtureCopyFile(file, buffer, capacity);
}

static uint64_t fixtureNow(void *userdata)
{
    return ((linux_fixture_t *) userdata)->now_ms;
}

static system_memory_linux_io_t fixtureIO(linux_fixture_t *fixture)
{
    return (system_memory_linux_io_t) {
        .read_text       = fixtureRead,
        .identity        = fixtureIdentity,
        .read_accounting = fixtureReadAccounting,
        .userdata        = fixture,
        .kernel_long_width =
            fixture->have_kernel_environment ? fixture->kernel_long_width : kSystemMemoryLinuxKernelLong64,
        .base_page_size_bytes = fixture->have_kernel_environment ? fixture->base_page_size_bytes : 4096U,
    };
}

static void fixtureSetKernelEnvironment(linux_fixture_t                        *fixture,
                                        system_memory_linux_kernel_long_width_t kernel_long_width,
                                        uint64_t                                base_page_size_bytes)
{
    fixture->kernel_long_width       = kernel_long_width;
    fixture->base_page_size_bytes    = base_page_size_bytes;
    fixture->have_kernel_environment = true;
}

static void addV2Level(linux_fixture_t *fixture, const char *path, const char *current, const char *limit,
                       uint64_t inode_base)
{
    char *current_path = memoryAllocate(kSystemMemoryLinuxPathCapacity);
    char *limit_path   = memoryAllocate(kSystemMemoryLinuxPathCapacity);
    require(current_path != NULL && limit_path != NULL, "failed to allocate v2 fixture path");
    require(snprintf(current_path, kSystemMemoryLinuxPathCapacity, "%s/memory.current", path) > 0,
            "failed to build memory.current fixture path");
    require(snprintf(limit_path, kSystemMemoryLinuxPathCapacity, "%s/memory.max", path) > 0,
            "failed to build memory.max fixture path");
    fixtureAddAccounting(fixture, current_path, current, 0, 26, inode_base);
    fixtureAddAccounting(fixture, limit_path, limit, 0, 26, inode_base + 1U);
}

static void addV1Level(linux_fixture_t *fixture, const char *path, const char *current, const char *limit,
                       const char *use_hierarchy, uint64_t inode_base)
{
    char *current_path   = memoryAllocate(kSystemMemoryLinuxPathCapacity);
    char *limit_path     = memoryAllocate(kSystemMemoryLinuxPathCapacity);
    char *hierarchy_path = memoryAllocate(kSystemMemoryLinuxPathCapacity);
    require(current_path != NULL && limit_path != NULL && hierarchy_path != NULL, "failed to allocate v1 paths");
    require(snprintf(current_path, kSystemMemoryLinuxPathCapacity, "%s/memory.usage_in_bytes", path) > 0 &&
                snprintf(limit_path, kSystemMemoryLinuxPathCapacity, "%s/memory.limit_in_bytes", path) > 0 &&
                snprintf(hierarchy_path, kSystemMemoryLinuxPathCapacity, "%s/memory.use_hierarchy", path) > 0,
            "failed to build v1 accounting paths");
    fixtureAddAccounting(fixture, current_path, current, 0, 26, inode_base);
    fixtureAddAccounting(fixture, limit_path, limit, 0, 26, inode_base + 1U);
    fixtureAddAccounting(fixture, hierarchy_path, use_hierarchy, 0, 26, inode_base + 2U);
}

static system_memory_provider_result_t resolveFixture(linux_fixture_t *fixture, const char *cgroup,
                                                      const char                       *mountinfo,
                                                      system_memory_linux_resolution_t *resolution)
{
    const system_memory_linux_io_t io = fixtureIO(fixture);
    return systemMemoryLinuxResolveCgroup(cgroup, mountinfo, &io, resolution);
}

static system_memory_linux_sample_result_t sampleFixture(linux_fixture_t                  *fixture,
                                                         system_memory_linux_resolution_t *resolution,
                                                         system_memory_snapshot_t         *snapshot)
{
    const system_memory_linux_io_t io = fixtureIO(fixture);
    return systemMemoryLinuxSampleResolvedCgroup(resolution, &io, snapshot);
}

static bool expectedV1Sentinels(uint64_t page_size, uint64_t *sentinel_32, uint64_t *sentinel_64)
{
    if (page_size == 0 || (page_size & (page_size - 1U)) != 0 || page_size > UINT64_MAX / (uint64_t) INT32_MAX ||
        sentinel_32 == NULL || sentinel_64 == NULL)
    {
        return false;
    }
    *sentinel_32            = (uint64_t) INT32_MAX * page_size;
    const uint64_t pages_64 = (uint64_t) INT64_MAX / page_size;
    if (pages_64 == 0 || pages_64 > UINT64_MAX / page_size)
    {
        return false;
    }
    *sentinel_64 = pages_64 * page_size;
    return true;
}

static void testV1LimitClassifier(void)
{
    static const uint64_t page_sizes[] = {4096U, 16384U, 65536U};
    for (size_t index = 0; index < ARRAY_SIZE(page_sizes); ++index)
    {
        const uint64_t page_size = page_sizes[index];
        uint64_t       sentinel_32;
        uint64_t       sentinel_64;
        require(expectedV1Sentinels(page_size, &sentinel_32, &sentinel_64),
                "failed to construct expected cgroup v1 sentinel values");
        require(sentinel_32 >= page_size && sentinel_32 <= UINT64_MAX - page_size && sentinel_64 >= page_size &&
                    sentinel_64 <= UINT64_MAX - page_size,
                "cgroup v1 sentinel neighbor construction would overflow");

        require(systemMemoryLinuxTestClassifyV1Limit(sentinel_32, kSystemMemoryLinuxKernelLong32, page_size) ==
                    kSystemMemoryLinuxV1LimitUnbounded,
                "known-32 exact cgroup v1 sentinel was not unbounded");
        require(systemMemoryLinuxTestClassifyV1Limit(sentinel_32 - page_size,
                                                     kSystemMemoryLinuxKernelLong32,
                                                     page_size) == kSystemMemoryLinuxV1LimitFinite,
                "known-32 value one page below the cgroup v1 sentinel was not finite");
        require(systemMemoryLinuxTestClassifyV1Limit(sentinel_32 + page_size,
                                                     kSystemMemoryLinuxKernelLong32,
                                                     page_size) == kSystemMemoryLinuxV1LimitUnavailable,
                "known-32 value above the cgroup v1 kernel maximum did not fail closed");

        require(systemMemoryLinuxTestClassifyV1Limit(sentinel_64, kSystemMemoryLinuxKernelLong64, page_size) ==
                    kSystemMemoryLinuxV1LimitUnbounded,
                "known-64 exact cgroup v1 sentinel was not unbounded");
        require(systemMemoryLinuxTestClassifyV1Limit(sentinel_64 - page_size,
                                                     kSystemMemoryLinuxKernelLong64,
                                                     page_size) == kSystemMemoryLinuxV1LimitFinite,
                "known-64 value one page below the cgroup v1 sentinel was not finite");
        require(systemMemoryLinuxTestClassifyV1Limit(sentinel_64 + page_size,
                                                     kSystemMemoryLinuxKernelLong64,
                                                     page_size) == kSystemMemoryLinuxV1LimitUnavailable,
                "known-64 value above the cgroup v1 kernel maximum did not fail closed");
        require(systemMemoryLinuxTestClassifyV1Limit(sentinel_32, kSystemMemoryLinuxKernelLong64, page_size) ==
                    kSystemMemoryLinuxV1LimitFinite,
                "known-64 kernel confused the finite 32-bit candidate with its sentinel");

        require(systemMemoryLinuxTestClassifyV1Limit(sentinel_32, kSystemMemoryLinuxKernelLongUnknown, page_size) ==
                        kSystemMemoryLinuxV1LimitUnavailable &&
                    systemMemoryLinuxTestClassifyV1Limit(sentinel_64, kSystemMemoryLinuxKernelLongUnknown, page_size) ==
                        kSystemMemoryLinuxV1LimitUnavailable,
                "unknown kernel width accepted an ambiguous cgroup v1 sentinel candidate");
        require(systemMemoryLinuxTestClassifyV1Limit(page_size * 1024U,
                                                     kSystemMemoryLinuxKernelLongUnknown,
                                                     page_size) == kSystemMemoryLinuxV1LimitFinite,
                "unknown kernel width rejected an ordinary finite cgroup v1 limit");
    }

    require(systemMemoryLinuxTestClassifyV1Limit(1024U, kSystemMemoryLinuxKernelLong64, 0) ==
                    kSystemMemoryLinuxV1LimitUnavailable &&
                systemMemoryLinuxTestClassifyV1Limit(1024U, kSystemMemoryLinuxKernelLong64, 6000U) ==
                    kSystemMemoryLinuxV1LimitUnavailable &&
                systemMemoryLinuxTestClassifyV1Limit(1024U, kSystemMemoryLinuxKernelLong64, UINT64_C(1) << 63U) ==
                    kSystemMemoryLinuxV1LimitUnavailable,
            "invalid or overflowing cgroup v1 page geometry did not fail closed");
}

typedef struct kernel_detection_fixture_s
{
    int           personality_results[3];
    unsigned long personality_requests[3];
    size_t        personality_calls;
    const char   *machine;
    int           uname_result;
    size_t        uname_calls;
} kernel_detection_fixture_t;

static int kernelFixturePersonality(void *userdata, unsigned long personality_value)
{
    kernel_detection_fixture_t *fixture = userdata;
    require(fixture->personality_calls < ARRAY_SIZE(fixture->personality_results),
            "kernel-width fixture received too many personality calls");
    const size_t call_index                   = fixture->personality_calls++;
    fixture->personality_requests[call_index] = personality_value;
    return fixture->personality_results[call_index];
}

static int kernelFixtureUnameMachine(void *userdata, char *machine, size_t capacity)
{
    kernel_detection_fixture_t *fixture = userdata;
    fixture->uname_calls++;
    if (fixture->uname_result != 0 || fixture->machine == NULL || strlen(fixture->machine) >= capacity)
    {
        return -1;
    }
    strcpy(machine, fixture->machine);
    return 0;
}

static kernel_detection_fixture_t kernelDetectionFixture(const char *machine)
{
    const int original = (int) ((unsigned int) ADDR_NO_RANDOMIZE | (unsigned int) PER_LINUX32);
    const int native   = (int) (((unsigned int) original & ~((unsigned int) PER_MASK)) | (unsigned int) PER_LINUX);
    return (kernel_detection_fixture_t) {
        .personality_results = {original, original, native},
        .machine             = machine,
    };
}

static system_memory_linux_kernel_long_width_t detectKernelFixture(kernel_detection_fixture_t *fixture,
                                                                   size_t                      userspace_long_size)
{
    const system_memory_linux_kernel_test_ops_t ops = {
        .personality   = kernelFixturePersonality,
        .uname_machine = kernelFixtureUnameMachine,
        .userdata      = fixture,
    };
    return systemMemoryLinuxTestDetectKernelLongWidth(userspace_long_size, &ops);
}

static void requireSuccessfulDetectionSequence(const kernel_detection_fixture_t *fixture)
{
    const unsigned long original = (unsigned int) fixture->personality_results[0];
    const unsigned long native   = (original & ~((unsigned long) PER_MASK)) | (unsigned long) PER_LINUX;
    require(fixture->personality_calls == 3 && fixture->uname_calls == 1 &&
                fixture->personality_requests[0] == UINT32_MAX && fixture->personality_requests[1] == native &&
                fixture->personality_requests[2] == original &&
                (fixture->personality_requests[1] & ~((unsigned long) PER_MASK)) ==
                    (original & ~((unsigned long) PER_MASK)),
            "kernel-width detection did not preserve flags, select native personality, and restore the exact original");
}

static void testKernelLongWidthDetection(void)
{
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
    static const char *const kernel_64_names[] = {"x86_64", "aarch64"};
    for (size_t index = 0; index < ARRAY_SIZE(kernel_32_names); ++index)
    {
        kernel_detection_fixture_t fixture = kernelDetectionFixture(kernel_32_names[index]);
        require(detectKernelFixture(&fixture, 4U) == kSystemMemoryLinuxKernelLong32,
                "supported 32-bit native uname machine was not classified known-32");
        requireSuccessfulDetectionSequence(&fixture);
    }
    for (size_t index = 0; index < ARRAY_SIZE(kernel_64_names); ++index)
    {
        kernel_detection_fixture_t fixture = kernelDetectionFixture(kernel_64_names[index]);
        require(detectKernelFixture(&fixture, 4U) == kSystemMemoryLinuxKernelLong64,
                "32-bit userspace did not recognize a supported 64-bit native kernel machine");
        requireSuccessfulDetectionSequence(&fixture);
    }

    kernel_detection_fixture_t native_64 = kernelDetectionFixture("ignored");
    require(detectKernelFixture(&native_64, 8U) == kSystemMemoryLinuxKernelLong64 && native_64.personality_calls == 0 &&
                native_64.uname_calls == 0,
            "64-bit userspace did not select known-64 without personality or uname calls");

    kernel_detection_fixture_t query_failure = kernelDetectionFixture("x86_64");
    query_failure.personality_results[0]     = -1;
    require(detectKernelFixture(&query_failure, 4U) == kSystemMemoryLinuxKernelLongUnknown &&
                query_failure.personality_calls == 1 && query_failure.uname_calls == 0,
            "personality query failure did not leave kernel width unknown");

    kernel_detection_fixture_t switch_failure = kernelDetectionFixture("x86_64");
    switch_failure.personality_results[1]     = -1;
    require(detectKernelFixture(&switch_failure, 4U) == kSystemMemoryLinuxKernelLongUnknown &&
                switch_failure.personality_calls == 2 && switch_failure.uname_calls == 0,
            "native personality switch failure did not leave kernel width unknown");

    kernel_detection_fixture_t uname_failure = kernelDetectionFixture("x86_64");
    uname_failure.uname_result               = -1;
    require(detectKernelFixture(&uname_failure, 4U) == kSystemMemoryLinuxKernelLongUnknown &&
                uname_failure.personality_calls == 3 &&
                uname_failure.personality_requests[2] == (unsigned int) uname_failure.personality_results[0],
            "uname failure did not restore the exact original personality and leave width unknown");

    kernel_detection_fixture_t unknown_machine = kernelDetectionFixture("riscv64");
    require(detectKernelFixture(&unknown_machine, 4U) == kSystemMemoryLinuxKernelLongUnknown &&
                unknown_machine.personality_calls == 3 &&
                unknown_machine.personality_requests[2] == (unsigned int) unknown_machine.personality_results[0],
            "unknown native machine did not restore the exact original personality and leave width unknown");

    kernel_detection_fixture_t empty_machine = kernelDetectionFixture("");
    require(detectKernelFixture(&empty_machine, 4U) == kSystemMemoryLinuxKernelLongUnknown &&
                empty_machine.personality_calls == 3 &&
                empty_machine.personality_requests[2] == (unsigned int) empty_machine.personality_results[0],
            "empty native machine did not restore the exact original personality and leave width unknown");

    kernel_detection_fixture_t unexpected_switch = kernelDetectionFixture("x86_64");
    unexpected_switch.personality_results[1]++;
    require(detectKernelFixture(&unexpected_switch, 4U) == kSystemMemoryLinuxKernelLongUnknown &&
                unexpected_switch.personality_calls == 3 && unexpected_switch.uname_calls == 0 &&
                unexpected_switch.personality_requests[2] == (unsigned int) unexpected_switch.personality_results[0],
            "unexpected successful native switch skipped exact-original restoration or guessed a width");

    kernel_detection_fixture_t restore_failure = kernelDetectionFixture("x86_64");
    restore_failure.personality_results[2]     = -1;
    require(detectKernelFixture(&restore_failure, 4U) == kSystemMemoryLinuxKernelLongUnknown,
            "personality restoration failure did not invalidate a detected kernel width");

    kernel_detection_fixture_t unexpected_restore = kernelDetectionFixture("x86_64");
    unexpected_restore.personality_results[2]++;
    require(detectKernelFixture(&unexpected_restore, 4U) == kSystemMemoryLinuxKernelLongUnknown,
            "unexpected restoration previous value did not invalidate a detected kernel width");
}

static void setupThreeLevelV2(linux_fixture_t *fixture)
{
    fixtureAddDirectory(fixture, "/cg", 0, 26, 10);
    fixtureAddDirectory(fixture, "/cg/tenant", 0, 26, 11);
    fixtureAddDirectory(fixture, "/cg/tenant/leaf", 0, 26, 12);
}

static void testHierarchicalV2Sampling(void)
{
    static const char mountinfo[] = "29 23 0:26 / /cg rw - cgroup2 cgroup rw\n";
    linux_fixture_t   fixture     = {0};
    fixtureSetKernelEnvironment(&fixture, kSystemMemoryLinuxKernelLongUnknown, 0);
    setupThreeLevelV2(&fixture);
    addV2Level(&fixture, "/cg/tenant/leaf", "100\n", "max\n", 100);
    addV2Level(&fixture, "/cg/tenant", "900\n", "1000\n", 110);
    addV2Level(&fixture, "/cg", "100\n", "500\n", 120);

    system_memory_linux_resolution_t resolution;
    require(resolveFixture(&fixture, "0::/tenant/leaf\n", mountinfo, &resolution) == kSystemMemoryProviderOk &&
                resolution.kind == kSystemMemoryLinuxCgroupV2 && resolution.depth == 3 &&
                strcmp(resolution.leaf_path, "/cg/tenant/leaf") == 0 && strcmp(resolution.boundary_path, "/cg") == 0,
            "v2 hierarchy did not resolve from leaf through mount boundary");

    system_memory_snapshot_t snapshot = {0};
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleValid &&
                snapshot.cgroup_limited && snapshot.cgroup_current_bytes == 900 &&
                snapshot.cgroup_limit_bytes == 1000 && snapshot.cgroup_available_bytes == 100,
            "an unbounded v2 leaf hid its finite pressured parent");

    fixtureAddDirectory(&fixture, "/", 0, 26, 9);
    addV2Level(&fixture, "/", "1000\n", "1000\n", 90);
    snapshot = (system_memory_snapshot_t) {0};
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleValid &&
                snapshot.cgroup_current_bytes == 900 && snapshot.cgroup_limit_bytes == 1000,
            "ancestor walking escaped above the selected mount boundary");

    fixtureFind(&fixture, "/cg/tenant/leaf/memory.current")->contents = "900\n";
    fixtureFind(&fixture, "/cg/tenant/leaf/memory.max")->contents     = "1000\n";
    fixtureFind(&fixture, "/cg/tenant/memory.current")->contents      = "1\n";
    fixtureFind(&fixture, "/cg/tenant/memory.max")->contents          = "11\n";
    snapshot                                                          = (system_memory_snapshot_t) {0};
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleValid &&
                snapshot.cgroup_current_bytes == 900 && snapshot.cgroup_limit_bytes == 1000 &&
                snapshot.cgroup_available_bytes == 10,
            "maximum pressure and minimum headroom were not retained from different ancestors");

    fixtureFind(&fixture, "/cg/memory.current")->contents = "500\n";
    snapshot                                              = (system_memory_snapshot_t) {0};
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleValid &&
                snapshot.cgroup_current_bytes == 500 && snapshot.cgroup_limit_bytes == 500 &&
                snapshot.cgroup_available_bytes == 0,
            "current-at-limit ancestor was not selected as 100 percent pressure");
    fixtureFind(&fixture, "/cg/memory.current")->contents = "600\n";
    snapshot                                              = (system_memory_snapshot_t) {0};
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleValid &&
                snapshot.cgroup_current_bytes == 600 && snapshot.cgroup_available_bytes == 0,
            "current-above-limit ancestor was not saturated conservatively");
}

static void testMissingPairsAndAllUnbounded(void)
{
    static const char mountinfo[] = "29 23 0:26 / /cg rw - cgroup2 cgroup rw\n";
    linux_fixture_t   fixture     = {0};
    setupThreeLevelV2(&fixture);
    addV2Level(&fixture, "/cg/tenant", "90\n", "100\n", 200);
    addV2Level(&fixture, "/cg", "1\n", "max\n", 210);

    system_memory_linux_resolution_t resolution;
    require(resolveFixture(&fixture, "0::/tenant/leaf\n", mountinfo, &resolution) == kSystemMemoryProviderOk,
            "missing-leaf hierarchy did not resolve structurally");
    system_memory_snapshot_t snapshot = {0};
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleValid &&
                snapshot.cgroup_current_bytes == 90 && snapshot.cgroup_limit_bytes == 100,
            "both-missing v2 leaf did not continue to a finite parent");

    fixtureAddAccounting(&fixture, "/cg/tenant/leaf/memory.current", "1\n", 0, 26, 220);
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleUnavailable,
            "one-file-missing v2 leaf did not fail closed");

    linux_fixture_t inverse_half_pair = {0};
    setupThreeLevelV2(&inverse_half_pair);
    fixtureAddAccounting(&inverse_half_pair, "/cg/tenant/leaf/memory.max", "100\n", 0, 26, 225);
    addV2Level(&inverse_half_pair, "/cg/tenant", "90\n", "100\n", 230);
    addV2Level(&inverse_half_pair, "/cg", "1\n", "max\n", 240);
    require(resolveFixture(&inverse_half_pair, "0::/tenant/leaf\n", mountinfo, &resolution) ==
                    kSystemMemoryProviderOk &&
                sampleFixture(&inverse_half_pair, &resolution, &snapshot) == kSystemMemoryLinuxSampleUnavailable,
            "limit-present/current-missing v2 leaf did not fail closed");

    fixtureAddAccounting(&fixture, "/cg/tenant/leaf/memory.max", "max\n", 0, 26, 221);
    fixtureFind(&fixture, "/cg/tenant/memory.current")->contents = "malformed\n";
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleUnavailable,
            "malformed ancestor accounting value did not fail closed");

    linux_fixture_t unbounded = {0};
    setupThreeLevelV2(&unbounded);
    addV2Level(&unbounded, "/cg/tenant/leaf", "1\n", "max\n", 300);
    addV2Level(&unbounded, "/cg/tenant", "2\n", "max\n", 310);
    addV2Level(&unbounded, "/cg", "3\n", "max\n", 320);
    require(resolveFixture(&unbounded, "0::/tenant/leaf\n", mountinfo, &resolution) == kSystemMemoryProviderOk,
            "all-unbounded hierarchy did not retain a structural resolution");
    require(sampleFixture(&unbounded, &resolution, &snapshot) == kSystemMemoryLinuxSampleUnavailable,
            "all-visible-unbounded hierarchy incorrectly published host-only data");

    linux_fixture_t apparent_root = {0};
    fixtureAddDirectory(&apparent_root, "/cg", 0, 26, 330);
    addV2Level(&apparent_root, "/cg", "1\n", "max\n", 331);
    require(resolveFixture(&apparent_root, "0::/\n", mountinfo, &resolution) == kSystemMemoryProviderOk &&
                sampleFixture(&apparent_root, &resolution, &snapshot) == kSystemMemoryLinuxSampleUnavailable,
            "apparent membership and mount root '/' incorrectly disproved a hidden ancestor");

    linux_fixture_t none = {0};
    fixtureSetKernelEnvironment(&none, kSystemMemoryLinuxKernelLongUnknown, 0);
    require(resolveFixture(&none, "4:cpu:/work\n", NULL, &resolution) == kSystemMemoryProviderOk &&
                resolution.kind == kSystemMemoryLinuxCgroupAbsent,
            "no applicable memory membership was not the sole host-only absence result");
}

static void testV1Hierarchy(void)
{
    static const char mountinfo[] = "31 23 0:26 / /cg rw - cgroup cgroup rw,memory\n";
    linux_fixture_t   fixture     = {0};
    fixtureAddDirectory(&fixture, "/cg", 0, 26, 400);
    fixtureAddDirectory(&fixture, "/cg/child", 0, 26, 401);
    addV1Level(&fixture, "/cg/child", "100\n", "1000\n", "1\n", 410);
    addV1Level(&fixture, "/cg", "950\n", "1000\n", "1\n", 420);

    system_memory_linux_resolution_t resolution;
    require(resolveFixture(&fixture, "5:cpu,memory:/child\n0::/ignored\n", mountinfo, &resolution) ==
                    kSystemMemoryProviderOk &&
                resolution.kind == kSystemMemoryLinuxCgroupV1,
            "explicit v1 memory hierarchy did not retain authority");
    system_memory_snapshot_t snapshot = {0};
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleValid &&
                snapshot.cgroup_current_bytes == 950 && snapshot.cgroup_available_bytes == 50,
            "v1 finite parent was not included in hierarchical pressure");

    fixtureFind(&fixture, "/cg/memory.limit_in_bytes")->contents = "9223372036854771712\n";
    snapshot                                                     = (system_memory_snapshot_t) {0};
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleValid &&
                snapshot.cgroup_current_bytes == 100 && snapshot.cgroup_limit_bytes == 1000 &&
                snapshot.cgroup_available_bytes == 900,
            "a v1 unlimited parent hid its finite child");

    fixtureFind(&fixture, "/cg/child/memory.limit_in_bytes")->contents = "9223372036854771712\n";
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleUnavailable,
            "all-unlimited v1 hierarchy incorrectly published host-only data");

    fixtureFind(&fixture, "/cg/memory.limit_in_bytes")->contents = "1000\n";
    snapshot                                                     = (system_memory_snapshot_t) {0};
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleValid &&
                snapshot.cgroup_current_bytes == 950 && snapshot.cgroup_available_bytes == 50,
            "a v1 unlimited child hid its finite parent");
    fixtureFind(&fixture, "/cg/memory.limit_in_bytes")->contents      = "9223372036854771712\n";
    fixtureFind(&fixture, "/cg/child/memory.use_hierarchy")->contents = "0\n";
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleUnavailable,
            "v1 memory.use_hierarchy=0 was silently treated as hierarchical");

    linux_fixture_t hybrid = {0};
    fixtureAddDirectory(&hybrid, "/v2", 0, 27, 430);
    fixtureAddDirectory(&hybrid, "/v2/unified", 0, 27, 431);
    require(resolveFixture(&hybrid,
                           "0::/unified\n5:cpu,memory:/missing-v1\n",
                           "31 23 0:26 / /v1 rw - cgroup cgroup rw,memory\n"
                           "32 23 0:27 / /v2 rw - cgroup2 cgroup rw\n",
                           &resolution) == kSystemMemoryProviderUnavailable,
            "unresolved explicit v1 memory membership downgraded to a readable v2 hierarchy");
}

static void setupTwoLevelV1(linux_fixture_t *fixture, const char *child_limit, const char *parent_limit)
{
    fixtureAddDirectory(fixture, "/cg", 0, 26, 450);
    fixtureAddDirectory(fixture, "/cg/child", 0, 26, 451);
    addV1Level(fixture, "/cg/child", "100\n", child_limit, "1\n", 460);
    addV1Level(fixture, "/cg", "200\n", parent_limit, "1\n", 470);
}

static void testV1KernelSentinelHierarchies(void)
{
    static const char mountinfo[] = "31 23 0:26 / /cg rw - cgroup cgroup rw,memory\n";
    const uint64_t    page_size   = 4096U;
    uint64_t          sentinel_32;
    uint64_t          sentinel_64;
    require(expectedV1Sentinels(page_size, &sentinel_32, &sentinel_64),
            "failed to construct v1 hierarchy sentinel values");
    require(sentinel_32 <= UINT64_MAX - page_size && sentinel_64 <= UINT64_MAX - page_size,
            "v1 hierarchy sentinel neighbor would overflow");

    char sentinel_32_text[64];
    char sentinel_64_text[64];
    char above_32_text[64];
    char above_64_text[64];
    require(snprintf(sentinel_32_text, sizeof(sentinel_32_text), "%" PRIu64 "\n", sentinel_32) > 0 &&
                snprintf(sentinel_64_text, sizeof(sentinel_64_text), "%" PRIu64 "\n", sentinel_64) > 0 &&
                snprintf(above_32_text, sizeof(above_32_text), "%" PRIu64 "\n", sentinel_32 + page_size) > 0 &&
                snprintf(above_64_text, sizeof(above_64_text), "%" PRIu64 "\n", sentinel_64 + page_size) > 0,
            "failed to format v1 hierarchy sentinel values");

    linux_fixture_t known_32 = {0};
    fixtureSetKernelEnvironment(&known_32, kSystemMemoryLinuxKernelLong32, page_size);
    setupTwoLevelV1(&known_32, sentinel_32_text, sentinel_32_text);
    system_memory_linux_resolution_t resolution;
    require(resolveFixture(&known_32, "5:memory:/child\n", mountinfo, &resolution) == kSystemMemoryProviderOk,
            "known-32 v1 hierarchy did not resolve");
    system_memory_snapshot_t snapshot = {0};
    require(sampleFixture(&known_32, &resolution, &snapshot) == kSystemMemoryLinuxSampleUnavailable,
            "all-unbounded known-32 v1 hierarchy was published");

    fixtureFind(&known_32, "/cg/memory.limit_in_bytes")->contents = "1000\n";
    require(sampleFixture(&known_32, &resolution, &snapshot) == kSystemMemoryLinuxSampleValid &&
                snapshot.cgroup_current_bytes == 200 && snapshot.cgroup_limit_bytes == 1000,
            "known-32 unbounded leaf hid an ordinary finite parent");

    fixtureFind(&known_32, "/cg/child/memory.limit_in_bytes")->contents = "500\n";
    fixtureFind(&known_32, "/cg/memory.limit_in_bytes")->contents       = sentinel_32_text;
    snapshot                                                            = (system_memory_snapshot_t) {0};
    require(sampleFixture(&known_32, &resolution, &snapshot) == kSystemMemoryLinuxSampleValid &&
                snapshot.cgroup_current_bytes == 100 && snapshot.cgroup_limit_bytes == 500,
            "known-32 unbounded parent hid an ordinary finite leaf");

    fixtureFind(&known_32, "/cg/child/memory.limit_in_bytes")->contents = above_32_text;
    require(sampleFixture(&known_32, &resolution, &snapshot) == kSystemMemoryLinuxSampleUnavailable,
            "known-32 value above the kernel maximum did not make the v1 sample unavailable");

    linux_fixture_t known_64 = {0};
    fixtureSetKernelEnvironment(&known_64, kSystemMemoryLinuxKernelLong64, page_size);
    setupTwoLevelV1(&known_64, sentinel_64_text, sentinel_64_text);
    require(resolveFixture(&known_64, "5:memory:/child\n", mountinfo, &resolution) == kSystemMemoryProviderOk,
            "known-64 v1 hierarchy did not resolve");
    snapshot = (system_memory_snapshot_t) {0};
    require(sampleFixture(&known_64, &resolution, &snapshot) == kSystemMemoryLinuxSampleUnavailable,
            "all-unbounded known-64 v1 hierarchy was published");

    fixtureFind(&known_64, "/cg/child/memory.limit_in_bytes")->contents = sentinel_32_text;
    snapshot                                                            = (system_memory_snapshot_t) {0};
    require(sampleFixture(&known_64, &resolution, &snapshot) == kSystemMemoryLinuxSampleValid &&
                snapshot.cgroup_current_bytes == 100 && snapshot.cgroup_limit_bytes == sentinel_32,
            "known-64 kernel misclassified the exact 32-bit sentinel candidate as unbounded");

    fixtureFind(&known_64, "/cg/child/memory.limit_in_bytes")->contents = above_64_text;
    require(sampleFixture(&known_64, &resolution, &snapshot) == kSystemMemoryLinuxSampleUnavailable,
            "known-64 value above the kernel maximum did not make the v1 sample unavailable");
}

static void addAliasDirectories(linux_fixture_t *fixture)
{
    fixtureAddDirectory(fixture, "/wide", 0, 26, 500);
    fixtureAddDirectory(fixture, "/wide/a/b", 0, 26, 599);
    fixtureAddDirectory(fixture, "/narrow", 0, 26, 501);
    fixtureAddDirectory(fixture, "/narrow/b", 0, 26, 599);
}

static void testDeterministicCandidateSelection(void)
{
    static const char aliases_a[] = "20 10 0:26 /a /narrow rw - cgroup2 cgroup rw\n"
                                    "21 10 0:26 / /wide rw - cgroup2 cgroup rw\n";
    static const char aliases_b[] = "21 10 0:26 / /wide rw - cgroup2 cgroup rw\n"
                                    "20 10 0:26 /a /narrow rw - cgroup2 cgroup rw\n";
    linux_fixture_t   fixture     = {0};
    addAliasDirectories(&fixture);
    system_memory_linux_resolution_t first;
    system_memory_linux_resolution_t second;
    require(resolveFixture(&fixture, "0::/a/b\n", aliases_a, &first) == kSystemMemoryProviderOk &&
                resolveFixture(&fixture, "0::/a/b\n", aliases_b, &second) == kSystemMemoryProviderOk &&
                strcmp(first.leaf_path, "/wide/a/b") == 0 && strcmp(second.leaf_path, first.leaf_path) == 0 &&
                strcmp(first.boundary_path, "/wide") == 0,
            "same-identity aliases depended on mountinfo order or hid the widest boundary");

    static const char relative_a[] = "30 10 0:26 /ns/one /r1 rw - cgroup2 cgroup rw\n"
                                     "31 10 0:26 /ns/two /r2 rw - cgroup2 cgroup rw\n";
    static const char relative_b[] = "31 10 0:26 /ns/two /r2 rw - cgroup2 cgroup rw\n"
                                     "30 10 0:26 /ns/one /r1 rw - cgroup2 cgroup rw\n";
    linux_fixture_t   relative     = {0};
    fixtureAddDirectory(&relative, "/r1", 0, 26, 510);
    fixtureAddDirectory(&relative, "/r1/child", 0, 26, 511);
    fixtureAddDirectory(&relative, "/r2", 0, 26, 520);
    fixtureAddDirectory(&relative, "/r2/child", 0, 26, 521);
    require(resolveFixture(&relative, "0::/child\n", relative_a, &first) == kSystemMemoryProviderUnavailable &&
                resolveFixture(&relative, "0::/child\n", relative_b, &first) == kSystemMemoryProviderUnavailable,
            "distinct readable namespace-relative candidates did not fail independent of order");

    static const char coincident_relative_a[] = "60 10 8:1 / /ordinary rw - ext4 /dev/test rw\n"
                                                "61 10 0:26 /other /other-cgroup rw - cgroup2 cgroup rw\n"
                                                "62 10 0:26 /tenant /coincident rw - cgroup2 cgroup rw\n"
                                                "63 10 8:2 / /ordinary-two rw - ext4 /dev/test2 rw\n";
    static const char coincident_relative_b[] = "63 10 8:2 / /ordinary-two rw - ext4 /dev/test2 rw\n"
                                                "62 10 0:26 /tenant /coincident rw - cgroup2 cgroup rw\n"
                                                "61 10 0:26 /other /other-cgroup rw - cgroup2 cgroup rw\n"
                                                "60 10 8:1 / /ordinary rw - ext4 /dev/test rw\n";
    linux_fixture_t   coincident_relative     = {0};
    fixtureAddDirectory(&coincident_relative, "/coincident", 0, 26, 525);
    fixtureAddDirectory(&coincident_relative, "/coincident/tenant/leaf", 0, 26, 526);
    require(
        resolveFixture(&coincident_relative, "0::/tenant/leaf\n", coincident_relative_a, &first) ==
                kSystemMemoryProviderOk &&
            strcmp(first.leaf_path, "/coincident/tenant/leaf") == 0 &&
            resolveFixture(&coincident_relative, "0::/tenant/leaf\n", coincident_relative_b, &second) ==
                kSystemMemoryProviderOk &&
            strcmp(second.leaf_path, first.leaf_path) == 0,
        "a syntactically direct but missing path hid a valid namespace-relative mapping or made it order-dependent");

    static const char direct_and_relative[] = "40 10 0:26 / /direct rw - cgroup2 cgroup rw\n"
                                              "41 10 0:26 /namespace /relative rw - cgroup2 cgroup rw\n";
    linux_fixture_t   precedence            = {0};
    fixtureAddDirectory(&precedence, "/direct", 0, 26, 530);
    fixtureAddDirectory(&precedence, "/direct/child", 0, 26, 531);
    fixtureAddDirectory(&precedence, "/relative", 0, 26, 540);
    fixtureAddDirectory(&precedence, "/relative/child", 0, 26, 541);
    require(resolveFixture(&precedence, "0::/child\n", direct_and_relative, &first) == kSystemMemoryProviderOk &&
                strcmp(first.leaf_path, "/direct/child") == 0,
            "readable namespace-relative impostor overrode an unambiguous direct mapping");

    linux_fixture_t inaccessible = {0};
    fixtureAddDirectory(&inaccessible, "/one", 0, 26, 550);
    fixtureAddDirectory(&inaccessible, "/one/child", 0, 26, 551);
    fixtureAddDirectory(&inaccessible, "/two", 0, 27, 560);
    fixture_file_t *inaccessible_leaf  = fixtureAddDirectory(&inaccessible, "/two/child", 0, 27, 561);
    inaccessible_leaf->identity_status = kSystemMemoryLinuxFsInaccessible;
    require(resolveFixture(&inaccessible,
                           "0::/child\n",
                           "50 10 0:26 / /one rw - cgroup2 cgroup rw\n"
                           "51 10 0:27 / /two rw - cgroup2 cgroup rw\n",
                           &first) == kSystemMemoryProviderUnavailable,
            "inaccessible applicable candidate did not prevent uniqueness proof");

    linux_fixture_t wrong_leaf_device = {0};
    fixtureAddDirectory(&wrong_leaf_device, "/wrong-leaf", 0, 26, 570);
    fixtureAddDirectory(&wrong_leaf_device, "/wrong-leaf/child", 0, 27, 571);
    require(resolveFixture(
                &wrong_leaf_device, "0::/child\n", "52 10 0:26 / /wrong-leaf rw - cgroup2 cgroup rw\n", &first) ==
                kSystemMemoryProviderUnavailable,
            "leaf directory on the wrong mountinfo device was accepted");

    linux_fixture_t wrong_boundary_device = {0};
    fixtureAddDirectory(&wrong_boundary_device, "/wrong-boundary", 0, 27, 580);
    fixtureAddDirectory(&wrong_boundary_device, "/wrong-boundary/child", 0, 26, 581);
    require(resolveFixture(&wrong_boundary_device,
                           "0::/child\n",
                           "53 10 0:26 / /wrong-boundary rw - cgroup2 cgroup rw\n",
                           &first) == kSystemMemoryProviderUnavailable,
            "boundary directory on the wrong mountinfo device was accepted");

    linux_fixture_t same_inode_different_device = {0};
    fixtureAddDirectory(&same_inode_different_device, "/dev-a", 0, 26, 590);
    fixtureAddDirectory(&same_inode_different_device, "/dev-a/child", 0, 26, 599);
    fixtureAddDirectory(&same_inode_different_device, "/dev-b", 0, 27, 591);
    fixtureAddDirectory(&same_inode_different_device, "/dev-b/child", 0, 27, 599);
    require(resolveFixture(&same_inode_different_device,
                           "0::/child\n",
                           "54 10 0:26 / /dev-a rw - cgroup2 cgroup rw\n"
                           "55 10 0:27 / /dev-b rw - cgroup2 cgroup rw\n",
                           &first) == kSystemMemoryProviderUnavailable,
            "equal inode numbers on different devices were treated as one cgroup");

    linux_fixture_t distinct_direct = {0};
    fixtureAddDirectory(&distinct_direct, "/direct-a", 0, 26, 592);
    fixtureAddDirectory(&distinct_direct, "/direct-a/child", 0, 26, 593);
    fixtureAddDirectory(&distinct_direct, "/direct-b", 0, 26, 594);
    fixtureAddDirectory(&distinct_direct, "/direct-b/child", 0, 26, 595);
    require(resolveFixture(&distinct_direct,
                           "0::/child\n",
                           "56 10 0:26 / /direct-a rw - cgroup2 cgroup rw\n"
                           "57 10 0:26 / /direct-b rw - cgroup2 cgroup rw\n",
                           &first) == kSystemMemoryProviderUnavailable,
            "distinct readable direct cgroup identities did not fail closed");
}

static void testCanonicalPathsEscapesAndDepth(void)
{
    system_memory_linux_resolution_t resolution;
    linux_fixture_t                  fixture = {0};
    fixtureAddDirectory(&fixture, "/cg", 0, 26, 600);
    fixtureAddDirectory(&fixture, "/cg/tenant2", 0, 26, 601);
    require(resolveFixture(&fixture, "0::/tenant2\n", "60 10 0:26 /tenant /cg rw - cgroup2 cgroup rw\n", &resolution) ==
                    kSystemMemoryProviderOk &&
                strcmp(resolution.leaf_path, "/cg/tenant2") == 0,
            "component-aware namespace fallback did not distinguish /tenant from /tenant2");
    require(resolveFixture(&fixture, "0::/../escape\n", "60 10 0:26 / /cg rw - cgroup2 cgroup rw\n", &resolution) ==
                kSystemMemoryProviderUnavailable,
            "upward traversal membership was accepted");
    require(resolveFixture(&fixture, "0::/a/../../escape\n", NULL, &resolution) == kSystemMemoryProviderUnavailable,
            "nested upward traversal membership was accepted");
    require(resolveFixture(&fixture, "0::/./a\n", NULL, &resolution) == kSystemMemoryProviderUnavailable,
            "dot membership component was accepted");
    require(resolveFixture(&fixture, "0::/a//b\n", NULL, &resolution) == kSystemMemoryProviderUnavailable,
            "repeated membership separator was accepted");

    linux_fixture_t dot_worker = {0};
    fixtureAddDirectory(&dot_worker, "/cg", 0, 26, 610);
    fixtureAddDirectory(&dot_worker, "/cg/..worker", 0, 26, 611);
    require(resolveFixture(&dot_worker, "0::/..worker\n", "61 10 0:26 / /cg rw - cgroup2 cgroup rw\n", &resolution) ==
                kSystemMemoryProviderOk,
            "ordinary '..worker' component was rejected");
    require(resolveFixture(&dot_worker,
                           "0::/..worker\n",
                           "61 10 0:26 / /cg rw - cgroup2 cgroup rw\n"
                           "malformed later mountinfo line\n",
                           &resolution) == kSystemMemoryProviderUnavailable,
            "a valid early candidate excused malformed later mountinfo input");

    char decoded[32];
    require(systemMemoryLinuxTestDecodeMountPath("/a\\040b", decoded, sizeof(decoded)) && strcmp(decoded, "/a b") == 0,
            "canonical mountinfo space escape was rejected");
    require(systemMemoryLinuxTestDecodeMountPath("/a\\011b", decoded, sizeof(decoded)) && decoded[2] == '\t',
            "canonical mountinfo tab escape was rejected");
    require(systemMemoryLinuxTestDecodeMountPath("/a\\012b", decoded, sizeof(decoded)) && decoded[2] == '\n',
            "canonical mountinfo newline escape was rejected");
    require(systemMemoryLinuxTestDecodeMountPath("/a\\134b", decoded, sizeof(decoded)) && decoded[2] == '\\',
            "canonical mountinfo backslash escape was rejected");
    static const char *invalid_escapes[] = {"/a\\", "/a\\1", "/a\\12", "/a\\08x", "/a\\400", "/a\\401", "/a\\777"};
    for (size_t index = 0; index < ARRAY_SIZE(invalid_escapes); ++index)
    {
        require(! systemMemoryLinuxTestDecodeMountPath(invalid_escapes[index], decoded, sizeof(decoded)),
                "noncanonical or overflowing mountinfo escape was accepted");
    }
    char exact[8];
    require(systemMemoryLinuxTestDecodeMountPath("/123456", exact, sizeof(exact)),
            "exact-capacity decoded mount path was rejected");
    require(! systemMemoryLinuxTestDecodeMountPath("/1234567", exact, sizeof(exact)),
            "one-byte-over-capacity decoded mount path was accepted");

    const size_t exact_membership_length = kSystemMemoryLinuxPathCapacity - strlen("/cg") - 1U;
    char        *exact_membership        = memoryAllocate(exact_membership_length + 1U);
    char        *over_membership         = memoryAllocate(exact_membership_length + 2U);
    char        *exact_cgroup            = memoryAllocate(exact_membership_length + 5U);
    char        *over_cgroup             = memoryAllocate(exact_membership_length + 6U);
    char        *exact_leaf              = memoryAllocate(kSystemMemoryLinuxPathCapacity);
    require(exact_membership != NULL && over_membership != NULL && exact_cgroup != NULL && over_cgroup != NULL &&
                exact_leaf != NULL,
            "failed to allocate canonical path-capacity fixtures");
    exact_membership[0] = '/';
    memorySet(exact_membership + 1U, 'x', exact_membership_length - 1U);
    exact_membership[exact_membership_length] = '\0';
    memoryCopy(over_membership, exact_membership, exact_membership_length);
    over_membership[exact_membership_length]      = 'y';
    over_membership[exact_membership_length + 1U] = '\0';
    require(snprintf(exact_cgroup, exact_membership_length + 5U, "0::%s\n", exact_membership) > 0 &&
                snprintf(over_cgroup, exact_membership_length + 6U, "0::%s\n", over_membership) > 0 &&
                snprintf(exact_leaf, kSystemMemoryLinuxPathCapacity, "/cg%s", exact_membership) ==
                    (int) kSystemMemoryLinuxPathCapacity - 1,
            "failed to construct exact cgroup path-capacity inputs");

    linux_fixture_t path_capacity = {0};
    fixtureAddDirectory(&path_capacity, "/cg", 0, 26, 615);
    fixtureAddDirectory(&path_capacity, exact_leaf, 0, 26, 616);
    static const char capacity_mountinfo[] = "64 10 0:26 / /cg rw - cgroup2 cgroup rw\n";
    require(resolveFixture(&path_capacity, exact_cgroup, capacity_mountinfo, &resolution) == kSystemMemoryProviderOk &&
                strlen(resolution.leaf_path) == kSystemMemoryLinuxPathCapacity - 1U,
            "an exact-capacity canonical membership/root join was rejected");
    const unsigned int identity_calls_before_overflow = path_capacity.identity_calls;
    require(resolveFixture(&path_capacity, over_cgroup, capacity_mountinfo, &resolution) ==
                    kSystemMemoryProviderUnavailable &&
                path_capacity.identity_calls == identity_calls_before_overflow,
            "a one-byte-over-capacity membership/root join reached the filesystem seam");
    memoryFree(exact_leaf);
    memoryFree(over_cgroup);
    memoryFree(exact_cgroup);
    memoryFree(over_membership);
    memoryFree(exact_membership);

    char membership[1024] = "/";
    for (unsigned int index = 0; index < 63U; ++index)
    {
        char component[12];
        require(snprintf(component, sizeof(component), "n%u%s", index, index == 62U ? "" : "/") > 0,
                "failed to build depth component");
        strcat(membership, component);
    }
    strcat(membership, "\n");
    linux_fixture_t depth = {0};
    fixtureAddDirectory(&depth, "/cg", 0, 26, 620);
    char leaf[kSystemMemoryLinuxPathCapacity];
    require(snprintf(leaf, sizeof(leaf), "/cg/%.*s", (int) strlen(membership) - 2, membership + 1U) > 0,
            "failed to build depth leaf");
    fixtureAddDirectory(&depth, leaf, 0, 26, 621);
    char cgroup_line[1100];
    require(snprintf(cgroup_line, sizeof(cgroup_line), "0::%s", membership) > 0,
            "failed to build 64-level cgroup membership line");
    const system_memory_provider_result_t depth_result =
        resolveFixture(&depth, cgroup_line, "62 10 0:26 / /cg rw - cgroup2 cgroup rw\n", &resolution);
    require(depth_result == kSystemMemoryProviderOk && resolution.depth == 64,
            "exact 64-level cgroup chain was rejected");
    memoryCopy(membership + strlen(membership) - 1U, "/overflow\n", sizeof("/overflow\n"));
    require(snprintf(cgroup_line, sizeof(cgroup_line), "0::%s", membership) > 0,
            "failed to build 65-level cgroup membership line");
    require(snprintf(leaf, sizeof(leaf), "/cg/%.*s", (int) strlen(membership) - 2, membership + 1U) > 0,
            "failed to build 65-level leaf");
    fixtureAddDirectory(&depth, leaf, 0, 26, 622);
    require(resolveFixture(&depth, cgroup_line, "62 10 0:26 / /cg rw - cgroup2 cgroup rw\n", &resolution) ==
                kSystemMemoryProviderUnavailable,
            "65-level cgroup chain was truncated instead of rejected");
}

static void testIdentityReplacement(void)
{
    static const char mountinfo[] = "70 10 0:26 / /cg rw - cgroup2 cgroup rw\n";
    linux_fixture_t   fixture     = {0};
    fixture_file_t   *boundary    = fixtureAddDirectory(&fixture, "/cg", 0, 26, 700);
    fixture_file_t   *leaf        = fixtureAddDirectory(&fixture, "/cg/leaf", 0, 26, 701);
    fixture_file_t   *current     = fixtureAddAccounting(&fixture, "/cg/leaf/memory.current", "10\n", 0, 26, 710);
    fixture_file_t   *limit       = fixtureAddAccounting(&fixture, "/cg/leaf/memory.max", "100\n", 0, 26, 711);
    addV2Level(&fixture, "/cg", "1\n", "max\n", 720);

    system_memory_linux_resolution_t resolution;
    require(resolveFixture(&fixture, "0::/leaf\n", mountinfo, &resolution) == kSystemMemoryProviderOk,
            "identity fixture did not resolve");
    system_memory_snapshot_t snapshot = {0};
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleValid,
            "identity fixture did not establish accounting identities");
    current->identity.inode++;
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleResolutionInvalid,
            "same-device accounting-file replacement did not invalidate resolution");
    current->identity.inode--;
    limit->identity.inode++;
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleResolutionInvalid,
            "same-device accounting-limit replacement did not invalidate resolution");
    limit->identity.inode--;
    leaf->identity.inode++;
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleResolutionInvalid,
            "same-device leaf recreation did not invalidate resolution");
    leaf->identity.inode--;
    boundary->identity.device_minor = 27;
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleResolutionInvalid,
            "boundary device replacement did not invalidate resolution");
    boundary->identity.device_minor = 26;
    boundary->identity.inode++;
    require(sampleFixture(&fixture, &resolution, &snapshot) == kSystemMemoryLinuxSampleResolutionInvalid,
            "same-device boundary recreation did not invalidate resolution");
}

static void testBoundedReadClassification(void)
{
    require(systemMemoryLinuxTestClassifyBoundedRead(8, 3, false, 0, EOF, false, 0, false, 0) == kSystemMemoryLinuxFsOk,
            "short bounded read success was misclassified");
    require(systemMemoryLinuxTestClassifyBoundedRead(8, 7, false, 0, EOF, false, 0, false, 0) == kSystemMemoryLinuxFsOk,
            "exact-fit clean EOF was misclassified");
    require(systemMemoryLinuxTestClassifyBoundedRead(8, 7, false, 0, 'x', false, 0, false, 0) ==
                kSystemMemoryLinuxFsTruncated,
            "byte beyond bounded capacity was not classified truncated");
    require(systemMemoryLinuxTestClassifyBoundedRead(8, 7, false, 0, 'x', false, 0, true, EIO) ==
                kSystemMemoryLinuxFsTruncated,
            "close failure incorrectly replaced an earlier truncation result");
    require(systemMemoryLinuxTestClassifyBoundedRead(8, 2, true, EIO, EOF, false, 0, false, 0) ==
                kSystemMemoryLinuxFsError,
            "initial fread failure was not classified as error");
    require(systemMemoryLinuxTestClassifyBoundedRead(8, 7, false, 0, EOF, true, EIO, false, 0) ==
                kSystemMemoryLinuxFsError,
            "probe EOF with stream error was not classified as error");
    require(systemMemoryLinuxTestClassifyBoundedRead(8, 7, false, 0, EOF, true, 0, false, 0) ==
                kSystemMemoryLinuxFsError,
            "probe error without errno did not use a generic filesystem error");
    require(systemMemoryLinuxTestClassifyBoundedRead(8, 3, false, 0, EOF, false, 0, true, EIO) ==
                kSystemMemoryLinuxFsError,
            "close failure was not classified as error");
}

static void testCachedProviderStateAndGetter(void)
{
    static const char cgroup_text[]    = "0::/tenant/leaf\n";
    static const char mountinfo_text[] = "80 10 0:26 / /cg rw - cgroup2 cgroup rw\n";
    static const char meminfo_text[]   = "MemTotal: 1000 kB\nMemAvailable: 500 kB\n";
    linux_fixture_t   fixture          = {.now_ms = 100};
    fixtureAdd(&fixture,
               "/proc/self/cgroup",
               cgroup_text,
               kSystemMemoryLinuxFsOk,
               kSystemMemoryLinuxFsOk,
               identity(0, 0, 1, kSystemMemoryLinuxFsTypeRegular));
    fixtureAdd(&fixture,
               "/proc/self/mountinfo",
               mountinfo_text,
               kSystemMemoryLinuxFsOk,
               kSystemMemoryLinuxFsOk,
               identity(0, 0, 2, kSystemMemoryLinuxFsTypeRegular));
    fixtureAdd(&fixture,
               "/proc/meminfo",
               meminfo_text,
               kSystemMemoryLinuxFsOk,
               kSystemMemoryLinuxFsOk,
               identity(0, 0, 3, kSystemMemoryLinuxFsTypeRegular));
    setupThreeLevelV2(&fixture);
    addV2Level(&fixture, "/cg/tenant/leaf", "1\n", "max\n", 800);
    addV2Level(&fixture, "/cg/tenant", "2\n", "max\n", 810);
    fixture_file_t *boundary_current = fixtureAddAccounting(&fixture, "/cg/memory.current", "3\n", 0, 26, 820);
    fixture_file_t *boundary_limit   = fixtureAddAccounting(&fixture, "/cg/memory.max", "max\n", 0, 26, 821);

    system_load_state_t sampler = {0};
    require(systemLoadSamplerTryInit(&sampler), "failed to initialize cached Linux provider fixture");
    const system_memory_linux_io_t io = fixtureIO(&fixture);
    systemLoadSamplerSetLinuxMemoryTestHooks(&sampler, &io, fixtureNow, &fixture);
    const unsigned int discovery_reads = fixture.cgroup_reads;
    discard            systemLoadSamplerUpdate(&sampler);
    fixture.now_ms = 600;
    discard systemLoadSamplerUpdate(&sampler);
    require(fixture.cgroup_reads == discovery_reads && fixture.mountinfo_reads == discovery_reads,
            "stable all-unbounded hierarchy triggered rediscovery");

    boundary_limit->contents = "100\n";
    fixture.now_ms           = 1100;
    require(systemLoadSamplerUpdate(&sampler), "cached unbounded level did not recover when its max became finite");
    require(fixture.cgroup_reads == discovery_reads, "finite recovery unnecessarily reread cgroup membership");

    system_load_state_t *saved_sampler = GSTATE.system_load;
    GSTATE.system_load                 = &sampler;
    system_memory_snapshot_t snapshot;
    require(systemMemorySnapshotGet(&snapshot) == kSystemMemorySnapshotFresh && snapshot.cgroup_limited &&
                snapshot.cgroup_current_bytes == 3 && snapshot.cgroup_limit_bytes == 100 &&
                snapshot.cgroup_available_bytes == 97,
            "cached hierarchy did not publish coherent pressure and headroom");
    const unsigned int reads_before_getter      = fixture.read_calls;
    const unsigned int identity_before_getter   = fixture.identity_calls;
    const unsigned int accounting_before_getter = fixture.accounting_calls;
    require(systemMemorySnapshotGet(&snapshot) == kSystemMemorySnapshotFresh &&
                fixture.read_calls == reads_before_getter && fixture.identity_calls == identity_before_getter &&
                fixture.accounting_calls == accounting_before_getter,
            "cached getter invoked a provider, identity, or accounting callback");

    fixtureFind(&fixture, "/cg/tenant")->identity_status = kSystemMemoryLinuxFsMissing;
    fixture.now_ms                                       = 1600;
    discard systemLoadSamplerUpdate(&sampler);
    require(fixture.cgroup_reads == discovery_reads + 1U,
            "disappearing ancestor did not trigger one bounded rediscovery");
    fixtureFind(&fixture, "/cg/tenant")->identity_status = kSystemMemoryLinuxFsOk;
    fixture.now_ms                                       = 1700;
    require(systemLoadSamplerUpdate(&sampler), "cached hierarchy did not recover after ancestor reappeared");
    require(fixture.cgroup_reads == discovery_reads + 1U, "ancestor recovery performed an unnecessary rediscovery");

    boundary_current->read_status = kSystemMemoryLinuxFsInaccessible;
    fixture.now_ms                = 1800;
    discard systemLoadSamplerUpdate(&sampler);
    require(fixture.cgroup_reads == discovery_reads + 1U,
            "transient accounting read error invalidated the cached resolution");

    GSTATE.system_load = saved_sampler;
    systemLoadSamplerDestroy(&sampler);
}

static void testAmbiguousV1SentinelRetainsCachedResolution(void)
{
    static const char cgroup_text[]    = "5:memory:/child\n";
    static const char mountinfo_text[] = "90 10 0:26 / /cg rw - cgroup cgroup rw,memory\n";
    static const char meminfo_text[]   = "MemTotal: 1000 kB\nMemAvailable: 500 kB\n";
    uint64_t          sentinel_32;
    uint64_t          sentinel_64;
    require(expectedV1Sentinels(4096U, &sentinel_32, &sentinel_64),
            "failed to construct ambiguous v1 provider sentinel");
    discard sentinel_64;
    char    sentinel_32_text[64];
    require(snprintf(sentinel_32_text, sizeof(sentinel_32_text), "%" PRIu64 "\n", sentinel_32) > 0,
            "failed to format ambiguous v1 provider sentinel");

    linux_fixture_t fixture = {.now_ms = 100};
    fixtureSetKernelEnvironment(&fixture, kSystemMemoryLinuxKernelLongUnknown, 4096U);
    fixtureAdd(&fixture,
               "/proc/self/cgroup",
               cgroup_text,
               kSystemMemoryLinuxFsOk,
               kSystemMemoryLinuxFsOk,
               identity(0, 0, 900, kSystemMemoryLinuxFsTypeRegular));
    fixtureAdd(&fixture,
               "/proc/self/mountinfo",
               mountinfo_text,
               kSystemMemoryLinuxFsOk,
               kSystemMemoryLinuxFsOk,
               identity(0, 0, 901, kSystemMemoryLinuxFsTypeRegular));
    fixtureAdd(&fixture,
               "/proc/meminfo",
               meminfo_text,
               kSystemMemoryLinuxFsOk,
               kSystemMemoryLinuxFsOk,
               identity(0, 0, 902, kSystemMemoryLinuxFsTypeRegular));
    fixtureAddDirectory(&fixture, "/cg", 0, 26, 910);
    fixtureAddDirectory(&fixture, "/cg/child", 0, 26, 911);
    addV1Level(&fixture, "/cg/child", "100\n", sentinel_32_text, "1\n", 920);
    addV1Level(&fixture, "/cg", "200\n", "1000\n", "1\n", 930);

    system_load_state_t sampler = {0};
    require(systemLoadSamplerTryInit(&sampler), "failed to initialize ambiguous v1 provider fixture");
    const system_memory_linux_io_t io = fixtureIO(&fixture);
    systemLoadSamplerSetLinuxMemoryTestHooks(&sampler, &io, fixtureNow, &fixture);
    const unsigned int discovery_reads = fixture.cgroup_reads;
    require(discovery_reads == 1U && fixture.mountinfo_reads == 1U,
            "ambiguous v1 provider fixture did not perform one initial discovery");

    system_load_state_t *saved_sampler = GSTATE.system_load;
    GSTATE.system_load                 = &sampler;
    system_memory_snapshot_t snapshot;
    discard                  systemLoadSamplerUpdate(&sampler);
    require(systemMemorySnapshotGet(&snapshot) == kSystemMemorySnapshotUnavailable,
            "ambiguous v1 sentinel did not make the cached sample unavailable");
    fixture.now_ms = 600;
    discard systemLoadSamplerUpdate(&sampler);
    require(fixture.cgroup_reads == discovery_reads && fixture.mountinfo_reads == discovery_reads,
            "ambiguous v1 sentinel invalidated and rediscovered a sound cached hierarchy");

    fixtureFind(&fixture, "/cg/child/memory.limit_in_bytes")->contents = "500\n";
    fixture.now_ms                                                     = 1100;
    discard systemLoadSamplerUpdate(&sampler);
    require(systemMemorySnapshotGet(&snapshot) == kSystemMemorySnapshotFresh && snapshot.cgroup_limited &&
                snapshot.cgroup_current_bytes == 100 && snapshot.cgroup_limit_bytes == 500 &&
                fixture.cgroup_reads == discovery_reads,
            "cached v1 hierarchy did not recover from an ambiguous sentinel without rediscovery");

    GSTATE.system_load = saved_sampler;
    systemLoadSamplerDestroy(&sampler);
}

int main(void)
{
    testV1LimitClassifier();
    testKernelLongWidthDetection();
    testHierarchicalV2Sampling();
    testMissingPairsAndAllUnbounded();
    testV1Hierarchy();
    testV1KernelSentinelHierarchies();
    testDeterministicCandidateSelection();
    testCanonicalPathsEscapesAndDepth();
    testIdentityReplacement();
    testBoundedReadClassification();
    testCachedProviderStateAndGetter();
    testAmbiguousV1SentinelRetainsCachedResolution();
    puts("system_memory_linux_provider_test: all cases passed");
    return 0;
}
