/**
 * @file wsysinfo_linux.h
 * @brief Internal Linux memory-controller discovery contract.
 *
 * This is a sampler/provider seam, not a MUX API. Production supplies procfs
 * and cgroupfs callbacks; native tests supply deterministic in-memory files.
 */

#pragma once

#include "wsysinfo.h"

#if defined(OS_LINUX)

typedef enum system_memory_linux_fs_status_e
{
    kSystemMemoryLinuxFsOk,
    kSystemMemoryLinuxFsMissing,
    kSystemMemoryLinuxFsInaccessible,
    kSystemMemoryLinuxFsTruncated,
    kSystemMemoryLinuxFsIdentityMismatch,
    kSystemMemoryLinuxFsError,
} system_memory_linux_fs_status_t;

typedef enum system_memory_linux_fs_type_e
{
    kSystemMemoryLinuxFsTypeUnknown,
    kSystemMemoryLinuxFsTypeDirectory,
    kSystemMemoryLinuxFsTypeRegular,
    kSystemMemoryLinuxFsTypeOther,
} system_memory_linux_fs_type_t;

typedef struct system_memory_linux_fs_identity_s
{
    uint32_t                      device_major;
    uint32_t                      device_minor;
    uint64_t                      inode;
    system_memory_linux_fs_type_t type;
} system_memory_linux_fs_identity_t;

typedef enum system_memory_linux_kernel_long_width_e
{
    kSystemMemoryLinuxKernelLongUnknown = 0,
    kSystemMemoryLinuxKernelLong32      = 32,
    kSystemMemoryLinuxKernelLong64      = 64,
} system_memory_linux_kernel_long_width_t;

typedef enum system_memory_linux_v1_limit_class_e
{
    kSystemMemoryLinuxV1LimitFinite,
    kSystemMemoryLinuxV1LimitUnbounded,
    kSystemMemoryLinuxV1LimitUnavailable,
} system_memory_linux_v1_limit_class_t;

typedef system_memory_linux_fs_status_t (*SystemMemoryLinuxReadTextFn)(void *userdata, const char *path, char *buffer,
                                                                       size_t capacity);
typedef system_memory_linux_fs_status_t (*SystemMemoryLinuxIdentityFn)(void *userdata, const char *path,
                                                                       system_memory_linux_fs_identity_t *identity);
typedef system_memory_linux_fs_status_t (*SystemMemoryLinuxReadAccountingFn)(
    void *userdata, const char *path, uint32_t expected_device_major, uint32_t expected_device_minor, char *buffer,
    size_t capacity, system_memory_linux_fs_identity_t *identity);

typedef struct system_memory_linux_io_s
{
    SystemMemoryLinuxReadTextFn             read_text;
    SystemMemoryLinuxIdentityFn             identity;
    SystemMemoryLinuxReadAccountingFn       read_accounting;
    void                                   *userdata;
    system_memory_linux_kernel_long_width_t kernel_long_width;
    uint64_t                                base_page_size_bytes;
} system_memory_linux_io_t;

typedef enum system_memory_linux_cgroup_kind_e
{
    kSystemMemoryLinuxCgroupUnknown,
    kSystemMemoryLinuxCgroupAbsent,
    kSystemMemoryLinuxCgroupV1,
    kSystemMemoryLinuxCgroupV2,
} system_memory_linux_cgroup_kind_t;

enum
{
    kSystemMemoryLinuxPathCapacity    = 8192,
    kSystemMemoryLinuxMaxCgroupLevels = 64,
};

typedef struct system_memory_linux_resolution_s
{
    system_memory_linux_cgroup_kind_t kind;
    char                              leaf_path[kSystemMemoryLinuxPathCapacity];
    char                              boundary_path[kSystemMemoryLinuxPathCapacity];
    system_memory_linux_fs_identity_t leaf_identity;
    system_memory_linux_fs_identity_t boundary_identity;
    uint32_t                          mount_device_major;
    uint32_t                          mount_device_minor;
    uint8_t                           depth;
    uint64_t                          readable_pair_levels;
    uint64_t                          readable_hierarchy_levels;
    system_memory_linux_fs_identity_t current_identities[kSystemMemoryLinuxMaxCgroupLevels];
    system_memory_linux_fs_identity_t limit_identities[kSystemMemoryLinuxMaxCgroupLevels];
    system_memory_linux_fs_identity_t hierarchy_identities[kSystemMemoryLinuxMaxCgroupLevels];
} system_memory_linux_resolution_t;

typedef enum system_memory_linux_sample_result_e
{
    kSystemMemoryLinuxSampleValid,
    kSystemMemoryLinuxSampleUnavailable,
    kSystemMemoryLinuxSampleResolutionInvalid,
} system_memory_linux_sample_result_t;

system_memory_provider_result_t     systemMemoryLinuxResolveCgroup(const char *cgroup_text, const char *mountinfo_text,
                                                                   const system_memory_linux_io_t   *io,
                                                                   system_memory_linux_resolution_t *resolution);
system_memory_linux_sample_result_t systemMemoryLinuxSampleResolvedCgroup(system_memory_linux_resolution_t *resolution,
                                                                          const system_memory_linux_io_t   *io,
                                                                          system_memory_snapshot_t         *snapshot);
system_memory_provider_result_t     systemMemoryLinuxReadResolvedCgroup(system_memory_linux_resolution_t *resolution,
                                                                        const system_memory_linux_io_t   *io,
                                                                        system_memory_snapshot_t         *snapshot);

#ifdef WW_SYSINFO_TEST_SEAM
typedef int (*SystemMemoryLinuxPersonalityFn)(void *userdata, unsigned long personality_value);
typedef int (*SystemMemoryLinuxUnameMachineFn)(void *userdata, char *machine, size_t capacity);

typedef struct system_memory_linux_kernel_test_ops_s
{
    SystemMemoryLinuxPersonalityFn  personality;
    SystemMemoryLinuxUnameMachineFn uname_machine;
    void                           *userdata;
} system_memory_linux_kernel_test_ops_t;

void systemLoadSamplerSetLinuxMemoryTestHooks(system_load_state_t *state, const system_memory_linux_io_t *io,
                                              SystemMemoryNowMsFn now_ms, void *now_userdata);
system_memory_linux_kernel_long_width_t systemMemoryLinuxTestDetectKernelLongWidth(
    size_t userspace_long_size, const system_memory_linux_kernel_test_ops_t *ops);
system_memory_linux_v1_limit_class_t systemMemoryLinuxTestClassifyV1Limit(
    uint64_t limit_bytes, system_memory_linux_kernel_long_width_t kernel_long_width, uint64_t base_page_size_bytes);
bool systemMemoryLinuxTestDecodeMountPath(const char *encoded, char *decoded, size_t capacity);
system_memory_linux_fs_status_t systemMemoryLinuxTestClassifyBoundedRead(size_t capacity, size_t read_length,
                                                                         bool read_failed, int read_error,
                                                                         int probe_value, bool probe_failed,
                                                                         int probe_error, bool close_failed,
                                                                         int close_error);
#endif

#endif
