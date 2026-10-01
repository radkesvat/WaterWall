#pragma once
#include "buffer_pool.h"
#include "devices/device_fragment_policy.h"
#include "worker.h"

typedef struct device_frag_affinity_table_s device_frag_affinity_table_t;
enum
{
    kDeviceFragAffinityMaxEntries        = 256,
    kDeviceFragAffinityMaxStagedPerEntry = 16,
    kDeviceFragAffinityMaxRanges         = 16,
    kDeviceFragAffinityMaxStaged         = 256,
    kDeviceFragAffinityMaxStagedBytes    = 32U * 1024U * 1024U,
    kDeviceFragAffinityMaxAssemblyBytes  = 4U * 1024U * 1024U,
    kDeviceFragAffinityMaxFragments      = 8192,
    kDeviceFragAffinityTimeoutMs         = 15000
};
typedef enum device_frag_affinity_action_e
{
    kDeviceFragAffinityNotFragment,  /* Input remains caller-owned. */
    kDeviceFragAffinityDispatch,     /* Raw input and released tails transfer to caller. */
    kDeviceFragAffinityStaged,       /* Input consumed; no output. */
    kDeviceFragAffinityConsumedDrop, /* Input recycled; no output. */
    kDeviceFragAffinityComplete      /* Input consumed; completed is caller-owned. */
} device_frag_affinity_action_t;
typedef struct device_frag_affinity_result_s
{
    sbuf_t **released;
    uint8_t  released_count;
    wid_t    wid;
    sbuf_t  *completed;
} device_frag_affinity_result_t;
device_frag_affinity_table_t *deviceFragAffinityCreate(buffer_pool_t *pool, device_fragment_policy_t policy);
/* Only before publishing a fresh table to its reader. Trust is fixed for its
 * lifetime; fragment shape/bounds and reconstructed header sums remain intact. */
void                          deviceFragAffinityTrustIpv4HeaderChecksum(device_frag_affinity_table_t *table);
void                          deviceFragAffinityDestroy(device_frag_affinity_table_t *table);
void                          deviceFragAffinityBeginGeneration(device_frag_affinity_table_t *table);
/* Metadata only; never recycle from the lifecycle thread before reader join. */
void deviceFragAffinityEndGeneration(device_frag_affinity_table_t *table);
/* Caller has joined the reader and reset exclusive pool ownership. */
void deviceFragAffinityReleaseStagedBuffers(device_frag_affinity_table_t *table);
void deviceFragAffinityRetireReleasePool(device_frag_affinity_table_t *table);
/* Raw released scratch remains valid until the next offer. */
device_frag_affinity_action_t deviceFragAffinityOffer(device_frag_affinity_table_t *table, const uint8_t *packet,
                                                      uint32_t length, sbuf_t *buf, device_frag_affinity_result_t *out);
