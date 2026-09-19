#pragma once
#include "buffer_pool.h"
#include "worker.h"

typedef enum device_fragment_policy_e
{
    kDeviceFragmentPolicyUnset = 0,
    kDeviceFragmentReassemble,
    kDeviceFragmentPreserve
} device_fragment_policy_t;
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

typedef enum device_ipv4_checksum_provenance_e
{
    /* The capture API positively reported that the header checksum is valid. */
    kDeviceIpv4ChecksumProvenValid = 0,
    /* The capture API positively reported checksum work that is not ready yet. */
    kDeviceIpv4ChecksumOffloadNotReady,
    /* No trustworthy positive metadata: verify the bytes before admission. */
    kDeviceIpv4ChecksumUntrusted
} device_ipv4_checksum_provenance_t;

typedef struct device_packet_checksum_provenance_s
{
    device_ipv4_checksum_provenance_t ipv4;
    device_ipv4_checksum_provenance_t tcp;
    device_ipv4_checksum_provenance_t udp;
} device_packet_checksum_provenance_t;

/*
 * Materializes trusted offload results and validates untrusted bytes for the
 * IPv4 header and the applicable TCP/UDP transport checksum. Fragmented L4
 * offload cannot be materialized from one fragment and is rejected.
 */
bool deviceIpv4PreparePacketChecksums(uint8_t *packet, uint32_t length, device_packet_checksum_provenance_t provenance);

typedef struct device_packet_checksum_validity_s
{
    bool ipv4;
    bool tcp;
    bool udp;
} device_packet_checksum_validity_t;

/*
 * Which checksums in this packet are provably correct, field by field.
 *
 * Used where a bit must assert a fact rather than a shape: a non-IPv4 or
 * malformed packet proves nothing, a fragment carries no complete transport
 * checksum, and a protocol without one proves nothing about TCP or UDP.
 */
device_packet_checksum_validity_t deviceIpv4ChecksumValidity(const uint8_t *packet, uint32_t length);
