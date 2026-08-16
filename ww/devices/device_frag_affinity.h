#pragma once

/*
 * Keeps every packet of one device-originated IPv4 transport flow on one worker,
 * fragmented or not.
 *
 * The flow hash cannot do this on its own. A fragment past offset zero carries no
 * ports, so deviceFlowAffinityHash() substitutes the IPv4 identification - which
 * is stable across the fragments of one datagram and different for every datagram
 * of the same flow. The two hashes therefore disagree, and the worker they pick
 * is the worker that owns the flow: PacketsToConnection builds one netif, one
 * route and one UDP flow table per packet worker, and patched TCP/UDP pcbs are
 * netif-specific. So a fragmented UDP datagram opens a second WaterWall flow
 * beside the unfragmented one, and a fragmented TCP SYN establishes state on a
 * netif the following unfragmented ACK never reaches.
 *
 * This table fixes it where worker ownership is actually chosen. Fragment zero
 * is hashed with the fragment bits masked out, so its ports select the same
 * worker an unfragmented packet of that flow would, and the rest of the datagram
 * inherits that answer. Tails that overtake fragment zero are held until it
 * arrives and then released ahead of it, in arrival order.
 *
 * Everything about it is bounded: associations, staged fragments per association,
 * staged bytes overall, and a lifetime. Traffic that never sends fragment zero
 * is the expected hostile case, and it can only occupy the caps until they expire.
 *
 * IPv4 only, deliberately. Classification and staged-buffer ownership run on
 * the device reader thread, while settlement and generation transitions also
 * run on event-worker/lifecycle threads. The table mutex protects that shared
 * metadata; staged buffers are returned only where the release-pool ownership
 * contract explicitly permits it.
 */

#include "buffer_pool.h"
#include "devices/device_frag_settlement.h"
#include "wlibc.h"
#include "worker.h"

#include "lwip/ip4_frag.h"

typedef struct device_frag_affinity_table_s device_frag_affinity_table_t;

enum
{
    /* Datagrams tracked at once. */
    kDeviceFragAffinityMaxEntries = 256,

    /*
     * Identities held after their association was released, so a datagram whose
     * residue in reassembly is unknown cannot be re-adopted while lwIP may still
     * hold a prefix of it.
     *
     * These are deliberately not associations: a quarantine record is an identity,
     * a wall-clock deadline, and a synchronized lwIP reassembly-timer epoch barrier,
     * with no staged payload and no coverage ranges. Keeping the full association
     * instead would let ordinary refusals occupy the 256 association slots for a
     * whole reassembly lifetime, which is the throughput ceiling this table was
     * built to avoid.
     */
    kDeviceFragAffinityMaxQuarantine = 512,

    /* Tails one association may hold while waiting for its fragment zero. */
    kDeviceFragAffinityMaxStagedPerEntry = 16,

    /* Disjoint coverage ranges retained for one association. */
    kDeviceFragAffinityMaxRanges = 16,

    /* Staged tails across the whole table. */
    kDeviceFragAffinityMaxStaged = 256,

    /* Reader-buffer payload retained across every association. */
    kDeviceFragAffinityMaxStagedBytes = 1024U * 1024U,

    /*
     * How long an incomplete association lives. lwIP's own reassembly gives up
     * after IP_REASS_MAXAGE seconds; there is no point holding a worker decision
     * for a datagram the stack behind it has already abandoned.
     */
    kDeviceFragAffinityTimeoutMs = 15U * 1000U,

    /*
     * A reassembly entry initialized to IP_REASS_MAXAGE is still present after
     * that many timer calls: the last call changes 1 to 0, and the following
     * call frees it. Unknown residue therefore needs one additional complete
     * IP timer interval. Keep this derived from the headers used to compile
     * both WaterWall and lwIP so an option change cannot silently shorten it.
     */
    kDeviceFragAffinityResidueTimeoutMs = (IP_REASS_MAXAGE + 1U) * IP_TMR_INTERVAL
};

enum
{
    /* Actual ip_reass_tmr() passes required to retire a newly retained key. */
    kDeviceFragAffinityResidueTimerPasses = IP_REASS_MAXAGE + 1U
};

static_assert(kDeviceFragAffinityResidueTimeoutMs >= (IP_REASS_MAXAGE + 1U) * IP_TMR_INTERVAL,
              "fragment residue quarantine is shorter than lwIP reassembly lifetime");

typedef enum device_frag_affinity_action_e
{
    /* This is not an IPv4 fragment; the ordinary flow hash owns the decision. */
    kDeviceFragAffinityNotFragment,

    /* Dispatch this packet, plus any released packets, to result.wid. */
    kDeviceFragAffinityDispatch,

    /* The table owns this packet while it waits for fragment zero. */
    kDeviceFragAffinityStaged,

    /* The table consumed and recycled this packet as part of a whole-datagram drop. */
    kDeviceFragAffinityConsumedDrop
} device_frag_affinity_action_t;

typedef struct device_frag_affinity_publication_s
{
    uint64_t serial;
    uint16_t slot;
    uint16_t count;
    bool     valid;
} device_frag_affinity_publication_t;

/* True only while this exact publication still belongs to an open, healthy generation. */
bool deviceFragAffinityPublicationMayEnter(device_frag_affinity_table_t             *table,
                                           const device_frag_affinity_publication_t *publication);

/*
 * What the table decided about one offered packet.
 *
 * `released` points into scratch owned by the table and stays valid only until
 * the next offer, which is all the caller needs: it posts them immediately.
 */
typedef struct device_frag_affinity_result_s
{
    sbuf_t **released;       /* staged tails this packet unblocked, arrival order */
    uint8_t  released_count; /* they belong to `wid`, and precede the offered buf */

    wid_t wid; /* the worker for `released` and the offered packet */

    /* Retires or poisons the association only after consumer delivery settles. */
    device_frag_affinity_publication_t publication;
} device_frag_affinity_result_t;

/*
 * `release_pool` takes back staged buffers the table drops - on expiry, on reset,
 * and on destruction. It must be the pool the offered buffers came from.
 */
device_frag_affinity_table_t *deviceFragAffinityCreate(buffer_pool_t *release_pool);
void                          deviceFragAffinityDestroy(device_frag_affinity_table_t *table);

/*
 * Returns staged buffers without forgetting anything. Called once the producer
 * has joined and the release pool's thread ownership has been reset, so the
 * lifecycle thread may touch a pool the reader used to own. Poison state and
 * quarantined identities survive, because they are what keeps a reopened
 * generation from re-adopting a datagram whose residue is still unknown.
 */
void deviceFragAffinityReleaseStagedBuffers(device_frag_affinity_table_t *table);

/*
 * The reader producer has joined and the release pool is still alive. Drop all
 * staged buffers, then sever the pool pointer so delayed session destruction
 * cannot dereference device-owned storage.
 */
void deviceFragAffinityRetireReleasePool(device_frag_affinity_table_t *table);

/*
 * Offers one packet. Only kDeviceFragAffinityNotFragment leaves the packet with
 * the ordinary flow hash. Every other action is an explicit dispatch, staging,
 * or consumed-drop ownership decision; the caller must post `released` first
 * for a dispatch and must not independently hash a staged or dropped fragment.
 */
device_frag_affinity_action_t deviceFragAffinityOffer(device_frag_affinity_table_t *table, const uint8_t *packet,
                                                      uint32_t length, sbuf_t *buf, device_frag_affinity_result_t *out);

/*
 * Settles actual consumer delivery or cleanup for the buffers represented by a
 * token. Queue admission alone is not settlement: a paused worker may retain a
 * fragment beyond the reader-side timeout, and a callback that returned is not
 * a consumer that accepted - see device_frag_settlement.h for how the three
 * outcomes are established.
 *
 * Only a factual `NoResidue` result releases an identity. Residue keeps the
 * association reserved, and `Unknown` quarantines it until both a full elapsed
 * reassembly interval and IP_REASS_MAXAGE + 1 actual synchronized timer passes
 * have completed.
 */
void deviceFragAffinitySettlePublication(device_frag_affinity_table_t             *table,
                                         const device_frag_affinity_publication_t *publication,
                                         device_frag_settlement_t                  settlement);

/*
 * Opens fragment classification for a new reader generation. Offers made while
 * no generation is open are consumed and recycled without touching the table.
 */
void deviceFragAffinityBeginGeneration(device_frag_affinity_table_t *table);

/*
 * Closes fragment classification and poisons every incomplete identity.
 *
 * Metadata only: staged reader buffers are deliberately left in place, because
 * this runs on the lifecycle thread while the reader thread still owns the
 * reader buffer pool. They are released by the next generation's reader sweep,
 * or by deviceFragAffinityRetireReleasePool() once the producer has joined.
 */
void deviceFragAffinityEndGeneration(device_frag_affinity_table_t *table);

/*
 * Capture APIs may report IPv4 receive-checksum offload metadata without
 * materializing a valid header checksum in the copied packet. Capture readers
 * use this explicit boundary normalization before fragment admission. TUN has
 * no such provenance: its unfragmented kernel packets are trusted at that
 * adapter boundary, while the fragment-affinity parser validates fragmented
 * IPv4 headers before association.
 */
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
