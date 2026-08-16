#pragma once

/*
 * Builds and owns ordered tunnel chains, including per-worker line pools and
 * optional packet-side helper lines.
 */

#include "wlibc.h"

#include "generic_pool.h"
#include "worker.h"

typedef struct tunnel_s tunnel_t;
typedef struct line_s   line_t;

enum
{
    kMaxChainLen = (16 * 4)
};

typedef enum
{
    kSCBlocked,
    kSCRequiredBytes,
    kSCSuccessNoData,
    kSCSuccess

} splice_retcode_t;

typedef struct tunnel_array_s
{
    uint16_t  len;
    tunnel_t *tuns[kMaxChainLen];

} tunnel_array_t;

typedef struct tunnel_chain_s
{
    tunnel_array_t  tunnels;
    uint16_t        sum_padding_left;
    uint32_t        sum_line_state_size;
    wid_t           workers_count;
    bool            contains_packet_node : 1;
    bool            mux_tunnel_present : 1;
    bool            packet_chain_init_sent : 1;
    bool            finalized : 1;
    bool            started : 1;
    line_t        **packet_lines;
    master_pool_t  *masterpool_line_pool;
    generic_pool_t *line_pools[];

} tunnel_chain_t;

/**
 * @brief Add one raw left-padding requirement without narrowing or alignment overflow.
 *
 * The returned sum remains unaligned; it is guaranteed that the buffer pool's
 * 32-byte alignment can still represent it as uint16_t.
 */
static inline bool tunnelchainTryAddPadding(uint16_t current, uint16_t additional, uint16_t *sum)
{
    const uint32_t wide_sum    = (uint32_t) current + (uint32_t) additional;
    const uint32_t aligned_sum = (wide_sum + 31U) & ~UINT32_C(31);
    if (sum == NULL || wide_sum > UINT16_MAX || aligned_sum > UINT16_MAX)
    {
        return false;
    }

    *sum = (uint16_t) wide_sum;
    return true;
}

/**
 * Compute the complete generic-pool item size for one line without narrowing.
 *
 * Line-state offsets and generic-pool item sizes are intentionally 32-bit. A
 * state aggregate that leaves no room for line_t must be rejected before a
 * chain publishes it.
 */
bool tunnelchainTryComputeLineItemSize(uint32_t aggregate_lstate_size, uint32_t *item_size);

/**
 * @brief Allocate a new empty tunnel chain for all workers.
 *
 * @param workers_count Total worker count.
 * @return tunnel_chain_t* Allocated chain instance.
 */
tunnel_chain_t *tunnelchainCreate(wid_t workers_count);

/**
 * @brief Finalize chain memory layout and create worker line pools.
 *
 * @param tc Chain instance.
 */
void tunnelchainFinalize(tunnel_chain_t *tc);

/**
 * @brief Destroy a chain and release all worker line resources.
 *
 * @param tc Chain instance.
 */
void tunnelchainDestroy(tunnel_chain_t *tc);

/**
 * @brief Merge all tunnels from source into destination and destroy source.
 *
 * @param destination Destination chain that keeps ownership.
 * @param source Source chain to consume.
 */
void tunnelchainCombine(tunnel_chain_t *destination, tunnel_chain_t *source);

/**
 * @brief Append a tunnel to a tunnel array.
 *
 * @param tc Target tunnel array.
 * @param t Tunnel instance to append.
 */
void tunnelarrayInsert(tunnel_array_t *tc, tunnel_t *t);

/**
 * @brief Append a tunnel to a chain and update aggregated chain metadata.
 *
 * @param tci Destination chain.
 * @param t Tunnel instance to append.
 */
void tunnelchainInsert(tunnel_chain_t *tci, tunnel_t *t);

/**
 * @brief Return per-worker line pools used by this chain.
 *
 * @param tc Chain instance.
 * @return generic_pool_t** Array indexed by worker id.
 */
static inline generic_pool_t **tunnelchainGetLinePools(tunnel_chain_t *tc)
{
    return tc->line_pools;
}

/**
 * @brief Return the line pool assigned to a specific worker.
 *
 * @param tc Chain instance.
 * @param wid Worker id.
 * @return generic_pool_t* Worker-specific line pool.
 */
static inline generic_pool_t *tunnelchainGetWorkerLinePool(tunnel_chain_t *tc, wid_t wid)
{
    return tc->line_pools[wid];
}

/**
 * @brief Return the packet helper line for a specific worker.
 *
 * @param tc Chain instance.
 * @param wid Worker id.
 * @return line_t* Packet helper line.
 */
static inline line_t *tunnelchainGetWorkerPacketLine(tunnel_chain_t *tc, wid_t wid)
{
    return tc->packet_lines[wid];
}

/**
 * @brief Check whether a line is one of this chain's persistent worker packet lines.
 *
 * Packet lines are owned by the chain and destroyed only by tunnelchainDestroy(),
 * so they are excluded from the owned-normal-line Finish postcondition. A handler
 * that can receive both a packet line and a normal line must branch on this
 * before any cleanup.
 *
 * @param tc Chain instance, may be NULL.
 * @param l Line to classify, may be NULL.
 * @return true The line is one of this chain's worker packet lines.
 * @return false The line is a normal line, or the chain has no packet lines.
 */
bool tunnelchainIsWorkerPacketLine(tunnel_chain_t *tc, const line_t *l);

/**
 * @brief Check whether chain finalization is complete.
 *
 * @param tc Chain instance.
 * @return true Chain has been finalized.
 * @return false Chain is still mutable.
 */
static inline bool tunnelchainIsFinalized(tunnel_chain_t *tc)
{
    return tc->finalized;
}
