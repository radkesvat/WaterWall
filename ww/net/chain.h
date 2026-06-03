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
void            tunnelchainFinalize(tunnel_chain_t *tc);

/**
 * @brief Destroy a chain and release all worker line resources.
 *
 * @param tc Chain instance.
 */
void            tunnelchainDestroy(tunnel_chain_t *tc);

/**
 * @brief Merge all tunnels from source into destination and destroy source.
 *
 * @param destination Destination chain that keeps ownership.
 * @param source Source chain to consume.
 */
void            tunnelchainCombine(tunnel_chain_t *destination, tunnel_chain_t *source);

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
