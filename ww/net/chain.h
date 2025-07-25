#pragma once
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
    bool            packet_chain_init_sent : 1;
    bool            finalized : 1;
    bool            started : 1;
    line_t        **packet_lines;
    master_pool_t  *masterpool_line_pool;
    generic_pool_t *line_pools[];

} tunnel_chain_t;

tunnel_chain_t *tunnelchainCreate(wid_t workers_count);
void            tunnelchainFinalize(tunnel_chain_t *tc);
void            tunnelchainDestroy(tunnel_chain_t *tc);
void            tunnelchainCombine(tunnel_chain_t *destination, tunnel_chain_t *source);

void tunnelarrayInsert(tunnel_array_t *tc, tunnel_t *t);
void tunnelchainInsert(tunnel_chain_t *tci, tunnel_t *t);

static inline generic_pool_t **tunnelchainGetLinePools(tunnel_chain_t *tc)
{
    return tc->line_pools;
}

static inline generic_pool_t *tunnelchainGetWorkerLinePool(tunnel_chain_t *tc, wid_t wid)
{
    return tc->line_pools[wid];
}



static inline line_t *tunnelchainGetWorkerPacketLine(tunnel_chain_t *tc, wid_t wid)
{
    return tc->packet_lines[wid];
}

static inline bool tunnelchainIsFinalized(tunnel_chain_t *tc)
{
    return tc->finalized;
}
