#pragma once
#include "wlibc.h"

#include "worker.h"
#include "generic_pool.h"

typedef struct tunnel_s tunnel_t;

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
    master_pool_t  *masterpool_line_pool;
    generic_pool_t *line_pools[];

} tunnel_chain_t;

tunnel_chain_t *tunnelchainCreate(wid_t workers_count);
void            tunnelchainFinalize(tunnel_chain_t *tc);
void            tunnelchainDestroy(tunnel_chain_t *tc);
generic_pool_t *tunnelchainGetLinePool(tunnel_chain_t *tc, wid_t wid);

void tunnelarrayInsert(tunnel_array_t *tc, tunnel_t *t);
void tunnelchainInsert(tunnel_chain_t *tci, tunnel_t *t);
