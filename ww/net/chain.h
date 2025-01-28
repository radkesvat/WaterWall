#pragma once
#include "wlibc.h"

#include "tunnel.h"

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

typedef struct tunnel_array_t
{
    uint16_t  len;
    tunnel_t *tuns[kMaxChainLen];

} tunnel_array_t;

typedef struct tunnel_chain_s
{
    generic_pool_t *line_pool;

    uint16_t sum_padding_left;
    uint16_t sum_line_state_size;

    tunnel_array_t tunnels;

} tunnel_chain_t;

tunnel_chain_t* tunnelChainCreate(void);

void tunnelChain(tunnel_t *from, tunnel_t *to);
void tunnelChainDown(tunnel_t *from, tunnel_t *to);
void tunnelChainUp(tunnel_t *from, tunnel_t *to);

void tunnelarrayInesert(tunnel_array_t *tc, tunnel_t *t);
void tunnelchainInestert(tunnel_chain_t *tci, tunnel_t *t);
