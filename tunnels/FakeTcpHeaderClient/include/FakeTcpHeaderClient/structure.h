#pragma once

#include "wwapi.h"

#include "FakeTcpHeaderCommon/faketcpheader_encryption.h"
#include "FakeTcpHeaderCommon/faketcpheader_wire.h"

enum
{
    kFakeTcpHeaderClientDropLogIntervalMs = 5U * 1000U,
};

typedef struct faketcpheaderclient_tstate_s
{
    faketcpheader_wire_config_t wire;
    atomic_log_rate_limiter_t   drop_log_limiter;
    faketcpheader_encryption_t  encryption;
    atomic_u32_t                values[];
} faketcpheaderclient_tstate_t;

WW_EXPORT tunnel_t *faketcpheaderclientCreate(node_t *node);

void faketcpheaderclientUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void faketcpheaderclientDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
