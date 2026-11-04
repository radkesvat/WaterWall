#pragma once

#include "wwapi.h"

#include "FakeTcpHeaderCommon/faketcpheader_wire.h"

enum
{
    kFakeTcpHeaderServerDropLogIntervalMs = 5U * 1000U,
};

typedef struct faketcpheaderserver_tstate_s
{
    faketcpheader_wire_config_t wire;
    atomic_log_rate_limiter_t   drop_log_limiter;
    atomic_u32_t                values[];
} faketcpheaderserver_tstate_t;

WW_EXPORT tunnel_t *faketcpheaderserverCreate(node_t *node);

void faketcpheaderserverUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void faketcpheaderserverDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
