#pragma once

#include "wwapi.h"

enum mode_dynamic_value_status
{
    kDvsSourceMode = kDvsFirstOption,
    kDvsDestMode
};

enum direction_dynamic_value_status
{
    kDvsUp = kDvsFirstOption,
    kDvsDown
};

typedef struct ipoverrider_tstate_s
{
    struct in6_addr ov_6;
    uint32_t        ov_4;
    bool            support4;
    bool            support6;
} ipoverrider_tstate_t;

typedef struct ipoverrider_lstate_s
{
    int unused;
} ipoverrider_lstate_t;

enum
{
    kTunnelStateSize = sizeof(ipoverrider_tstate_t),
    kLineStateSize   = sizeof(ipoverrider_lstate_t)
};

WW_EXPORT void         ipoverriderDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *ipoverriderCreate(node_t *node);
WW_EXPORT api_result_t ipoverriderApi(tunnel_t *instance, sbuf_t *message);

void ipoverriderOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void ipoverriderOnChain(tunnel_t *t, tunnel_chain_t *chain);
void ipoverriderOnPrepair(tunnel_t *t);
void ipoverriderOnStart(tunnel_t *t);

void ipoverriderUpStreamInit(tunnel_t *t, line_t *l);
void ipoverriderUpStreamEst(tunnel_t *t, line_t *l);
void ipoverriderUpStreamFinish(tunnel_t *t, line_t *l);
void ipoverriderUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ipoverriderUpStreamPause(tunnel_t *t, line_t *l);
void ipoverriderUpStreamResume(tunnel_t *t, line_t *l);

void ipoverriderDownStreamInit(tunnel_t *t, line_t *l);
void ipoverriderDownStreamEst(tunnel_t *t, line_t *l);
void ipoverriderDownStreamFinish(tunnel_t *t, line_t *l);
void ipoverriderDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ipoverriderDownStreamPause(tunnel_t *t, line_t *l);
void ipoverriderDownStreamResume(tunnel_t *t, line_t *l);

void ipoverriderLinestateInitialize(ipoverrider_lstate_t *ls);
void ipoverriderLinestateDestroy(ipoverrider_lstate_t *ls);


void ipoverriderReplacerDestModeUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ipoverriderReplacerSrcModeUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ipoverriderReplacerDestModeDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ipoverriderReplacerSrcModeDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
