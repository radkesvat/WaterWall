#pragma once

#include "wwapi.h"

enum
{
    kFakeTcpHeaderMaxOptions = 40,
    kFakeTcpHeaderPadding    = IP_HLEN + TCP_HLEN + kFakeTcpHeaderMaxOptions
};

typedef struct faketcpheader_tstate_s
{
    uint32_t                  sequence;
    uint32_t                  acknowledgment;
    uint32_t                  local_ipv4;
    uint32_t                  peer_ipv4;
    uint16_t                  local_port;
    uint16_t                  peer_port;
    uint16_t                  mtu;
    uint16_t                  window;
    uint16_t                  urgent_pointer;
    uint8_t                   protocol;
    uint8_t                   options_length;
    uint8_t                   options[kFakeTcpHeaderMaxOptions];
    bool                      server;
    atomic_log_rate_limiter_t drop_log;
} faketcpheader_tstate_t;

tunnel_t *faketcpheaderCreate(node_t *node);
void      faketcpheaderDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
void      faketcpheaderUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void      faketcpheaderDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void      faketcpheaderProcessPayload(tunnel_t *t, line_t *l, sbuf_t *buf, bool upstream);

/* Failure leaves bytes, cursor, length and checksum intent unchanged. The caller
 * keeps buffer ownership on either result. These helpers do not access a line. */
bool faketcpheaderEncode(const faketcpheader_tstate_t *config, sbuf_t *buf);
bool faketcpheaderDecode(const faketcpheader_tstate_t *config, sbuf_t *buf);

static inline uint16_t faketcpheaderOverhead(const faketcpheader_tstate_t *config)
{
    return (uint16_t) (IP_HLEN + TCP_HLEN + config->options_length);
}

static inline uint16_t faketcpheaderInnerMtu(const faketcpheader_tstate_t *config)
{
    assert(config->mtu >= faketcpheaderOverhead(config) + 68U);
    return (uint16_t) (config->mtu - faketcpheaderOverhead(config));
}
