#pragma once

#include "wwapi.h"

/*
 * SniffRouter
 * -----------
 * A tiny layer-4 content router that is meant to sit right after a TlsServer
 * (TLS termination) node. It peeks at the first decrypted bytes of every
 * connection and decides where the connection should go:
 *
 *   - if the bytes look like a normal HTTP request  -> send to the "web" node
 *                                                      (a TcpConnector pointing
 *                                                       at a local web server)
 *   - otherwise (binary VLESS / VMess / Trojan ...) -> send to "next"
 *                                                      (e.g. a Bridge that feeds
 *                                                       an already-established
 *                                                       ReverseServer tunnel)
 *
 * The "next" branch is a normal chain continuation (upstream payload). The
 * "web" branch is a second node that we fold into the same chain during
 * onChain so it gets a per-line state slot and so its downstream traffic
 * returns through us. The decision is made lazily on the first payload, and
 * the buffered bytes are replayed to the chosen branch with no loss.
 */

enum sniffrouter_route_e
{
    kSniffUndecided   = 0,
    kSniffRouteWeb    = 1, // HTTP  -> web connector (local web server)
    kSniffRouteTunnel = 2  // other -> next (reverse tunnel branch)
};

typedef struct sniffrouter_tstate_s
{
    node_t   *web_node;   // resolved from settings "web"
    tunnel_t *web_tunnel; // web_node->instance, wired in onChain
} sniffrouter_tstate_t;

typedef struct sniffrouter_lstate_s
{
    sbuf_t *pending; // bytes buffered before a routing decision is made
    uint8_t decided; // enum sniffrouter_route_e
} sniffrouter_lstate_t;

enum
{
    kTunnelStateSize = sizeof(sniffrouter_tstate_t),
    kLineStateSize   = sizeof(sniffrouter_lstate_t),

    // Longest HTTP method token we test ("CONNECT "/"OPTIONS ") is 8 bytes, so
    // 8 buffered bytes are always enough to reach a verdict.
    kSniffDecideBytes = 8
};

WW_EXPORT void         sniffrouterTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *sniffrouterTunnelCreate(node_t *node);
WW_EXPORT api_result_t sniffrouterTunnelApi(tunnel_t *instance, sbuf_t *message);

void sniffrouterTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void sniffrouterTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void sniffrouterTunnelOnPrepair(tunnel_t *t);
void sniffrouterTunnelOnStart(tunnel_t *t);

void sniffrouterTunnelUpStreamInit(tunnel_t *t, line_t *l);
void sniffrouterTunnelUpStreamEst(tunnel_t *t, line_t *l);
void sniffrouterTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void sniffrouterTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void sniffrouterTunnelUpStreamPause(tunnel_t *t, line_t *l);
void sniffrouterTunnelUpStreamResume(tunnel_t *t, line_t *l);

void sniffrouterTunnelDownStreamFinish(tunnel_t *t, line_t *l);
