#pragma once

#include "wwapi.h"

/*
 * SniffRouter
 * -----------
 * A layer-4 content router. It can sit right after a TlsServer (TLS
 * termination) node and inspect the first decrypted HTTP/1 request, or sit
 * before TLS termination and inspect the TLS ClientHello SNI. It then
 * decides where the connection should go:
 *
 *   - if the HTTP Host or TLS SNI matches one configured route -> send to
 *                                                                  that route
 *   - otherwise                                               -> normal "next"
 *
 * The "next" branch is a normal chain continuation (upstream payload). The
 * configured route targets are folded into the same chain during onChain so
 * they get per-line state slots and so their downstream traffic returns through
 * us. The decision is made lazily on the first payload, and the buffered bytes
 * are replayed to the chosen branch with no loss.
 */

enum sniffrouter_route_e
{
    kSniffRouteUndecided = 0,
    kSniffRouteTarget    = 1,
    kSniffRouteDefault   = 2
};

enum sniffrouter_classify_result_e
{
    kSniffClassifyNeedMore = 0,
    kSniffClassifyDefault  = 1,
    kSniffClassifyTarget   = 2
};

enum sniffrouter_detection_e
{
    kSniffDetectionHttp           = 1U << 0U,
    kSniffDetectionTlsClientHello = 1U << 1U
};

typedef struct sniffrouter_route_s
{
    node_t   *node;
    tunnel_t *tunnel;
    char    **domains;
    uint32_t  domains_count;
    uint8_t   detection;
} sniffrouter_route_t;

typedef struct sniffrouter_match_s
{
    enum sniffrouter_classify_result_e result;
    tunnel_t                          *target;
} sniffrouter_match_t;

typedef struct sniffrouter_tstate_s
{
    sniffrouter_route_t *routes;
    uint32_t             routes_count;
} sniffrouter_tstate_t;

typedef struct sniffrouter_lstate_s
{
    sbuf_t   *pending;       // bytes buffered before a routing decision is made
    tunnel_t *target;        // selected route tunnel; NULL means normal next branch
    uint8_t   decided;       // enum sniffrouter_route_e
    bool      next_finished; // finish already propagated to the chosen upstream branch
    bool      prev_finished; // finish already propagated downstream to prev (TlsServer)
} sniffrouter_lstate_t;

enum
{
    kTunnelStateSize = sizeof(sniffrouter_tstate_t),
    kLineStateSize   = sizeof(sniffrouter_lstate_t),

    // Longest HTTP method token we test ("CONNECT "/"OPTIONS ") is 8 bytes.
    kSniffMethodDecideBytes = 8,

    // Keep the sniff window bounded. Normal Host headers and ClientHello SNI
    // extensions arrive well before this; if they do not, traffic falls back
    // to "next".
    kSniffMaxHeaderBytes = 8192
};

WW_EXPORT void         sniffrouterTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *sniffrouterTunnelCreate(node_t *node);
WW_EXPORT api_result_t sniffrouterTunnelApi(tunnel_t *instance, sbuf_t *message);

sniffrouter_match_t sniffrouterClassify(sniffrouter_tstate_t *ts, const uint8_t *p, uint32_t n);
bool                sniffrouterDomainMatches(const char *pattern, const uint8_t *host, uint32_t host_len);
void                sniffrouterLinestateInitialize(sniffrouter_lstate_t *ls);
void                sniffrouterLinestateDestroy(line_t *l, sniffrouter_lstate_t *ls);
void                sniffrouterRouteTableDestroy(sniffrouter_tstate_t *ts);

void sniffrouterTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void sniffrouterTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void sniffrouterTunnelOnPrepair(tunnel_t *t);
void sniffrouterTunnelOnStart(tunnel_t *t);
void sniffrouterTunnelOnStop(tunnel_t *t);

void sniffrouterTunnelUpStreamInit(tunnel_t *t, line_t *l);
void sniffrouterTunnelUpStreamEst(tunnel_t *t, line_t *l);
void sniffrouterTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void sniffrouterTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void sniffrouterTunnelUpStreamPause(tunnel_t *t, line_t *l);
void sniffrouterTunnelUpStreamResume(tunnel_t *t, line_t *l);

void sniffrouterTunnelDownStreamInit(tunnel_t *t, line_t *l);
void sniffrouterTunnelDownStreamEst(tunnel_t *t, line_t *l);
void sniffrouterTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void sniffrouterTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void sniffrouterTunnelDownStreamPause(tunnel_t *t, line_t *l);
void sniffrouterTunnelDownStreamResume(tunnel_t *t, line_t *l);
