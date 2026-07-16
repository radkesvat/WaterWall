#pragma once
#include "wwapi.h"

typedef struct tlsclient_handshake_binding_s
{
    uint8_t  client_random[32];
    uint8_t  server_random[32];
    uint64_t next_read_sequence;
    uint64_t next_write_sequence;
    uint16_t tls_version;
    uint16_t cipher_suite;
    bool     tls12_sequences_valid;
} tlsclient_handshake_binding_t;

WW_EXPORT node_t    nodeTlsClientGet(void);
WW_EXPORT tunnel_t *tlsclientTunnelCreate(node_t *node);
WW_EXPORT void      tlsclientTunnelEnableHandshakeTakeover(tunnel_t *t);
WW_EXPORT bool      tlsclientTunnelIsHandshakeCompleted(tunnel_t *t, line_t *l);
WW_EXPORT bool      tlsclientTunnelGetHandshakeBinding(tunnel_t *t, line_t *l,
                                                       tlsclient_handshake_binding_t *binding);
WW_EXPORT bool      tlsclientTunnelDeinitAfterHandshake(tunnel_t *t, line_t *l, sbuf_t **pending_raw);
