#pragma once

#include "wwapi.h"
#include "lwip/prot/icmp.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"

enum
{
    kTesterServerChunkCount = 11,
    kTesterServerSplitPayloadDelayMs = 1,
    kTesterServerPacketIpv4ProtocolDefault = 253,
    kTesterServerPacketIpv4TtlDefault = 64
};

typedef enum testerserver_direction_e
{
    kTesterServerDirectionRequest = 0,
    kTesterServerDirectionResponse = 1
} testerserver_direction_e;

typedef enum testerserver_packet_ipv4_transport_e
{
    kTesterServerPacketIpv4TransportNone = 0,
    kTesterServerPacketIpv4TransportTcp,
    kTesterServerPacketIpv4TransportUdp,
    kTesterServerPacketIpv4TransportIcmp
} testerserver_packet_ipv4_transport_e;

typedef struct testerserver_tstate_s
{
    bool        packet_mode;
    bool        packet_stateless;
    bool        packet_init_on_start;
    bool        streaming_response;
    bool        packet_ipv4_mode;
    uint32_t    packet_ipv4_source_addr;
    uint32_t    packet_ipv4_dest_addr;
    uint32_t    max_payload_size;
    uint8_t     chunk_count;
    uint8_t     packet_ipv4_protocol;
    uint8_t     packet_ipv4_ttl;
    atomic_uint packet_ipv4_identification;
    testerserver_packet_ipv4_transport_e packet_ipv4_transport;
} testerserver_tstate_t;

typedef struct testerserver_lstate_s
{
    buffer_stream_t read_stream;
    buffer_queue_t  response_queue;

    uint8_t request_rx_index;
    uint8_t response_tx_index;
    uint8_t flow_id;
    uint32_t response_tx_offset;

    bool    response_ready;
    bool    response_paused;
    bool    response_send_scheduled;
    bool    response_sent;
    bool    response_to_next;
} testerserver_lstate_t;

enum
{
    kTunnelStateSize = sizeof(testerserver_tstate_t),
    kLineStateSize   = sizeof(testerserver_lstate_t)
};

WW_EXPORT void         testerserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *testerserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t testerserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void testerserverTunnelOnPrepair(tunnel_t *t);
void testerserverTunnelOnStart(tunnel_t *t);

void testerserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void testerserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void testerserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void testerserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void testerserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void testerserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void testerserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void testerserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void testerserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void testerserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void testerserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void testerserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void     testerserverLinestateInitialize(testerserver_lstate_t *ls, buffer_pool_t *pool);
void     testerserverLinestateDestroy(testerserver_lstate_t *ls);
void     testerserverFail(tunnel_t *t, line_t *l, const char *reason);
uint8_t  testerserverGetChunkCount(tunnel_t *t);
uint32_t testerserverGetChunkSize(tunnel_t *t, uint8_t index);
uint64_t testerserverGetRemainingBytes(tunnel_t *t, uint8_t index);
sbuf_t  *testerserverCreatePayload(tunnel_t *t, line_t *l, uint8_t chunk_index, uint32_t chunk_offset,
                                   uint32_t payload_len, testerserver_direction_e direction);
bool     testerserverVerifyChunk(tunnel_t *t, line_t *l, sbuf_t *buf, uint8_t chunk_index, testerserver_direction_e direction,
                                 uint32_t *bad_offset, uint8_t *expected, uint8_t *actual);
void     testerserverHandlePacketRequestPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void     testerserverHandlePacketStatelessRequestPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void     testerserverResponseSendTask(tunnel_t *t, line_t *l);
void     testerserverScheduleResponseSend(tunnel_t *t, line_t *l, testerserver_lstate_t *ls);
