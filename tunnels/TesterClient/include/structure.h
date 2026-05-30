#pragma once

#include "wwapi.h"
#include "lwip/prot/icmp.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"

enum
{
    kTesterClientChunkCount = 11,
    kTesterClientMaxWorkers = 254,
    kTesterClientStartDelayMs = 50,
    kTesterClientWatchdogMs = 30000,
    kTesterClientSplitPayloadDelayMs = 1,
    kTesterClientPacketIpv4ProtocolDefault = 253,
    kTesterClientPacketIpv4TtlDefault = 64
};

typedef enum testerclient_direction_e
{
    kTesterClientDirectionRequest = 0,
    kTesterClientDirectionResponse = 1
} testerclient_direction_e;

typedef enum testerclient_packet_ipv4_transport_e
{
    kTesterClientPacketIpv4TransportNone = 0,
    kTesterClientPacketIpv4TransportTcp,
    kTesterClientPacketIpv4TransportUdp,
    kTesterClientPacketIpv4TransportIcmp
} testerclient_packet_ipv4_transport_e;

typedef struct testerclient_worker_state_s
{
    line_t *line;
    bool    completed;
} testerclient_worker_state_t;

typedef struct testerclient_tstate_s
{
    atomic_uint                 completed_workers;
    bool                        allow_early_response;
    bool                        packet_mode;
    bool                        packet_stateless;
    bool                        packet_start_immediately;
    bool                        packet_ipv4_mode;
    uint32_t                    packet_ipv4_source_addr;
    uint32_t                    packet_ipv4_dest_addr;
    uint32_t                    max_payload_size;
    uint32_t                    packet_start_delay_ms;
    uint8_t                     chunk_count;
    uint8_t                     packet_ipv4_protocol;
    uint8_t                     packet_ipv4_ttl;
    atomic_uint                 packet_ipv4_identification;
    testerclient_packet_ipv4_transport_e packet_ipv4_transport;
    testerclient_worker_state_t workers[kTesterClientMaxWorkers];
} testerclient_tstate_t;

typedef struct testerclient_lstate_s
{
    buffer_stream_t read_stream;

    uint8_t request_tx_index;
    uint8_t response_rx_index;
    uint8_t flow_id;
    uint32_t request_tx_offset;
    uint32_t packet_stateless_response_mask;

    bool    est_received;
    bool    request_paused;
    bool    request_send_scheduled;
    bool    request_complete;
    bool    response_complete;
} testerclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(testerclient_tstate_t),
    kLineStateSize   = sizeof(testerclient_lstate_t)
};

WW_EXPORT void         testerclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *testerclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t testerclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void testerclientTunnelOnPrepair(tunnel_t *t);
void testerclientTunnelOnStart(tunnel_t *t);

void testerclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void testerclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void testerclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void testerclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void testerclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void testerclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void testerclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void testerclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void testerclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void testerclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void testerclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void testerclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void     testerclientLinestateInitialize(testerclient_lstate_t *ls, buffer_pool_t *pool);
void     testerclientLinestateDestroy(testerclient_lstate_t *ls);
void     testerclientFail(tunnel_t *t, line_t *l, const char *reason);
uint8_t  testerclientGetChunkCount(tunnel_t *t);
uint32_t testerclientGetChunkSize(tunnel_t *t, uint8_t index);
uint64_t testerclientGetRemainingBytes(tunnel_t *t, uint8_t index);
sbuf_t  *testerclientCreatePayload(tunnel_t *t, line_t *l, uint8_t chunk_index, uint32_t chunk_offset,
                                   uint32_t payload_len, testerclient_direction_e direction);
bool     testerclientVerifyChunk(tunnel_t *t, line_t *l, sbuf_t *buf, uint8_t chunk_index, testerclient_direction_e direction,
                                 uint32_t *bad_offset, uint8_t *expected, uint8_t *actual);
void     testerclientRequestSendTask(tunnel_t *t, line_t *l);
void     testerclientWatchdogTask(tunnel_t *t, line_t *l);
void     testerclientScheduleRequestSend(tunnel_t *t, line_t *l, testerclient_lstate_t *ls);
void     testerclientMarkWorkerComplete(tunnel_t *t, line_t *l);
