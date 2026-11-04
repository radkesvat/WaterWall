#pragma once

#include "ikcp.h"
#include "ww_fec.h"
#include "wwapi.h"

/* Explicit network-order envelope. Never cast datagrams to a C structure. */
enum
{
    kTouWireMagic        = 0x57574b43U, /* WWKC */
    kTouEnvelopeSize     = 40,
    kTouSettingsSize     = 8,
    kTouNonceSize        = 16,
    kTouHello            = 1,
    kTouChallenge        = 2,
    kTouConfirm          = 3,
    kTouReady            = 4,
    kTouKcp              = 5,
    kTouFec              = 6,
    kTouFrameData        = 0,
    kTouFramePing        = 0xf0,
    kTouFrameClose       = 0xff,
    kTouDefaultCloseMs   = 30000,
    kTouHandshakeRetryMs = 250,
    kTouMaximumSessions  = 64,
    kTouMaximumKcpPacketSize = 64000,
};

typedef struct tou_settings_s
{
    uint32_t close_ms;
    uint8_t  data_shards; /* Both zero means FEC disabled. */
    uint8_t  parity_shards;
} tou_settings_t;

typedef struct tou_wire_s
{
    uint8_t        kind;
    uint8_t        client_nonce[kTouNonceSize];
    uint8_t        server_nonce[kTouNonceSize];
    const uint8_t *body; /* Borrowed from decoded packet. */
    size_t         body_len;
} tou_wire_t;

bool     touWireDecode(const uint8_t *packet, size_t size, tou_wire_t *wire);
bool     touSettingsDecode(const uint8_t *body, size_t size, tou_settings_t *settings);
void     touSettingsEncode(uint8_t body[kTouSettingsSize], const tou_settings_t *settings);
bool     touSettingsEqual(const tou_settings_t *a, const tou_settings_t *b);
bool     touNonceIsZero(const uint8_t nonce[kTouNonceSize]);
void     touNonceGenerate(uint8_t nonce[kTouNonceSize]);
uint64_t touDeadline(uint64_t start, uint32_t interval);
/* Returns NULL only for unrepresentable packet geometry. */
bool    touWireEncode(uint8_t *packet, size_t capacity, uint8_t kind, const uint8_t client[kTouNonceSize],
                      const uint8_t server[kTouNonceSize], const uint8_t *body, size_t body_len);
sbuf_t *touWireCreate(buffer_pool_t *pool, uint8_t kind, const uint8_t client[kTouNonceSize],
                      const uint8_t server[kTouNonceSize], const uint8_t *body, size_t body_len);
sbuf_t *touControlCreate(buffer_pool_t *pool, uint8_t kind, const uint8_t client[kTouNonceSize],
                         const uint8_t server[kTouNonceSize], const tou_settings_t *settings);

typedef struct tou_session_s tou_session_t;
typedef enum tou_result_e
{
    kTouConfirmed,
    kTouPeerDrained,
    kTouUnconfirmed,
    kTouAborted,
    kTouProtocolFailure,
    kTouIdleTimeout,
    kTouHandshakeTimeout,
    kTouCapacityFailure,
} tou_result_t;

typedef struct tou_config_s
{
    uint16_t       send_mtu; /* Outgoing IPv4 + UDP + envelope + optional FEC + KCP budget. */
    bool           fec_enabled;
    uint8_t        fec_data_shards;
    uint8_t        fec_parity_shards;
    bool           kcp_nodelay;
    bool           kcp_no_congestion_control;
    int            kcp_interval_ms;
    int            kcp_resend;
    int            kcp_send_window;
    int            kcp_recv_window;
    int            kcp_initial_cwnd;
    int            kcp_rx_minrto_ms;
    int            kcp_send_buffer_limit;
    uint32_t       ping_interval_ms;
    uint32_t       no_recv_timeout_ms;
    uint32_t       close_drain_timeout_ms;
    buffer_pool_t *pool;               /* Owner worker, outlives the session. */
    wloop_t       *loop;               /* NULL permits deterministic explicit Tick calls. */
    uint64_t (*now)(void *clock_user); /* NULL uses loop's monotonic clock. */
    void *clock_user;
} tou_config_t;

typedef struct tou_callbacks_s
{
    /* Payload and emit transfer the entire buffer on every return. */
    void (*emit)(void *user, sbuf_t *packet);
    void (*payload)(void *user, sbuf_t *payload);
    void (*peer_close)(void *user);
    void (*pressure)(void *user, bool paused);
    /* terminal may release the owner's reference; destroy_user runs at final release. */
    void (*terminal)(void *user, tou_result_t result);
    void (*destroy_user)(void *user);
} tou_callbacks_t;

int touKcpMtu(const tou_config_t *config);
/* Create owns one reference. False client means pre-negotiated server session. */
tou_session_t *touSessionCreate(const tou_config_t *config, const tou_callbacks_t *callbacks, void *user, bool client,
                                const uint8_t client_nonce[kTouNonceSize], const uint8_t server_nonce[kTouNonceSize],
                                const tou_settings_t *accepted);
void           touSessionRetain(tou_session_t *session);
void           touSessionRelease(tou_session_t *session);
/* Start after the neighboring transport Init has safely returned. */
void touSessionStart(tou_session_t *session);
/* Server startup gate: no KCP output/delivery until the service Init is safe. */
void touSessionSetReady(tou_session_t *session);
void touSessionSend(tou_session_t *session, sbuf_t *payload);
/* Input takes ownership of the complete outer datagram. Identity is checked before FEC/KCP. */
void                  touSessionInput(tou_session_t *session, sbuf_t *packet);
void                  touSessionAppFinish(tou_session_t *session);
void                  touSessionAbort(tou_session_t *session, tou_result_t result);
void                  touSessionTick(tou_session_t *session, uint64_t now);
void                  touSessionQuiesce(tou_session_t *session);
bool                  touSessionIsAlive(const tou_session_t *session);
bool                  touSessionIsReady(const tou_session_t *session);
const tou_settings_t *touSessionSettings(const tou_session_t *session);
const uint8_t        *touSessionClientNonce(const tou_session_t *session);
const uint8_t        *touSessionServerNonce(const tou_session_t *session);
/* Read-only diagnostics for focused fixtures. */
ikcpcb  *touSessionKcp(tou_session_t *session);
uint64_t touSessionSendDeadline(const tou_session_t *session);
uint64_t touSessionRetentionDeadline(const tou_session_t *session);
bool     touSessionCloseConfirmed(const tou_session_t *session);
