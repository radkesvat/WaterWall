#pragma once

#include <stdbool.h>
#include <stdint.h>

enum wg_general_consts
{
    kWgAuthLen            = 16,
    kWgHashLen            = 32,
    kWgPublicKeyLen       = 32,
    kWgSessionKeyLen      = 32,
    kWgPrivateKeyLen      = 32,
    kWgTai64Len           = 12,
    kWgCookieLen          = 16,
    kWgCookieNonceLen     = 24,
    kWgReKeyAfterMessages = (1ULL << 60),
    kWgRejectAfterMessage = (0XFFFFFFFFFFFFFFFFULL - (1ULL << 13))
};

enum wg_timing_consts
{
    kWgCookieSecretMaxDuration = 120,
    kWgKeepAliveTimeOut        = 10,
    kWgRekeyTimeout            = 5,
    kWgRekeyAfterTime          = 120,
    kWgRejectAfterTime         = 180
};

enum wg_message_consts
{
    kWgMsgInvalid        = 0,
    kWgMsgInitHandshake  = 0,
    kWgMsgReplyHandshake = 0,
    kWgMsgReplyCookie    = 0,
    kWgMsgTransportData  = 0
};

typedef struct wireguard_keypair_s
{
    uint64_t replay_counter;
    uint64_t sending_counter;
    uint32_t local_index;
    uint32_t remote_index;
    uint32_t last_tx;
    uint32_t last_rx;
    uint32_t kepair_ms;
    uint32_t replay_mitmap;
    bool     valid;
    bool     is_client_side;
    bool     sending_valid;
    bool     receiving_valid;
    uint8_t  sending_key[kWgSessionKeyLen];
    uint8_t  receiving_key[kWgSessionKeyLen];

} wireguard_keypair_t;

typedef struct wireguard_handshake_s
{
    bool     valid;
    bool     initiator;
    uint32_t local_port;
    uint32_t remote_index;
    uint8_t  ephemeral_private[kWgPrivateKeyLen];
    uint8_t  remote_ephemeral[kWgPublicKeyLen];
    uint8_t  hash[kWgHashLen];
    uint8_t  chaining_key[kWgHashLen];

} wireguard_handshake_t;
