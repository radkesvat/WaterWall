#pragma once

/*
    Most of the code is taken and renamed, from the awesome projects wireguard-lwip and lwip

    Author of lwip:              Adam Dunkels  https://github.com/smartalock/wireguard-lwip
    Author of wireguard-lwip:    Daniel Hope   https://github.com/lwip-tcpip/lwip

    their license files are placed next to this file
*/

#include <stdbool.h>
#include <stdint.h>

struct ip4_addr {
  uint32_t addr;
};
typedef struct ip4_addr ip4_addr_t;

enum wg_general_limits
{
    // Peers are allocated statically inside the device structure to avoid malloc
    kWgMaxPeers  = 1,
    kWgMaxSrcIPs = 2,
    // Per device limit on accepting (valid) initiation requests - per peer
    kMaxInitiationPerSecond = 2
};

enum wg_general_consts
{
    kWgAuthTagLen     = 16,
    kWgHashLen        = 32,
    kWgPublicKeyLen   = 32,
    kWgSessionKeyLen  = 32,
    kWgPrivateKeyLen  = 32,
    kWgTai64Len       = 12,
    kWgCookieLen      = 16,
    kWgCookieNonceLen = 24
};

// ISO C restricts enumerator values to range of 'int' (1152921504606846976) is too large
#define kWgReKeyAfterMessages (1ULL << 60)                           // NOLINT
#define kWgRejectAfterMessage (0XFFFFFFFFFFFFFFFFULL - (1ULL << 13)) // NOLINT

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

typedef struct wireguard_allowed_ip_s {
	bool valid;
	ip_addr_t ip;
	ip_addr_t mask;
} wireguard_allowed_ip_t;

struct wireguard_peer
{
    bool valid;  // Is this peer initialised?
    bool active; // Should we be actively trying to connect?

    // This is the configured IP of the peer (endpoint)
    ip_addr_t connect_ip;
    uint16_t  connect_port;
    // This is the latest received IP/port
    ip_addr_t ip;
    uint16_t  port;
    // keep-alive interval in seconds, 0 is disable
    uint16_t keepalive_interval;

    struct wireguard_allowed_ip allowed_source_ips[kWgMaxSrcIPs];

    uint8_t public_key[kWgPublicKeyLen];
    uint8_t preshared_key[kWgSessionKeyLen];

    // Precomputed DH(Sprivi,Spubr) with device private key, and peer public key
    uint8_t public_key_dh[kWgPublicKeyLen];

    // Session keypairs
    struct wireguard_keypair curr_keypair;
    struct wireguard_keypair prev_keypair;
    struct wireguard_keypair next_keypair;

    // 5.1 Silence is a Virtue: The responder keeps track of the greatest timestamp received per peer
    uint8_t greatest_timestamp[kWgTai64Len];

    // The active handshake that is happening
    struct wireguard_handshake handshake;

    // Decrypted cookie from the responder
    uint32_t cookie_millis;
    uint8_t  cookie[kWgCookieLen];

    // The latest mac1 we sent with initiation
    bool    handshake_mac1_valid;
    uint8_t handshake_mac1[kWgCookieLen];

    // Precomputed keys for use in mac validation
    uint8_t label_cookie_key[kWgSessionKeyLen];
    uint8_t label_mac1_key[kWgSessionKeyLen];

    // The last time we received a valid initiation message
    uint32_t last_initiation_rx;
    // The last time we sent an initiation message to this peer
    uint32_t last_initiation_tx;

    // last_tx and last_rx of data packets
    uint32_t last_tx;
    uint32_t last_rx;

    // We set this flag on RX/TX of packets if we think that we should initiate a new handshake
    bool send_handshake;
};

struct wireguard_device
{
    // Maybe have a "Device private" member to abstract these?
    struct netif   *netif;
    struct udp_pcb *udp_pcb;

    uint8_t public_key[kWgPublicKeyLen];
    uint8_t private_key[kWgPrivateKeyLen];

    uint8_t  cookie_secret[kWgHashLen];
    uint32_t cookie_secret_millis;

    // Precalculated
    uint8_t label_cookie_key[kWgSessionKeyLen];
    uint8_t label_mac1_key[kWgSessionKeyLen];

    // List of peers associated with this device
    struct wireguard_peer peers[kWgMaxPeers];

    bool valid;
};

#define MESSAGE_INVALID              0
#define MESSAGE_HANDSHAKE_INITIATION 1
#define MESSAGE_HANDSHAKE_RESPONSE   2
#define MESSAGE_COOKIE_REPLY         3
#define MESSAGE_TRANSPORT_DATA       4

// 5.4.2 First Message: Initiator to Responder
struct message_handshake_initiation
{
    uint8_t  type;
    uint8_t  reserved[3];
    uint32_t sender;
    uint8_t  ephemeral[32];
    uint8_t  enc_static[32 + kWgAuthTagLen];
    uint8_t  enc_timestamp[kWgTai64Len + kWgAuthTagLen];
    uint8_t  mac1[kWgCookieLen];
    uint8_t  mac2[kWgCookieLen];
} __attribute__((__packed__));

// 5.4.3 Second Message: Responder to Initiator
struct message_handshake_response
{
    uint8_t  type;
    uint8_t  reserved[3];
    uint32_t sender;
    uint32_t receiver;
    uint8_t  ephemeral[32];
    uint8_t  enc_empty[0 + kWgAuthTagLen];
    uint8_t  mac1[kWgCookieLen];
    uint8_t  mac2[kWgCookieLen];
} __attribute__((__packed__));

// 5.4.7 Under Load: Cookie Reply Message
struct message_cookie_reply
{
    uint8_t  type;
    uint8_t  reserved[3];
    uint32_t receiver;
    uint8_t  nonce[kWgCookieNonceLen];
    uint8_t  enc_cookie[kWgCookieLen + kWgAuthTagLen];
} __attribute__((__packed__));

// 5.4.6 Subsequent Messages: Transport Data Messages
struct message_transport_data
{
    uint8_t  type;
    uint8_t  reserved[3];
    uint32_t receiver;
    uint8_t  counter[8];
    // Followed by encrypted data
    uint8_t enc_packet[];
} __attribute__((__packed__));
