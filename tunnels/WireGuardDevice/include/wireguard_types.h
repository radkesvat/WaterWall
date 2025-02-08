#pragma once
#include "wireguard_constants.h"
#include "wwapi.h"

/** Note that from this to end of the macro all sturcts are packed */
#ifdef COMPILER_MSVC

#pragma pack(push, 1)

#define ATTR_PACKED

#else

#define ATTR_PACKED __attribute__((__packed__))

#endif

// 5.4.2 First Message: Initiator to Responder
struct message_handshake_initiation_s
{
    uint8_t  type;
    uint8_t  reserved[3];
    uint32_t sender;
    uint8_t  ephemeral[32];
    uint8_t  enc_static[32 + WIREGUARD_AUTHTAG_LEN];
    uint8_t  enc_timestamp[WIREGUARD_TAI64N_LEN + WIREGUARD_AUTHTAG_LEN];
    uint8_t  mac1[WIREGUARD_COOKIE_LEN];
    uint8_t  mac2[WIREGUARD_COOKIE_LEN];
} ATTR_PACKED;
typedef struct message_handshake_initiation_s message_handshake_initiation_t;

// 5.4.3 Second Message: Responder to Initiator
struct message_handshake_response_s
{
    uint8_t  type;
    uint8_t  reserved[3];
    uint32_t sender;
    uint32_t receiver;
    uint8_t  ephemeral[32];
    uint8_t  enc_empty[0 + WIREGUARD_AUTHTAG_LEN];
    uint8_t  mac1[WIREGUARD_COOKIE_LEN];
    uint8_t  mac2[WIREGUARD_COOKIE_LEN];
} ATTR_PACKED;
typedef struct message_handshake_response_s message_handshake_response_t;

// 5.4.7 Under Load: Cookie Reply Message
struct message_cookie_reply_s
{
    uint8_t  type;
    uint8_t  reserved[3];
    uint32_t receiver;
    uint8_t  nonce[COOKIE_NONCE_LEN];
    uint8_t  enc_cookie[WIREGUARD_COOKIE_LEN + WIREGUARD_AUTHTAG_LEN];
} ATTR_PACKED;
typedef struct message_cookie_reply_s message_cookie_reply_t;

// 5.4.6 Subsequent Messages: Transport Data Messages
struct message_transport_data_s
{
    uint8_t  type;
    uint8_t  reserved[3];
    uint32_t receiver;
    uint8_t  counter[8];
    // Followed by encrypted data
    uint8_t enc_packet[];
} ATTR_PACKED;
typedef struct message_transport_data_s message_transport_data_t;

#ifdef COMPILER_MSVC
#pragma pack(pop) // Restore previous packing setting
#endif

typedef struct wireguard_device_init_data_s
{
    // Required: the private key of this WireGuard network interface
    const uint8_t *private_key;
    // Required: What UDP port to listen on
    // uint16 listen_port;
    // Optional: restrict send/receive of encapsulated WireGuard traffic to this network interface only (NULL to use
    // routing table)
    // struct netif *bind_netif;
} wireguard_device_init_data_t;

typedef struct wireguard_peer_init_data_s
{
    const uint8_t *public_key;
    // Optional pre-shared key (32 bytes) - make sure this is NULL if not to be used
    const uint8_t *preshared_key;
    // tai64n of largest timestamp we have seen during handshake to avoid replays
    uint8_t greatest_timestamp[12];

    // Allowed ip/netmask (can add additional later but at least one is required)
    ip_addr_t allowed_ip;
    ip_addr_t allowed_mask;

    // End-point details (may be blank)
    ip_addr_t endpoint_ip;
    uint16    endpoint_port;
    uint16    keep_alive;
} wireguard_peer_init_data_t;

struct wireguard_keypair_s
{
    bool valid;
    bool initiator; // Did we initiate this session (send the initiation packet rather than sending the response packet)
    uint32_t keypair_millis;

    uint8_t  sending_key[WIREGUARD_SESSION_KEY_LEN];
    bool     sending_valid;
    uint64_t sending_counter;

    uint8_t receiving_key[WIREGUARD_SESSION_KEY_LEN];
    bool    receiving_valid;

    uint32_t last_tx;
    uint32_t last_rx;

    uint32_t replay_bitmap;
    uint64_t replay_counter;

    uint32_t local_index;  // This is the index we generated for our end
    uint32_t remote_index; // This is the index on the other end
};
typedef struct wireguard_keypair_s wireguard_keypair_t;

struct wireguard_handshake_s
{
    bool     valid;
    bool     initiator;
    uint32_t local_index;
    uint32_t remote_index;
    uint8_t  ephemeral_private[WIREGUARD_PRIVATE_KEY_LEN];
    uint8_t  remote_ephemeral[WIREGUARD_PUBLIC_KEY_LEN];
    uint8_t  hash[WIREGUARD_HASH_LEN];
    uint8_t  chaining_key[WIREGUARD_HASH_LEN];
};
typedef struct wireguard_handshake_s wireguard_handshake_t;

typedef struct wireguard_allowed_ip_s
{
    bool      valid;
    ip_addr_t ip;
    ip_addr_t mask;
} wireguard_allowed_ip_t;

struct wireguard_peer_s
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

    wireguard_allowed_ip_t allowed_source_ips[WIREGUARD_MAX_SRC_IPS];

    uint8_t public_key[WIREGUARD_PUBLIC_KEY_LEN];
    uint8_t preshared_key[WIREGUARD_SESSION_KEY_LEN];

    // Precomputed DH(Sprivi,Spubr) with device private key, and peer public key
    uint8_t public_key_dh[WIREGUARD_PUBLIC_KEY_LEN];

    // Session keypairs
    struct wireguard_keypair_s curr_keypair;
    struct wireguard_keypair_s prev_keypair;
    struct wireguard_keypair_s next_keypair;

    // 5.1 Silence is a Virtue: The responder keeps track of the greatest timestamp received per peer
    uint8_t greatest_timestamp[WIREGUARD_TAI64N_LEN];

    // The active handshake that is happening
    struct wireguard_handshake_s handshake;

    // Decrypted cookie from the responder
    uint32_t cookie_millis;
    uint8_t  cookie[WIREGUARD_COOKIE_LEN];

    // The latest mac1 we sent with initiation
    bool    handshake_mac1_valid;
    uint8_t handshake_mac1[WIREGUARD_COOKIE_LEN];

    // Precomputed keys for use in mac validation
    uint8_t label_cookie_key[WIREGUARD_SESSION_KEY_LEN];
    uint8_t label_mac1_key[WIREGUARD_SESSION_KEY_LEN];

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
typedef struct wireguard_peer_s wireguard_peer_t;

struct wireguard_device_s
{
    // Maybe have a "Device private" member to abstract these?
    struct netif   *netif;
    struct udp_pcb *udp_pcb;
    wtimer_t       *loop_timer;
    uint64_t        status_connected : 1;

    uint8_t public_key[WIREGUARD_PUBLIC_KEY_LEN];
    uint8_t private_key[WIREGUARD_PRIVATE_KEY_LEN];

    uint8_t  cookie_secret[WIREGUARD_HASH_LEN];
    uint32_t cookie_secret_millis;

    // Precalculated
    uint8_t label_cookie_key[WIREGUARD_SESSION_KEY_LEN];
    uint8_t label_mac1_key[WIREGUARD_SESSION_KEY_LEN];

    // List of peers associated with this device
    struct wireguard_peer_s peers[WIREGUARD_MAX_PEERS];

    bool valid;
};
typedef struct wireguard_device_s wireguard_device_t;

