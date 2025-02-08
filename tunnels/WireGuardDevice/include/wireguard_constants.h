#pragma once

// Default MTU for WireGuard is 1420 bytes
#define WIREGUARDIF_MTU (1420)

#define WIREGUARDIF_TIMER_MSECS 400

#define WIREGUARDIF_DEFAULT_PORT      (51820)
#define WIREGUARDIF_KEEPALIVE_DEFAULT (0xFFFF)

#define WIREGUARD_MAX_PEERS   1
#define WIREGUARD_MAX_SRC_IPS 2

// Per device limit on accepting (valid) initiation requests - per peer
#define MAX_INITIATIONS_PER_SECOND (2)


// tai64n contains 64-bit seconds and 32-bit nano offset (12 bytes)
#define WIREGUARD_TAI64N_LEN		(12)
// Auth algorithm is chacha20pol1305 which is 128bit (16 byte) authenticator
#define WIREGUARD_AUTHTAG_LEN		(16)
// Hash algorithm is blake2s which makes 32 byte hashes
#define WIREGUARD_HASH_LEN			(32)
// Public key algo is curve22519 which uses 32 byte keys
#define WIREGUARD_PUBLIC_KEY_LEN	(32)
// Public key algo is curve22519 which uses 32 byte keys
#define WIREGUARD_PRIVATE_KEY_LEN	(32)
// Symmetric session keys are chacha20/poly1305 which uses 32 byte keys
#define WIREGUARD_SESSION_KEY_LEN	(32)

// Timers / Limits
#define WIREGUARD_COOKIE_LEN		(16)
#define COOKIE_SECRET_MAX_AGE		(2 * 60)
#define COOKIE_NONCE_LEN			(24)

#define REKEY_AFTER_MESSAGES		(1ULL << 60)
#define REJECT_AFTER_MESSAGES		(0xFFFFFFFFFFFFFFFFULL - (1ULL << 13))
#define REKEY_AFTER_TIME			(120)
#define REJECT_AFTER_TIME			(180)
#define REKEY_TIMEOUT				(5)
#define KEEPALIVE_TIMEOUT			(10)


#define SYSTEM_LOAD_THRESHOULD (0.9)

#define MESSAGE_INVALID              0
#define MESSAGE_HANDSHAKE_INITIATION 1
#define MESSAGE_HANDSHAKE_RESPONSE   2
#define MESSAGE_COOKIE_REPLY         3
#define MESSAGE_TRANSPORT_DATA       4


#define WIREGUARDIF_INVALID_INDEX (0xFF)
