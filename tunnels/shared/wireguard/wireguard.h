#pragma once

/*
    Most of the code is taken and renamed, from the awesome projects wireguard-lwip and lwip

    Author of lwip:              Adam Dunkels  https://github.com/smartalock/wireguard-lwip
    Author of wireguard-lwip:    Daniel Hope   https://github.com/lwip-tcpip/lwip

    their license files are placed next to this file
*/

#include "defs.h"

// Initialise the WireGuard system - need to call this before anything else
void wireguard_init();
bool wireguard_device_init(struct wireguard_device *device, const uint8_t *private_key);
bool wireguard_peer_init(struct wireguard_device *device, struct wireguard_peer *peer, const uint8_t *public_key, const uint8_t *preshared_key);

struct wireguard_peer *peer_alloc(struct wireguard_device *device);
uint8_t wireguard_peer_index(struct wireguard_device *device, struct wireguard_peer *peer);
struct wireguard_peer *peer_lookup_by_pubkey(struct wireguard_device *device, uint8_t *public_key);
struct wireguard_peer *peer_lookup_by_peer_index(struct wireguard_device *device, uint8_t peer_index);
struct wireguard_peer *peer_lookup_by_receiver(struct wireguard_device *device, uint32_t receiver);
struct wireguard_peer *peer_lookup_by_handshake(struct wireguard_device *device, uint32_t receiver);

void wireguard_start_session(struct wireguard_peer *peer, bool initiator);

void keypair_update(struct wireguard_peer *peer, struct wireguard_keypair *received_keypair);
void keypair_destroy(struct wireguard_keypair *keypair);

struct wireguard_keypair *get_peer_keypair_for_idx(struct wireguard_peer *peer, uint32_t idx);
bool wireguard_check_replay(struct wireguard_keypair *keypair, uint64_t seq);

uint8_t wireguard_get_message_type(const uint8_t *data, size_t len);

struct wireguard_peer *wireguard_process_initiation_message(struct wireguard_device *device, struct message_handshake_initiation *msg);
bool wireguard_process_handshake_response(struct wireguard_device *device, struct wireguard_peer *peer, struct message_handshake_response *src);
bool wireguard_process_cookie_message(struct wireguard_device *device, struct wireguard_peer *peer, struct message_cookie_reply *src);

bool wireguard_create_handshake_initiation(struct wireguard_device *device, struct wireguard_peer *peer, struct message_handshake_initiation *dst);
bool wireguard_create_handshake_response(struct wireguard_device *device, struct wireguard_peer *peer, struct message_handshake_response *dst);
void wireguard_create_cookie_reply(struct wireguard_device *device, struct message_cookie_reply *dst, const uint8_t *mac1, uint32_t index, uint8_t *source_addr_port, size_t source_length);


bool wireguard_check_mac1(struct wireguard_device *device, const uint8_t *data, size_t len, const uint8_t *mac1);
bool wireguard_check_mac2(struct wireguard_device *device, const uint8_t *data, size_t len, uint8_t *source_addr_port, size_t source_length, const uint8_t *mac2);

bool wireguard_expired(uint32_t created_millis, uint32_t valid_seconds);

void wireguard_encrypt_packet(uint8_t *dst, const uint8_t *src, size_t src_len, struct wireguard_keypair *keypair);
bool wireguard_decrypt_packet(uint8_t *dst, const uint8_t *src, size_t src_len, uint64_t counter, struct wireguard_keypair *keypair);

bool wireguard_base64_decode(const char *str, uint8_t *out, size_t *outlen);
bool wireguard_base64_encode(const uint8_t *in, size_t inlen, char *out, size_t *outlen);

