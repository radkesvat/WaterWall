#pragma once

#include "wwapi.h"

enum
{
    kEncryptionPacketNonceSize = WCRYPTO_XCHACHA20POLY1305_NONCE_SIZE,
    kEncryptionPacketTagSize   = WCRYPTO_AEAD_TAG_SIZE,
    kEncryptionPacketOverhead  = kEncryptionPacketNonceSize + kEncryptionPacketTagSize,
    kEncryptionPacketMaxLength = UINT16_MAX,
};

typedef enum encryption_packet_result_e
{
    kEncryptionPacketOk,
    kEncryptionPacketMalformed,
    kEncryptionPacketFragmented,
    kEncryptionPacketProtocol,
    kEncryptionPacketChecksum,
    kEncryptionPacketTooLarge,
    kEncryptionPacketAuthentication,
    kEncryptionPacketCryptoFailed,
} encryption_packet_result_t;

/* Derive independent client-to-server and server-to-client keys. Outputs must
 * not overlap the base key or each other. */
bool encryptionPacketDeriveKeys(const uint8_t base_key[32], uint8_t upload_key[32], uint8_t download_key[32]);

/* One complete unfragmented IPv4 TCP/UDP packet. UDP must fill its IPv4 payload.
 * Encode requires the advertised nonce-size left padding and may replace *buf
 * to grow the authentication-tag tail. Both operations may mutate on failure;
 * callers must discard a refused packet. Neither operation consumes the sbuf. */
encryption_packet_result_t encryptionEncodePacket(const uint8_t key[32], sbuf_t **buf);
encryption_packet_result_t encryptionDecodePacket(const uint8_t key[32], sbuf_t *buf);
const char                *encryptionPacketResultName(encryption_packet_result_t result);
