#pragma once

#include "wwapi.h"

enum
{
    VMESS_REQUEST_PREFIX_SIZE        = 42,
    VMESS_REQUEST_HEADER_MAX         = 316,
    VMESS_REQUEST_WIRE_MAX           = 374,
    VMESS_RESPONSE_HEADER_SIZE       = 38,
    VMESS_RESPONSE_HEADER_MAX        = 259,
    VMESS_RESPONSE_WIRE_MAX          = 293,
    VMESS_MAX_BODY_WIRE_SIZE         = 65551,
    VMESS_SECURITY_AES128_GCM        = 3,
    VMESS_SECURITY_CHACHA20_POLY1305 = 4,
    VMESS_SECURITY_NONE              = 5,
    VMESS_OPTION_CHUNK               = 1,
    VMESS_OPTION_MASK                = 4,
    VMESS_OPTION_PADDING             = 8,
    VMESS_OPTION_AUTH_LENGTH         = 16,
};

/* Strict policy would reuse a wire nonce. The caller must close the connection. */
#define kVmessCounterExhausted ((wcrypto_status_t) - 100)

#define VMESS_PACKETADDR_DOMAIN "sp.packet-addr.v2fly.arpa"

typedef enum vmess_counter_policy_e
{
    kVmessCounterWrap,
    kVmessCounterStrict,
} vmess_counter_policy_t;

/* Exact UTF-8 bytes: strict UUIDs are preserved, short IDs use UUIDv5(nil, id).
 * On failure uuid is cleared. Invalid UUID-sized values never become short IDs. */
WCRYPTO_MUST_USE wcrypto_status_t vmessNormalizeId(const char *id, size_t length, uint8_t uuid[16]);

/* Provider availability is checked independently of the generic crypto backend.
 * Pure selection accepts capability facts to permit host-independent tests. */
bool                              vmessCipherAvailable(uint8_t security);
WCRYPTO_MUST_USE wcrypto_status_t vmessAutoSecuritySelect(bool accelerated_aes, bool aes_available,
                                                          bool chacha_available, uint8_t *security);
WCRYPTO_MUST_USE wcrypto_status_t vmessAutoSecurity(uint8_t *security);

typedef struct vmess_prepared_key_s
{
    uint8_t cmd_key[16];
    uint8_t auth_key[16];
} vmess_prepared_key_t;

/* Initialize to zero. Mutable contexts belong to one handshake/line worker. */
typedef struct vmess_auth_id_ctx_s
{
    void *cipher;
} vmess_auth_id_ctx_t;

typedef struct vmess_request_header_s
{
    uint8_t  version;
    uint8_t  command;
    uint8_t  security;
    uint8_t  options;
    uint8_t  response;
    uint8_t  key[16];
    uint8_t  iv[16];
    uint8_t  address_type;
    uint8_t  address_length;
    uint8_t  address[255];
    uint16_t port;
} vmess_request_header_t;

/* Internal family uses the outer VMess types (1=IPv4, 3=IPv6); the envelope
 * translates these to its independent 1=IPv4, 2=IPv6 address-family bytes. */
typedef struct vmess_packet_addr_s
{
    uint8_t  address_type;
    uint8_t  address[16];
    uint16_t port;
} vmess_packet_addr_t;

/* The reserved packetaddr domain must never become an ordinary final target. */
bool vmessIsPacketAddrDomain(const uint8_t *domain, size_t length);
bool vmessRequestIsPacketAddr(const vmess_request_header_t *header);
/* Zero means an unsupported family. Encoding rejects port zero; decoding accepts
 * a header-only record as an empty datagram. Header length is zero on failure. */
size_t                            vmessPacketAddrHeaderSize(const vmess_packet_addr_t *address);
WCRYPTO_MUST_USE wcrypto_status_t vmessPacketAddrEncode(const vmess_packet_addr_t *address, uint8_t *out,
                                                        size_t capacity, size_t *header_length);
WCRYPTO_MUST_USE wcrypto_status_t vmessPacketAddrDecode(const uint8_t *record, size_t length, vmess_packet_addr_t *out,
                                                        size_t *header_length);

typedef struct vmess_kdf_segment_s
{
    const uint8_t *data;
    size_t         length;
} vmess_kdf_segment_t;

/* Protocol-local KDF: at most three path segments, each at most 64 bytes. */
WCRYPTO_MUST_USE wcrypto_status_t vmessKdf(const uint8_t *key, size_t key_length, const vmess_kdf_segment_t *path,
                                           size_t path_count, uint8_t out[32]);
WCRYPTO_MUST_USE wcrypto_status_t vmessPrepareKey(const uint8_t uuid[16], vmess_prepared_key_t *out);
/* Timestamp and random bytes are explicit; callers obtain fresh material when
 * committing the first request. No mutable AuthID trial context is needed. */
WCRYPTO_MUST_USE wcrypto_status_t vmessAuthIdCreate(const vmess_prepared_key_t *key, uint64_t timestamp,
                                                    const uint8_t random[4], uint8_t out[16]);
WCRYPTO_MUST_USE wcrypto_status_t vmessAuthIdInit(vmess_auth_id_ctx_t *ctx);
void                              vmessAuthIdDestroy(vmess_auth_id_ctx_t *ctx);
/* AuthenticationFailed means CRC mismatch and permits the next candidate.
 * RejectedKey means CRC matched but the timestamp is outside the inclusive
 * +/-120-second window (or negative); this is a recognized terminal rejection.
 * timestamp is set only for CRC-valid candidates. */
WCRYPTO_MUST_USE wcrypto_status_t vmessAuthIdCheck(vmess_auth_id_ctx_t *ctx, const vmess_prepared_key_t *key,
                                                   const uint8_t auth_id[16], uint64_t now, uint64_t *timestamp);
WCRYPTO_MUST_USE wcrypto_status_t vmessRequestLengthOpen(const uint8_t cmd_key[16], const uint8_t auth_id[16],
                                                         const uint8_t encrypted_length[18], const uint8_t nonce[8],
                                                         uint16_t *plaintext_length);
WCRYPTO_MUST_USE wcrypto_status_t vmessRequestHeaderOpen(const uint8_t cmd_key[16], const uint8_t auth_id[16],
                                                         const uint8_t nonce[8], const uint8_t *encrypted_header,
                                                         size_t encrypted_length, vmess_request_header_t *out);
WCRYPTO_MUST_USE wcrypto_status_t vmessRequestHeaderParse(const uint8_t *plaintext, size_t length,
                                                          vmess_request_header_t *out);
bool                              vmessModeValid(uint8_t security, uint8_t options, uint8_t command);
/* Emits AuthID, sealed length, nonce and sealed request. Padding is 0..15 bytes;
 * it is independent of body padding. Outputs must not overlap the inputs. */
WCRYPTO_MUST_USE wcrypto_status_t vmessRequestHeaderSeal(const uint8_t cmd_key[16], const uint8_t auth_id[16],
                                                         const uint8_t nonce[8], const vmess_request_header_t *header,
                                                         const uint8_t *padding, size_t padding_length, uint8_t *out,
                                                         size_t capacity, size_t *wire_length);
WCRYPTO_MUST_USE wcrypto_status_t vmessResponseKeys(const uint8_t request_key[16], const uint8_t request_iv[16],
                                                    uint8_t response_key[16], uint8_t response_iv[16]);
WCRYPTO_MUST_USE wcrypto_status_t vmessResponseHeaderSeal(const uint8_t response_key[16], const uint8_t response_iv[16],
                                                          uint8_t response, uint8_t out[VMESS_RESPONSE_HEADER_SIZE]);
/* Use the derived response keys. Authenticate this fixed prefix before retaining
 * the bounded payload. Response options/commands are consumed without applying
 * remote account or endpoint changes. */
WCRYPTO_MUST_USE wcrypto_status_t vmessResponseLengthOpen(const uint8_t response_key[16], const uint8_t response_iv[16],
                                                          const uint8_t encrypted_length[18],
                                                          uint16_t     *plaintext_length);
WCRYPTO_MUST_USE wcrypto_status_t vmessResponseHeaderOpen(const uint8_t response_key[16], const uint8_t response_iv[16],
                                                          uint8_t expected_response, const uint8_t *encrypted_header,
                                                          size_t encrypted_length);

typedef struct vmess_body_ctx_s
{
    void                  *cipher;
    void                  *length_cipher;
    void                  *shake;
    uint8_t                key[32];
    uint8_t                length_key[32];
    uint8_t                length_iv[16];
    uint8_t                iv[16];
    uint32_t               counter;
    uint32_t               pending_wire_length;
    uint16_t               pending_padding;
    uint8_t                security;
    uint8_t                options;
    vmess_counter_policy_t counter_policy;
    bool                   raw;
    bool                   encrypt;
    bool                   pending;
    bool                   ended;
    bool                   failed;
} vmess_body_ctx_t;

/* All contexts must start zeroed. Failure leaves a destroyable context. */
WCRYPTO_MUST_USE wcrypto_status_t vmessBodyInit(vmess_body_ctx_t *ctx, const uint8_t key[16], const uint8_t iv[16],
                                                uint8_t security, uint8_t options, uint8_t command, bool encrypt,
                                                vmess_counter_policy_t counter_policy);
/* Before processing the first record, response-direction authenticated lengths
 * use the request key/IV, independently of response body encryption/masking. */
WCRYPTO_MUST_USE wcrypto_status_t vmessBodySetLengthMaterial(vmess_body_ctx_t *ctx, const uint8_t request_key[16],
                                                             const uint8_t request_iv[16]);
void                              vmessBodyDestroy(vmess_body_ctx_t *ctx);
size_t                            vmessBodyLengthSize(const vmess_body_ctx_t *ctx);
size_t                            vmessBodyMaxPlaintext(const vmess_body_ctx_t *ctx);
/* LengthOpen advances its parser exactly once. Retain the returned length until
 * that complete body arrives, then call Open exactly once. Any failure is terminal. */
WCRYPTO_MUST_USE wcrypto_status_t vmessBodyLengthOpen(vmess_body_ctx_t *ctx, const uint8_t *prefix,
                                                      size_t prefix_length, uint32_t *body_wire_length);
/* Exact in-place body opening is supported. No unauthenticated output survives a
 * failure. An empty authenticated body is EOF only after its tag is verified. */
WCRYPTO_MUST_USE wcrypto_status_t vmessBodyOpen(vmess_body_ctx_t *ctx, const uint8_t *body, size_t body_length,
                                                uint8_t *out, size_t capacity, size_t *plaintext_length, bool *eof);
/* Seal emits one complete frame. Wrap uses every 16-bit ordinal, then repeats
 * the nonce sequence without rekeying. Strict reserves 65535 for EOF. Raw NONE
 * has no framing and no explicit EOF bytes. */
WCRYPTO_MUST_USE wcrypto_status_t vmessBodySeal(vmess_body_ctx_t *ctx, const uint8_t *plaintext,
                                                size_t plaintext_length, bool eof, uint8_t *out, size_t capacity,
                                                size_t *wire_length);
