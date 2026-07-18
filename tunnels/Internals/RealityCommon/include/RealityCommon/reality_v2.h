#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum reality_v2_size_e
{
    kRealityV2MinCredentialByteLength = 1,
    kRealityV2MaxPasswordByteLength   = 32,
    kRealityV2MaxSaltByteLength       = 32,
    kRealityV2MinKdfIterations        = 1,
    kRealityV2MaxKdfIterations        = 1000000,
    kRealityV2SessionIdSize       = 32,
    kRealityV2KeySize             = 32,
    kRealityV2IvSize              = 12,
    kRealityV2TlsRandomSize       = 32,
    kRealityV2TlsRecordHeaderSize  = 5,
    kRealityV2Tls12GcmPrefixSize   = 8,
    kRealityV2Tls12CbcPrefixSize   = 16,
    kRealityV2MaxVisiblePrefixSize = 16,
    kRealityV2TagSize              = 16,
    kRealityV2AlertMessageSize     = 2,
    kRealityV2ControlFormatVersion = 1,
    kRealityV2ControlHeaderSize    = 2,
    /*
     * TLS 1.3 handoff controls vary across the protected-record envelope
     * observed by the in-memory BoringSSL wire fixture: 22-byte KeyUpdate
     * records, a 55-byte early-application record, a 381-byte two-ticket
     * flight, and the 1172-byte protected server-handshake record.
     * A control body adds the two-byte control header, TLSInnerPlaintext type,
     * and AEAD tag, so this maps to 3..1153 authenticated padding bytes.
     */
    kRealityV2ControlMinTlsRecordBody = 22,
    kRealityV2ControlMaxTlsRecordBody = 1172,
    kRealityV2ControlMinPadding       = 3,
    kRealityV2ControlMaxPadding       = 1153,
    kRealityV2ControlMinPayload       = kRealityV2ControlHeaderSize + kRealityV2ControlMinPadding,
    kRealityV2ControlMaxPayload       = kRealityV2ControlHeaderSize + kRealityV2ControlMaxPadding,
    kRealityV2ControlMaxInnerPlaintext = kRealityV2ControlMaxPayload + 1,
    kRealityV2RecordAadMaxSize     = 102,
    kRealityV2MaxPlaintextFragment = 16384,
    kRealityV2MaxTlsRecordBody     = 18432,
};

enum reality_v2_tls_version_e
{
    kRealityV2Tls12 = 0x0303,
    kRealityV2Tls13 = 0x0304,
};

enum reality_v2_direction_e
{
    kRealityV2DirectionClientToServer = 0x01,
    kRealityV2DirectionServerToClient = 0x02,
};

typedef enum reality_v2_record_kind_e
{
    kRealityV2RecordKindInvalid         = 0,
    kRealityV2RecordKindApplicationData = 1,
    kRealityV2RecordKindAlert           = 2,
    kRealityV2RecordKindHandoffRequest  = 3,
    kRealityV2RecordKindHandoffAck      = 4,
    kRealityV2RecordKindHandoffConfirm  = 5,
} reality_v2_record_kind_t;

typedef bool (*reality_v2_random_bytes_fn)(void *context, void *bytes, size_t size);

typedef int (*reality_v2_aead_decrypt_fn)(void *context, unsigned char *dst,
                                          const unsigned char *src, size_t src_len,
                                          const unsigned char *ad, size_t ad_len,
                                          const unsigned char *nonce, const unsigned char *key);

typedef enum reality_v2_alert_e
{
    kRealityV2AlertInvalid      = 0,
    kRealityV2AlertCloseNotify  = 1,
    kRealityV2AlertBadRecordMac = 2,
} reality_v2_alert_t;

typedef enum reality_v2_record_profile_id_e
{
    kRealityV2RecordProfileInvalid     = 0,
    kRealityV2RecordProfileTls13Aead   = 1,
    kRealityV2RecordProfileTls12ChaCha = 2,
    kRealityV2RecordProfileTls12Gcm    = 3,
    kRealityV2RecordProfileTls12Cbc    = 4,
} reality_v2_record_profile_id_t;

typedef struct reality_v2_record_profile_s
{
    uint8_t profile_id;
    uint8_t visible_prefix_len;
    uint8_t block_size;
    uint8_t tls_mac_len;
} reality_v2_record_profile_t;

typedef struct reality_v2_record_layout_s
{
    uint32_t wire_body_len;
    uint32_t inner_plaintext_len;
    uint32_t filler_len;
} reality_v2_record_layout_t;

typedef struct reality_v2_record_descriptor_s
{
    reality_v2_record_profile_t profile;
    uint16_t                    tls_version;
    uint8_t                     record_kind;
    uint8_t                     outer_content_type;
    uint8_t                     visible_prefix_len;
    uint8_t                     tls13_inner_content_type;
} reality_v2_record_descriptor_t;

typedef struct reality_v2_handshake_binding_s
{
    uint8_t  client_random[kRealityV2TlsRandomSize];
    uint8_t  server_random[kRealityV2TlsRandomSize];
    uint16_t tls_version;
    uint16_t cipher_suite;
} reality_v2_handshake_binding_t;

typedef struct reality_v2_session_material_s
{
    uint8_t session_id[kRealityV2SessionIdSize];
    uint8_t c2s_key[kRealityV2KeySize];
    uint8_t s2c_key[kRealityV2KeySize];
    uint8_t c2s_iv[kRealityV2IvSize];
    uint8_t s2c_iv[kRealityV2IvSize];
} reality_v2_session_material_t;

bool realityV2DeriveRootKey(const char *password, const char *salt, uint32_t iterations,
                            uint8_t out_key[kRealityV2KeySize]);
bool realityV2DeriveSessionId(const reality_v2_handshake_binding_t *binding,
                              uint8_t session_id[kRealityV2SessionIdSize]);
bool realityV2DeriveSessionMaterial(const uint8_t root_key[kRealityV2KeySize],
                                    const reality_v2_handshake_binding_t *binding,
                                    reality_v2_session_material_t *material);
bool realityV2SelectRecordProfile(uint16_t tls_version, uint16_t cipher_suite,
                                  reality_v2_record_profile_t *profile);
bool realityV2RecordProfileIsValid(const reality_v2_record_profile_t *profile);
bool realityV2BuildRecordDescriptor(uint16_t tls_version, const reality_v2_record_profile_t *profile,
                                    uint8_t record_kind, reality_v2_record_descriptor_t *descriptor);
bool realityV2RecordDescriptorIsValid(const reality_v2_record_descriptor_t *descriptor);
bool realityV2CalculateRecordLayout(const reality_v2_record_profile_t *profile, uint32_t payload_len,
                                    reality_v2_record_layout_t *layout);
bool realityV2CalculateDescriptorLayout(const reality_v2_record_descriptor_t *descriptor,
                                        uint32_t payload_len, reality_v2_record_layout_t *layout);
bool realityV2ValidateRecordBodyLength(const reality_v2_record_profile_t *profile, uint32_t body_len);
bool realityV2ValidateDescriptorBodyLength(const reality_v2_record_descriptor_t *descriptor,
                                           uint32_t body_len);
bool realityV2ClassifyRecord(uint16_t tls_version, const reality_v2_record_profile_t *profile,
                             const uint8_t tls_record_header[kRealityV2TlsRecordHeaderSize],
                             reality_v2_record_descriptor_t *descriptor);
bool realityV2ValidateCbcInnerPlaintext(const reality_v2_record_profile_t *profile,
                                        const uint8_t *inner_plaintext, uint32_t inner_plaintext_len,
                                        uint32_t *payload_len);
bool realityV2BuildInnerPlaintext(const reality_v2_record_descriptor_t *descriptor,
                                  const uint8_t *payload, uint32_t payload_len,
                                  uint8_t *inner_plaintext, uint32_t inner_plaintext_len);
bool realityV2ValidateInnerPlaintext(const reality_v2_record_descriptor_t *descriptor,
                                     const uint8_t *inner_plaintext, uint32_t inner_plaintext_len,
                                     uint32_t *payload_offset, uint32_t *payload_len);
bool realityV2RecordKindIsControl(uint8_t record_kind);
bool realityV2ControlPaddingLengthIsValid(uint32_t padding_len);
bool realityV2CalculateControlPayloadLength(uint32_t padding_len, uint32_t *payload_len);
bool realityV2SerializeControl(uint8_t record_kind, const uint8_t *padding, uint32_t padding_len,
                               uint8_t *out, uint32_t out_len);
bool realityV2ParseControl(uint8_t expected_record_kind, const uint8_t *data, uint32_t len);
bool realityV2BuildControlPayloadWithRandom(uint8_t record_kind, reality_v2_random_bytes_fn random_bytes,
                                            void *random_context, uint8_t *out, uint32_t out_capacity,
                                            uint32_t *out_len);
bool realityV2BuildControlPayload(uint8_t record_kind, uint8_t *out, uint32_t out_capacity,
                                  uint32_t *out_len);
bool realityV2TryDecryptExpectedRecord(const reality_v2_record_descriptor_t *descriptor,
                                       uint8_t direction, uint64_t sequence_number,
                                       const uint8_t session_id[kRealityV2SessionIdSize],
                                       const uint8_t key[kRealityV2KeySize],
                                       const uint8_t base_iv[kRealityV2IvSize],
                                       const uint8_t *record, uint32_t record_len,
                                       reality_v2_aead_decrypt_fn decrypt, void *decrypt_context,
                                       uint8_t *plaintext, uint32_t plaintext_capacity,
                                       uint32_t *payload_offset, uint32_t *payload_len);
bool realityV2SerializeAlert(uint8_t alert, uint8_t out[kRealityV2AlertMessageSize]);
bool realityV2ParseAlert(const uint8_t *data, uint32_t len, uint8_t *alert);
bool realityV2SequenceAvailable(uint64_t sequence_number);
bool realityV2AddTlsRecordSequence(uint64_t base, uint64_t reality_sequence, uint64_t *tls_sequence);
void realityV2WriteBe64(uint8_t out[8], uint64_t value);
uint64_t realityV2ReadBe64(const uint8_t in[8]);
void realityV2BuildNonce(const uint8_t base_iv[kRealityV2IvSize], uint64_t sequence_number,
                         uint8_t nonce[kRealityV2IvSize]);
bool realityV2BuildRecordAad(const reality_v2_record_descriptor_t *descriptor, uint8_t direction,
                            uint64_t sequence_number,
                            const uint8_t session_id[kRealityV2SessionIdSize],
                            const uint8_t tls_record_header[kRealityV2TlsRecordHeaderSize],
                            const uint8_t *visible_prefix, uint8_t visible_prefix_len,
                            uint8_t aad[kRealityV2RecordAadMaxSize], size_t *aad_len);
