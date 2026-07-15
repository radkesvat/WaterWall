#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum reality_v2_size_e
{
    kRealityV2SessionIdSize      = 32,
    kRealityV2KeySize            = 32,
    kRealityV2IvSize             = 12,
    kRealityV2TlsRandomSize      = 32,
    kRealityV2TlsRecordHeaderSize = 5,
    kRealityV2CoverPrefixSize    = 12,
    kRealityV2TagSize            = 16,
    kRealityV2RecordAadSize      = 85,
};

enum reality_v2_direction_e
{
    kRealityV2DirectionClientToServer = 0x01,
    kRealityV2DirectionServerToClient = 0x02,
};

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

bool realityV2DeriveSessionId(const reality_v2_handshake_binding_t *binding,
                              uint8_t session_id[kRealityV2SessionIdSize]);
bool realityV2DeriveSessionMaterial(const uint8_t root_key[kRealityV2KeySize],
                                    const reality_v2_handshake_binding_t *binding,
                                    reality_v2_session_material_t *material);
bool realityV2SequenceAvailable(uint64_t sequence_number);
void realityV2BuildNonce(const uint8_t base_iv[kRealityV2IvSize], uint64_t sequence_number,
                         uint8_t nonce[kRealityV2IvSize]);
bool realityV2BuildRecordAad(uint8_t direction, uint64_t sequence_number,
                            const uint8_t session_id[kRealityV2SessionIdSize],
                            const uint8_t tls_record_header[kRealityV2TlsRecordHeaderSize],
                            const uint8_t cover_prefix[kRealityV2CoverPrefixSize],
                            uint8_t aad[kRealityV2RecordAadSize]);
