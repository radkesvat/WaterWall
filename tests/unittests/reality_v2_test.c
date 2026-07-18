#include "RealityCommon/reality_v2.h"
#include "wcrypto.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(WCRYPTO_BACKEND_SODIUM)
#include <sodium.h>
#endif

#ifndef REALITY_TLS_CLIENT_HANDSHAKE_SOURCE
#error "REALITY_TLS_CLIENT_HANDSHAKE_SOURCE must name the patched TlsClient handshake source"
#endif

enum
{
    kPlaintextSize      = 19,
    kInnerPlaintextSize = kPlaintextSize + 1,
    kCiphertextSize     = kInnerPlaintextSize + kRealityV2TagSize,
};

typedef struct test_record_s
{
    uint8_t header[kRealityV2TlsRecordHeaderSize];
    uint8_t ciphertext[kCiphertextSize];
} test_record_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void requireEqual(const uint8_t *actual, const uint8_t *expected, size_t len, const char *message)
{
    require(memcmp(actual, expected, len) == 0, message);
}

static reality_v2_handshake_binding_t makeBinding(void)
{
    reality_v2_handshake_binding_t binding = {
        .tls_version  = 0x0304,
        .cipher_suite = 0x1301,
    };
    for (uint32_t i = 0; i < kRealityV2TlsRandomSize; ++i)
    {
        binding.client_random[i] = (uint8_t) i;
        binding.server_random[i] = (uint8_t) (i + 32U);
    }
    return binding;
}

static void makeRecord(const reality_v2_session_material_t *material, uint8_t direction, uint64_t sequence,
                       uint8_t marker, test_record_t *record)
{
    const uint8_t plaintext[kPlaintextSize] = "Reality v2 payload";
    const uint8_t *key = direction == kRealityV2DirectionClientToServer ? material->c2s_key : material->s2c_key;
    const uint8_t *iv  = direction == kRealityV2DirectionClientToServer ? material->c2s_iv : material->s2c_iv;
    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadMaxSize];
    uint8_t inner[kInnerPlaintextSize];
    size_t  aad_len = 0;
    const reality_v2_record_profile_t profile = {
        .profile_id = kRealityV2RecordProfileTls13Aead,
    };
    reality_v2_record_descriptor_t descriptor;
    require(realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                            &profile,
                                            kRealityV2RecordKindApplicationData,
                                            &descriptor),
            "data descriptor construction failed");

    record->header[0] = 0x17;
    record->header[1] = 0x03;
    record->header[2] = 0x03;
    record->header[3] = 0;
    record->header[4] = kCiphertextSize;
    require(realityV2BuildInnerPlaintext(&descriptor,
                                         plaintext,
                                         sizeof(plaintext),
                                         inner,
                                         sizeof(inner)),
            "record inner plaintext construction failed");
    inner[0] ^= marker;

    realityV2BuildNonce(iv, sequence, nonce);
    require(realityV2BuildRecordAad(&descriptor,
                                    direction,
                                    sequence,
                                    material->session_id,
                                    record->header,
                                    NULL,
                                    0,
                                    aad,
                                    &aad_len),
            "record AAD construction failed");
    require(chacha20poly1305Encrypt(record->ciphertext,
                                    inner,
                                    sizeof(inner),
                                    aad,
                                    aad_len,
                                    nonce,
                                    key) == 0,
            "record encryption failed");
}

static bool receiveRecord(const reality_v2_session_material_t *material, uint8_t direction,
                          uint64_t *expected_sequence, const test_record_t *record)
{
    if (! realityV2SequenceAvailable(*expected_sequence))
    {
        return false;
    }

    const uint8_t *key = direction == kRealityV2DirectionClientToServer ? material->c2s_key : material->s2c_key;
    const uint8_t *iv  = direction == kRealityV2DirectionClientToServer ? material->c2s_iv : material->s2c_iv;
    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadMaxSize];
    uint8_t plaintext[kInnerPlaintextSize];
    size_t  aad_len = 0;
    const reality_v2_record_profile_t profile = {
        .profile_id = kRealityV2RecordProfileTls13Aead,
    };
    reality_v2_record_descriptor_t descriptor;
    if (! realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                          &profile,
                                          kRealityV2RecordKindApplicationData,
                                          &descriptor))
    {
        return false;
    }

    realityV2BuildNonce(iv, *expected_sequence, nonce);
    if (! realityV2BuildRecordAad(&descriptor,
                                  direction,
                                  *expected_sequence,
                                  material->session_id,
                                  record->header,
                                  NULL,
                                  0,
                                  aad,
                                  &aad_len) ||
        chacha20poly1305Decrypt(plaintext,
                                record->ciphertext,
                                sizeof(record->ciphertext),
                                aad,
                                aad_len,
                                nonce,
                                key) != 0)
    {
        return false;
    }

    uint32_t payload_offset;
    uint32_t payload_len;
    if (! realityV2ValidateInnerPlaintext(&descriptor,
                                          plaintext,
                                          sizeof(plaintext),
                                          &payload_offset,
                                          &payload_len) ||
        payload_offset != 0 || payload_len != kPlaintextSize)
    {
        return false;
    }

    ++*expected_sequence;
    return true;
}

static void testDeterministicDerivation(void)
{
    static const uint8_t expected_session_id[kRealityV2SessionIdSize] = {
        0x5a, 0x0f, 0x1b, 0xca, 0xe9, 0xd9, 0xfc, 0xb0, 0x02, 0x5f, 0x90, 0x56, 0xa3, 0xf9, 0xd4, 0x84,
        0x44, 0x15, 0xcb, 0xe5, 0x4c, 0x4f, 0xdf, 0x6f, 0xa3, 0xe7, 0x62, 0xf5, 0x44, 0x29, 0x37, 0xcd,
    };
    static const uint8_t expected_c2s_key[kRealityV2KeySize] = {
        0x4b, 0xc3, 0x8c, 0x68, 0x48, 0xba, 0x51, 0xfb, 0x4b, 0xc4, 0x4f, 0x23, 0xb0, 0x95, 0x40, 0xa0,
        0x98, 0x6e, 0x08, 0x47, 0x3b, 0x70, 0xf6, 0xb5, 0xfb, 0xcd, 0x4c, 0x3f, 0x1d, 0xd6, 0x5d, 0xc4,
    };
    static const uint8_t expected_s2c_key[kRealityV2KeySize] = {
        0xbc, 0x0e, 0x1e, 0xa4, 0x2e, 0x1b, 0xdc, 0x1e, 0xec, 0xd2, 0xc8, 0x22, 0xca, 0x96, 0x1c, 0x66,
        0xa6, 0x6a, 0xb1, 0x95, 0xa5, 0xb0, 0xec, 0xe7, 0xed, 0x34, 0x72, 0xb1, 0xfb, 0x02, 0x81, 0x53,
    };
    static const uint8_t expected_c2s_iv[kRealityV2IvSize] = {
        0xd1, 0xbf, 0x7f, 0xb6, 0x50, 0xce, 0x6c, 0x32, 0x35, 0x2f, 0xc5, 0xcf,
    };
    static const uint8_t expected_s2c_iv[kRealityV2IvSize] = {
        0xfc, 0x1a, 0xdf, 0xe3, 0xf8, 0x66, 0xe4, 0xb0, 0x29, 0xcf, 0xd4, 0xd4,
    };

    uint8_t root_key[kRealityV2KeySize];
    for (uint32_t i = 0; i < sizeof(root_key); ++i)
    {
        root_key[i] = (uint8_t) i;
    }

    reality_v2_handshake_binding_t binding = makeBinding();
    reality_v2_session_material_t  material = {0};
    require(realityV2DeriveSessionMaterial(root_key, &binding, &material), "session derivation failed");
    requireEqual(material.session_id, expected_session_id, sizeof(expected_session_id), "session-id vector mismatch");
    requireEqual(material.c2s_key, expected_c2s_key, sizeof(expected_c2s_key), "c2s key vector mismatch");
    requireEqual(material.s2c_key, expected_s2c_key, sizeof(expected_s2c_key), "s2c key vector mismatch");
    requireEqual(material.c2s_iv, expected_c2s_iv, sizeof(expected_c2s_iv), "c2s IV vector mismatch");
    requireEqual(material.s2c_iv, expected_s2c_iv, sizeof(expected_s2c_iv), "s2c IV vector mismatch");
    require(memcmp(material.c2s_key, material.s2c_key, sizeof(material.c2s_key)) != 0,
            "direction keys must differ");
    require(memcmp(material.c2s_iv, material.s2c_iv, sizeof(material.c2s_iv)) != 0,
            "direction IVs must differ");

    reality_v2_session_material_t changed = {0};
    binding.server_random[31] ^= 1;
    require(realityV2DeriveSessionMaterial(root_key, &binding, &changed), "changed-session derivation failed");
    require(memcmp(material.session_id, changed.session_id, sizeof(material.session_id)) != 0,
            "changing a TLS random must change the session");
    require(memcmp(material.c2s_key, changed.c2s_key, sizeof(material.c2s_key)) != 0,
            "changing a TLS random must change c2s key");
    require(memcmp(material.s2c_iv, changed.s2c_iv, sizeof(material.s2c_iv)) != 0,
            "changing a TLS random must change s2c IV");

    binding = makeBinding();
    binding.tls_version = 0x0303;
    require(realityV2DeriveSessionMaterial(root_key, &binding, &changed), "changed-version derivation failed");
    require(memcmp(material.session_id, changed.session_id, sizeof(material.session_id)) != 0,
            "changing TLS version must change session");
    binding = makeBinding();
    binding.cipher_suite = 0x1302;
    require(realityV2DeriveSessionMaterial(root_key, &binding, &changed), "changed-cipher derivation failed");
    require(memcmp(material.session_id, changed.session_id, sizeof(material.session_id)) != 0,
            "changing cipher suite must change session");
}

static void testDeterministicAlertAeadVectors(void)
{
    static const uint8_t expected_chacha[2][kRealityV2AlertMessageSize + 1 + kRealityV2TagSize] = {
        {0xad, 0x50, 0x9b, 0xdb, 0xd1, 0xd7, 0x2c, 0x45, 0x78, 0x7f,
         0x02, 0x9d, 0x07, 0x42, 0x4b, 0x45, 0x88, 0x39, 0x23},
        {0xa3, 0xc9, 0x84, 0xd8, 0x9d, 0x0c, 0x3b, 0x9d, 0x02, 0xab,
         0xe3, 0x71, 0xe6, 0xde, 0x7e, 0x60, 0x9b, 0xf1, 0x43},
    };
    static const uint8_t expected_aes256gcm[2][kRealityV2AlertMessageSize + 1 + kRealityV2TagSize] = {
        {0xfb, 0x1d, 0x40, 0x10, 0x07, 0x59, 0xd1, 0x07, 0xdf, 0x36,
         0x6f, 0xda, 0x33, 0x7a, 0xd0, 0x1a, 0xeb, 0x71, 0x26},
        {0x51, 0x4e, 0x1d, 0x81, 0x81, 0xdf, 0x0d, 0x19, 0x1a, 0xf6,
         0x83, 0x4f, 0x72, 0x1c, 0x4a, 0xb5, 0xe9, 0x59, 0x7f},
    };
    const reality_v2_record_profile_t profile = {
        kRealityV2RecordProfileTls13Aead, 0, 0, 0};
    reality_v2_record_descriptor_t descriptor;
    reality_v2_record_layout_t layout;
    require(realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                            &profile,
                                            kRealityV2RecordKindAlert,
                                            &descriptor) &&
                realityV2CalculateDescriptorLayout(&descriptor,
                                                    kRealityV2AlertMessageSize,
                                                    &layout),
            "deterministic alert shape construction failed");

    uint8_t root_key[kRealityV2KeySize];
    for (uint32_t i = 0; i < sizeof(root_key); ++i)
    {
        root_key[i] = (uint8_t) i;
    }
    reality_v2_handshake_binding_t binding = makeBinding();
    reality_v2_session_material_t material = {0};
    require(realityV2DeriveSessionMaterial(root_key, &binding, &material),
            "deterministic alert material derivation failed");
    require(aes256gcmIsAvailable(), "AES-256-GCM is unavailable for deterministic alert vectors");

    uint8_t alert[kRealityV2AlertMessageSize];
    uint8_t inner[kRealityV2AlertMessageSize + 1];
    require(realityV2SerializeAlert(kRealityV2AlertCloseNotify, alert) &&
                realityV2BuildInnerPlaintext(&descriptor,
                                             alert,
                                             sizeof(alert),
                                             inner,
                                             sizeof(inner)),
            "deterministic close_notify plaintext construction failed");
    const uint8_t header[kRealityV2TlsRecordHeaderSize] = {
        0x17, 0x03, 0x03, 0x00, (uint8_t) layout.wire_body_len};

    for (uint8_t direction = kRealityV2DirectionClientToServer;
         direction <= kRealityV2DirectionServerToClient;
         ++direction)
    {
        const size_t vector_index = direction - kRealityV2DirectionClientToServer;
        const uint8_t *key = direction == kRealityV2DirectionClientToServer ? material.c2s_key
                                                                            : material.s2c_key;
        const uint8_t *iv = direction == kRealityV2DirectionClientToServer ? material.c2s_iv
                                                                           : material.s2c_iv;
        uint8_t nonce[kRealityV2IvSize];
        uint8_t aad[kRealityV2RecordAadMaxSize];
        uint8_t ciphertext[sizeof(inner) + kRealityV2TagSize];
        uint8_t decoded[sizeof(inner)];
        size_t aad_len = 0;
        realityV2BuildNonce(iv, 4, nonce);
        require(realityV2BuildRecordAad(&descriptor,
                                        direction,
                                        4,
                                        material.session_id,
                                        header,
                                        NULL,
                                        0,
                                        aad,
                                        &aad_len),
                "deterministic alert AAD construction failed");

        require(chacha20poly1305Encrypt(ciphertext,
                                        inner,
                                        sizeof(inner),
                                        aad,
                                        aad_len,
                                        nonce,
                                        key) == 0,
                "deterministic ChaCha20-Poly1305 alert encryption failed");
        requireEqual(ciphertext,
                     expected_chacha[vector_index],
                     sizeof(ciphertext),
                     "deterministic ChaCha20-Poly1305 alert vector mismatch");
        require(chacha20poly1305Decrypt(decoded,
                                        expected_chacha[vector_index],
                                        sizeof(ciphertext),
                                        aad,
                                        aad_len,
                                        nonce,
                                        key) == 0 &&
                    memcmp(decoded, inner, sizeof(inner)) == 0,
                "deterministic ChaCha20-Poly1305 alert vector did not decrypt");

        require(aes256gcmEncrypt(ciphertext,
                                 inner,
                                 sizeof(inner),
                                 aad,
                                 aad_len,
                                 nonce,
                                 key) == 0,
                "deterministic AES-256-GCM alert encryption failed");
        requireEqual(ciphertext,
                     expected_aes256gcm[vector_index],
                     sizeof(ciphertext),
                     "deterministic AES-256-GCM alert vector mismatch");
        require(aes256gcmDecrypt(decoded,
                                 expected_aes256gcm[vector_index],
                                 sizeof(ciphertext),
                                 aad,
                                 aad_len,
                                 nonce,
                                 key) == 0 &&
                    memcmp(decoded, inner, sizeof(inner)) == 0,
                "deterministic AES-256-GCM alert vector did not decrypt");
    }
}

static void testNonceAndAadEncoding(void)
{
    static const uint8_t expected_nonce[kRealityV2IvSize] = {
        0x00, 0x01, 0x02, 0x03, 0x05, 0x07, 0x05, 0x03, 0x0d, 0x0f, 0x0d, 0x03,
    };
    static const uint8_t expected_aad[] = {
        0x57, 0x61, 0x74, 0x65, 0x72, 0x57, 0x61, 0x6c, 0x6c, 0x20, 0x52, 0x65, 0x61, 0x6c, 0x69, 0x74,
        0x79, 0x20, 0x76, 0x32, 0x2f, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x20, 0x72, 0x65, 0x63,
        0x6f, 0x72, 0x64, 0x01, 0x03, 0x04, 0x01, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x5a, 0x0f, 0x1b,
        0xca, 0xe9, 0xd9, 0xfc, 0xb0, 0x02, 0x5f, 0x90, 0x56, 0xa3, 0xf9, 0xd4, 0x84, 0x44, 0x15, 0xcb,
        0xe5, 0x4c, 0x4f, 0xdf, 0x6f, 0xa3, 0xe7, 0x62, 0xf5, 0x44, 0x29, 0x37, 0xcd, 0x17, 0x03, 0x03,
        0x00, 0x24, 0x00,
    };
    const uint64_t sequence = UINT64_C(0x0102030405060708);
    uint8_t base_iv[kRealityV2IvSize];
    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadMaxSize];
    uint8_t header[kRealityV2TlsRecordHeaderSize] = {0x17, 0x03, 0x03, 0x00, 0x24};
    reality_v2_handshake_binding_t binding = makeBinding();
    uint8_t session_id[kRealityV2SessionIdSize];
    size_t aad_len = 0;
    const reality_v2_record_profile_t profile = {
        .profile_id = kRealityV2RecordProfileTls13Aead,
    };
    reality_v2_record_descriptor_t descriptor;

    for (uint32_t i = 0; i < sizeof(base_iv); ++i)
    {
        base_iv[i] = (uint8_t) i;
    }
    require(realityV2DeriveSessionId(&binding, session_id), "session-id derivation failed");
    require(realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                            &profile,
                                            kRealityV2RecordKindApplicationData,
                                            &descriptor),
            "AAD descriptor construction failed");
    realityV2BuildNonce(base_iv, sequence, nonce);
    requireEqual(nonce, expected_nonce, sizeof(nonce), "nonce encoding mismatch");
    require(realityV2BuildRecordAad(&descriptor,
                                    kRealityV2DirectionClientToServer,
                                    sequence,
                                    session_id,
                                    header,
                                    NULL,
                                    0,
                                    aad,
                                    &aad_len),
            "AAD encoding failed");
    require(aad_len == sizeof(expected_aad), "AAD encoding length mismatch");
    requireEqual(aad, expected_aad, aad_len, "AAD encoding vector mismatch");
    require(! realityV2BuildRecordAad(&descriptor, 0xff, sequence, session_id, header, NULL,
                                      0, aad, &aad_len),
            "invalid direction must be rejected");
    require(realityV2SequenceAvailable(0), "sequence zero must be available");
    require(realityV2SequenceAvailable(UINT64_MAX - 1), "last permitted sequence must be available");
    require(! realityV2SequenceAvailable(UINT64_MAX), "UINT64_MAX must be rejected before use");

    uint64_t tls_sequence = 0;
    require(realityV2AddTlsRecordSequence(7, 9, &tls_sequence) && tls_sequence == 16,
            "TLS facade sequence addition failed");
    require(! realityV2AddTlsRecordSequence(UINT64_MAX - 1, 2, &tls_sequence),
            "TLS facade sequence overflow must fail");
    uint8_t sequence_be[8];
    realityV2WriteBe64(sequence_be, UINT64_C(0x0102030405060708));
    require(realityV2ReadBe64(sequence_be) == UINT64_C(0x0102030405060708),
            "TLS facade sequence serialization failed");
}

static void testReplayOrderingAndBinding(void)
{
    uint8_t root_key[kRealityV2KeySize];
    memset(root_key, 0x42, sizeof(root_key));
    reality_v2_handshake_binding_t binding = makeBinding();
    reality_v2_session_material_t material = {0};
    reality_v2_session_material_t other_session = {0};
    require(realityV2DeriveSessionMaterial(root_key, &binding, &material), "record session derivation failed");
    binding.server_random[0] ^= 0x80;
    require(realityV2DeriveSessionMaterial(root_key, &binding, &other_session), "other session derivation failed");

    test_record_t records[3];
    makeRecord(&material, kRealityV2DirectionClientToServer, 0, 0x10, &records[0]);
    makeRecord(&material, kRealityV2DirectionClientToServer, 1, 0x20, &records[1]);
    makeRecord(&material, kRealityV2DirectionClientToServer, 2, 0x30, &records[2]);

    uint64_t expected = 0;
    require(receiveRecord(&material, kRealityV2DirectionClientToServer, &expected, &records[0]),
            "record zero must authenticate");
    require(! receiveRecord(&material, kRealityV2DirectionClientToServer, &expected, &records[0]),
            "replayed record zero must fail");
    require(expected == 1, "failed replay must not advance expected sequence");
    require(! receiveRecord(&material, kRealityV2DirectionClientToServer, &expected, &records[2]),
            "record two before record one must fail");
    require(expected == 1, "reordering failure must not advance expected sequence");
    require(receiveRecord(&material, kRealityV2DirectionClientToServer, &expected, &records[1]),
            "record one must authenticate after failed reorder");
    require(! receiveRecord(&material, kRealityV2DirectionClientToServer, &expected, &records[1]),
            "duplicate record one must fail");
    require(receiveRecord(&material, kRealityV2DirectionClientToServer, &expected, &records[2]),
            "record two must authenticate in order");

    expected = 0;
    require(! receiveRecord(&other_session, kRealityV2DirectionClientToServer, &expected, &records[0]),
            "record from another TLS binding must fail");
    require(! receiveRecord(&material, kRealityV2DirectionServerToClient, &expected, &records[0]),
            "reflected c2s record must fail in s2c direction");

    test_record_t downstream;
    makeRecord(&material, kRealityV2DirectionServerToClient, 0, 0x40, &downstream);
    require(! receiveRecord(&material, kRealityV2DirectionClientToServer, &expected, &downstream),
            "reflected s2c record must fail in c2s direction");

    test_record_t tampered = records[0];
    tampered.header[4] ^= 1;
    require(! receiveRecord(&material, kRealityV2DirectionClientToServer, &expected, &tampered),
            "header tampering must fail");
    tampered = records[0];
    tampered.ciphertext[3] ^= 1;
    require(! receiveRecord(&material, kRealityV2DirectionClientToServer, &expected, &tampered),
            "ciphertext tampering must fail");
}

static uint32_t roundUp(uint32_t value, uint32_t block_size)
{
    uint32_t remainder = value % block_size;
    return remainder == 0 ? value : value + block_size - remainder;
}

static bool profileRecordDecrypts(const reality_v2_session_material_t *material,
                                  const reality_v2_record_profile_t *profile,
                                  uint8_t direction,
                                  uint64_t sequence,
                                  const uint8_t header[kRealityV2TlsRecordHeaderSize],
                                  const uint8_t *visible_prefix,
                                  const uint8_t *ciphertext,
                                  size_t ciphertext_len)
{
    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadMaxSize];
    uint8_t plaintext[64];
    size_t  aad_len = 0;
    uint16_t tls_version = profile->profile_id == kRealityV2RecordProfileTls13Aead
                               ? kRealityV2Tls13
                               : kRealityV2Tls12;
    reality_v2_record_descriptor_t descriptor;

    realityV2BuildNonce(material->c2s_iv, sequence, nonce);
    return realityV2BuildRecordDescriptor(tls_version,
                                          profile,
                                          kRealityV2RecordKindApplicationData,
                                          &descriptor) &&
           realityV2BuildRecordAad(&descriptor,
                                   direction,
                                   sequence,
                                   material->session_id,
                                   header,
                                   visible_prefix,
                                   profile->visible_prefix_len,
                                   aad,
                                   &aad_len) &&
           chacha20poly1305Decrypt(plaintext,
                                   ciphertext,
                                   ciphertext_len,
                                   aad,
                                   aad_len,
                                   nonce,
                                   material->c2s_key) == 0;
}

static void testEveryProfileAuthenticatesPublicShape(void)
{
    const reality_v2_record_profile_t profiles[] = {
        {kRealityV2RecordProfileTls13Aead, 0, 0, 0},
        {kRealityV2RecordProfileTls12ChaCha, 0, 0, 0},
        {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0},
        {kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20},
    };
    uint8_t root_key[kRealityV2KeySize];
    memset(root_key, 0x73, sizeof(root_key));
    reality_v2_handshake_binding_t binding = makeBinding();
    reality_v2_session_material_t material = {0};
    require(realityV2DeriveSessionMaterial(root_key, &binding, &material),
            "profile authentication material derivation failed");

    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        const reality_v2_record_profile_t *profile = &profiles[i];
        uint16_t tls_version = profile->profile_id == kRealityV2RecordProfileTls13Aead
                                   ? kRealityV2Tls13
                                   : kRealityV2Tls12;
        reality_v2_record_descriptor_t descriptor;
        reality_v2_record_layout_t layout;
        require(realityV2BuildRecordDescriptor(tls_version,
                                                profile,
                                                kRealityV2RecordKindApplicationData,
                                                &descriptor) &&
                    realityV2CalculateDescriptorLayout(&descriptor, 1, &layout),
                "profile authentication layout failed");

        uint8_t header[kRealityV2TlsRecordHeaderSize] = {
            0x17,
            0x03,
            0x03,
            (uint8_t) (layout.wire_body_len >> 8),
            (uint8_t) layout.wire_body_len,
        };
        uint8_t visible_prefix[kRealityV2MaxVisiblePrefixSize];
        uint8_t inner[64];
        uint8_t ciphertext[64 + kRealityV2TagSize];
        uint8_t nonce[kRealityV2IvSize];
        uint8_t aad[kRealityV2RecordAadMaxSize];
        size_t  aad_len = 0;
        for (uint8_t j = 0; j < profile->visible_prefix_len; ++j)
        {
            visible_prefix[j] = (uint8_t) (0x40U + j);
        }
        const uint8_t application_payload = 0xa5;
        require(realityV2BuildInnerPlaintext(&descriptor,
                                             &application_payload,
                                             sizeof(application_payload),
                                             inner,
                                             layout.inner_plaintext_len),
                "profile authentication inner plaintext construction failed");

        realityV2BuildNonce(material.c2s_iv, 7, nonce);
        require(realityV2BuildRecordAad(&descriptor,
                                        kRealityV2DirectionClientToServer,
                                        7,
                                        material.session_id,
                                        header,
                                        visible_prefix,
                                        profile->visible_prefix_len,
                                        aad,
                                        &aad_len),
                "profile authentication AAD construction failed");
        require(chacha20poly1305Encrypt(ciphertext,
                                        inner,
                                        layout.inner_plaintext_len,
                                        aad,
                                        aad_len,
                                        nonce,
                                        material.c2s_key) == 0,
                "profile authentication encryption failed");
        size_t ciphertext_len = layout.inner_plaintext_len + kRealityV2TagSize;

        require(profileRecordDecrypts(&material,
                                      profile,
                                      kRealityV2DirectionClientToServer,
                                      7,
                                      header,
                                      visible_prefix,
                                      ciphertext,
                                      ciphertext_len),
                "untampered profile record failed authentication");

        uint8_t tampered_header[kRealityV2TlsRecordHeaderSize];
        memcpy(tampered_header, header, sizeof(tampered_header));
        tampered_header[4] ^= 1;
        require(! profileRecordDecrypts(&material,
                                        profile,
                                        kRealityV2DirectionClientToServer,
                                        7,
                                        tampered_header,
                                        visible_prefix,
                                        ciphertext,
                                        ciphertext_len),
                "profile header tampering must fail authentication");

        if (profile->visible_prefix_len != 0)
        {
            uint8_t tampered_prefix[kRealityV2MaxVisiblePrefixSize];
            memcpy(tampered_prefix, visible_prefix, profile->visible_prefix_len);
            tampered_prefix[0] ^= 1;
            require(! profileRecordDecrypts(&material,
                                            profile,
                                            kRealityV2DirectionClientToServer,
                                            7,
                                            header,
                                            tampered_prefix,
                                            ciphertext,
                                            ciphertext_len),
                    "profile visible-prefix tampering must fail authentication");
        }
        require(! profileRecordDecrypts(&material,
                                        profile,
                                        kRealityV2DirectionServerToClient,
                                        7,
                                        header,
                                        visible_prefix,
                                        ciphertext,
                                        ciphertext_len),
                "profile direction reflection must fail authentication");
        require(! profileRecordDecrypts(&material,
                                        profile,
                                        kRealityV2DirectionClientToServer,
                                        8,
                                        header,
                                        visible_prefix,
                                        ciphertext,
                                        ciphertext_len),
                "profile sequence tampering must fail authentication");

        reality_v2_session_material_t other_session = material;
        other_session.session_id[0] ^= 1;
        require(! profileRecordDecrypts(&other_session,
                                        profile,
                                        kRealityV2DirectionClientToServer,
                                        7,
                                        header,
                                        visible_prefix,
                                        ciphertext,
                                        ciphertext_len),
                "profile cross-connection binding must fail authentication");

        const reality_v2_record_profile_t *other_profile =
            &profiles[(i + 1) % (sizeof(profiles) / sizeof(profiles[0]))];
        uint8_t other_prefix[kRealityV2MaxVisiblePrefixSize] = {0};
        memcpy(other_prefix,
               visible_prefix,
               min(profile->visible_prefix_len, other_profile->visible_prefix_len));
        require(! profileRecordDecrypts(&material,
                                        other_profile,
                                        kRealityV2DirectionClientToServer,
                                        7,
                                        header,
                                        other_prefix,
                                        ciphertext,
                                        ciphertext_len),
                "record profile substitution must fail authentication");
    }
}

static void testAlertRecords(void)
{
    static const struct
    {
        uint16_t tls_version;
        reality_v2_record_profile_t profile;
        uint8_t outer_type;
        uint8_t visible_prefix_len;
        uint32_t body_len;
        uint32_t inner_len;
    } cases[] = {
        {kRealityV2Tls13, {kRealityV2RecordProfileTls13Aead, 0, 0, 0}, 0x17, 0, 19, 3},
        {kRealityV2Tls12, {kRealityV2RecordProfileTls12Gcm, 8, 0, 0}, 0x15, 8, 26, 2},
        {kRealityV2Tls12, {kRealityV2RecordProfileTls12Cbc, 16, 16, 20}, 0x15, 16, 48, 16},
        {kRealityV2Tls12, {kRealityV2RecordProfileTls12ChaCha, 0, 0, 0}, 0x15, 0, 18, 2},
    };

    uint8_t root_key[kRealityV2KeySize];
    memset(root_key, 0x91, sizeof(root_key));
    reality_v2_handshake_binding_t binding = makeBinding();
    reality_v2_session_material_t material = {0};
    require(realityV2DeriveSessionMaterial(root_key, &binding, &material),
            "alert authentication material derivation failed");

    uint8_t close_notify[kRealityV2AlertMessageSize];
    uint8_t bad_record_mac[kRealityV2AlertMessageSize];
    require(realityV2SerializeAlert(kRealityV2AlertCloseNotify, close_notify),
            "close_notify serialization failed");
    require(realityV2SerializeAlert(kRealityV2AlertBadRecordMac, bad_record_mac),
            "bad_record_mac serialization failed");
    require(close_notify[0] == 0x01 && close_notify[1] == 0x00,
            "close_notify wire value is wrong");
    require(bad_record_mac[0] == 0x02 && bad_record_mac[1] == 0x14,
            "bad_record_mac wire value is wrong");
    uint8_t parsed_alert = kRealityV2AlertInvalid;
    require(realityV2ParseAlert(close_notify, sizeof(close_notify), &parsed_alert) &&
                parsed_alert == kRealityV2AlertCloseNotify,
            "close_notify parsing failed");
    require(realityV2ParseAlert(bad_record_mac, sizeof(bad_record_mac), &parsed_alert) &&
                parsed_alert == kRealityV2AlertBadRecordMac,
            "bad_record_mac parsing failed");
    uint8_t unknown_alert[2] = {0x02, 0x28};
    require(! realityV2ParseAlert(unknown_alert, sizeof(unknown_alert), &parsed_alert),
            "unknown authenticated alert must fail closed");

    reality_v2_record_profile_t tls12_gcm_profile = {
        kRealityV2RecordProfileTls12Gcm, 8, 0, 0};
    reality_v2_record_descriptor_t invalid_descriptor;
    require(! realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                              &tls12_gcm_profile,
                                              kRealityV2RecordKindAlert,
                                              &invalid_descriptor),
            "TLS 1.3 must reject a TLS 1.2 record profile");

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        reality_v2_record_descriptor_t descriptor;
        reality_v2_record_layout_t layout;
        require(realityV2BuildRecordDescriptor(cases[i].tls_version,
                                                &cases[i].profile,
                                                kRealityV2RecordKindAlert,
                                                &descriptor),
                "alert descriptor construction failed");
        require(descriptor.outer_content_type == cases[i].outer_type &&
                    descriptor.visible_prefix_len == cases[i].visible_prefix_len,
                "alert public shape is wrong");
        require((cases[i].tls_version == kRealityV2Tls13 &&
                 descriptor.outer_content_type == 0x17 &&
                 descriptor.tls13_inner_content_type == 0x15) ||
                    (cases[i].tls_version == kRealityV2Tls12 &&
                     descriptor.outer_content_type == 0x15 &&
                     descriptor.tls13_inner_content_type == 0),
                "TLS-version-specific alert content types are wrong");
        require(realityV2CalculateDescriptorLayout(&descriptor,
                                                    kRealityV2AlertMessageSize,
                                                    &layout) &&
                    layout.wire_body_len == cases[i].body_len &&
                    layout.inner_plaintext_len == cases[i].inner_len,
                "alert layout is wrong");

        uint8_t header[kRealityV2TlsRecordHeaderSize] = {
            descriptor.outer_content_type,
            0x03,
            0x03,
            (uint8_t) (layout.wire_body_len >> 8),
            (uint8_t) layout.wire_body_len,
        };
        reality_v2_record_descriptor_t classified;
        require(realityV2ClassifyRecord(cases[i].tls_version,
                                        &cases[i].profile,
                                        header,
                                        &classified) &&
                    classified.record_kind == kRealityV2RecordKindAlert,
                "alert classification failed");
        uint8_t wrong_length_header[kRealityV2TlsRecordHeaderSize];
        memcpy(wrong_length_header, header, sizeof(wrong_length_header));
        ++wrong_length_header[4];
        bool wrong_length_classified = realityV2ClassifyRecord(cases[i].tls_version,
                                                                &cases[i].profile,
                                                                wrong_length_header,
                                                                &classified);
        require(! wrong_length_classified || classified.record_kind != kRealityV2RecordKindAlert,
                "non-exact alert length must not classify as an alert");

        uint8_t visible_prefix[kRealityV2MaxVisiblePrefixSize];
        for (uint8_t j = 0; j < descriptor.visible_prefix_len; ++j)
        {
            visible_prefix[j] = (uint8_t) (0xb0U + j);
        }
        uint8_t inner[64];
        require(realityV2BuildInnerPlaintext(&descriptor,
                                              close_notify,
                                              sizeof(close_notify),
                                              inner,
                                              layout.inner_plaintext_len),
                "alert inner plaintext construction failed");
        uint32_t payload_offset = UINT32_MAX;
        uint32_t payload_len = UINT32_MAX;
        require(realityV2ValidateInnerPlaintext(&descriptor,
                                                inner,
                                                layout.inner_plaintext_len,
                                                &payload_offset,
                                                &payload_len) &&
                    payload_len == kRealityV2AlertMessageSize &&
                    realityV2ParseAlert(inner + payload_offset, payload_len, &parsed_alert),
                "alert inner plaintext validation failed");

        uint8_t nonce[kRealityV2IvSize];
        uint8_t aad[kRealityV2RecordAadMaxSize];
        uint8_t ciphertext[64 + kRealityV2TagSize];
        uint8_t decoded[64];
        size_t aad_len = 0;
        realityV2BuildNonce(material.c2s_iv, 4, nonce);
        require(realityV2BuildRecordAad(&descriptor,
                                        kRealityV2DirectionClientToServer,
                                        4,
                                        material.session_id,
                                        header,
                                        visible_prefix,
                                        descriptor.visible_prefix_len,
                                        aad,
                                        &aad_len),
                "alert AAD construction failed");
        size_t server_aad_len = 0;
        uint8_t server_aad[kRealityV2RecordAadMaxSize];
        require(realityV2BuildRecordAad(&descriptor,
                                        kRealityV2DirectionServerToClient,
                                        4,
                                        material.session_id,
                                        header,
                                        visible_prefix,
                                        descriptor.visible_prefix_len,
                                        server_aad,
                                        &server_aad_len) &&
                    server_aad_len == aad_len && ! memoryEqual(server_aad, aad, aad_len),
                "alert descriptor must support distinct c2s-fatal and s2c-close AAD");
        require(chacha20poly1305Encrypt(ciphertext,
                                        inner,
                                        layout.inner_plaintext_len,
                                        aad,
                                        aad_len,
                                        nonce,
                                        material.c2s_key) == 0 &&
                    chacha20poly1305Decrypt(decoded,
                                            ciphertext,
                                            layout.inner_plaintext_len + kRealityV2TagSize,
                                            aad,
                                            aad_len,
                                            nonce,
                                            material.c2s_key) == 0,
                "authenticated alert did not round-trip");

        reality_v2_record_descriptor_t data_descriptor;
        reality_v2_record_layout_t data_layout;
        require(realityV2BuildRecordDescriptor(cases[i].tls_version,
                                                &cases[i].profile,
                                                kRealityV2RecordKindApplicationData,
                                                &data_descriptor) &&
                    realityV2CalculateDescriptorLayout(&data_descriptor, 2, &data_layout) &&
                    data_layout.wire_body_len == layout.wire_body_len,
                "data/alert kind-substitution fixture shape mismatch");
        uint8_t data_header[kRealityV2TlsRecordHeaderSize];
        memcpy(data_header, header, sizeof(data_header));
        data_header[0] = data_descriptor.outer_content_type;
        size_t data_aad_len = 0;
        uint8_t data_aad[kRealityV2RecordAadMaxSize];
        require(realityV2BuildRecordAad(&data_descriptor,
                                        kRealityV2DirectionClientToServer,
                                        4,
                                        material.session_id,
                                        data_header,
                                        visible_prefix,
                                        data_descriptor.visible_prefix_len,
                                        data_aad,
                                        &data_aad_len),
                "data substitution AAD construction failed");
        require(chacha20poly1305Decrypt(decoded,
                                        ciphertext,
                                        layout.inner_plaintext_len + kRealityV2TagSize,
                                        data_aad,
                                        data_aad_len,
                                        nonce,
                                        material.c2s_key) != 0,
                "record-kind substitution must fail authentication");
    }
}

static void testPatchedTls12CipherListCoverage(void)
{
    static const uint16_t expected[] = {
        0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
        0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
    };

    FILE *source = fopen(REALITY_TLS_CLIENT_HANDSHAKE_SOURCE, "rb");
    require(source != NULL, "failed to open patched TlsClient handshake source");
    require(fseek(source, 0, SEEK_END) == 0, "failed to seek patched TlsClient handshake source");
    long file_size = ftell(source);
    require(file_size > 0, "failed to size patched TlsClient handshake source");
    require(fseek(source, 0, SEEK_SET) == 0, "failed to rewind patched TlsClient handshake source");

    char *text = malloc((size_t) file_size + 1U);
    require(text != NULL, "failed to allocate patched TlsClient source buffer");
    require(fread(text, 1, (size_t) file_size, source) == (size_t) file_size,
            "failed to read patched TlsClient handshake source");
    fclose(source);
    text[file_size] = '\0';

    char *cursor = strstr(text, "static const uint16_t kChromeTLS12Ciphers[]");
    require(cursor != NULL, "patched TLS 1.2 cipher list was not found");
    char *end = strstr(cursor, "};");
    require(end != NULL, "patched TLS 1.2 cipher list terminator was not found");

    size_t count = 0;
    while ((cursor = strstr(cursor, "0x")) != NULL && cursor < end)
    {
        char *number_end = NULL;
        unsigned long value = strtoul(cursor, &number_end, 16);
        require(number_end != cursor && value <= UINT16_MAX, "invalid patched TLS 1.2 cipher identifier");
        require(count < sizeof(expected) / sizeof(expected[0]),
                "TlsClient advertises a TLS 1.2 suite missing from the Reality coverage test");
        require((uint16_t) value == expected[count], "patched TLS 1.2 cipher list order or value drifted");
        reality_v2_record_profile_t profile;
        require(realityV2SelectRecordProfile(kRealityV2Tls12, (uint16_t) value, &profile),
                "patched TLS 1.2 cipher has no Reality profile");
        ++count;
        cursor = number_end;
    }
    require(count == sizeof(expected) / sizeof(expected[0]),
            "Reality TLS 1.2 coverage contains a suite no longer advertised by TlsClient");
    free(text);
}

static void testRecordProfilesAndLayouts(void)
{
    static const struct
    {
        uint16_t suite;
        uint8_t  profile_id;
    } tls12_suites[] = {
        {0xC02B, kRealityV2RecordProfileTls12Gcm},
        {0xC02F, kRealityV2RecordProfileTls12Gcm},
        {0xC02C, kRealityV2RecordProfileTls12Gcm},
        {0xC030, kRealityV2RecordProfileTls12Gcm},
        {0xCCA9, kRealityV2RecordProfileTls12ChaCha},
        {0xCCA8, kRealityV2RecordProfileTls12ChaCha},
        {0xC013, kRealityV2RecordProfileTls12Cbc},
        {0xC014, kRealityV2RecordProfileTls12Cbc},
        {0x009C, kRealityV2RecordProfileTls12Gcm},
        {0x009D, kRealityV2RecordProfileTls12Gcm},
        {0x002F, kRealityV2RecordProfileTls12Cbc},
        {0x0035, kRealityV2RecordProfileTls12Cbc},
    };

    static const struct
    {
        uint16_t tls_version;
        reality_v2_record_profile_t profile;
        uint8_t visible_prefix_len;
        uint8_t inner_content_type;
        uint32_t maximum_body_len;
    } profiles[] = {
        {kRealityV2Tls13, {kRealityV2RecordProfileTls13Aead, 0, 0, 0}, 0, 0x17, 16401},
        {kRealityV2Tls12, {kRealityV2RecordProfileTls12ChaCha, 0, 0, 0}, 0, 0, 16400},
        {kRealityV2Tls12,
         {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0},
         kRealityV2Tls12GcmPrefixSize,
         0,
         16408},
        {kRealityV2Tls12,
         {kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20},
         kRealityV2Tls12CbcPrefixSize,
         0,
         16432},
    };
    static const uint32_t payload_lengths[] = {0, 1, 16383, 16384};

    reality_v2_record_profile_t profile = {0};
    for (size_t i = 0; i < sizeof(tls12_suites) / sizeof(tls12_suites[0]); ++i)
    {
        require(realityV2SelectRecordProfile(kRealityV2Tls12, tls12_suites[i].suite, &profile),
                "advertised TLS 1.2 suite has no Reality profile");
        require(profile.profile_id == tls12_suites[i].profile_id,
                "advertised TLS 1.2 suite mapped to the wrong Reality profile");
        require(realityV2RecordProfileIsValid(&profile), "selected Reality profile is invalid");
    }
    require(! realityV2SelectRecordProfile(kRealityV2Tls12, 0xFFFF, &profile),
            "unknown TLS 1.2 suite must not fall back to another profile");
    const uint16_t tls13_suites[] = {0x1301, 0x1302, 0x1303};
    for (size_t i = 0; i < sizeof(tls13_suites) / sizeof(tls13_suites[0]); ++i)
    {
        require(realityV2SelectRecordProfile(kRealityV2Tls13, tls13_suites[i], &profile) &&
                    profile.profile_id == kRealityV2RecordProfileTls13Aead &&
                    profile.visible_prefix_len == 0,
                "TLS 1.3 suite mapped to the wrong Reality profile");
    }

    require(profiles[0].profile.profile_id != profiles[1].profile.profile_id,
            "TLS 1.3 and TLS 1.2 ChaCha must use distinct authenticated profiles");
    require(! realityV2BuildRecordDescriptor(kRealityV2Tls12,
                                              &profiles[0].profile,
                                              kRealityV2RecordKindApplicationData,
                                              &(reality_v2_record_descriptor_t) {0}) &&
                ! realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                                  &profiles[1].profile,
                                                  kRealityV2RecordKindApplicationData,
                                                  &(reality_v2_record_descriptor_t) {0}),
            "invalid TLS-version/profile pairings must fail closed");

    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        reality_v2_record_descriptor_t descriptor;
        require(realityV2BuildRecordDescriptor(profiles[i].tls_version,
                                                &profiles[i].profile,
                                                kRealityV2RecordKindApplicationData,
                                                &descriptor),
                "application descriptor construction failed");
        require(descriptor.outer_content_type == 0x17 &&
                    descriptor.visible_prefix_len == profiles[i].visible_prefix_len &&
                    descriptor.tls13_inner_content_type == profiles[i].inner_content_type,
                "application descriptor has the wrong native TLS shape");

        for (size_t j = 0; j < sizeof(payload_lengths) / sizeof(payload_lengths[0]); ++j)
        {
            uint32_t payload_len = payload_lengths[j];
            reality_v2_record_layout_t layout;
            require(realityV2CalculateDescriptorLayout(&descriptor, payload_len, &layout),
                    "native application layout calculation failed");
            uint32_t expected_body_len;
            if (profiles[i].profile.profile_id == kRealityV2RecordProfileTls13Aead)
            {
                expected_body_len = payload_len + 1 + kRealityV2TagSize;
            }
            else if (profiles[i].profile.profile_id == kRealityV2RecordProfileTls12ChaCha)
            {
                expected_body_len = payload_len + kRealityV2TagSize;
            }
            else if (profiles[i].profile.profile_id == kRealityV2RecordProfileTls12Gcm)
            {
                expected_body_len = kRealityV2Tls12GcmPrefixSize + payload_len + kRealityV2TagSize;
            }
            else
            {
                expected_body_len = kRealityV2Tls12CbcPrefixSize + roundUp(payload_len + 20 + 1, 16);
            }
            require(layout.wire_body_len == expected_body_len,
                    "profile application body length is not native-sized");

            uint8_t header[kRealityV2TlsRecordHeaderSize] = {
                descriptor.outer_content_type,
                0x03,
                0x03,
                (uint8_t) (layout.wire_body_len >> 8),
                (uint8_t) layout.wire_body_len,
            };
            reality_v2_record_descriptor_t classified;
            require(realityV2ClassifyRecord(profiles[i].tls_version,
                                            &profiles[i].profile,
                                            header,
                                            &classified) &&
                        classified.record_kind == kRealityV2RecordKindApplicationData,
                    "valid native application record was not classified");
        }

        reality_v2_record_layout_t maximum;
        require(realityV2CalculateDescriptorLayout(&descriptor,
                                                    kRealityV2MaxPlaintextFragment,
                                                    &maximum) &&
                    maximum.wire_body_len == profiles[i].maximum_body_len &&
                    maximum.wire_body_len <= kRealityV2MaxTlsRecordBody,
                "profile maximum record body length is wrong or unsafe");
        require(! realityV2CalculateDescriptorLayout(&descriptor,
                                                      kRealityV2MaxPlaintextFragment + 1U,
                                                      &maximum),
                "a 16385-byte payload must be split by the sender");
    }

    const reality_v2_record_profile_t *cbc_profile = &profiles[3].profile;
    reality_v2_record_layout_t layout;
    require(realityV2CalculateRecordLayout(cbc_profile, 17, &layout), "CBC inner fixture layout failed");
    uint8_t inner[64] = {0};
    inner[0] = 0;
    inner[1] = 17;
    memset(inner + 2, 0x5a, 17);
    uint32_t decoded_len = 0;
    require(realityV2ValidateCbcInnerPlaintext(cbc_profile, inner, layout.inner_plaintext_len, &decoded_len) &&
                decoded_len == 17,
            "CBC inner length did not round-trip");
    inner[layout.inner_plaintext_len - 1] = 1;
    require(! realityV2ValidateCbcInnerPlaintext(cbc_profile, inner, layout.inner_plaintext_len, &decoded_len),
            "non-zero CBC filler must fail");
    inner[layout.inner_plaintext_len - 1] = 0;
    inner[1] = 33;
    require(! realityV2ValidateCbcInnerPlaintext(cbc_profile, inner, layout.inner_plaintext_len, &decoded_len),
            "mismatched CBC encrypted payload length must fail");

    const reality_v2_record_profile_t impossible = {
        .profile_id         = kRealityV2RecordProfileTls12Cbc,
        .visible_prefix_len = 8,
        .block_size         = 0,
        .tls_mac_len        = 20,
    };
    require(! realityV2RecordProfileIsValid(&impossible), "impossible profile sizes must fail");

    const reality_v2_record_profile_t wrong_mac = {
        .profile_id         = kRealityV2RecordProfileTls12Cbc,
        .visible_prefix_len = kRealityV2Tls12CbcPrefixSize,
        .block_size         = 16,
        .tls_mac_len        = 32,
    };
    require(! realityV2RecordProfileIsValid(&wrong_mac), "unmapped CBC MAC length must fail");
}

static void testTls13ApplicationInnerType(void)
{
    const reality_v2_record_profile_t profile = {
        kRealityV2RecordProfileTls13Aead, 0, 0, 0};
    reality_v2_record_descriptor_t descriptor;
    require(realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                            &profile,
                                            kRealityV2RecordKindApplicationData,
                                            &descriptor),
            "TLS 1.3 application descriptor construction failed");

    const uint8_t payload[] = {0x41, 0x42, 0x43};
    uint8_t inner[sizeof(payload) + 1];
    require(realityV2BuildInnerPlaintext(&descriptor,
                                         payload,
                                         sizeof(payload),
                                         inner,
                                         sizeof(inner)) &&
                inner[sizeof(payload)] == 0x17,
            "TLS 1.3 application inner type was not appended");

    uint32_t payload_offset = UINT32_MAX;
    uint32_t payload_len = UINT32_MAX;
    require(realityV2ValidateInnerPlaintext(&descriptor,
                                            inner,
                                            sizeof(inner),
                                            &payload_offset,
                                            &payload_len) &&
                payload_offset == 0 && payload_len == sizeof(payload) &&
                memcmp(inner, payload, sizeof(payload)) == 0,
            "TLS 1.3 application inner type was not stripped");

    inner[sizeof(payload)] = 0x15;
    require(! realityV2ValidateInnerPlaintext(&descriptor,
                                              inner,
                                              sizeof(inner),
                                              &payload_offset,
                                              &payload_len),
            "wrong TLS 1.3 application inner type must fail");
    require(! realityV2ValidateInnerPlaintext(&descriptor,
                                              payload,
                                              sizeof(payload),
                                              &payload_offset,
                                              &payload_len),
            "missing TLS 1.3 application inner type must fail");
}

static size_t buildOldOpaqueApplicationAad(uint8_t direction, uint64_t sequence,
                                           const uint8_t session_id[kRealityV2SessionIdSize],
                                           const uint8_t header[kRealityV2TlsRecordHeaderSize],
                                           const uint8_t prefix[12], uint8_t aad[kRealityV2RecordAadMaxSize])
{
    static const uint8_t domain[] = "WaterWall Reality v2/profile record";
    uint8_t *cursor = aad;
    memcpy(cursor, domain, sizeof(domain) - 1);
    cursor += sizeof(domain) - 1;
    *cursor++ = kRealityV2RecordKindApplicationData;
    *cursor++ = 0x03;
    *cursor++ = 0x04;
    *cursor++ = 1;
    *cursor++ = direction;
    realityV2WriteBe64(cursor, sequence);
    cursor += 8;
    memcpy(cursor, session_id, kRealityV2SessionIdSize);
    cursor += kRealityV2SessionIdSize;
    memcpy(cursor, header, kRealityV2TlsRecordHeaderSize);
    cursor += kRealityV2TlsRecordHeaderSize;
    *cursor++ = 12;
    memcpy(cursor, prefix, 12);
    cursor += 12;
    return (size_t) (cursor - aad);
}

static void testOldOpaqueApplicationRecordIsRejected(void)
{
    uint8_t root_key[kRealityV2KeySize];
    memset(root_key, 0x6d, sizeof(root_key));
    reality_v2_handshake_binding_t binding = makeBinding();
    reality_v2_session_material_t material = {0};
    require(realityV2DeriveSessionMaterial(root_key, &binding, &material),
            "old-format rejection material derivation failed");

    enum
    {
        kOldPrefixSize = 12,
        kOldPayloadSize = 1,
        kOldCiphertextSize = kOldPayloadSize + kRealityV2TagSize,
        kOldBodySize = kOldPrefixSize + kOldCiphertextSize,
    };
    uint8_t record[kRealityV2TlsRecordHeaderSize + kOldBodySize] = {
        0x17, 0x03, 0x03, 0x00, kOldBodySize};
    uint8_t *old_prefix = record + kRealityV2TlsRecordHeaderSize;
    uint8_t *old_ciphertext = old_prefix + kOldPrefixSize;
    for (uint8_t i = 0; i < kOldPrefixSize; ++i)
    {
        old_prefix[i] = (uint8_t) (0xa0U + i);
    }

    uint8_t old_aad[kRealityV2RecordAadMaxSize];
    size_t old_aad_len = buildOldOpaqueApplicationAad(kRealityV2DirectionClientToServer,
                                                       0,
                                                       material.session_id,
                                                       record,
                                                       old_prefix,
                                                       old_aad);
    uint8_t nonce[kRealityV2IvSize];
    const uint8_t payload = 0x5a;
    realityV2BuildNonce(material.c2s_iv, 0, nonce);
    require(chacha20poly1305Encrypt(old_ciphertext,
                                    &payload,
                                    sizeof(payload),
                                    old_aad,
                                    old_aad_len,
                                    nonce,
                                    material.c2s_key) == 0,
            "old-format rejection record encryption failed");

    const reality_v2_record_profile_t new_profile = {
        kRealityV2RecordProfileTls13Aead, 0, 0, 0};
    reality_v2_record_descriptor_t descriptor;
    require(realityV2ClassifyRecord(kRealityV2Tls13,
                                    &new_profile,
                                    record,
                                    &descriptor),
            "old-format fixture must reach new-format authentication");
    uint8_t new_aad[kRealityV2RecordAadMaxSize];
    size_t new_aad_len = 0;
    require(realityV2BuildRecordAad(&descriptor,
                                    kRealityV2DirectionClientToServer,
                                    0,
                                    material.session_id,
                                    record,
                                    NULL,
                                    0,
                                    new_aad,
                                    &new_aad_len),
            "new-format rejection AAD construction failed");
    uint8_t decoded[kOldBodySize - kRealityV2TagSize];
    require(chacha20poly1305Decrypt(decoded,
                                    old_prefix,
                                    kOldBodySize,
                                    new_aad,
                                    new_aad_len,
                                    nonce,
                                    material.c2s_key) != 0,
            "old 12-byte-prefix application record must not authenticate under the new format");

    const reality_v2_record_profile_t old_profile = {1, 12, 0, 0};
    require(! realityV2RecordProfileIsValid(&old_profile),
            "old opaque-prefix profile must not remain valid");
}

typedef struct test_random_s
{
    uint16_t sample;
    uint32_t calls;
    uint32_t fail_on_call;
} test_random_t;

static bool testControlRandom(void *context, void *bytes, size_t size)
{
    test_random_t *random = context;
    ++random->calls;
    if (random->calls == random->fail_on_call)
    {
        return false;
    }
    if (random->calls == 1)
    {
        require(size == 2, "control padding selection did not request a 16-bit sample");
        uint8_t *out = bytes;
        out[0] = (uint8_t) (random->sample >> 8);
        out[1] = (uint8_t) random->sample;
        return true;
    }
    memset(bytes, 0xa5, size);
    return true;
}

static int testChachaDecrypt(void *context, unsigned char *dst, const unsigned char *src,
                             size_t src_len, const unsigned char *ad, size_t ad_len,
                             const unsigned char *nonce, const unsigned char *key)
{
    (void) context;
    return chacha20poly1305Decrypt(dst, src, src_len, ad, ad_len, nonce, key);
}

static bool makeControlRecord(const reality_v2_session_material_t *material, uint8_t direction,
                              uint64_t sequence, uint8_t kind, uint32_t padding_len,
                              uint8_t record[kRealityV2TlsRecordHeaderSize + kRealityV2ControlMaxTlsRecordBody],
                              uint32_t *record_len)
{
    const reality_v2_record_profile_t profile = {
        kRealityV2RecordProfileTls13Aead, 0, 0, 0};
    reality_v2_record_descriptor_t descriptor;
    reality_v2_record_layout_t layout;
    uint32_t control_len = 0;
    uint8_t padding[kRealityV2ControlMaxPadding];
    uint8_t control[kRealityV2ControlMaxPayload];
    memset(padding, 0x5c, sizeof(padding));
    if (! realityV2CalculateControlPayloadLength(padding_len, &control_len) ||
        ! realityV2SerializeControl(kind, padding, padding_len, control, control_len) ||
        ! realityV2BuildRecordDescriptor(kRealityV2Tls13, &profile, kind, &descriptor) ||
        ! realityV2CalculateDescriptorLayout(&descriptor, control_len, &layout))
    {
        return false;
    }

    record[0] = descriptor.outer_content_type;
    record[1] = 0x03;
    record[2] = 0x03;
    record[3] = (uint8_t) (layout.wire_body_len >> 8);
    record[4] = (uint8_t) layout.wire_body_len;
    uint8_t *ciphertext = record + kRealityV2TlsRecordHeaderSize;
    if (! realityV2BuildInnerPlaintext(&descriptor,
                                       control,
                                       control_len,
                                       ciphertext,
                                       layout.inner_plaintext_len))
    {
        return false;
    }

    const uint8_t *key = direction == kRealityV2DirectionClientToServer
                             ? material->c2s_key
                             : material->s2c_key;
    const uint8_t *iv = direction == kRealityV2DirectionClientToServer
                            ? material->c2s_iv
                            : material->s2c_iv;
    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadMaxSize];
    size_t aad_len = 0;
    realityV2BuildNonce(iv, sequence, nonce);
    bool ok = realityV2BuildRecordAad(&descriptor,
                                      direction,
                                      sequence,
                                      material->session_id,
                                      record,
                                      NULL,
                                      0,
                                      aad,
                                      &aad_len) &&
              chacha20poly1305Encrypt(ciphertext,
                                      ciphertext,
                                      layout.inner_plaintext_len,
                                      aad,
                                      aad_len,
                                      nonce,
                                      key) == 0;
    memset(control, 0, sizeof(control));
    memset(padding, 0, sizeof(padding));
    memset(nonce, 0, sizeof(nonce));
    memset(aad, 0, sizeof(aad));
    if (ok)
    {
        *record_len = kRealityV2TlsRecordHeaderSize + layout.wire_body_len;
    }
    return ok;
}

static void testTls13HandoffControls(void)
{
    const reality_v2_record_profile_t tls13_profile = {
        kRealityV2RecordProfileTls13Aead, 0, 0, 0};
    const reality_v2_record_profile_t tls12_profile = {
        kRealityV2RecordProfileTls12ChaCha, 0, 0, 0};
    const uint8_t kinds[] = {
        kRealityV2RecordKindHandoffRequest,
        kRealityV2RecordKindHandoffAck,
        kRealityV2RecordKindHandoffConfirm,
    };
    require(kinds[0] == 3 && kinds[1] == 4 && kinds[2] == 5,
            "handoff record kind values drifted");

    for (size_t i = 0; i < sizeof(kinds); ++i)
    {
        reality_v2_record_descriptor_t descriptor;
        require(realityV2RecordKindIsControl(kinds[i]) &&
                    realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                                   &tls13_profile,
                                                   kinds[i],
                                                   &descriptor) &&
                    descriptor.outer_content_type == 0x17 &&
                    descriptor.tls13_inner_content_type == 0x17 &&
                    descriptor.visible_prefix_len == 0,
                "TLS 1.3 control descriptor has the wrong public shape");
        require(! realityV2BuildRecordDescriptor(kRealityV2Tls12,
                                                  &tls12_profile,
                                                  kinds[i],
                                                  &descriptor),
                "TLS 1.2 must reject handoff controls");
    }

    reality_v2_record_descriptor_t request_descriptor;
    reality_v2_record_layout_t layout;
    require(realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                            &tls13_profile,
                                            kRealityV2RecordKindHandoffRequest,
                                            &request_descriptor) &&
                realityV2CalculateDescriptorLayout(&request_descriptor,
                                                    kRealityV2ControlMinPayload,
                                                    &layout) &&
                layout.wire_body_len == kRealityV2ControlMinTlsRecordBody,
            "minimum control layout does not match the measured TLS envelope");
    require(realityV2CalculateDescriptorLayout(&request_descriptor,
                                                kRealityV2ControlMaxPayload,
                                                &layout) &&
                layout.wire_body_len == kRealityV2ControlMaxTlsRecordBody,
            "maximum control layout does not match the measured TLS envelope");
    require(! realityV2CalculateDescriptorLayout(&request_descriptor,
                                                  kRealityV2ControlMinPayload - 1U,
                                                  &layout) &&
                ! realityV2CalculateDescriptorLayout(&request_descriptor,
                                                     kRealityV2ControlMaxPayload + 1U,
                                                     &layout),
            "control descriptor accepted a payload adjacent to its reviewed bounds");
    require(! realityV2ControlPaddingLengthIsValid(kRealityV2ControlMinPadding - 1U) &&
                realityV2ControlPaddingLengthIsValid(kRealityV2ControlMinPadding) &&
                realityV2ControlPaddingLengthIsValid(kRealityV2ControlMaxPadding) &&
                ! realityV2ControlPaddingLengthIsValid(kRealityV2ControlMaxPadding + 1U),
            "control padding bounds are not exact");

    uint8_t built[kRealityV2ControlMaxPayload];
    uint32_t built_len = UINT32_MAX;
    test_random_t minimum_random = {.sample = 0};
    require(realityV2BuildControlPayloadWithRandom(kRealityV2RecordKindHandoffRequest,
                                                   testControlRandom,
                                                   &minimum_random,
                                                   built,
                                                   sizeof(built),
                                                   &built_len) &&
                built_len == kRealityV2ControlMinPayload &&
                realityV2ParseControl(kRealityV2RecordKindHandoffRequest, built, built_len),
            "minimum randomized control payload failed");
    test_random_t maximum_random = {.sample = kRealityV2ControlMaxPadding -
                                              kRealityV2ControlMinPadding};
    require(realityV2BuildControlPayloadWithRandom(kRealityV2RecordKindHandoffConfirm,
                                                   testControlRandom,
                                                   &maximum_random,
                                                   built,
                                                   sizeof(built),
                                                   &built_len) &&
                built_len == kRealityV2ControlMaxPayload &&
                realityV2ParseControl(kRealityV2RecordKindHandoffConfirm, built, built_len),
            "maximum randomized control payload failed");
    require(! realityV2ParseControl(kRealityV2RecordKindHandoffRequest, built, built_len),
            "control code substitution must fail");
    built[0] ^= 1;
    require(! realityV2ParseControl(kRealityV2RecordKindHandoffConfirm, built, built_len),
            "unknown control format version must fail");

    memset(built, 0xa7, sizeof(built));
    test_random_t failed_random = {.fail_on_call = 1};
    built_len = UINT32_MAX;
    require(! realityV2BuildControlPayloadWithRandom(kRealityV2RecordKindHandoffAck,
                                                      testControlRandom,
                                                      &failed_random,
                                                      built,
                                                      sizeof(built),
                                                      &built_len) &&
                built_len == 0,
            "CSPRNG failure must not build a control");
    for (size_t i = 0; i < sizeof(built); ++i)
    {
        require(built[i] == 0, "CSPRNG failure did not clear control output");
    }

    memset(built, 0xa7, sizeof(built));
    test_random_t padding_random_failure = {.sample = 0, .fail_on_call = 2};
    built_len = UINT32_MAX;
    require(! realityV2BuildControlPayloadWithRandom(kRealityV2RecordKindHandoffAck,
                                                      testControlRandom,
                                                      &padding_random_failure,
                                                      built,
                                                      sizeof(built),
                                                      &built_len) &&
                built_len == 0,
            "CSPRNG padding-byte failure must not build a control");
    for (size_t i = 0; i < sizeof(built); ++i)
    {
        require(built[i] == 0, "CSPRNG padding-byte failure did not clear control output");
    }

    uint8_t root_key[kRealityV2KeySize];
    memset(root_key, 0x6e, sizeof(root_key));
    reality_v2_handshake_binding_t binding = makeBinding();
    reality_v2_session_material_t material = {0};
    require(realityV2DeriveSessionMaterial(root_key, &binding, &material),
            "control trial material derivation failed");

    uint8_t record[kRealityV2TlsRecordHeaderSize + kRealityV2ControlMaxTlsRecordBody];
    uint8_t original[sizeof(record)];
    uint32_t record_len = 0;
    require(makeControlRecord(&material,
                              kRealityV2DirectionClientToServer,
                              0,
                              kRealityV2RecordKindHandoffRequest,
                              kRealityV2ControlMinPadding,
                              record,
                              &record_len),
            "failed to build request control record");
    memcpy(original, record, record_len);

    uint8_t plaintext[kRealityV2ControlMaxInnerPlaintext];
    uint32_t payload_offset = UINT32_MAX;
    uint32_t payload_len = UINT32_MAX;
    require(realityV2TryDecryptExpectedRecord(&request_descriptor,
                                               kRealityV2DirectionClientToServer,
                                               0,
                                               material.session_id,
                                               material.c2s_key,
                                               material.c2s_iv,
                                               record,
                                               record_len,
                                               testChachaDecrypt,
                                               NULL,
                                               plaintext,
                                               sizeof(plaintext),
                                               &payload_offset,
                                               &payload_len) &&
                realityV2ParseControl(kRealityV2RecordKindHandoffRequest,
                                      plaintext + payload_offset,
                                      payload_len) &&
                memcmp(record, original, record_len) == 0,
            "expected-kind request trial failed or mutated ciphertext");

    for (size_t i = 1; i < sizeof(kinds); ++i)
    {
        reality_v2_record_descriptor_t wrong_descriptor;
        require(realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                                &tls13_profile,
                                                kinds[i],
                                                &wrong_descriptor) &&
                    ! realityV2TryDecryptExpectedRecord(&wrong_descriptor,
                                                        kRealityV2DirectionClientToServer,
                                                        0,
                                                        material.session_id,
                                                        material.c2s_key,
                                                        material.c2s_iv,
                                                        record,
                                                        record_len,
                                                        testChachaDecrypt,
                                                        NULL,
                                                        plaintext,
                                                        sizeof(plaintext),
                                                        &payload_offset,
                                                        &payload_len),
                "control AAD kind substitution must fail");
    }
    reality_v2_record_descriptor_t application_descriptor;
    require(realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                            &tls13_profile,
                                            kRealityV2RecordKindApplicationData,
                                            &application_descriptor) &&
                ! realityV2TryDecryptExpectedRecord(&application_descriptor,
                                                    kRealityV2DirectionClientToServer,
                                                    0,
                                                    material.session_id,
                                                    material.c2s_key,
                                                    material.c2s_iv,
                                                    record,
                                                    record_len,
                                                    testChachaDecrypt,
                                                    NULL,
                                                    plaintext,
                                                    sizeof(plaintext),
                                                    &payload_offset,
                                                    &payload_len),
            "request must not authenticate as application data");
    reality_v2_record_descriptor_t alert_descriptor;
    require(realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                            &tls13_profile,
                                            kRealityV2RecordKindAlert,
                                            &alert_descriptor) &&
                ! realityV2TryDecryptExpectedRecord(&alert_descriptor,
                                                    kRealityV2DirectionClientToServer,
                                                    0,
                                                    material.session_id,
                                                    material.c2s_key,
                                                    material.c2s_iv,
                                                    record,
                                                    record_len,
                                                    testChachaDecrypt,
                                                    NULL,
                                                    plaintext,
                                                    sizeof(plaintext),
                                                    &payload_offset,
                                                    &payload_len),
            "request must not authenticate as an alert");
    require(! realityV2TryDecryptExpectedRecord(&request_descriptor,
                                                kRealityV2DirectionServerToClient,
                                                0,
                                                material.session_id,
                                                material.c2s_key,
                                                material.c2s_iv,
                                                record,
                                                record_len,
                                                testChachaDecrypt,
                                                NULL,
                                                plaintext,
                                                sizeof(plaintext),
                                                &payload_offset,
                                                &payload_len),
            "request must not authenticate in the opposite direction");

    reality_v2_record_descriptor_t classified;
    require(realityV2ClassifyRecord(kRealityV2Tls13,
                                    &tls13_profile,
                                    record,
                                    &classified) &&
                ! realityV2RecordKindIsControl(classified.record_kind),
            "public TLS header must not infer a handoff control kind");

    uint64_t c2s_sequence = 1;
    require(! realityV2TryDecryptExpectedRecord(&request_descriptor,
                                                kRealityV2DirectionClientToServer,
                                                c2s_sequence,
                                                material.session_id,
                                                material.c2s_key,
                                                material.c2s_iv,
                                                record,
                                                record_len,
                                                testChachaDecrypt,
                                                NULL,
                                                plaintext,
                                                sizeof(plaintext),
                                                &payload_offset,
                                                &payload_len) &&
                c2s_sequence == 1,
            "replayed control authenticated or changed caller sequence");
    require(memcmp(record, original, record_len) == 0,
            "failed control authentication mutated ciphertext input");

    reality_v2_session_material_t other_material = {0};
    binding.server_random[0] ^= 1;
    require(realityV2DeriveSessionMaterial(root_key, &binding, &other_material) &&
                ! realityV2TryDecryptExpectedRecord(&request_descriptor,
                                                    kRealityV2DirectionClientToServer,
                                                    0,
                                                    other_material.session_id,
                                                    other_material.c2s_key,
                                                    other_material.c2s_iv,
                                                    record,
                                                    record_len,
                                                    testChachaDecrypt,
                                                    NULL,
                                                    plaintext,
                                                    sizeof(plaintext),
                                                    &payload_offset,
                                                    &payload_len),
            "control authenticated against another TLS binding");

    uint64_t s2c_sequence = 0;
    c2s_sequence = 1;

    reality_v2_record_descriptor_t ack_descriptor;
    require(makeControlRecord(&material,
                              kRealityV2DirectionServerToClient,
                              s2c_sequence,
                              kRealityV2RecordKindHandoffAck,
                              kRealityV2ControlMinPadding + 1U,
                              record,
                              &record_len) &&
                realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                               &tls13_profile,
                                               kRealityV2RecordKindHandoffAck,
                                               &ack_descriptor) &&
                realityV2TryDecryptExpectedRecord(&ack_descriptor,
                                                  kRealityV2DirectionServerToClient,
                                                  s2c_sequence,
                                                  material.session_id,
                                                  material.s2c_key,
                                                  material.s2c_iv,
                                                  record,
                                                  record_len,
                                                  testChachaDecrypt,
                                                  NULL,
                                                  plaintext,
                                                  sizeof(plaintext),
                                                  &payload_offset,
                                                  &payload_len) &&
                realityV2ParseControl(kRealityV2RecordKindHandoffAck,
                                      plaintext + payload_offset,
                                      payload_len),
            "ACK did not authenticate at s2c sequence zero");
    require(! realityV2TryDecryptExpectedRecord(&ack_descriptor,
                                                kRealityV2DirectionClientToServer,
                                                s2c_sequence,
                                                material.session_id,
                                                material.s2c_key,
                                                material.s2c_iv,
                                                record,
                                                record_len,
                                                testChachaDecrypt,
                                                NULL,
                                                plaintext,
                                                sizeof(plaintext),
                                                &payload_offset,
                                                &payload_len),
            "ACK authenticated in the client-to-server direction");
    ++s2c_sequence;
    require(! realityV2TryDecryptExpectedRecord(&ack_descriptor,
                                                kRealityV2DirectionServerToClient,
                                                s2c_sequence,
                                                material.session_id,
                                                material.s2c_key,
                                                material.s2c_iv,
                                                record,
                                                record_len,
                                                testChachaDecrypt,
                                                NULL,
                                                plaintext,
                                                sizeof(plaintext),
                                                &payload_offset,
                                                &payload_len),
            "replayed ACK authenticated at the next s2c sequence");

    reality_v2_record_descriptor_t confirm_descriptor;
    require(makeControlRecord(&material,
                              kRealityV2DirectionClientToServer,
                              c2s_sequence,
                              kRealityV2RecordKindHandoffConfirm,
                              kRealityV2ControlMaxPadding,
                              record,
                              &record_len) &&
                realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                               &tls13_profile,
                                               kRealityV2RecordKindHandoffConfirm,
                                               &confirm_descriptor) &&
                realityV2TryDecryptExpectedRecord(&confirm_descriptor,
                                                  kRealityV2DirectionClientToServer,
                                                  c2s_sequence,
                                                  material.session_id,
                                                  material.c2s_key,
                                                  material.c2s_iv,
                                                  record,
                                                  record_len,
                                                  testChachaDecrypt,
                                                  NULL,
                                                  plaintext,
                                                  sizeof(plaintext),
                                                  &payload_offset,
                                                  &payload_len) &&
                realityV2ParseControl(kRealityV2RecordKindHandoffConfirm,
                                      plaintext + payload_offset,
                                      payload_len),
            "CONFIRM did not authenticate at c2s sequence one");
    require(! realityV2TryDecryptExpectedRecord(&application_descriptor,
                                                kRealityV2DirectionClientToServer,
                                                c2s_sequence,
                                                material.session_id,
                                                material.c2s_key,
                                                material.c2s_iv,
                                                record,
                                                record_len,
                                                testChachaDecrypt,
                                                NULL,
                                                plaintext,
                                                sizeof(plaintext),
                                                &payload_offset,
                                                &payload_len),
            "CONFIRM authenticated as application data");
    ++c2s_sequence;
    require(! realityV2TryDecryptExpectedRecord(&confirm_descriptor,
                                                kRealityV2DirectionClientToServer,
                                                c2s_sequence,
                                                material.session_id,
                                                material.c2s_key,
                                                material.c2s_iv,
                                                record,
                                                record_len,
                                                testChachaDecrypt,
                                                NULL,
                                                plaintext,
                                                sizeof(plaintext),
                                                &payload_offset,
                                                &payload_len),
            "replayed CONFIRM authenticated at the first application sequence");
    require(c2s_sequence == 2 && s2c_sequence == 1,
            "post-handoff Reality sequences are incorrect");
    memset(plaintext, 0, sizeof(plaintext));
    memset(record, 0, sizeof(record));
    memset(original, 0, sizeof(original));
    memset(&material, 0, sizeof(material));
    memset(&other_material, 0, sizeof(other_material));
}

int main(void)
{
#if defined(WCRYPTO_BACKEND_SODIUM)
    require(sodium_init() != -1, "sodium_init failed");
#endif
    testDeterministicDerivation();
    testDeterministicAlertAeadVectors();
    testNonceAndAadEncoding();
    testReplayOrderingAndBinding();
    testEveryProfileAuthenticatesPublicShape();
    testAlertRecords();
    testPatchedTls12CipherListCoverage();
    testRecordProfilesAndLayouts();
    testTls13ApplicationInnerType();
    testOldOpaqueApplicationRecordIsRejected();
    testTls13HandoffControls();
    return 0;
}
