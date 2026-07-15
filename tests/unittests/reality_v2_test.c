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

enum
{
    kPlaintextSize = 19,
    kCiphertextSize = kPlaintextSize + kRealityV2TagSize,
};

typedef struct test_record_s
{
    uint8_t header[kRealityV2TlsRecordHeaderSize];
    uint8_t cover[kRealityV2CoverPrefixSize];
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
    uint8_t aad[kRealityV2RecordAadSize];

    record->header[0] = 0x17;
    record->header[1] = 0x03;
    record->header[2] = 0x03;
    record->header[3] = 0;
    record->header[4] = kRealityV2CoverPrefixSize + kCiphertextSize;
    for (uint32_t i = 0; i < kRealityV2CoverPrefixSize; ++i)
    {
        record->cover[i] = (uint8_t) (marker + i);
    }

    realityV2BuildNonce(iv, sequence, nonce);
    require(realityV2BuildRecordAad(direction,
                                    sequence,
                                    material->session_id,
                                    record->header,
                                    record->cover,
                                    aad),
            "record AAD construction failed");
    require(chacha20poly1305Encrypt(record->ciphertext,
                                    plaintext,
                                    sizeof(plaintext),
                                    aad,
                                    sizeof(aad),
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
    uint8_t aad[kRealityV2RecordAadSize];
    uint8_t plaintext[kPlaintextSize];

    realityV2BuildNonce(iv, *expected_sequence, nonce);
    if (! realityV2BuildRecordAad(direction,
                                  *expected_sequence,
                                  material->session_id,
                                  record->header,
                                  record->cover,
                                  aad) ||
        chacha20poly1305Decrypt(plaintext,
                                record->ciphertext,
                                sizeof(record->ciphertext),
                                aad,
                                sizeof(aad),
                                nonce,
                                key) != 0)
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

static void testNonceAndAadEncoding(void)
{
    static const uint8_t expected_nonce[kRealityV2IvSize] = {
        0x00, 0x01, 0x02, 0x03, 0x05, 0x07, 0x05, 0x03, 0x0d, 0x0f, 0x0d, 0x03,
    };
    static const uint8_t expected_aad[kRealityV2RecordAadSize] = {
        0x57, 0x61, 0x74, 0x65, 0x72, 0x57, 0x61, 0x6c, 0x6c, 0x20, 0x52, 0x65, 0x61, 0x6c, 0x69, 0x74,
        0x79, 0x20, 0x76, 0x32, 0x2f, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x01, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x5a, 0x0f, 0x1b, 0xca, 0xe9, 0xd9, 0xfc, 0xb0, 0x02, 0x5f, 0x90, 0x56,
        0xa3, 0xf9, 0xd4, 0x84, 0x44, 0x15, 0xcb, 0xe5, 0x4c, 0x4f, 0xdf, 0x6f, 0xa3, 0xe7, 0x62, 0xf5,
        0x44, 0x29, 0x37, 0xcd, 0x17, 0x03, 0x03, 0x00, 0x2c, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6,
        0xa7, 0xa8, 0xa9, 0xaa, 0xab,
    };
    const uint64_t sequence = UINT64_C(0x0102030405060708);
    uint8_t base_iv[kRealityV2IvSize];
    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadSize];
    uint8_t header[kRealityV2TlsRecordHeaderSize] = {0x17, 0x03, 0x03, 0x00, 0x2c};
    uint8_t cover[kRealityV2CoverPrefixSize];
    reality_v2_handshake_binding_t binding = makeBinding();
    uint8_t session_id[kRealityV2SessionIdSize];

    for (uint32_t i = 0; i < sizeof(base_iv); ++i)
    {
        base_iv[i] = (uint8_t) i;
        cover[i]   = (uint8_t) (0xa0U + i);
    }
    require(realityV2DeriveSessionId(&binding, session_id), "session-id derivation failed");
    realityV2BuildNonce(base_iv, sequence, nonce);
    requireEqual(nonce, expected_nonce, sizeof(nonce), "nonce encoding mismatch");
    require(realityV2BuildRecordAad(kRealityV2DirectionClientToServer,
                                    sequence,
                                    session_id,
                                    header,
                                    cover,
                                    aad),
            "AAD encoding failed");
    requireEqual(aad, expected_aad, sizeof(aad), "AAD encoding vector mismatch");
    require(! realityV2BuildRecordAad(0xff, sequence, session_id, header, cover, aad),
            "invalid direction must be rejected");
    require(realityV2SequenceAvailable(0), "sequence zero must be available");
    require(realityV2SequenceAvailable(UINT64_MAX - 1), "last permitted sequence must be available");
    require(! realityV2SequenceAvailable(UINT64_MAX), "UINT64_MAX must be rejected before use");
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
    tampered.cover[3] ^= 1;
    require(! receiveRecord(&material, kRealityV2DirectionClientToServer, &expected, &tampered),
            "cover-prefix tampering must fail");
}

int main(void)
{
#if defined(WCRYPTO_BACKEND_SODIUM)
    require(sodium_init() != -1, "sodium_init failed");
#endif
    testDeterministicDerivation();
    testNonceAndAadEncoding();
    testReplayOrderingAndBinding();
    return 0;
}
