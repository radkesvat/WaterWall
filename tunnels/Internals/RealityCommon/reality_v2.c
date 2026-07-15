#include "RealityCommon/reality_v2.h"

#include "wcrypto.h"
#include "wlibc.h"

static const uint8_t kSessionDomain[] = "WaterWall Reality v2/session";
static const uint8_t kC2sKeyDomain[]  = "WaterWall Reality v2/c2s key";
static const uint8_t kS2cKeyDomain[]  = "WaterWall Reality v2/s2c key";
static const uint8_t kC2sIvDomain[]   = "WaterWall Reality v2/c2s iv";
static const uint8_t kS2cIvDomain[]   = "WaterWall Reality v2/s2c iv";
static const uint8_t kRecordDomain[]  = "WaterWall Reality v2/record";

static void realityV2WriteBe16(uint8_t out[2], uint16_t value)
{
    out[0] = (uint8_t) (value >> 8);
    out[1] = (uint8_t) value;
}

static void realityV2WriteBe64(uint8_t out[8], uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i)
    {
        out[7U - i] = (uint8_t) value;
        value >>= 8;
    }
}

bool realityV2DeriveSessionId(const reality_v2_handshake_binding_t *binding,
                              uint8_t session_id[kRealityV2SessionIdSize])
{
    if (binding == NULL || session_id == NULL)
    {
        return false;
    }

    enum
    {
        kBindingSize = 2 + 2 + kRealityV2TlsRandomSize + kRealityV2TlsRandomSize,
        kInputSize   = sizeof(kSessionDomain) - 1 + kBindingSize,
    };

    uint8_t input[kInputSize];
    uint8_t *cursor = input;

    memoryCopy(cursor, kSessionDomain, sizeof(kSessionDomain) - 1);
    cursor += sizeof(kSessionDomain) - 1;
    realityV2WriteBe16(cursor, binding->tls_version);
    cursor += 2;
    realityV2WriteBe16(cursor, binding->cipher_suite);
    cursor += 2;
    memoryCopy(cursor, binding->client_random, kRealityV2TlsRandomSize);
    cursor += kRealityV2TlsRandomSize;
    memoryCopy(cursor, binding->server_random, kRealityV2TlsRandomSize);

    bool ok = blake2s(session_id, kRealityV2SessionIdSize, NULL, 0, input, sizeof(input)) == 0;
    memoryZero(input, sizeof(input));
    return ok;
}

static bool realityV2DeriveLabeled(const uint8_t root_key[kRealityV2KeySize], const uint8_t *domain,
                                   size_t domain_len, const uint8_t session_id[kRealityV2SessionIdSize],
                                   uint8_t *out, size_t out_len)
{
    uint8_t input[64];
    if (domain_len + kRealityV2SessionIdSize > sizeof(input))
    {
        return false;
    }

    memoryCopy(input, domain, domain_len);
    memoryCopy(input + domain_len, session_id, kRealityV2SessionIdSize);
    bool ok = blake2s(out, out_len, root_key, kRealityV2KeySize, input,
                      domain_len + kRealityV2SessionIdSize) == 0;
    memoryZero(input, sizeof(input));
    return ok;
}

bool realityV2DeriveSessionMaterial(const uint8_t root_key[kRealityV2KeySize],
                                    const reality_v2_handshake_binding_t *binding,
                                    reality_v2_session_material_t *material)
{
    if (root_key == NULL || binding == NULL || material == NULL)
    {
        return false;
    }

    reality_v2_session_material_t result = {0};
    bool ok = realityV2DeriveSessionId(binding, result.session_id) &&
              realityV2DeriveLabeled(root_key, kC2sKeyDomain, sizeof(kC2sKeyDomain) - 1, result.session_id,
                                     result.c2s_key, sizeof(result.c2s_key)) &&
              realityV2DeriveLabeled(root_key, kS2cKeyDomain, sizeof(kS2cKeyDomain) - 1, result.session_id,
                                     result.s2c_key, sizeof(result.s2c_key)) &&
              realityV2DeriveLabeled(root_key, kC2sIvDomain, sizeof(kC2sIvDomain) - 1, result.session_id,
                                     result.c2s_iv, sizeof(result.c2s_iv)) &&
              realityV2DeriveLabeled(root_key, kS2cIvDomain, sizeof(kS2cIvDomain) - 1, result.session_id,
                                     result.s2c_iv, sizeof(result.s2c_iv));

    if (ok)
    {
        *material = result;
    }
    memoryZero(&result, sizeof(result));
    return ok;
}

bool realityV2SequenceAvailable(uint64_t sequence_number)
{
    return sequence_number != UINT64_MAX;
}

void realityV2BuildNonce(const uint8_t base_iv[kRealityV2IvSize], uint64_t sequence_number,
                         uint8_t nonce[kRealityV2IvSize])
{
    uint8_t sequence_be[8];
    realityV2WriteBe64(sequence_be, sequence_number);
    memoryCopy(nonce, base_iv, kRealityV2IvSize);

    for (uint32_t i = 0; i < sizeof(sequence_be); ++i)
    {
        nonce[4U + i] ^= sequence_be[i];
    }
    memoryZero(sequence_be, sizeof(sequence_be));
}

bool realityV2BuildRecordAad(uint8_t direction, uint64_t sequence_number,
                            const uint8_t session_id[kRealityV2SessionIdSize],
                            const uint8_t tls_record_header[kRealityV2TlsRecordHeaderSize],
                            const uint8_t cover_prefix[kRealityV2CoverPrefixSize],
                            uint8_t aad[kRealityV2RecordAadSize])
{
    if ((direction != kRealityV2DirectionClientToServer && direction != kRealityV2DirectionServerToClient) ||
        session_id == NULL || tls_record_header == NULL || cover_prefix == NULL || aad == NULL)
    {
        return false;
    }

    static_assert(sizeof(kRecordDomain) - 1 + 1 + 8 + kRealityV2SessionIdSize +
                          kRealityV2TlsRecordHeaderSize + kRealityV2CoverPrefixSize ==
                      kRealityV2RecordAadSize,
                  "Reality v2 record AAD size drifted");

    uint8_t *cursor = aad;
    memoryCopy(cursor, kRecordDomain, sizeof(kRecordDomain) - 1);
    cursor += sizeof(kRecordDomain) - 1;
    *cursor++ = direction;
    realityV2WriteBe64(cursor, sequence_number);
    cursor += 8;
    memoryCopy(cursor, session_id, kRealityV2SessionIdSize);
    cursor += kRealityV2SessionIdSize;
    memoryCopy(cursor, tls_record_header, kRealityV2TlsRecordHeaderSize);
    cursor += kRealityV2TlsRecordHeaderSize;
    memoryCopy(cursor, cover_prefix, kRealityV2CoverPrefixSize);
    return true;
}
