#include "RealityCommon/reality_v2.h"

#include "wcrypto.h"
#include "wlibc.h"

bool realityV2ShouldRetryAmbiguousTls13Decrypt(wcrypto_status_t status)
{
    /* A second descriptor is an authentication ambiguity, not a backend
     * recovery path. Operational failures must remain visible to the caller. */
    return status == kWCryptoAuthenticationFailed;
}

static const uint8_t kSessionDomain[] = "WaterWall Reality v2/session";
static const uint8_t kC2sKeyDomain[]  = "WaterWall Reality v2/c2s key";
static const uint8_t kS2cKeyDomain[]  = "WaterWall Reality v2/s2c key";
static const uint8_t kC2sIvDomain[]   = "WaterWall Reality v2/c2s iv";
static const uint8_t kS2cIvDomain[]   = "WaterWall Reality v2/s2c iv";
static const uint8_t kRecordDomain[]  = "WaterWall Reality v2/profile record";

static_assert(kRealityV2ControlMinPayload + 1 + kRealityV2TagSize == kRealityV2ControlMinTlsRecordBody,
              "Reality v2 minimum handoff control envelope drifted");
static_assert(kRealityV2ControlMaxPayload + 1 + kRealityV2TagSize == kRealityV2ControlMaxTlsRecordBody,
              "Reality v2 maximum handoff control envelope drifted");

enum
{
    kTlsContentTypeAlert                  = 0x15,
    kTlsContentTypeApplicationData        = 0x17,
    kTls13InnerContentTypeAlert           = 0x15,
    kTls13InnerContentTypeApplicationData = 0x17,
};

typedef struct reality_v2_profile_map_s
{
    uint16_t                    tls_version;
    uint16_t                    cipher_suite;
    reality_v2_record_profile_t profile;
} reality_v2_profile_map_t;

static const reality_v2_profile_map_t kRealityV2Profiles[] = {
    {kRealityV2Tls13, 0x1301, {kRealityV2RecordProfileTls13Aead, 0, 0, 0}},
    {kRealityV2Tls13, 0x1302, {kRealityV2RecordProfileTls13Aead, 0, 0, 0}},
    {kRealityV2Tls13, 0x1303, {kRealityV2RecordProfileTls13Aead, 0, 0, 0}},
    {kRealityV2Tls12, 0xC02B, {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0}},
    {kRealityV2Tls12, 0xC02F, {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0}},
    {kRealityV2Tls12, 0xC02C, {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0}},
    {kRealityV2Tls12, 0xC030, {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0}},
    {kRealityV2Tls12, 0xCCA9, {kRealityV2RecordProfileTls12ChaCha, 0, 0, 0}},
    {kRealityV2Tls12, 0xCCA8, {kRealityV2RecordProfileTls12ChaCha, 0, 0, 0}},
    {kRealityV2Tls12, 0xC013, {kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20}},
    {kRealityV2Tls12, 0xC014, {kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20}},
    {kRealityV2Tls12, 0x009C, {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0}},
    {kRealityV2Tls12, 0x009D, {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0}},
    {kRealityV2Tls12, 0x002F, {kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20}},
    {kRealityV2Tls12, 0x0035, {kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20}},
};

static void realityV2WriteBe16(uint8_t out[2], uint16_t value)
{
    out[0] = (uint8_t) (value >> 8);
    out[1] = (uint8_t) value;
}

bool realityV2DeriveRootKey(const char *password, const char *salt, uint32_t iterations,
                            uint8_t out_key[kRealityV2KeySize])
{
    if (out_key != NULL)
    {
        memoryZero(out_key, kRealityV2KeySize);
    }
    if (password == NULL || salt == NULL || out_key == NULL || iterations < kRealityV2MinKdfIterations ||
        iterations > kRealityV2MaxKdfIterations)
    {
        return false;
    }

    size_t password_len = stringLength(password);
    size_t salt_len     = stringLength(salt);
    if (password_len < kRealityV2MinCredentialByteLength || password_len > kRealityV2MaxPasswordByteLength ||
        salt_len < kRealityV2MinCredentialByteLength || salt_len > kRealityV2MaxSaltByteLength)
    {
        return false;
    }

    if (wCryptoBlake2s(out_key,
                       kRealityV2KeySize,
                       (const unsigned char *) salt,
                       salt_len,
                       (const unsigned char *) password,
                       password_len) != kWCryptoOk)
    {
        return false;
    }

    uint8_t iter_block[kRealityV2KeySize + sizeof(uint32_t)] = {0};
    for (uint32_t i = 1; i < iterations; ++i)
    {
        uint32_t iter_be = htobe32(i);

        memoryCopy(iter_block, out_key, kRealityV2KeySize);
        memoryCopy(iter_block + kRealityV2KeySize, &iter_be, sizeof(iter_be));

        if (wCryptoBlake2s(out_key,
                           kRealityV2KeySize,
                           (const unsigned char *) password,
                           password_len,
                           iter_block,
                           sizeof(iter_block)) != kWCryptoOk)
        {
            memoryZero(iter_block, sizeof(iter_block));
            memoryZero(out_key, kRealityV2KeySize);
            return false;
        }

        memoryZero(iter_block, sizeof(iter_block));
    }

    memoryZero(iter_block, sizeof(iter_block));
    return true;
}

void realityV2WriteBe64(uint8_t out[8], uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i)
    {
        out[7U - i] = (uint8_t) value;
        value >>= 8;
    }
}

uint64_t realityV2ReadBe64(const uint8_t in[8])
{
    uint64_t value = 0;
    for (uint32_t i = 0; i < 8; ++i)
    {
        value = (value << 8) | in[i];
    }
    return value;
}

bool realityV2DeriveSessionId(const reality_v2_handshake_binding_t *binding,
                              uint8_t                               session_id[kRealityV2SessionIdSize])
{
    if (session_id != NULL)
    {
        memoryZero(session_id, kRealityV2SessionIdSize);
    }
    if (binding == NULL || session_id == NULL)
    {
        return false;
    }

    enum
    {
        kBindingSize = 2 + 2 + kRealityV2TlsRandomSize + kRealityV2TlsRandomSize,
        kInputSize   = sizeof(kSessionDomain) - 1 + kBindingSize,
    };

    uint8_t  input[kInputSize];
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

    bool ok = wCryptoBlake2s(session_id, kRealityV2SessionIdSize, NULL, 0, input, sizeof(input)) == kWCryptoOk;
    memoryZero(input, sizeof(input));
    if (! ok)
    {
        memoryZero(session_id, kRealityV2SessionIdSize);
    }
    return ok;
}

static bool realityV2DeriveLabeled(const uint8_t root_key[kRealityV2KeySize], const uint8_t *domain, size_t domain_len,
                                   const uint8_t session_id[kRealityV2SessionIdSize], uint8_t *out, size_t out_len)
{
    if (out != NULL)
    {
        memoryZero(out, out_len);
    }
    if (root_key == NULL || domain == NULL || session_id == NULL || out == NULL)
    {
        return false;
    }

    uint8_t input[64];
    if (domain_len + kRealityV2SessionIdSize > sizeof(input))
    {
        return false;
    }

    memoryCopy(input, domain, domain_len);
    memoryCopy(input + domain_len, session_id, kRealityV2SessionIdSize);
    bool ok = wCryptoBlake2s(out, out_len, root_key, kRealityV2KeySize, input, domain_len + kRealityV2SessionIdSize) ==
              kWCryptoOk;
    memoryZero(input, sizeof(input));
    if (! ok)
    {
        memoryZero(out, out_len);
    }
    return ok;
}

bool realityV2DeriveSessionMaterial(const uint8_t                         root_key[kRealityV2KeySize],
                                    const reality_v2_handshake_binding_t *binding,
                                    reality_v2_session_material_t        *material)
{
    if (material != NULL)
    {
        memoryZero(material, sizeof(*material));
    }
    if (root_key == NULL || binding == NULL || material == NULL)
    {
        return false;
    }

    reality_v2_session_material_t result = {0};
    bool                          ok =
        realityV2DeriveSessionId(binding, result.session_id) &&
        realityV2DeriveLabeled(root_key,
                               kC2sKeyDomain,
                               sizeof(kC2sKeyDomain) - 1,
                               result.session_id,
                               result.c2s_key,
                               sizeof(result.c2s_key)) &&
        realityV2DeriveLabeled(root_key,
                               kS2cKeyDomain,
                               sizeof(kS2cKeyDomain) - 1,
                               result.session_id,
                               result.s2c_key,
                               sizeof(result.s2c_key)) &&
        realityV2DeriveLabeled(root_key,
                               kC2sIvDomain,
                               sizeof(kC2sIvDomain) - 1,
                               result.session_id,
                               result.c2s_iv,
                               sizeof(result.c2s_iv)) &&
        realityV2DeriveLabeled(
            root_key, kS2cIvDomain, sizeof(kS2cIvDomain) - 1, result.session_id, result.s2c_iv, sizeof(result.s2c_iv));

    if (ok)
    {
        *material = result;
    }
    memoryZero(&result, sizeof(result));
    return ok;
}

bool realityV2RecordProfileIsValid(const reality_v2_record_profile_t *profile)
{
    if (profile == NULL || profile->visible_prefix_len > kRealityV2MaxVisiblePrefixSize)
    {
        return false;
    }

    switch (profile->profile_id)
    {
    case kRealityV2RecordProfileTls13Aead:
    case kRealityV2RecordProfileTls12ChaCha:
        return profile->visible_prefix_len == 0 && profile->block_size == 0 && profile->tls_mac_len == 0;
    case kRealityV2RecordProfileTls12Gcm:
        return profile->visible_prefix_len == kRealityV2Tls12GcmPrefixSize && profile->block_size == 0 &&
               profile->tls_mac_len == 0;
    case kRealityV2RecordProfileTls12Cbc:
        return profile->visible_prefix_len == kRealityV2Tls12CbcPrefixSize &&
               profile->block_size == kRealityV2Tls12CbcPrefixSize && profile->tls_mac_len == 20;
    default:
        return false;
    }
}

bool realityV2SelectRecordProfile(uint16_t tls_version, uint16_t cipher_suite, reality_v2_record_profile_t *profile)
{
    if (profile == NULL)
    {
        return false;
    }

    for (size_t i = 0; i < sizeof(kRealityV2Profiles) / sizeof(kRealityV2Profiles[0]); ++i)
    {
        if (kRealityV2Profiles[i].tls_version == tls_version && kRealityV2Profiles[i].cipher_suite == cipher_suite)
        {
            if (! realityV2RecordProfileIsValid(&kRealityV2Profiles[i].profile))
            {
                return false;
            }
            *profile = kRealityV2Profiles[i].profile;
            return true;
        }
    }
    return false;
}

bool realityV2RecordDescriptorIsValid(const reality_v2_record_descriptor_t *descriptor)
{
    if (descriptor == NULL || ! realityV2RecordProfileIsValid(&descriptor->profile) ||
        (descriptor->tls_version != kRealityV2Tls12 && descriptor->tls_version != kRealityV2Tls13))
    {
        return false;
    }
    if ((descriptor->tls_version == kRealityV2Tls13 &&
         descriptor->profile.profile_id != kRealityV2RecordProfileTls13Aead) ||
        (descriptor->tls_version == kRealityV2Tls12 &&
         descriptor->profile.profile_id != kRealityV2RecordProfileTls12ChaCha &&
         descriptor->profile.profile_id != kRealityV2RecordProfileTls12Gcm &&
         descriptor->profile.profile_id != kRealityV2RecordProfileTls12Cbc))
    {
        return false;
    }

    if (realityV2RecordKindIsControl(descriptor->record_kind))
    {
        return descriptor->tls_version == kRealityV2Tls13 &&
               descriptor->profile.profile_id == kRealityV2RecordProfileTls13Aead &&
               descriptor->outer_content_type == kTlsContentTypeApplicationData &&
               descriptor->visible_prefix_len == 0 &&
               descriptor->tls13_inner_content_type == kTls13InnerContentTypeApplicationData;
    }

    if (descriptor->record_kind == kRealityV2RecordKindApplicationData)
    {
        uint8_t expected_inner_type =
            descriptor->tls_version == kRealityV2Tls13 ? kTls13InnerContentTypeApplicationData : 0;
        return descriptor->outer_content_type == kTlsContentTypeApplicationData &&
               descriptor->visible_prefix_len == descriptor->profile.visible_prefix_len &&
               descriptor->tls13_inner_content_type == expected_inner_type;
    }

    if (descriptor->record_kind != kRealityV2RecordKindAlert)
    {
        return false;
    }

    if (descriptor->tls_version == kRealityV2Tls13)
    {
        return descriptor->profile.profile_id == kRealityV2RecordProfileTls13Aead &&
               descriptor->outer_content_type == kTlsContentTypeApplicationData &&
               descriptor->visible_prefix_len == 0 &&
               descriptor->tls13_inner_content_type == kTls13InnerContentTypeAlert;
    }

    uint8_t expected_prefix = 0;
    if (descriptor->profile.profile_id == kRealityV2RecordProfileTls12Gcm)
    {
        expected_prefix = kRealityV2Tls12GcmPrefixSize;
    }
    else if (descriptor->profile.profile_id == kRealityV2RecordProfileTls12Cbc)
    {
        expected_prefix = kRealityV2Tls12CbcPrefixSize;
    }
    else if (descriptor->profile.profile_id != kRealityV2RecordProfileTls12ChaCha)
    {
        return false;
    }

    return descriptor->outer_content_type == kTlsContentTypeAlert &&
           descriptor->visible_prefix_len == expected_prefix && descriptor->tls13_inner_content_type == 0;
}

bool realityV2BuildRecordDescriptor(uint16_t tls_version, const reality_v2_record_profile_t *profile,
                                    uint8_t record_kind, reality_v2_record_descriptor_t *descriptor)
{
    if (! realityV2RecordProfileIsValid(profile) || descriptor == NULL)
    {
        return false;
    }

    reality_v2_record_descriptor_t result = {
        .profile            = *profile,
        .tls_version        = tls_version,
        .record_kind        = record_kind,
        .outer_content_type = kTlsContentTypeApplicationData,
        .visible_prefix_len = profile->visible_prefix_len,
    };

    if ((record_kind == kRealityV2RecordKindApplicationData || realityV2RecordKindIsControl(record_kind)) &&
        tls_version == kRealityV2Tls13)
    {
        result.tls13_inner_content_type = kTls13InnerContentTypeApplicationData;
    }

    if (record_kind == kRealityV2RecordKindAlert)
    {
        if (tls_version == kRealityV2Tls13)
        {
            result.visible_prefix_len       = 0;
            result.tls13_inner_content_type = kTls13InnerContentTypeAlert;
        }
        else if (tls_version == kRealityV2Tls12)
        {
            result.outer_content_type = kTlsContentTypeAlert;
            if (profile->profile_id == kRealityV2RecordProfileTls12ChaCha)
            {
                result.visible_prefix_len = 0;
            }
        }
    }

    if (! realityV2RecordDescriptorIsValid(&result))
    {
        return false;
    }
    *descriptor = result;
    return true;
}

bool realityV2CalculateDescriptorLayout(const reality_v2_record_descriptor_t *descriptor, uint32_t payload_len,
                                        reality_v2_record_layout_t *layout)
{
    if (! realityV2RecordDescriptorIsValid(descriptor) || layout == NULL)
    {
        return false;
    }

    if ((descriptor->record_kind == kRealityV2RecordKindApplicationData &&
         payload_len > kRealityV2MaxPlaintextFragment) ||
        (descriptor->record_kind == kRealityV2RecordKindAlert && payload_len != kRealityV2AlertMessageSize) ||
        (realityV2RecordKindIsControl(descriptor->record_kind) &&
         (payload_len < kRealityV2ControlMinPayload || payload_len > kRealityV2ControlMaxPayload)))
    {
        return false;
    }

    uint64_t encoded_payload_len = payload_len;
    if (descriptor->tls13_inner_content_type != 0)
    {
        ++encoded_payload_len;
    }

    uint64_t body_len;
    uint64_t inner_len  = encoded_payload_len;
    uint64_t filler_len = 0;
    if (descriptor->profile.profile_id == kRealityV2RecordProfileTls12Cbc)
    {
        uint64_t padded_len = (uint64_t) payload_len + descriptor->profile.tls_mac_len + 1U;
        uint64_t remainder  = padded_len % descriptor->profile.block_size;
        if (remainder != 0)
        {
            padded_len += descriptor->profile.block_size - remainder;
        }
        if (padded_len < kRealityV2TagSize)
        {
            return false;
        }
        inner_len = padded_len - kRealityV2TagSize;
        if (inner_len < (uint64_t) payload_len + 2U)
        {
            return false;
        }
        filler_len = inner_len - payload_len - 2U;
        body_len   = descriptor->visible_prefix_len + padded_len;
    }
    else
    {
        body_len = (uint64_t) descriptor->visible_prefix_len + inner_len + kRealityV2TagSize;
    }

    if (body_len > kRealityV2MaxTlsRecordBody || body_len > UINT32_MAX || inner_len > UINT32_MAX ||
        filler_len > UINT32_MAX)
    {
        return false;
    }

    *layout = (reality_v2_record_layout_t) {
        .wire_body_len       = (uint32_t) body_len,
        .inner_plaintext_len = (uint32_t) inner_len,
        .filler_len          = (uint32_t) filler_len,
    };
    return true;
}

bool realityV2CalculateRecordLayout(const reality_v2_record_profile_t *profile, uint32_t payload_len,
                                    reality_v2_record_layout_t *layout)
{
    reality_v2_record_descriptor_t descriptor;
    uint16_t                       tls_version =
        profile != NULL && profile->profile_id == kRealityV2RecordProfileTls13Aead ? kRealityV2Tls13 : kRealityV2Tls12;
    return realityV2BuildRecordDescriptor(tls_version, profile, kRealityV2RecordKindApplicationData, &descriptor) &&
           realityV2CalculateDescriptorLayout(&descriptor, payload_len, layout);
}

bool realityV2ValidateDescriptorBodyLength(const reality_v2_record_descriptor_t *descriptor, uint32_t body_len)
{
    if (! realityV2RecordDescriptorIsValid(descriptor) || body_len > kRealityV2MaxTlsRecordBody)
    {
        return false;
    }

    if (descriptor->record_kind == kRealityV2RecordKindAlert)
    {
        reality_v2_record_layout_t exact;
        return realityV2CalculateDescriptorLayout(descriptor, kRealityV2AlertMessageSize, &exact) &&
               body_len == exact.wire_body_len;
    }

    if (realityV2RecordKindIsControl(descriptor->record_kind))
    {
        reality_v2_record_layout_t minimum;
        reality_v2_record_layout_t maximum;
        return realityV2CalculateDescriptorLayout(descriptor, kRealityV2ControlMinPayload, &minimum) &&
               realityV2CalculateDescriptorLayout(descriptor, kRealityV2ControlMaxPayload, &maximum) &&
               body_len >= minimum.wire_body_len && body_len <= maximum.wire_body_len;
    }

    reality_v2_record_layout_t maximum;
    if (! realityV2CalculateDescriptorLayout(descriptor, kRealityV2MaxPlaintextFragment, &maximum) ||
        body_len > maximum.wire_body_len)
    {
        return false;
    }

    if (descriptor->profile.profile_id == kRealityV2RecordProfileTls12Cbc)
    {
        reality_v2_record_layout_t minimum;
        if (! realityV2CalculateDescriptorLayout(descriptor, 0, &minimum) || body_len < minimum.wire_body_len)
        {
            return false;
        }
        return ((body_len - descriptor->visible_prefix_len) % descriptor->profile.block_size) == 0;
    }

    reality_v2_record_layout_t minimum;
    return realityV2CalculateDescriptorLayout(descriptor, 0, &minimum) && body_len >= minimum.wire_body_len;
}

bool realityV2ValidateRecordBodyLength(const reality_v2_record_profile_t *profile, uint32_t body_len)
{
    reality_v2_record_descriptor_t descriptor;
    uint16_t                       tls_version =
        profile != NULL && profile->profile_id == kRealityV2RecordProfileTls13Aead ? kRealityV2Tls13 : kRealityV2Tls12;
    return realityV2BuildRecordDescriptor(tls_version, profile, kRealityV2RecordKindApplicationData, &descriptor) &&
           realityV2ValidateDescriptorBodyLength(&descriptor, body_len);
}

bool realityV2ClassifyRecord(uint16_t tls_version, const reality_v2_record_profile_t *profile,
                             const uint8_t                   tls_record_header[kRealityV2TlsRecordHeaderSize],
                             reality_v2_record_descriptor_t *descriptor)
{
    if (tls_record_header == NULL || descriptor == NULL || tls_record_header[1] != 0x03 || tls_record_header[2] != 0x03)
    {
        return false;
    }

    uint32_t                       body_len = ((uint32_t) tls_record_header[3] << 8) | tls_record_header[4];
    reality_v2_record_descriptor_t candidate;
    if (realityV2BuildRecordDescriptor(tls_version, profile, kRealityV2RecordKindAlert, &candidate) &&
        tls_record_header[0] == candidate.outer_content_type &&
        realityV2ValidateDescriptorBodyLength(&candidate, body_len))
    {
        *descriptor = candidate;
        return true;
    }

    if (realityV2BuildRecordDescriptor(tls_version, profile, kRealityV2RecordKindApplicationData, &candidate) &&
        tls_record_header[0] == candidate.outer_content_type &&
        realityV2ValidateDescriptorBodyLength(&candidate, body_len))
    {
        *descriptor = candidate;
        return true;
    }
    return false;
}

bool realityV2ValidateCbcInnerPlaintext(const reality_v2_record_profile_t *profile, const uint8_t *inner_plaintext,
                                        uint32_t inner_plaintext_len, uint32_t *payload_len)
{
    if (! realityV2RecordProfileIsValid(profile) || profile->profile_id != kRealityV2RecordProfileTls12Cbc ||
        inner_plaintext == NULL || payload_len == NULL || inner_plaintext_len < 2)
    {
        return false;
    }

    uint32_t                   declared_len = ((uint32_t) inner_plaintext[0] << 8) | inner_plaintext[1];
    reality_v2_record_layout_t expected;
    if (declared_len > kRealityV2MaxPlaintextFragment ||
        ! realityV2CalculateRecordLayout(profile, declared_len, &expected) ||
        expected.inner_plaintext_len != inner_plaintext_len)
    {
        return false;
    }

    uint32_t filler_start = 2U + declared_len;
    for (uint32_t i = filler_start; i < inner_plaintext_len; ++i)
    {
        if (inner_plaintext[i] != 0)
        {
            return false;
        }
    }

    *payload_len = declared_len;
    return true;
}

bool realityV2BuildInnerPlaintext(const reality_v2_record_descriptor_t *descriptor, const uint8_t *payload,
                                  uint32_t payload_len, uint8_t *inner_plaintext, uint32_t inner_plaintext_len)
{
    reality_v2_record_layout_t layout;
    if (! realityV2CalculateDescriptorLayout(descriptor, payload_len, &layout) || inner_plaintext == NULL ||
        (payload == NULL && payload_len != 0) || inner_plaintext_len != layout.inner_plaintext_len)
    {
        return false;
    }

    if (descriptor->profile.profile_id == kRealityV2RecordProfileTls12Cbc)
    {
        if (payload_len > UINT16_MAX)
        {
            return false;
        }
        realityV2WriteBe16(inner_plaintext, (uint16_t) payload_len);
        if (payload_len != 0)
        {
            memoryCopy(inner_plaintext + 2, payload, payload_len);
        }
        memoryZero(inner_plaintext + 2 + payload_len, layout.filler_len);
        return true;
    }

    if (payload_len != 0)
    {
        memoryCopy(inner_plaintext, payload, payload_len);
    }
    if (descriptor->tls13_inner_content_type != 0)
    {
        inner_plaintext[payload_len] = descriptor->tls13_inner_content_type;
    }
    return true;
}

bool realityV2ValidateInnerPlaintext(const reality_v2_record_descriptor_t *descriptor, const uint8_t *inner_plaintext,
                                     uint32_t inner_plaintext_len, uint32_t *payload_offset, uint32_t *payload_len)
{
    if (! realityV2RecordDescriptorIsValid(descriptor) || inner_plaintext == NULL || payload_offset == NULL ||
        payload_len == NULL)
    {
        return false;
    }

    if (descriptor->profile.profile_id == kRealityV2RecordProfileTls12Cbc)
    {
        if (inner_plaintext_len < 2)
        {
            return false;
        }
        uint32_t                   declared_len = ((uint32_t) inner_plaintext[0] << 8) | inner_plaintext[1];
        reality_v2_record_layout_t expected;
        if ((descriptor->record_kind == kRealityV2RecordKindApplicationData &&
             declared_len > kRealityV2MaxPlaintextFragment) ||
            (descriptor->record_kind == kRealityV2RecordKindAlert && declared_len != kRealityV2AlertMessageSize) ||
            ! realityV2CalculateDescriptorLayout(descriptor, declared_len, &expected) ||
            expected.inner_plaintext_len != inner_plaintext_len)
        {
            return false;
        }
        uint32_t filler_start = 2U + declared_len;
        for (uint32_t i = filler_start; i < inner_plaintext_len; ++i)
        {
            if (inner_plaintext[i] != 0)
            {
                return false;
            }
        }
        *payload_offset = 2;
        *payload_len    = declared_len;
        return true;
    }

    if (descriptor->record_kind == kRealityV2RecordKindAlert)
    {
        uint32_t expected_len = kRealityV2AlertMessageSize;
        if (descriptor->tls13_inner_content_type != 0)
        {
            ++expected_len;
        }
        if (inner_plaintext_len != expected_len ||
            (descriptor->tls13_inner_content_type != 0 &&
             inner_plaintext[inner_plaintext_len - 1] != descriptor->tls13_inner_content_type))
        {
            return false;
        }
        *payload_offset = 0;
        *payload_len    = kRealityV2AlertMessageSize;
        return true;
    }

    if (realityV2RecordKindIsControl(descriptor->record_kind))
    {
        if (inner_plaintext_len < 1 || inner_plaintext[inner_plaintext_len - 1] != descriptor->tls13_inner_content_type)
        {
            return false;
        }
        uint32_t control_payload_len = inner_plaintext_len - 1U;
        if (control_payload_len < kRealityV2ControlMinPayload || control_payload_len > kRealityV2ControlMaxPayload)
        {
            return false;
        }
        *payload_offset = 0;
        *payload_len    = control_payload_len;
        return true;
    }

    uint32_t application_payload_len = inner_plaintext_len;
    if (descriptor->tls13_inner_content_type != 0)
    {
        if (inner_plaintext_len == 0 ||
            inner_plaintext[inner_plaintext_len - 1] != descriptor->tls13_inner_content_type)
        {
            return false;
        }
        --application_payload_len;
    }
    if (application_payload_len > kRealityV2MaxPlaintextFragment)
    {
        return false;
    }
    *payload_offset = 0;
    *payload_len    = application_payload_len;
    return true;
}

bool realityV2RecordKindIsControl(uint8_t record_kind)
{
    return record_kind == kRealityV2RecordKindHandoffRequest || record_kind == kRealityV2RecordKindHandoffAck ||
           record_kind == kRealityV2RecordKindHandoffConfirm;
}

bool realityV2ControlPaddingLengthIsValid(uint32_t padding_len)
{
    return padding_len >= kRealityV2ControlMinPadding && padding_len <= kRealityV2ControlMaxPadding;
}

bool realityV2CalculateControlPayloadLength(uint32_t padding_len, uint32_t *payload_len)
{
    if (! realityV2ControlPaddingLengthIsValid(padding_len) || payload_len == NULL)
    {
        return false;
    }
    *payload_len = kRealityV2ControlHeaderSize + padding_len;
    return true;
}

bool realityV2SerializeControl(uint8_t record_kind, const uint8_t *padding, uint32_t padding_len, uint8_t *out,
                               uint32_t out_len)
{
    uint32_t expected_len;
    if (! realityV2RecordKindIsControl(record_kind) || padding == NULL || out == NULL ||
        ! realityV2CalculateControlPayloadLength(padding_len, &expected_len) || out_len != expected_len)
    {
        return false;
    }

    out[0] = kRealityV2ControlFormatVersion;
    out[1] = record_kind;
    memoryCopy(out + kRealityV2ControlHeaderSize, padding, padding_len);
    return true;
}

bool realityV2ParseControl(uint8_t expected_record_kind, const uint8_t *data, uint32_t len)
{
    return realityV2RecordKindIsControl(expected_record_kind) && data != NULL && len >= kRealityV2ControlMinPayload &&
           len <= kRealityV2ControlMaxPayload && data[0] == kRealityV2ControlFormatVersion &&
           data[1] == expected_record_kind;
}

static bool realityV2SecureRandomAdapter(void *context, void *bytes, size_t size)
{
    discard context;
    return secureRandomBytes(bytes, size);
}

static bool realityV2SelectControlPaddingLength(reality_v2_random_bytes_fn random_bytes, void *random_context,
                                                uint32_t *padding_len)
{
    enum
    {
        kSampleCardinality = UINT16_MAX + 1U,
        kMaximumAttempts   = 32,
    };
    const uint32_t choice_count     = kRealityV2ControlMaxPadding - kRealityV2ControlMinPadding + 1U;
    const uint32_t acceptance_limit = kSampleCardinality - (kSampleCardinality % choice_count);

    if (random_bytes == NULL || padding_len == NULL)
    {
        return false;
    }

    for (uint32_t attempt = 0; attempt < kMaximumAttempts; ++attempt)
    {
        uint8_t sample_bytes[2] = {0};
        if (! random_bytes(random_context, sample_bytes, sizeof(sample_bytes)))
        {
            memoryZero(sample_bytes, sizeof(sample_bytes));
            return false;
        }
        uint32_t sample = ((uint32_t) sample_bytes[0] << 8) | sample_bytes[1];
        memoryZero(sample_bytes, sizeof(sample_bytes));
        if (sample < acceptance_limit)
        {
            *padding_len = kRealityV2ControlMinPadding + (sample % choice_count);
            return true;
        }
    }
    return false;
}

bool realityV2BuildControlPayloadWithRandom(uint8_t record_kind, reality_v2_random_bytes_fn random_bytes,
                                            void *random_context, uint8_t *out, uint32_t out_capacity,
                                            uint32_t *out_len)
{
    uint32_t padding_len = 0;
    uint32_t payload_len = 0;
    if (out_len != NULL)
    {
        *out_len = 0;
    }
    if (! realityV2RecordKindIsControl(record_kind) || random_bytes == NULL || out == NULL || out_len == NULL ||
        out_capacity < kRealityV2ControlMaxPayload ||
        ! realityV2SelectControlPaddingLength(random_bytes, random_context, &padding_len) ||
        ! realityV2CalculateControlPayloadLength(padding_len, &payload_len))
    {
        if (out != NULL)
        {
            uint32_t clear_len =
                out_capacity < kRealityV2ControlMaxPayload ? out_capacity : kRealityV2ControlMaxPayload;
            memoryZero(out, clear_len);
        }
        return false;
    }

    uint8_t padding[kRealityV2ControlMaxPadding] = {0};
    if (! random_bytes(random_context, padding, padding_len) ||
        ! realityV2SerializeControl(record_kind, padding, padding_len, out, payload_len))
    {
        memoryZero(padding, sizeof(padding));
        uint32_t clear_len = out_capacity < kRealityV2ControlMaxPayload ? out_capacity : kRealityV2ControlMaxPayload;
        memoryZero(out, clear_len);
        return false;
    }

    memoryZero(padding, sizeof(padding));
    *out_len = payload_len;
    return true;
}

bool realityV2BuildControlPayload(uint8_t record_kind, uint8_t *out, uint32_t out_capacity, uint32_t *out_len)
{
    return realityV2BuildControlPayloadWithRandom(
        record_kind, realityV2SecureRandomAdapter, NULL, out, out_capacity, out_len);
}

bool realityV2TryDecryptExpectedRecord(const reality_v2_record_descriptor_t *descriptor, uint8_t direction,
                                       uint64_t sequence_number, const uint8_t session_id[kRealityV2SessionIdSize],
                                       const uint8_t key[kRealityV2KeySize], const uint8_t base_iv[kRealityV2IvSize],
                                       const uint8_t *record, uint32_t record_len, reality_v2_aead_decrypt_fn decrypt,
                                       void *decrypt_context, uint8_t *plaintext, uint32_t plaintext_capacity,
                                       uint32_t *payload_offset, uint32_t *payload_len)
{
    if (payload_offset != NULL)
    {
        *payload_offset = 0;
    }
    if (payload_len != NULL)
    {
        *payload_len = 0;
    }
    if (! realityV2RecordDescriptorIsValid(descriptor) ||
        (direction != kRealityV2DirectionClientToServer && direction != kRealityV2DirectionServerToClient) ||
        ! realityV2SequenceAvailable(sequence_number) || session_id == NULL || key == NULL || base_iv == NULL ||
        record == NULL || decrypt == NULL || plaintext == NULL || payload_offset == NULL || payload_len == NULL ||
        record_len < kRealityV2TlsRecordHeaderSize || record[0] != descriptor->outer_content_type ||
        record[1] != 0x03 || record[2] != 0x03)
    {
        return false;
    }

    uint32_t body_len = ((uint32_t) record[3] << 8) | record[4];
    if (body_len != record_len - kRealityV2TlsRecordHeaderSize ||
        ! realityV2ValidateDescriptorBodyLength(descriptor, body_len) ||
        body_len < (uint32_t) descriptor->visible_prefix_len + kRealityV2TagSize)
    {
        return false;
    }

    const uint8_t *visible_prefix      = record + kRealityV2TlsRecordHeaderSize;
    const uint8_t *ciphertext          = visible_prefix + descriptor->visible_prefix_len;
    uint32_t       ciphertext_len      = body_len - descriptor->visible_prefix_len;
    uint32_t       inner_plaintext_len = ciphertext_len - kRealityV2TagSize;
    if (plaintext_capacity < inner_plaintext_len)
    {
        return false;
    }

    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadMaxSize];
    size_t  aad_len = 0;
    realityV2BuildNonce(base_iv, sequence_number, nonce);
    bool             aad_ok = realityV2BuildRecordAad(descriptor,
                                          direction,
                                          sequence_number,
                                          session_id,
                                          record,
                                          visible_prefix,
                                          descriptor->visible_prefix_len,
                                          aad,
                                          &aad_len);
    wcrypto_status_t decrypt_result =
        aad_ok
            ? decrypt(
                  decrypt_context, plaintext, plaintext_capacity, ciphertext, ciphertext_len, aad, aad_len, nonce, key)
            : kWCryptoInvalidArgument;
    memoryZero(nonce, sizeof(nonce));
    memoryZero(aad, sizeof(aad));
    if (decrypt_result != kWCryptoOk ||
        ! realityV2ValidateInnerPlaintext(descriptor, plaintext, inner_plaintext_len, payload_offset, payload_len))
    {
        memoryZero(plaintext, inner_plaintext_len);
        *payload_offset = 0;
        *payload_len    = 0;
        return false;
    }
    return true;
}

bool realityV2SerializeAlert(uint8_t alert, uint8_t out[kRealityV2AlertMessageSize])
{
    if (out == NULL)
    {
        return false;
    }
    if (alert == kRealityV2AlertCloseNotify)
    {
        out[0] = 0x01;
        out[1] = 0x00;
        return true;
    }
    if (alert == kRealityV2AlertBadRecordMac)
    {
        out[0] = 0x02;
        out[1] = 0x14;
        return true;
    }
    return false;
}

bool realityV2ParseAlert(const uint8_t *data, uint32_t len, uint8_t *alert)
{
    if (data == NULL || alert == NULL || len != kRealityV2AlertMessageSize)
    {
        return false;
    }
    if (data[0] == 0x01 && data[1] == 0x00)
    {
        *alert = kRealityV2AlertCloseNotify;
        return true;
    }
    if (data[0] == 0x02 && data[1] == 0x14)
    {
        *alert = kRealityV2AlertBadRecordMac;
        return true;
    }
    return false;
}

bool realityV2SequenceAvailable(uint64_t sequence_number)
{
    return sequence_number != UINT64_MAX;
}

bool realityV2AddTlsRecordSequence(uint64_t base, uint64_t reality_sequence, uint64_t *tls_sequence)
{
    if (tls_sequence == NULL || UINT64_MAX - base < reality_sequence)
    {
        return false;
    }
    *tls_sequence = base + reality_sequence;
    return true;
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

bool realityV2BuildRecordAad(const reality_v2_record_descriptor_t *descriptor, uint8_t direction,
                             uint64_t sequence_number, const uint8_t session_id[kRealityV2SessionIdSize],
                             const uint8_t  tls_record_header[kRealityV2TlsRecordHeaderSize],
                             const uint8_t *visible_prefix, uint8_t visible_prefix_len,
                             uint8_t aad[kRealityV2RecordAadMaxSize], size_t *aad_len)
{
    if ((direction != kRealityV2DirectionClientToServer && direction != kRealityV2DirectionServerToClient) ||
        ! realityV2RecordDescriptorIsValid(descriptor) || session_id == NULL || tls_record_header == NULL ||
        (visible_prefix == NULL && visible_prefix_len != 0) || visible_prefix_len != descriptor->visible_prefix_len ||
        aad == NULL || aad_len == NULL || tls_record_header[0] != descriptor->outer_content_type ||
        tls_record_header[1] != 0x03 || tls_record_header[2] != 0x03)
    {
        return false;
    }

    static_assert(sizeof(kRecordDomain) - 1 + 1 + 2 + 1 + 1 + 8 + kRealityV2SessionIdSize +
                          kRealityV2TlsRecordHeaderSize + 1 + kRealityV2MaxVisiblePrefixSize ==
                      kRealityV2RecordAadMaxSize,
                  "Reality v2 maximum record AAD size drifted");

    uint8_t *cursor = aad;
    memoryCopy(cursor, kRecordDomain, sizeof(kRecordDomain) - 1);
    cursor += sizeof(kRecordDomain) - 1;
    *cursor++ = descriptor->record_kind;
    realityV2WriteBe16(cursor, descriptor->tls_version);
    cursor += 2;
    *cursor++ = descriptor->profile.profile_id;
    *cursor++ = direction;
    realityV2WriteBe64(cursor, sequence_number);
    cursor += 8;
    memoryCopy(cursor, session_id, kRealityV2SessionIdSize);
    cursor += kRealityV2SessionIdSize;
    memoryCopy(cursor, tls_record_header, kRealityV2TlsRecordHeaderSize);
    cursor += kRealityV2TlsRecordHeaderSize;
    *cursor++ = visible_prefix_len;
    if (visible_prefix_len != 0)
    {
        memoryCopy(cursor, visible_prefix, visible_prefix_len);
    }
    cursor += visible_prefix_len;
    *aad_len = (size_t) (cursor - aad);
    return true;
}
