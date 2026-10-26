#include "VmessCommon/crypto.h"

#include <openssl/evp.h>

#if (defined(__i386__) || defined(__x86_64__)) && (defined(__GNUC__) || defined(__clang__))
#include <cpuid.h>
#elif defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
#include <intrin.h>
#endif

#if defined(__linux__) && defined(__aarch64__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#elif defined(__APPLE__) && defined(__aarch64__)
#include <sys/sysctl.h>
#endif

/* Xray-core v25.10.15 common/uuid/uuid.go: SHA1(nil UUID || exact ID),
 * then RFC4122 version 5 and variant bits. Encoding checks are WaterWall's
 * configuration contract; no case folding or Unicode normalization occurs. */
wcrypto_status_t vmessNormalizeId(const char *id, size_t length, uint8_t uuid[16])
{
    assert(id != NULL && uuid != NULL);
    memset(uuid, 0, 16);
    if (length == 0 || length > 36 || ! configLexicalCheckEncodingQuiet(id, length))
    {
        return kWCryptoInvalidArgument;
    }
    if (length == 32 || length == 36)
    {
        char text[37];
        memcpy(text, id, length);
        text[length] = '\0';
        bool valid   = wwUuidParseString(text, uuid);
        wCryptoZero(text, sizeof(text));
        if (! valid)
        {
            wCryptoZero(uuid, 16);
        }
        return valid ? kWCryptoOk : kWCryptoInvalidArgument;
    }
    if (length > 30)
    {
        return kWCryptoInvalidArgument;
    }
    uint8_t input[46] = {0};
    uint8_t hash[20]  = {0};
    memcpy(input + 16, id, length);
    unsigned actual = 0;
    bool     ok     = EVP_Digest(input, 16 + length, hash, &actual, EVP_sha1(), NULL) == 1 && actual == sizeof(hash);
    if (ok)
    {
        memcpy(uuid, hash, 16);
        uuid[6] = (uuid[6] & 0x0f) | 0x50;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
    }
    wCryptoZero(input, sizeof(input));
    wCryptoZero(hash, sizeof(hash));
    return ok ? kWCryptoOk : kWCryptoBackendFailed;
}

bool vmessCipherAvailable(uint8_t security)
{
    if (security == VMESS_SECURITY_NONE)
    {
        return true;
    }
    const char *name = security == VMESS_SECURITY_AES128_GCM          ? "AES-128-GCM"
                       : security == VMESS_SECURITY_CHACHA20_POLY1305 ? "CHACHA20-POLY1305"
                                                                      : NULL;
    if (name == NULL)
    {
        return false;
    }
    EVP_CIPHER     *cipher  = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *ctx     = cipher != NULL ? EVP_CIPHER_CTX_new() : NULL;
    const uint8_t   key[32] = {0}, iv[12] = {0};
    bool            ok = ctx != NULL && EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) == 1;
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}

wcrypto_status_t vmessAutoSecuritySelect(bool accelerated_aes, bool aes_available, bool chacha_available,
                                         uint8_t *security)
{
    assert(security != NULL);
    *security = 0;
    if (aes_available && (accelerated_aes || ! chacha_available))
    {
        *security = VMESS_SECURITY_AES128_GCM;
    }
    else if (chacha_available)
    {
        *security = VMESS_SECURITY_CHACHA20_POLY1305;
    }
    return *security != 0 ? kWCryptoOk : kWCryptoUnavailable;
}

static bool acceleratedAes(void)
{
#if (defined(__i386__) || defined(__x86_64__)) && (defined(__GNUC__) || defined(__clang__))
    unsigned a, b, c, d;
    /* AES-NI/PCLMUL use XMM state, whose OS support is baseline on x86-64.
     * On 32-bit targets require OSXSAVE/XCR0 rather than assume enabled XMM. */
    if (! __get_cpuid(1, &a, &b, &c, &d) || (c & bit_AES) == 0 || (c & bit_PCLMUL) == 0)
    {
        return false;
    }
#if defined(__i386__)
    if ((c & bit_OSXSAVE) == 0)
    {
        return false;
    }
    uint32_t xcr_low, xcr_high;
    __asm__ volatile("xgetbv" : "=a"(xcr_low), "=d"(xcr_high) : "c"(0));
    return (xcr_low & 2U) != 0;
#else
    return true;
#endif
#elif defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
    int regs[4];
    __cpuid(regs, 1);
    if ((regs[2] & (1 << 25)) == 0 || (regs[2] & (1 << 1)) == 0)
    {
        return false;
    }
#if defined(_M_IX86)
    return (regs[2] & (1 << 27)) != 0 && (_xgetbv(0) & 2U) != 0;
#else
    return true;
#endif
#elif defined(__linux__) && defined(__aarch64__) && defined(HWCAP_AES) && defined(HWCAP_PMULL)
    unsigned long capabilities = getauxval(AT_HWCAP);
    return (capabilities & (HWCAP_AES | HWCAP_PMULL)) == (HWCAP_AES | HWCAP_PMULL);
#elif defined(__APPLE__) && defined(__aarch64__)
    int    aes = 0, pmull = 0;
    size_t aes_length = sizeof(aes), pmull_length = sizeof(pmull);
    return sysctlbyname("hw.optional.arm.FEAT_AES", &aes, &aes_length, NULL, 0) == 0 && aes != 0 &&
           sysctlbyname("hw.optional.arm.FEAT_PMULL", &pmull, &pmull_length, NULL, 0) == 0 && pmull != 0;
#elif defined(_WIN32) && defined(_M_ARM64) && defined(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE)
    return IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0;
#else
    return false;
#endif
}

wcrypto_status_t vmessAutoSecurity(uint8_t *security)
{
    return vmessAutoSecuritySelect(acceleratedAes(),
                                   vmessCipherAvailable(VMESS_SECURITY_AES128_GCM),
                                   vmessCipherAvailable(VMESS_SECURITY_CHACHA20_POLY1305),
                                   security);
}
