#include "ntp.h"

enum
{
    kNtpPacketLen              = 48,
    kNtpModeClient             = 3,
    kNtpTransmitSecondsOffset  = 40,
    kNtpTransmitFractionOffset = 44,
};

static const uint64_t kNtpUnixToNtpEpochDelta = 2208988800ULL;

static void junkdatagramsenderNtpWriteU32At(uint8_t *out, uint32_t offset, uint32_t value)
{
    uint32_t network_value = htobe32(value);
    memoryCopy(out + offset, &network_value, sizeof(network_value));
}

static uint32_t junkdatagramsenderNtpFractionFromNanoseconds(uint32_t nanoseconds)
{
    return (uint32_t) (((uint64_t) nanoseconds << 32) / 1000000000ULL);
}

static uint8_t junkdatagramsenderNtpRandomVersion(void)
{
    return (fastRand32() % 100U) < 85U ? 4 : 3;
}

static uint8_t junkdatagramsenderNtpRandomPoll(void)
{
    static const uint8_t polls[] = {4, 6, 8, 10};
    return polls[fastRand32() % (sizeof(polls) / sizeof(polls[0]))];
}

static int8_t junkdatagramsenderNtpRandomPrecision(void)
{
    static const int8_t precisions[] = {-18, -19, -20, -21, -22, -24};
    return precisions[fastRand32() % (sizeof(precisions) / sizeof(precisions[0]))];
}

static bool junkdatagramsenderNtpBuildClientRequest(sbuf_t *buf, uint8_t version, uint8_t poll, int8_t precision,
                                                    bool set_transmit_timestamp, uint64_t unix_seconds,
                                                    uint32_t nanoseconds)
{
    if (version < 3 || version > 4 || nanoseconds >= 1000000000UL || sbufGetMaximumWriteableSize(buf) < kNtpPacketLen)
    {
        return false;
    }

    sbufSetLength(buf, kNtpPacketLen);
    uint8_t *out = sbufGetMutablePtr(buf);
    memoryZero(out, kNtpPacketLen);

    out[0] = (uint8_t) (((version & 0x07U) << 3) | kNtpModeClient);
    out[1] = 0;
    out[2] = poll;
    out[3] = (uint8_t) precision;

    if (set_transmit_timestamp)
    {
        uint64_t ntp_seconds_64 = unix_seconds + kNtpUnixToNtpEpochDelta;
        uint32_t ntp_seconds    = (uint32_t) (ntp_seconds_64 & UINT32_MAX);
        uint32_t ntp_fraction   = junkdatagramsenderNtpFractionFromNanoseconds(nanoseconds);

        junkdatagramsenderNtpWriteU32At(out, kNtpTransmitSecondsOffset, ntp_seconds);
        junkdatagramsenderNtpWriteU32At(out, kNtpTransmitFractionOffset, ntp_fraction);
    }

    return true;
}

bool junkdatagramsenderNtpGenerate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    discard args;

    struct timeval tv;
    getTimeOfDay(&tv, NULL);

    uint64_t unix_seconds = (uint64_t) tv.tv_sec;
    uint32_t nanoseconds  = (uint32_t) tv.tv_usec * 1000U;

    if ((fastRand32() % 100U) < 35U)
    {
        unix_seconds += fastRand32() % 5U;
        nanoseconds = fastRand32() % 1000000000U;
    }

    sbufSetLength(buf, 0);
    return junkdatagramsenderNtpBuildClientRequest(buf,
                                                   junkdatagramsenderNtpRandomVersion(),
                                                   junkdatagramsenderNtpRandomPoll(),
                                                   junkdatagramsenderNtpRandomPrecision(),
                                                   (fastRand32() % 100U) < 90U,
                                                   unix_seconds,
                                                   nanoseconds);
}
