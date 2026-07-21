#include "wcrypto.h"

const char *wCryptoStatusString(wcrypto_status_t status)
{
    switch (status)
    {
    case kWCryptoOk:
        return "success";
    case kWCryptoInvalidArgument:
        return "invalid argument";
    case kWCryptoAuthenticationFailed:
        return "authentication failed";
    case kWCryptoUnavailable:
        return "algorithm unavailable";
    case kWCryptoInputTooLarge:
        return "input too large";
    case kWCryptoInvalidState:
        return "invalid crypto state";
    case kWCryptoRejectedKey:
        return "rejected key";
    case kWCryptoBackendFailed:
        return "crypto backend failed";
    default:
        return "unknown crypto status";
    }
}
