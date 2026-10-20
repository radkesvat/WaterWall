#include "modules/lookup.h"
sbuf_t *authenticationserverLookup(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], tunnel_t *t,
                                   line_t *l, const uint8_t *data, uint32_t length, authenticationserver_lookup_t kind,
                                   authenticationserver_encoding_t encoding, const char *operation,
                                   const char *invalid_error)
{
    authenticationserver_tstate_t *ts   = tunnelGetState(t);
    cJSON                         *user = NULL;
    if (kind == kAuthLookupPassword)
    {
        if (length == 0 || length > kAuthenticationServerMaxPasswordLength || memchr(data, 0, length) != NULL)
            return authenticationserverCreateErrorResponseFrame(l, correlation_id, invalid_error);
        char *password = memoryAllocate((size_t) length + 1);
        memoryCopy(password, data, length);
        password[length] = 0;
        user             = usersUserToJsonByPassword(&ts->store.users, password);
        memorySecureZero(password, (size_t) length + 1);
        memoryFree(password);
    }
    else
    {
        uint8_t      digest[SHA256_DIGEST_SIZE];
        const size_t size = kind == kAuthLookupSHA224 ? SHA224_DIGEST_SIZE : SHA256_DIGEST_SIZE;
        bool         valid;
        if (encoding == kAuthLookupHex)
            valid = asciiHexDecodeBytes(data, length, digest, size);
        else if (encoding == kAuthLookupBase64)
            valid = length == BASE64_ENCODE_OUT_SIZE(size) &&
                    wwBase64DecodeCanonical((const char *) data, length, digest, size) == (int) size;
        else
        {
            valid = length == size;
            if (valid)
                memoryCopy(digest, data, size);
        }
        if (! valid)
            return authenticationserverCreateErrorResponseFrame(l, correlation_id, invalid_error);
        user = kind == kAuthLookupSHA224 ? usersUserToJsonBySHA224(&ts->store.users, digest)
                                         : usersUserToJsonBySHA256(&ts->store.users, digest);
    }
    if (user == NULL)
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-not-found");
    return authenticationserverCreateUserJsonResponseFrame(l, correlation_id, user, operation);
}
