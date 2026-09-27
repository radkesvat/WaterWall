#include "AuthenticationClient/interface.h"
#include "internal.h"

hps_auth_result_t hpsEvaluateAuth(const hps_tstate_t *ts, const char *credentials, char username[256],
                                  char password[256], char key[512], user_handle_t *identity)
{
    assert(ts->auth_mode != kHpsAuthNone);
    if (! hpsDecodeBasic(credentials, username, password, key))
        return kHpsAuthDenied;
    if (ts->auth_mode == kHpsAuthLocal)
    {
        for (size_t i = 0; i < ts->user_count; ++i)
            if (! stringCompare(username, ts->users[i].username) && ! stringCompare(password, ts->users[i].password))
                return kHpsAuthAccepted;
        return kHpsAuthDenied;
    }
    if (! authenticationclientIsReady(ts->auth))
        return kHpsAuthUnavailable;

    authenticationclient_user_lookup_result_t result =
        authenticationclientGetUserByPasswordWithResult(ts->auth, key, identity);
    switch (result)
    {
    case kAuthenticationClientUserLookupOk:
        return kHpsAuthAccepted;
    case kAuthenticationClientUserLookupUsersUnavailable:
        return kHpsAuthUnavailable;
    case kAuthenticationClientUserLookupUserNotFound:
    case kAuthenticationClientUserLookupPasswordMismatch:
    case kAuthenticationClientUserLookupUserDisabled:
    case kAuthenticationClientUserLookupUserExpired:
    case kAuthenticationClientUserLookupUserLimitReached:
    case kAuthenticationClientUserLookupUserIdRequired:
        return kHpsAuthDenied;
    case kAuthenticationClientUserLookupInvalidArgument:
    case kAuthenticationClientUserLookupHashFailed:
    default:
        return kHpsAuthInternalFailure;
    }
}
