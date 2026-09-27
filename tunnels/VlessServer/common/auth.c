#include "internal.h"

#include "AuthenticationClient/interface.h"
#include "loggers/network_logger.h"

static const char *vlessserverAuthClientStateName(authenticationclient_state_t state)
{
    switch (state)
    {
    case kAuthenticationClientStateStopped:
        return "authentication client stopped";
    case kAuthenticationClientStateConnecting:
        return "authentication client connecting";
    case kAuthenticationClientStateAuthenticating:
        return "authentication client not authenticated";
    case kAuthenticationClientStateReady:
        return "authentication client ready";
    default:
        return "authentication client state unknown";
    }
}

static const vlessserver_user_t *vlessserverFindLocalUser(tunnel_t *t, line_t *l,
                                                          const uint8_t uuid[kVlessServerUuidLen])
{
    vlessserver_tstate_t     *ts      = tunnelGetState(t);
    const vlessserver_user_t *matched = NULL;

    for (uint32_t i = 0; i < ts->user_count; ++i)
    {
        if (memoryEqual(ts->users[i].uuid, uuid, kVlessServerUuidLen))
        {
            matched = &ts->users[i];
            break;
        }
    }

    if (UNLIKELY(matched == NULL && ts->verbose))
    {
        LOGW("VlessServer: rejected unknown UUID on worker %u", (unsigned int) lineGetWID(l));
    }

    return matched;
}

vlessserver_auth_result_t vlessserverAuthenticateUuid(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls,
                                                      const uint8_t uuid[kVlessServerUuidLen])
{
    vlessserver_tstate_t *ts = tunnelGetState(t);

    if (ts->auth_client_tunnel == NULL)
    {
        const vlessserver_user_t *matched = vlessserverFindLocalUser(t, l, uuid);
        if (matched == NULL)
        {
            return kVlessServerAuthRejected;
        }

        /* Acquire the whole local identity before publishing its cache marker. */
        char uuid_password[kVlessServerCanonicalUuidStringLen + 1U] = {0};
        wwUuidToCanonicalString(uuid, uuid_password);
        char *name_copy     = matched->username != NULL ? stringDuplicate(matched->username) : NULL;
        char *password_copy = stringDuplicate(uuid_password);
        memoryZero(uuid_password, sizeof(uuid_password));
        if ((matched->username != NULL && name_copy == NULL) || password_copy == NULL)
        {
            memoryFree(name_copy);
            memoryFree(password_copy);
            return kVlessServerAuthResourceFailure;
        }
        memoryFree(ls->auth_username);
        memoryFree(ls->auth_password);
        ls->auth_username = name_copy;
        ls->auth_password = password_copy;
        return kVlessServerAuthAccepted;
    }

    if (userHandleIsValid(&ls->user_handle))
    {
        return kVlessServerAuthAccepted;
    }

    authenticationclient_state_t auth_state = authenticationclientGetState(ts->auth_client_tunnel);
    if (UNLIKELY(auth_state != kAuthenticationClientStateReady))
    {
        if (ts->verbose)
        {
            LOGW("VlessServer: authentication unavailable on worker %u: %s",
                 (unsigned int) lineGetWID(l),
                 vlessserverAuthClientStateName(auth_state));
        }
        return kVlessServerAuthRejected;
    }

    user_handle_t                             handle  = userHandleEmpty();
    authenticationclient_user_profile_t       profile = {0};
    authenticationclient_user_lookup_result_t result =
        authenticationclientGetUserByUUIDWithProfile(ts->auth_client_tunnel, uuid, &handle, &profile);

    if (UNLIKELY(result != kAuthenticationClientUserLookupOk))
    {
        if (ts->verbose)
        {
            LOGW("VlessServer: rejected UUID authentication on worker %u: %s",
                 (unsigned int) lineGetWID(l),
                 authenticationclientUserLookupResultString(result));
        }
        return kVlessServerAuthRejected;
    }

    // Keep the resolved account name/password (from the same locked lookup) on the
    // line state so a downstream Router can match by username/password. Ownership
    // of the duplicated strings is transferred from the profile to the line state.
    if (ls->auth_username != NULL)
    {
        memoryFree(ls->auth_username);
    }
    ls->auth_username = profile.name;
    if (ls->auth_password != NULL)
    {
        memoryFree(ls->auth_password);
    }
    ls->auth_password = profile.password;

    ls->user_handle = handle;
    return kVlessServerAuthAccepted;
}

bool vlessserverLineAuthenticated(const vlessserver_lstate_t *ls)
{
    return userHandleIsValid(&ls->user_handle) || ls->auth_password != NULL;
}

void vlessserverRecordLineUser(line_t *l, vlessserver_lstate_t *ls)
{
    if (UNLIKELY(ls->user_handle_recorded))
    {
        return;
    }

    if (userHandleIsValid(&ls->user_handle))
    {
        lineAddUser(l, &ls->user_handle, ls->auth_username, ls->auth_password);
    }
    else if (ls->auth_username != NULL || ls->auth_password != NULL)
    {
        lineAddAuthenticatedCredentials(l, ls->auth_username, ls->auth_password);
    }
    else
    {
        return;
    }

    ls->user_handle_recorded = true;
}
