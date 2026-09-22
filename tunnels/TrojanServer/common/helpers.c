#include "structure.h"

#include "loggers/network_logger.h"

#include "AuthenticationClient/interface.h"

void trojanserverApplyDestinationContext(line_t *l, const address_context_t *target, bool udp)
{
    address_context_t *dest = lineGetDestinationAddressContext(l);

    addresscontextCopy(dest, target);
    addresscontextSetOnlyProtocol(dest, udp ? IP_PROTO_UDP : IP_PROTO_TCP);
}

static const char *trojanserverAuthClientStateName(authenticationclient_state_t state)
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

bool trojanserverAuthenticateHash(tunnel_t *t, line_t *l, const uint8_t sha224[SHA224_DIGEST_SIZE],
                                  user_handle_t *user_handle_out)
{
    trojanserver_tstate_t *ts = tunnelGetState(t);

    assert(user_handle_out != NULL);

    if (ts->auth_client_tunnel == NULL)
    {
        trojanserver_lstate_t     *ls      = lineGetState(l, t);
        const trojanserver_user_t *matched = NULL;

        for (uint32_t i = 0; i < ts->user_count; ++i)
        {
            if (memoryEqual(ts->users[i].sha224, sha224, SHA224_DIGEST_SIZE))
            {
                matched = &ts->users[i];
                break;
            }
        }

        if (UNLIKELY(matched == NULL))
        {
            if (ts->verbose)
            {
                LOGW("TrojanServer: rejected local password authentication on worker %u", (unsigned int) lineGetWID(l));
            }
            return false;
        }

        if (ls->auth_username != NULL)
        {
            memoryFree(ls->auth_username);
        }
        ls->auth_username = matched->username != NULL ? stringDuplicate(matched->username) : NULL;
        if (ls->auth_password != NULL)
        {
            memoryFree(ls->auth_password);
        }
        ls->auth_password = stringDuplicate(matched->password);
        *user_handle_out  = userHandleEmpty();
        return true;
    }

    authenticationclient_state_t auth_state = authenticationclientGetState(ts->auth_client_tunnel);
    if (UNLIKELY(auth_state != kAuthenticationClientStateReady))
    {
        if (ts->verbose)
        {
            LOGW("TrojanServer: authentication unavailable on worker %u: %s",
                 (unsigned int) lineGetWID(l),
                 trojanserverAuthClientStateName(auth_state));
        }
        return false;
    }

    user_handle_t                       handle  = userHandleEmpty();
    authenticationclient_user_profile_t profile = {0};
    if (UNLIKELY(! authenticationclientGetUserBySHA224WithProfile(ts->auth_client_tunnel, sha224, &handle, &profile)))
    {
        if (ts->verbose)
        {
            LOGW("TrojanServer: rejected authentication on worker %u", (unsigned int) lineGetWID(l));
        }
        return false;
    }

    // Resolve the account name/password in the same locked lookup that produced
    // the handle and keep them on the line state so a downstream Router can match
    // by username/password without re-querying the auth client. Ownership of the
    // duplicated strings is transferred from the profile to the line state.
    trojanserver_lstate_t *ls = lineGetState(l, t);
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

    *user_handle_out = handle;
    return true;
}

void trojanserverRecordLineUser(line_t *l, trojanserver_lstate_t *ls, const user_handle_t *user_handle)
{
    if (UNLIKELY(ls->user_handle_recorded))
    {
        return;
    }

    if (userHandleIsValid(user_handle))
    {
        lineAddUser(l, user_handle, ls->auth_username, ls->auth_password);
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

tunnel_t *trojanserverSelectedUpstream(tunnel_t *t, const trojanserver_lstate_t *ls)
{
    trojanserver_tstate_t *ts = tunnelGetState(t);

    if (ls->branch == kTrojanServerBranchFallback)
    {
        return ts->fallback_tunnel;
    }

    return NULL;
}

bool trojanserverQueuePayload(buffer_queue_t *queue, sbuf_t **buf)
{
    return sbufGetLength(*buf) <= kTrojanServerMaxPendingBytes - bufferqueueGetBufLen(queue) &&
           bufferqueueGetBufCount(queue) < kTrojanServerMaxQueuedBuffers && bufferqueueTryPushBack(queue, buf);
}
