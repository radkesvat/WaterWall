#include "internal.h"

#include "AuthenticationClient/interface.h"
#include "loggers/network_logger.h"

static bool socks5serverFieldHasNul(const uint8_t *field, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        if (field[i] == '\0')
        {
            return true;
        }
    }
    return false;
}

static const char *socks5serverAuthClientStateName(authenticationclient_state_t state)
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

static void socks5serverSanitizeUsername(const uint8_t *username, uint8_t username_len, char out[UINT8_MAX + 1U])
{
    if (username == NULL || username_len == 0)
    {
        out[0] = '\0';
        return;
    }

    for (uint8_t i = 0; i < username_len; ++i)
    {
        uint8_t ch = username[i];
        out[i]     = (ch >= 0x20U && ch <= 0x7EU && ch != '"') ? (char) ch : '?';
    }
    out[username_len] = '\0';
}

void socks5serverLogAuthRejected(tunnel_t *t, line_t *l, const uint8_t *username, uint8_t username_len,
                                 const char *reason)
{
    socks5server_tstate_t *ts = tunnelGetState(t);

    if (ts->verbose && username != NULL && username_len > 0)
    {
        char username_text[UINT8_MAX + 1U];
        socks5serverSanitizeUsername(username, username_len, username_text);
        LOGW("Socks5Server: rejected SOCKS5 authentication for user \"%s\" on worker %d: %s",
             username_text,
             workerWIDForLog(l != NULL ? lineGetWID(l) : getWID()),
             reason != NULL ? reason : "unknown");
        return;
    }

    LOGW("Socks5Server: rejected SOCKS5 authentication: %s", reason != NULL ? reason : "unknown");
}

bool socks5serverAuthUserFromClient(tunnel_t *t, line_t *l, const uint8_t *username, uint8_t username_len,
                                    const uint8_t *password, uint8_t password_len, user_handle_t *user_handle_out)
{
    socks5server_tstate_t *ts            = tunnelGetState(t);
    size_t                 username_size = username_len;
    size_t                 password_size = password_len;
    assert(user_handle_out != NULL);
    if (username_len == 0)
    {
        socks5serverLogAuthRejected(t, l, NULL, 0, "empty username");
        return false;
    }
    if (password_len == 0)
    {
        socks5serverLogAuthRejected(t, l, username, username_len, "empty password");
        return false;
    }
    if (ts->auth_client_tunnel == NULL)
    {
        socks5serverLogAuthRejected(t, l, username, username_len, "authentication client unavailable");
        return false;
    }
    if (socks5serverFieldHasNul(username, username_size))
    {
        socks5serverLogAuthRejected(t, l, username, username_len, "username contains NUL byte");
        return false;
    }
    if (socks5serverFieldHasNul(password, password_size))
    {
        socks5serverLogAuthRejected(t, l, username, username_len, "password contains NUL byte");
        return false;
    }

    authenticationclient_state_t auth_state = authenticationclientGetState(ts->auth_client_tunnel);
    if (auth_state != kAuthenticationClientStateReady)
    {
        socks5serverLogAuthRejected(t, l, username, username_len, socks5serverAuthClientStateName(auth_state));
        return false;
    }

    char auth_password_buf[(UINT8_MAX * 2U) + 2U] = {0};
    memoryCopy(auth_password_buf, username, username_size);
    auth_password_buf[username_size] = ':';
    memoryCopy(auth_password_buf + username_size + 1U, password, password_size);

    user_handle_t                             handle = userHandleEmpty();
    authenticationclient_user_lookup_result_t result =
        authenticationclientGetUserByPasswordWithResult(ts->auth_client_tunnel, auth_password_buf, &handle);
    memoryZero(auth_password_buf, sizeof(auth_password_buf));

    if (result == kAuthenticationClientUserLookupOk)
    {
        *user_handle_out = handle;
        return true;
    }

    socks5serverLogAuthRejected(t, l, username, username_len, authenticationclientUserLookupResultString(result));
    return false;
}

bool socks5serverStoreAuthCredentials(socks5server_lstate_t *ls, const uint8_t *username, uint8_t username_len,
                                      const uint8_t *password, uint8_t password_len)
{
    char *new_username = memoryAllocate((size_t) username_len + 1U);
    char *new_password = memoryAllocate((size_t) password_len + 1U);
    if (UNLIKELY(new_username == NULL || new_password == NULL))
    {
        memoryFree(new_username);
        memoryFree(new_password);
        return false;
    }

    if (username_len > 0)
    {
        memoryCopy(new_username, username, username_len);
    }
    new_username[username_len] = '\0';

    if (password_len > 0)
    {
        memoryCopy(new_password, password, password_len);
    }
    new_password[password_len] = '\0';

    memoryFree(ls->auth_username);
    memoryFree(ls->auth_password);
    ls->auth_username = new_username;
    ls->auth_password = new_password;
    return true;
}

void socks5serverRecordLineUser(line_t *l, socks5server_lstate_t *ls, const user_handle_t *user_handle)
{
    if (ls->user_handle_recorded)
    {
        return;
    }

    lineAddUser(l, user_handle, ls->auth_username, ls->auth_password);
    ls->user_handle_recorded = true;
}

void socks5serverAssocEntryFreeCreds(socks5server_assoc_entry_t *entry)
{
    if (entry->auth_username != NULL)
    {
        memoryFree(entry->auth_username);
        entry->auth_username = NULL;
    }
    if (entry->auth_password != NULL)
    {
        memoryFree(entry->auth_password);
        entry->auth_password = NULL;
    }
}
