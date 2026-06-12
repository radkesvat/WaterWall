#include "structure.h"

#include "loggers/network_logger.h"

#if defined(OS_LINUX)
#include <errno.h>
#include <sys/syscall.h>

#if defined(SYS_getrandom)
#define AUTHENTICATIONSERVER_SYS_GETRANDOM SYS_getrandom
#elif defined(__NR_getrandom)
#define AUTHENTICATIONSERVER_SYS_GETRANDOM __NR_getrandom
#endif
#endif

#if defined(OS_WIN)
#include <limits.h>
#include <windows.h>
#endif

#if defined(OS_UNIX)
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#if defined(OS_DARWIN) || defined(OS_BSD)
#include <stdlib.h>
#endif

#if defined(OS_LINUX) && defined(AUTHENTICATIONSERVER_SYS_GETRANDOM)
static bool authenticationserverRandomBytesGetrandom(uint8_t *dest, size_t len)
{
    size_t offset = 0;
    while (offset < len)
    {
        ssize_t nread = (ssize_t) syscall(AUTHENTICATIONSERVER_SYS_GETRANDOM, dest + offset, len - offset, 0);
        if (nread < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            break;
        }
        if (nread == 0)
        {
            break;
        }
        offset += (size_t) nread;
    }
    return offset == len;
}
#endif

#if defined(OS_WIN)
static bool authenticationserverRandomBytesWindows(uint8_t *dest, size_t len)
{
    typedef LONG(WINAPI * authenticationserver_bcrypt_gen_random_fn)(void *, unsigned char *, ULONG, ULONG);
    enum
    {
        kAuthenticationServerBcryptUseSystemPreferredRng = 0x00000002UL
    };

    HMODULE bcrypt = LoadLibraryA("bcrypt.dll");
    if (bcrypt == NULL)
    {
        return false;
    }

    authenticationserver_bcrypt_gen_random_fn gen_random =
        (authenticationserver_bcrypt_gen_random_fn) (void *) GetProcAddress(bcrypt, "BCryptGenRandom");
    if (gen_random == NULL)
    {
        FreeLibrary(bcrypt);
        return false;
    }

    size_t offset = 0;
    bool   ok     = true;
    while (offset < len)
    {
        const size_t remaining = len - offset;
        const ULONG  chunk     = remaining > (size_t) ULONG_MAX ? ULONG_MAX : (ULONG) remaining;

        if (gen_random(NULL, dest + offset, chunk, kAuthenticationServerBcryptUseSystemPreferredRng) < 0)
        {
            ok = false;
            break;
        }
        offset += chunk;
    }

    FreeLibrary(bcrypt);
    return ok;
}
#endif

#if defined(OS_UNIX) && ! (defined(OS_DARWIN) || defined(OS_BSD))
static bool authenticationserverRandomBytesUrandom(uint8_t *dest, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        return false;
    }

    size_t offset = 0;
    while (offset < len)
    {
        ssize_t nread = read(fd, dest + offset, len - offset);
        if (nread < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            break;
        }
        if (nread == 0)
        {
            break;
        }
        offset += (size_t) nread;
    }

    discard close(fd);
    return offset == len;
}
#endif

static bool authenticationserverRandomBytes(uint8_t *dest, size_t len)
{
#if defined(OS_LINUX) && defined(AUTHENTICATIONSERVER_SYS_GETRANDOM)
    if (authenticationserverRandomBytesGetrandom(dest, len))
    {
        return true;
    }
#endif

#if defined(OS_DARWIN) || defined(OS_BSD)
    arc4random_buf(dest, len);
    return true;
#elif defined(OS_WIN)
    return authenticationserverRandomBytesWindows(dest, len);
#elif defined(OS_UNIX)
    return authenticationserverRandomBytesUrandom(dest, len);
#else
    discard dest;
    discard len;
    return false;
#endif
}

static void authenticationserverBytesToHex(const uint8_t *src, size_t src_len, uint8_t *hex)
{
    static const uint8_t digits[] = "0123456789abcdef";

    for (size_t i = 0; i < src_len; ++i)
    {
        hex[i * 2U]      = digits[src[i] >> 4U];
        hex[i * 2U + 1U] = digits[src[i] & 0x0FU];
    }
}

static bool authenticationserverTokenIsZero(const uint8_t token[kAuthenticationServerSessionTokenSize])
{
    uint8_t zero[kAuthenticationServerSessionTokenSize] = {0};

    return wCryptoEqual(token, zero, sizeof(zero));
}

static void authenticationserverSessionDestroyFields(authenticationserver_session_t *session)
{
    if (session == NULL)
    {
        return;
    }

    usersDestroy(&session->baseline_users);
    memoryFree(session->client_name);
    wCryptoZero(session->token, sizeof(session->token));
    memoryZero(session, sizeof(*session));
}

static void authenticationserverSessionFree(authenticationserver_session_t *session)
{
    if (session == NULL)
    {
        return;
    }

    authenticationserverSessionDestroyFields(session);
    memoryFree(session);
}

bool authenticationserverCopyUsersTable(users_t *dest, const users_t *src)
{
    cJSON *json = usersToJson(src);
    if (json == NULL)
    {
        return false;
    }

    bool ok = usersClear(dest) && usersFeedJson(dest, json);
    cJSON_Delete(json);
    return ok;
}

bool authenticationserverSessionReplaceBaselineFromUsers(authenticationserver_session_t *session, const users_t *src,
                                                         uint64_t config_revision, uint64_t stats_revision)
{
    if (session == NULL || src == NULL)
    {
        return false;
    }

    if (! authenticationserverCopyUsersTable(&session->baseline_users, src))
    {
        return false;
    }

    session->baseline_config_revision = config_revision;
    session->baseline_stats_revision  = stats_revision;
    return true;
}

static const authenticationserver_auth_client_t *authenticationserverFindAuthClient(
    const authenticationserver_tstate_t *ts, const char *name, const char *secret)
{
    if (name == NULL || secret == NULL)
    {
        return NULL;
    }

    for (uint32_t i = 0; i < ts->auth_clients_count; ++i)
    {
        const authenticationserver_auth_client_t *client = &ts->auth_clients[i];

        if (stringCompare(client->name, name) != 0)
        {
            continue;
        }

        size_t expected_len = stringLength(client->secret);
        size_t actual_len   = stringLength(secret);
        if (expected_len == actual_len && wCryptoEqual(client->secret, secret, expected_len))
        {
            return client;
        }
    }

    return NULL;
}

authenticationserver_session_t *authenticationserverSessionFindByTokenLocked(
    tunnel_t *t, const uint8_t token[kAuthenticationServerSessionTokenSize])
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    if (token == NULL || authenticationserverTokenIsZero(token))
    {
        return NULL;
    }

    for (uint32_t i = 0; i < ts->sessions_count; ++i)
    {
        authenticationserver_session_t *session = ts->sessions[i];
        if (session != NULL && wCryptoEqual(session->token, token, kAuthenticationServerSessionTokenSize))
        {
            return session;
        }
    }

    return NULL;
}

static bool authenticationserverGenerateUniqueToken(tunnel_t *t, uint8_t token[kAuthenticationServerSessionTokenSize])
{
    uint8_t raw[kAuthenticationServerSessionTokenSize / 2U];

    for (uint32_t attempt = 0; attempt < 16U; ++attempt)
    {
        if (! authenticationserverRandomBytes(raw, sizeof(raw)))
        {
            wCryptoZero(raw, sizeof(raw));
            return false;
        }

        authenticationserverBytesToHex(raw, sizeof(raw), token);
        if (authenticationserverSessionFindByTokenLocked(t, token) == NULL)
        {
            wCryptoZero(raw, sizeof(raw));
            return true;
        }
    }

    wCryptoZero(raw, sizeof(raw));
    return false;
}

static bool authenticationserverEnsureSessionCapacity(authenticationserver_tstate_t *ts)
{
    if (ts->sessions_count < ts->sessions_capacity)
    {
        return true;
    }

    uint32_t                         new_capacity = ts->sessions_capacity == 0 ? 4U : ts->sessions_capacity * 2U;
    authenticationserver_session_t **new_sessions =
        memoryReAllocate(ts->sessions, sizeof(*new_sessions) * (size_t) new_capacity);
    if (new_sessions == NULL)
    {
        return false;
    }

    memorySet(&new_sessions[ts->sessions_capacity],
              0,
              sizeof(*new_sessions) * (size_t) (new_capacity - ts->sessions_capacity));
    ts->sessions          = new_sessions;
    ts->sessions_capacity = new_capacity;
    return true;
}

static void authenticationserverSessionsRemoveClientLocked(authenticationserver_tstate_t *ts, const char *client_name);

authenticationserver_session_t *authenticationserverSessionCreate(tunnel_t *t, const char *name, const char *secret)
{
    authenticationserver_tstate_t            *ts     = tunnelGetState(t);
    const authenticationserver_auth_client_t *client = authenticationserverFindAuthClient(ts, name, secret);

    if (client == NULL)
    {
        return NULL;
    }

    authenticationserverSessionsRemoveClientLocked(ts, client->name);

    if (! authenticationserverEnsureSessionCapacity(ts))
    {
        return NULL;
    }

    authenticationserver_session_t *session = memoryAllocateZero(sizeof(*session));
    if (session == NULL)
    {
        return NULL;
    }

    if (! usersCreate(&session->baseline_users))
    {
        memoryFree(session);
        return NULL;
    }

    if (! authenticationserverGenerateUniqueToken(t, session->token))
    {
        authenticationserverSessionFree(session);
        return NULL;
    }

    session->client_name = stringDuplicate(client->name);
    if (session->client_name == NULL)
    {
        authenticationserverSessionFree(session);
        return NULL;
    }

    session->allow_stats_push        = client->allow_stats_push;
    session->allow_user_pull         = client->allow_user_pull;
    session->allow_user_write        = client->allow_user_write;
    session->session_idle_timeout_ms = client->session_idle_timeout_ms;
    session->last_activity_ms        = getTickMS();

    if (! authenticationserverSessionReplaceBaselineFromUsers(
            session, &ts->store.users, ts->store.config_revision, ts->store.stats_revision))
    {
        authenticationserverSessionFree(session);
        return NULL;
    }

    ts->sessions[ts->sessions_count] = session;
    ts->sessions_count += 1U;
    LOGI("AuthenticationServer: authenticated auth client \"%s\"", client->name);
    return session;
}

void authenticationserverSessionTouch(authenticationserver_session_t *session, uint32_t now_ms)
{
    if (session != NULL)
    {
        session->last_activity_ms = now_ms;
    }
}

static void authenticationserverSessionRemoveAtLocked(authenticationserver_tstate_t *ts, uint32_t index)
{
    assert(ts != NULL);
    assert(index < ts->sessions_count);

    authenticationserverSessionFree(ts->sessions[index]);

    const uint32_t last_index = ts->sessions_count - 1U;
    if (index < last_index)
    {
        memoryMove(
            &ts->sessions[index], &ts->sessions[index + 1U], sizeof(*ts->sessions) * (size_t) (last_index - index));
    }

    ts->sessions_count               = last_index;
    ts->sessions[ts->sessions_count] = NULL;
}

static void authenticationserverSessionsRemoveClientLocked(authenticationserver_tstate_t *ts, const char *client_name)
{
    if (client_name == NULL)
    {
        return;
    }

    uint32_t removed_count = 0;
    for (uint32_t i = 0; i < ts->sessions_count;)
    {
        authenticationserver_session_t *session = ts->sessions[i];
        if (session != NULL && session->client_name != NULL && stringCompare(session->client_name, client_name) == 0)
        {
            authenticationserverSessionRemoveAtLocked(ts, i);
            ++removed_count;
            continue;
        }
        ++i;
    }

    if (removed_count > 0)
    {
        LOGD("AuthenticationServer: removed %u previous session(s) for auth client \"%s\"",
             (unsigned int) removed_count,
             client_name);
    }
}

void authenticationserverSessionsExpireIdle(tunnel_t *t)
{
    authenticationserver_tstate_t *ts            = tunnelGetState(t);
    const uint32_t                 now_ms        = getTickMS();
    uint32_t                       expired_count = 0;

    recursivemutexLock(&ts->database_mutex);
    for (uint32_t i = 0; i < ts->sessions_count;)
    {
        authenticationserver_session_t *session = ts->sessions[i];
        if (session == NULL)
        {
            authenticationserverSessionRemoveAtLocked(ts, i);
            continue;
        }

        const uint32_t idle_ms = now_ms - session->last_activity_ms;

        if (idle_ms < session->session_idle_timeout_ms)
        {
            ++i;
            continue;
        }

        LOGI("AuthenticationServer: deauthenticated inactive auth client \"%s\" after %u ms idle",
             session->client_name != NULL ? session->client_name : "",
             (unsigned int) idle_ms);
        authenticationserverSessionRemoveAtLocked(ts, i);
        ++expired_count;
    }
    recursivemutexUnlock(&ts->database_mutex);

    if (expired_count > 0)
    {
        LOGD("AuthenticationServer: expired %u inactive session(s)", (unsigned int) expired_count);
    }
}

void authenticationserverSessionExpiryTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (t == NULL || isApplicationTerminating())
    {
        return;
    }

    authenticationserverSessionsExpireIdle(t);
}

void authenticationserverSessionsDestroy(authenticationserver_tstate_t *ts)
{
    if (ts == NULL || ts->sessions == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < ts->sessions_count; ++i)
    {
        authenticationserverSessionFree(ts->sessions[i]);
        ts->sessions[i] = NULL;
    }

    memoryFree(ts->sessions);
    ts->sessions          = NULL;
    ts->sessions_count    = 0;
    ts->sessions_capacity = 0;
}

void authenticationserverAuthClientsDestroy(authenticationserver_tstate_t *ts)
{
    if (ts == NULL || ts->auth_clients == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < ts->auth_clients_count; ++i)
    {
        authenticationserver_auth_client_t *client = &ts->auth_clients[i];
        memoryFree(client->name);
        if (client->secret != NULL)
        {
            wCryptoZero(client->secret, stringLength(client->secret));
        }
        memoryFree(client->secret);
        memoryZero(client, sizeof(*client));
    }

    memoryFree(ts->auth_clients);
    ts->auth_clients       = NULL;
    ts->auth_clients_count = 0;
}
