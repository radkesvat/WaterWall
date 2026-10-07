#include "structure.h"

#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/nid.h>
#include <time.h>

typedef struct tlsclient_session_cache_s
{
    SSL_SESSION *sessions[2];
    size_t       ticket_limit;
    int          verify_mode;
    char         server_name[kTlsClientMaxSniLength + 1U];
} tlsclient_session_cache_t;

static int     tlsclientSessionContextIndex   = -1;
static int     tlsclientSessionAdmissionIndex = -1;
static wonce_t tlsclientSessionIndicesOnce    = WONCE_INIT;
static char    tlsclientSessionAdmission;

static void tlsclientSessionCacheClear(tlsclient_session_cache_t *cache)
{
    SSL_SESSION_free(cache->sessions[0]);
    SSL_SESSION_free(cache->sessions[1]);
    cache->sessions[0] = NULL;
    cache->sessions[1] = NULL;
}

static void tlsclientSessionCacheFree(void *parent, void *ptr, CRYPTO_EX_DATA *data, int index, long argl, void *argp)
{
    discard                    parent;
    discard                    data;
    discard                    index;
    discard                    argl;
    discard                    argp;
    tlsclient_session_cache_t *cache = ptr;
    if (cache != NULL)
    {
        tlsclientSessionCacheClear(cache);
        OPENSSL_free(cache);
    }
}

static void tlsclientSessionIndicesInit(void)
{
    tlsclientSessionContextIndex   = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, tlsclientSessionCacheFree);
    tlsclientSessionAdmissionIndex = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
}

static bool tlsclientSessionExpired(const SSL_SESSION *session, time_t now)
{
    if (now < 0)
        return true;
    const uint64_t current = (uint64_t) now;
    const uint64_t created = SSL_SESSION_get_time(session);
    /* Chrome permits one second of clock skew. Subtraction avoids lifetime overflow. */
    return (created > current && created - current > 1U) ||
           (current >= created && current - created >= SSL_SESSION_get_timeout(session));
}

static void tlsclientSessionCacheExpire(tlsclient_session_cache_t *cache)
{
    const time_t now = time(NULL);
    if (cache->sessions[0] != NULL && tlsclientSessionExpired(cache->sessions[0], now))
    {
        tlsclientSessionCacheClear(cache);
    }
    else if (cache->sessions[1] != NULL && tlsclientSessionExpired(cache->sessions[1], now))
    {
        SSL_SESSION_free(cache->sessions[1]);
        cache->sessions[1] = NULL;
    }
}

static bool tlsclientSessionIdentityMatches(const tlsclient_session_cache_t *cache, SSL *ssl)
{
    const char *server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    return server_name != NULL && stringCompare(server_name, cache->server_name) == 0 &&
           SSL_get_verify_mode(ssl) == cache->verify_mode;
}

static bool tlsclientSessionTicketFits(const tlsclient_session_cache_t *cache, const SSL_SESSION *session)
{
    const uint8_t *ticket;
    size_t         ticket_length;
    SSL_SESSION_get0_ticket(session, &ticket, &ticket_length);
    return ticket_length <= cache->ticket_limit;
}

static int tlsclientCacheNewSession(SSL *ssl, SSL_SESSION *session)
{
    if (SSL_get_ex_data(ssl, tlsclientSessionAdmissionIndex) != &tlsclientSessionAdmission)
        return 0;

    tlsclient_session_cache_t *cache  = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), tlsclientSessionContextIndex);
    const SSL_CIPHER          *cipher = SSL_SESSION_get0_cipher(session);
    if (cache == NULL || ! tlsclientSessionIdentityMatches(cache, ssl) || ! SSL_SESSION_is_resumable(session) ||
        ! tlsclientSessionTicketFits(cache, session) || cipher == NULL || SSL_CIPHER_get_kx_nid(cipher) == NID_kx_rsa ||
        (cache->verify_mode != SSL_VERIFY_NONE && SSL_get_verify_result(ssl) != X509_V_OK))
        return 0;

    /* Chrome binds static-RSA sessions to the peer IP. A transform cannot infer
     * that endpoint from mutable routing metadata, so those sessions stay fresh. */
    tlsclientSessionCacheExpire(cache);
    if (cache->sessions[0] != NULL && SSL_SESSION_should_be_single_use(cache->sessions[0]))
    {
        SSL_SESSION_free(cache->sessions[1]);
        cache->sessions[1] = cache->sessions[0];
    }
    else
    {
        SSL_SESSION_free(cache->sessions[0]);
    }
    cache->sessions[0] = session;
    return 1; /* The cache takes the callback's reference. */
}

bool tlsclientConfigureSessionCache(SSL_CTX *ctx, const char *server_name, size_t fresh_hello_wire_length)
{
    assert(ctx != NULL && server_name != NULL && fresh_hello_wire_length > 0);
    const size_t name_length = stringLength(server_name);
    assert(name_length > 0 && name_length <= kTlsClientMaxSniLength);
    wonce(&tlsclientSessionIndicesOnce, tlsclientSessionIndicesInit);
    if (tlsclientSessionContextIndex < 0 || tlsclientSessionAdmissionIndex < 0)
        return false;
    assert(SSL_CTX_get_ex_data(ctx, tlsclientSessionContextIndex) == NULL);

    tlsclient_session_cache_t *cache = OPENSSL_zalloc(sizeof(*cache));
    if (cache == NULL)
        return false;
    /* The worst-case fresh wire image overbounds its extension block. A TLS 1.3
     * PSK adds the ticket plus 15 bytes of framing/age and one binder; TLS 1.2
     * only adds the ticket. Real ECH may add up to 31 bytes when rounding its
     * encoded inner hello to a 32-byte boundary. Leave room in the uint16 extension block, including
     * when custom ALPN or an ECH override already nearly fills it. */
    const size_t psk_overhead = 15U + EVP_MAX_MD_SIZE + 31U;
    cache->ticket_limit =
        fresh_hello_wire_length < UINT16_MAX - psk_overhead ? UINT16_MAX - psk_overhead - fresh_hello_wire_length : 0;
    cache->verify_mode = SSL_CTX_get_verify_mode(ctx);
    memoryCopy(cache->server_name, server_name, name_length + 1U);
    if (! SSL_CTX_set_ex_data(ctx, tlsclientSessionContextIndex, cache))
    {
        OPENSSL_free(cache);
        return false;
    }

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(ctx, tlsclientCacheNewSession);
    return true;
}

bool tlsclientPrepareSession(SSL *ssl)
{
    assert(ssl != NULL && ! SSL_is_init_finished(ssl));
    wonce(&tlsclientSessionIndicesOnce, tlsclientSessionIndicesInit);
    if (tlsclientSessionContextIndex < 0 || tlsclientSessionAdmissionIndex < 0)
        return true;
    tlsclient_session_cache_t *cache = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), tlsclientSessionContextIndex);
    if (cache == NULL || ! tlsclientSessionIdentityMatches(cache, ssl))
        return true;
    if (! SSL_set_ex_data(ssl, tlsclientSessionAdmissionIndex, &tlsclientSessionAdmission))
        return false;

    tlsclientSessionCacheExpire(cache);
    /* At most two candidates: an unusable cached identity falls back to a full handshake. */
    for (size_t attempt = 0; attempt < ARRAY_SIZE(cache->sessions) && cache->sessions[0] != NULL; ++attempt)
    {
        SSL_SESSION *session = cache->sessions[0];
        if (! tlsclientSessionTicketFits(cache, session) || ! tlsclientReverifySession(ssl, session))
        {
            cache->sessions[0] = cache->sessions[1];
            cache->sessions[1] = NULL;
            SSL_SESSION_free(session);
            continue;
        }

        const int configured = SSL_set_session(ssl, session);
        if (SSL_SESSION_should_be_single_use(session))
        {
            /* Consume even if this connection never sends its ClientHello or the peer declines. */
            cache->sessions[0] = cache->sessions[1];
            cache->sessions[1] = NULL;
            SSL_SESSION_free(session);
        }
        return configured == 1;
    }
    return true;
}
