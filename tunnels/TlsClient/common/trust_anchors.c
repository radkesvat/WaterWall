#include "structure.h"

#include "chrome_trust_anchors.h"

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

static int     tlsclientIntermediateIndex = -1;
static wonce_t tlsclientIntermediateOnce  = WONCE_INIT;

static void tlsclientIntermediatesFree(void *parent, void *ptr, CRYPTO_EX_DATA *data, int index, long argl, void *argp)
{
    discard parent;
    discard data;
    discard index;
    discard argl;
    discard argp;
    sk_X509_pop_free(ptr, X509_free);
}

static void tlsclientIntermediateIndexInit(void)
{
    tlsclientIntermediateIndex = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, tlsclientIntermediatesFree);
}

static int tlsclientVerifyWithIntermediateCandidates(X509_STORE_CTX *ctx, STACK_OF(X509) * candidates)
{
    if (candidates == NULL)
        return X509_verify_cert(ctx);

    /* A TAI match permits elision, not trust. Keep every candidate untrusted,
     * and preserve the peer's chain, configured roots, hostname and parameters. */
    STACK_OF(X509) *original = X509_STORE_CTX_get0_untrusted(ctx);
    STACK_OF(X509) *combined = original != NULL ? sk_X509_dup(original) : sk_X509_new_null();
    if (combined == NULL)
    {
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_OUT_OF_MEM);
        return 0;
    }

    for (size_t i = 0; i < sk_X509_num(candidates); ++i)
    {
        if (! sk_X509_push(combined, sk_X509_value(candidates, i)))
        {
            sk_X509_free(combined);
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_OUT_OF_MEM);
            return 0;
        }
    }

    X509_STORE_CTX_set_chain(ctx, combined);
    const int result = X509_verify_cert(ctx);
    X509_STORE_CTX_set_chain(ctx, original);
    /* Only the temporary container is ours. BoringSSL retains references to
     * the selected chain; the SSL_CTX owns the cached candidates. */
    sk_X509_free(combined);
    return result;
}

int tlsclientVerifyCertificateWithIntermediates(X509_STORE_CTX *ctx, void *arg)
{
    assert(ctx != NULL && arg != NULL);
    SSL *ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    assert(ssl != NULL);
    return tlsclientVerifyWithIntermediateCandidates(ctx, SSL_peer_matched_trust_anchor(ssl) ? arg : NULL);
}

bool tlsclientReverifySession(SSL *ssl, const SSL_SESSION *session)
{
    assert(ssl != NULL && session != NULL);
    if (SSL_get_verify_mode(ssl) == SSL_VERIFY_NONE)
        return true;

    /* Resumption omits certificate verification in BoringSSL's X509 path.
     * Probe the cached chain with this connection's current trust and hostname
     * before offering its ticket. A cache miss still gets a full TLS handshake. */
    const STACK_OF(CRYPTO_BUFFER) *encoded = SSL_SESSION_get0_peer_certificates(session);
    if (encoded == NULL || sk_CRYPTO_BUFFER_num(encoded) == 0)
        return false;

    ERR_clear_error();
    bool result                  = false;
    STACK_OF(X509) *peer         = sk_X509_new_null();
    X509_STORE_CTX *verification = X509_STORE_CTX_new();
    if (peer == NULL || verification == NULL)
        goto done;

    for (size_t i = 0; i < sk_CRYPTO_BUFFER_num(encoded); ++i)
    {
        X509 *certificate = X509_parse_from_buffer(sk_CRYPTO_BUFFER_value(encoded, i));
        if (certificate == NULL || ! sk_X509_push(peer, certificate))
        {
            X509_free(certificate);
            goto done;
        }
    }

    SSL_CTX *context = SSL_get_SSL_CTX(ssl);
    if (! X509_STORE_CTX_init(verification, SSL_CTX_get_cert_store(context), sk_X509_value(peer, 0), peer) ||
        ! X509_STORE_CTX_set_ex_data(verification, SSL_get_ex_data_X509_STORE_CTX_idx(), ssl) ||
        ! X509_STORE_CTX_set_default(verification, "ssl_server") ||
        ! X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(verification), SSL_get0_param(ssl)))
        goto done;

    if (SSL_get_verify_callback(ssl) != NULL)
        X509_STORE_CTX_set_verify_cb(verification, SSL_get_verify_callback(ssl));

    STACK_OF(X509) *candidates =
        tlsclientIntermediateIndex >= 0 ? SSL_CTX_get_ex_data(context, tlsclientIntermediateIndex) : NULL;
    /* The stored peer chain may have elided intermediates. The new SSL has no
     * TAI response yet, so restore candidates without treating them as roots. */
    result = tlsclientVerifyWithIntermediateCandidates(verification, candidates) == 1;

done:
    X509_STORE_CTX_free(verification);
    sk_X509_pop_free(peer, X509_free);
    ERR_clear_error();
    return result;
}

bool tlsclientConfigureTrustAnchors(SSL_CTX *ctx)
{
    assert(ctx != NULL);
    if (! SSL_CTX_set1_requested_trust_anchors(ctx, kChromeRequestedTrustAnchors, sizeof(kChromeRequestedTrustAnchors)))
    {
        return false;
    }

    if (SSL_CTX_get_verify_mode(ctx) == SSL_VERIFY_NONE)
    {
        return true;
    }

    wonce(&tlsclientIntermediateOnce, tlsclientIntermediateIndexInit);
    if (tlsclientIntermediateIndex < 0)
    {
        return false;
    }

    STACK_OF(X509) *certificates = SSL_CTX_get_ex_data(ctx, tlsclientIntermediateIndex);
    if (certificates == NULL)
    {
        certificates = sk_X509_new_null();
        if (certificates == NULL)
        {
            return false;
        }

        for (size_t i = 0; i < ARRAY_SIZE(kChromeTrustAnchorIntermediatesPem); ++i)
        {
            BIO  *bio         = BIO_new_mem_buf(kChromeTrustAnchorIntermediatesPem[i], -1);
            X509 *certificate = bio != NULL ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
            BIO_free(bio);
            if (certificate == NULL || ! sk_X509_push(certificates, certificate))
            {
                X509_free(certificate);
                sk_X509_pop_free(certificates, X509_free);
                return false;
            }
        }

        if (! SSL_CTX_set_ex_data(ctx, tlsclientIntermediateIndex, certificates))
        {
            sk_X509_pop_free(certificates, X509_free);
            return false;
        }
    }

    /* SSL_CTX ownership keeps the immutable cache alive for all its SSLs and
     * frees it after synchronous verification callbacks can no longer run. */
    SSL_CTX_set_cert_verify_callback(ctx, tlsclientVerifyCertificateWithIntermediates, certificates);
    return true;
}
