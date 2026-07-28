/*
 * TlsClient line-state initialization failure injection.
 *
 * Every allocation inside tlsclientLinestateInitialize() happens before SSL_set_bio(), so the SSL object does not
 * own the detached BIOs yet and each object has to be released by its own owner. A failure there is per-line: the
 * line state must come back fully zeroed, nothing may leak, and only the previous side may be closed because the
 * next tunnel never received Init.
 *
 * Both callers are covered: the real-line upstream Init and the temporary ClientHello helper.
 */
#include "TlsClient/structure.h"

#include "tunnel_line_failure_harness.h"

// ---------------------------------------------------------------------------
// BoringSSL injection
//
// The symbols carry the BORINGSSL_PREFIX mangling, so the wrappers are spelled out with the prefix; the prefix
// header would rewrite a plain BIO_new into the same name but leaves __wrap_/__real_ identifiers alone.
// ---------------------------------------------------------------------------

typedef enum tlsclient_injection_e
{
    kInjectNothing = 0,
    kInjectFirstBio,
    kInjectSecondBio,
    kInjectSsl,
    kInjectAlps
} tlsclient_injection_t;

static tlsclient_injection_t g_injection = kInjectNothing;
static uint32_t              g_bio_calls = 0;

BIO *__real_WW_BSSL_BIO_new(const BIO_METHOD *method);
BIO *__wrap_WW_BSSL_BIO_new(const BIO_METHOD *method);
SSL *__real_WW_BSSL_SSL_new(SSL_CTX *ctx);
SSL *__wrap_WW_BSSL_SSL_new(SSL_CTX *ctx);
int  __real_WW_BSSL_SSL_add_application_settings(SSL *ssl, const uint8_t *proto, size_t proto_len,
                                                 const uint8_t *settings, size_t settings_len);
int  __wrap_WW_BSSL_SSL_add_application_settings(SSL *ssl, const uint8_t *proto, size_t proto_len,
                                                 const uint8_t *settings, size_t settings_len);

BIO *__wrap_WW_BSSL_BIO_new(const BIO_METHOD *method)
{
    ++g_bio_calls;

    if (g_injection == kInjectFirstBio && g_bio_calls == 1)
    {
        return NULL;
    }
    if (g_injection == kInjectSecondBio && g_bio_calls == 2)
    {
        return NULL;
    }

    return __real_WW_BSSL_BIO_new(method);
}

SSL *__wrap_WW_BSSL_SSL_new(SSL_CTX *ctx)
{
    if (g_injection == kInjectSsl)
    {
        return NULL;
    }
    return __real_WW_BSSL_SSL_new(ctx);
}

int __wrap_WW_BSSL_SSL_add_application_settings(SSL *ssl, const uint8_t *proto, size_t proto_len,
                                                const uint8_t *settings, size_t settings_len)
{
    if (g_injection == kInjectAlps)
    {
        return 0;
    }
    return __real_WW_BSSL_SSL_add_application_settings(ssl, proto, proto_len, settings, settings_len);
}

static void injectionArm(tlsclient_injection_t injection)
{
    g_injection = injection;
    g_bio_calls = 0;
}

static void injectionDisarm(void)
{
    g_injection = kInjectNothing;
    g_bio_calls = 0;
}

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

enum
{
    kTestLargeBufferSize = 8192
};

// Wire-format ALPN offer of a single "h2" protocol, which is what makes the ALPS registration run.
static const uint8_t kAlpnWireH2[] = {0x02, 'h', '2'};

typedef struct tlsclient_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    SSL_CTX         *ssl_ctx;
    SSL_CTX         *ssl_ctx_slot[1];
    tunnel_t        *prev;
    tunnel_t        *tls;
    tunnel_t        *next;
} tlsclient_fixture_t;

static void fixtureSetup(tlsclient_fixture_t *fixture)
{
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->ssl_ctx = SSL_CTX_new(TLS_client_method());
    twfRequire(fixture->ssl_ctx != NULL, "failed to create the TlsClient test SSL_CTX");
    fixture->ssl_ctx_slot[0] = fixture->ssl_ctx;

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->tls  = tunnelCreate(NULL, sizeof(tlsclient_tstate_t), sizeof(tlsclient_lstate_t));
    twfRequire(fixture->tls != NULL, "failed to create the TlsClient tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->prev, fixture->tls);
    tunnelBind(fixture->tls, fixture->next);

    tlsclient_tstate_t *ts       = tunnelGetState(fixture->tls);
    ts->threadlocal_ssl_contexts = fixture->ssl_ctx_slot;
    ts->alpn_wire                = (uint8_t *) (uintptr_t) kAlpnWireH2;
    ts->alpn_wire_len            = sizeof(kAlpnWireH2);
    ts->sni                      = (char *) (uintptr_t) "example.com";
    ts->verbose                  = false;
}

static void fixtureTeardown(tlsclient_fixture_t *fixture)
{
    twfRequireNoLeakedBuffers();
    SSL_CTX_free(fixture->ssl_ctx);
    memoryFree(fixture->prev);
    memoryFree(fixture->tls);
    memoryFree(fixture->next);
}

// ---------------------------------------------------------------------------
// cases
// ---------------------------------------------------------------------------

static void caseRealLineInitFails(tlsclient_injection_t injection, const char *case_name)
{
    twfSetCase(case_name);

    tlsclient_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t        *l             = twfLineCreate(fixture.tls->lstate_size);
    const uint32_t refc_at_start = twfLineRefCount(l);

    injectionArm(injection);
    tlsclientTunnelUpStreamInit(fixture.tls, l);
    injectionDisarm();

    twfRequireEqualText(fixture.trace.seq, "f", "the failing line did not close exactly the previous side");
    twfRequireEqualU32(fixture.trace.next_init, 0, "the next tunnel received Init after the allocation failure");
    twfRequireEqualU32(fixture.trace.next_payload, 0, "a ClientHello escaped after the allocation failure");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "the next tunnel received Finish it never opened");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "the previous side was not finished exactly once");
    twfRequireLineStateZeroed(l, fixture.tls, "the failing TlsClient line state was not zeroed");
    twfRequireEqualU32(twfLineRefCount(l), refc_at_start, "the line reference count did not return to its start");
    twfRequireNoLeakedBuffers();

    twfLineDestroy(l);

    // A second line must still initialize and hand its ClientHello to the next tunnel.
    memoryZero(&fixture.trace, sizeof(fixture.trace));
    line_t *sibling = twfLineCreate(fixture.tls->lstate_size);
    tlsclientTunnelUpStreamInit(fixture.tls, sibling);

    twfRequireEqualU32(fixture.trace.prev_finish, 0, "the sibling line was closed even though nothing failed");
    twfRequireEqualU32(fixture.trace.next_init, 1, "the sibling line did not reach the next tunnel");
    twfRequire(fixture.trace.next_payload_bytes > 0, "the sibling line produced no ClientHello bytes");

    tlsclient_lstate_t *sibling_ls = lineGetState(sibling, fixture.tls);
    tlsclientLinestateDestroy(sibling_ls);
    twfRequireLineStateZeroed(sibling, fixture.tls, "the sibling line state was not zeroed");
    twfLineDestroy(sibling);

    fixtureTeardown(&fixture);
}

static void caseClientHelloHelperFails(tlsclient_injection_t injection, const char *case_name)
{
    twfSetCase(case_name);

    tlsclient_fixture_t fixture;
    fixtureSetup(&fixture);

    sbuf_t *out = (sbuf_t *) (uintptr_t) 0x1; // must be overwritten with NULL by the helper

    injectionArm(injection);
    const bool created = tlsclientCreateClientHelloFromContext(
        fixture.ssl_ctx, "example.com", NULL, 0, kAlpnWireH2, sizeof(kAlpnWireH2), &out);
    injectionDisarm();

    twfRequire(! created, "the temporary ClientHello helper reported success after an allocation failure");
    twfRequire(out == NULL, "the temporary ClientHello helper left a dangling output buffer");
    twfRequireNoLeakedBuffers();

    // The helper must stay usable once the allocator recovers.
    out = NULL;
    twfRequire(tlsclientCreateClientHelloFromContext(
                   fixture.ssl_ctx, "example.com", NULL, 0, kAlpnWireH2, sizeof(kAlpnWireH2), &out),
               "the temporary ClientHello helper stopped working after a failed attempt");
    twfRequire(out != NULL && sbufGetLength(out) > 0, "the temporary ClientHello helper produced no bytes");
    bufferpoolReuseBuffer(fixture.env.pool, out);

    fixtureTeardown(&fixture);
}

int main(void)
{
    caseRealLineInitFails(kInjectFirstBio, "real line: first BIO allocation fails");
    caseRealLineInitFails(kInjectSecondBio, "real line: second BIO allocation fails");
    caseRealLineInitFails(kInjectSsl, "real line: SSL allocation fails");
    caseRealLineInitFails(kInjectAlps, "real line: ALPS registration fails");

    caseClientHelloHelperFails(kInjectFirstBio, "ClientHello helper: first BIO allocation fails");
    caseClientHelloHelperFails(kInjectSsl, "ClientHello helper: SSL allocation fails");
    caseClientHelloHelperFails(kInjectAlps, "ClientHello helper: ALPS registration fails");

    printf("tlsclient_line_failure_test: all cases passed\n");
    return 0;
}
