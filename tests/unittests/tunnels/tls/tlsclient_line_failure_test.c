/*
 * Covers: tlsclient line failure; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseRealLineInitFails, caseClientHelloHelperFails, caseInnerClientHelloFailureReleasesRuntimeBios
 * Checks: Assertion labels include: the failing line did not close exactly the previous side; the next
 * tunnel received Finish it never opened; the previous side was not finished exactly once; the failing
 * TlsClient line state was not zeroed
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tlsclient_line_failure_unit
 */
/*
 * TlsClient line-state initialization failure injection.
 *
 * The three SSL/BIO object allocations precede SSL_set_bio(), so partial allocation failure releases the
 * detached objects individually. Later configuration and ECH-inner failures release the BIOs through SSL.
 * Each failure is per-line: state must return fully zeroed, nothing may leak, and only the previous side
 * may be closed because the next tunnel never received Init.
 *
 * Both callers are covered: the real-line upstream Init and the temporary ClientHello helper.
 */
#include "TlsClient/structure.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"

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
    kInjectAlps,
    kInjectInnerFirstBio,
    kInjectInnerSecondBio,
    kInjectInnerSsl
} tlsclient_injection_t;

static tlsclient_injection_t g_injection = kInjectNothing;
static uint32_t              g_bio_calls = 0;
static uint32_t              g_ssl_calls;
static bool                  g_track_runtime_bios, g_inner_failure_triggered;
static BIO                  *g_runtime_bios[2];

BIO *__real_WW_BSSL_BIO_new(const BIO_METHOD *method);
BIO *__wrap_WW_BSSL_BIO_new(const BIO_METHOD *method);
int  __real_WW_BSSL_BIO_free(BIO *bio);
int  __wrap_WW_BSSL_BIO_free(BIO *bio);
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
    if ((g_injection == kInjectInnerFirstBio && g_bio_calls == 3) ||
        (g_injection == kInjectInnerSecondBio && g_bio_calls == 4))
    {
        g_inner_failure_triggered = true;
        return NULL;
    }

    BIO *bio = __real_WW_BSSL_BIO_new(method);
    if (g_track_runtime_bios && g_bio_calls <= ARRAY_SIZE(g_runtime_bios))
        g_runtime_bios[g_bio_calls - 1] = bio;
    return bio;
}

int __wrap_WW_BSSL_BIO_free(BIO *bio)
{
    for (size_t i = 0; i < ARRAY_SIZE(g_runtime_bios); ++i)
        if (g_runtime_bios[i] == bio)
            g_runtime_bios[i] = NULL;
    return __real_WW_BSSL_BIO_free(bio);
}

SSL *__wrap_WW_BSSL_SSL_new(SSL_CTX *ctx)
{
    ++g_ssl_calls;
    if (g_injection == kInjectSsl)
    {
        return NULL;
    }
    if (g_injection == kInjectInnerSsl && g_ssl_calls == 2)
    {
        g_inner_failure_triggered = true;
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
    g_injection               = injection;
    g_bio_calls               = 0;
    g_ssl_calls               = 0;
    g_inner_failure_triggered = false;
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
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->tls);
    tunnelDestroy(fixture->next);
    twfWorkerEnvTeardown(&fixture->env);
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

static void caseInnerClientHelloFailureReleasesRuntimeBios(tlsclient_injection_t injection)
{
    twfSetCase("ECH inner ClientHello failure releases the outer runtime BIOs");
    tlsclient_fixture_t fixture;
    fixtureSetup(&fixture);
    tlsclient_tstate_t *ts                        = tunnelGetState(fixture.tls);
    ts->ech_grease_sni_override                   = (char *) "inner.example.com";
    ts->threadlocal_ech_grease_inner_ssl_contexts = fixture.ssl_ctx_slot;
    line_t        *l                              = twfLineCreate(fixture.tls->lstate_size);
    const uint32_t refs                           = twfLineRefCount(l);

    injectionArm(injection);
    g_track_runtime_bios = true;
    tlsclientTunnelUpStreamInit(fixture.tls, l);
    g_track_runtime_bios = false;
    injectionDisarm();

    twfRequire(g_inner_failure_triggered, "inner TLS-object failure was not exercised");
    twfRequire(g_runtime_bios[0] == NULL && g_runtime_bios[1] == NULL,
               "outer runtime BIOs leaked before SSL configuration");
    twfRequireEqualText(fixture.trace.seq, "f", "inner failure notified an uninitialized next side");
    twfRequireLineStateZeroed(l, fixture.tls, "inner failure retained outer line state");
    twfRequireEqualU32(twfLineRefCount(l), refs, "inner failure retained a line reference");
    twfLineDestroy(l);
    fixtureTeardown(&fixture);
}

int main(void)
{
    caseInnerClientHelloFailureReleasesRuntimeBios(kInjectInnerFirstBio);
    caseInnerClientHelloFailureReleasesRuntimeBios(kInjectInnerSecondBio);
    caseInnerClientHelloFailureReleasesRuntimeBios(kInjectInnerSsl);
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
