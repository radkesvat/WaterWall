/*
 * Covers: tlsserver line failure; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseHandshakeDeadlineTimerFails, caseTlsAllocationFails, caseZeroTimeoutNeedsNoTimer
 * Checks: Assertion labels include: the failing line did not close exactly the previous side; the protected
 * branch received Init after the timer failure; the protected branch received Finish it never opened;
 * the previous side was not finished exactly once
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tlsserver_line_failure_unit
 */
/*
 * TlsServer TLS-object and handshake-deadline timer failure injection.
 *
 * A handshake deadline that cannot be armed is a per-line resource failure. TlsServer must destroy the TLS line
 * state it has already built and close only the previous side: neither the protected branch nor the fallback
 * branch has received Init at that point, so nothing may be sent upstream.
 */
#include "TlsServer/structure.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"

// ---------------------------------------------------------------------------
// wtimerAdd injection
// ---------------------------------------------------------------------------

static bool     g_timer_fails = false;
static bool     g_tls_injection;
static bool     g_ssl_fails;
static unsigned g_bio_calls;
static unsigned g_bio_failure;
static BIO     *g_detached_bios[2];

BIO *__real_BIO_new(const BIO_METHOD *method);
BIO *__wrap_BIO_new(const BIO_METHOD *method);
int  __real_BIO_free(BIO *bio);
int  __wrap_BIO_free(BIO *bio);
SSL *__real_SSL_new(SSL_CTX *ctx);
SSL *__wrap_SSL_new(SSL_CTX *ctx);

BIO *__wrap_BIO_new(const BIO_METHOD *method)
{
    unsigned call = g_tls_injection ? ++g_bio_calls : 0;
    if (call != 0 && call == g_bio_failure)
        return NULL;
    BIO *bio = __real_BIO_new(method);
    if (call > 0 && call <= ARRAY_SIZE(g_detached_bios))
        g_detached_bios[call - 1] = bio;
    return bio;
}

int __wrap_BIO_free(BIO *bio)
{
    if (g_tls_injection)
    {
        for (size_t i = 0; i < ARRAY_SIZE(g_detached_bios); ++i)
            if (g_detached_bios[i] == bio)
                g_detached_bios[i] = NULL;
    }
    return __real_BIO_free(bio);
}

SSL *__wrap_SSL_new(SSL_CTX *ctx)
{
    return g_tls_injection && g_ssl_fails ? NULL : __real_SSL_new(ctx);
}

wtimer_t *__real_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);

wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat)
{
    if (g_timer_fails)
    {
        return NULL;
    }
    return __real_wtimerAdd(loop, cb, timeout_ms, repeat);
}

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

enum
{
    kTestLargeBufferSize    = 8192,
    kTestHandshakeTimeoutMs = 5000
};

typedef struct tlsserver_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    SSL_CTX         *ssl_ctx;
    SSL_CTX         *ssl_ctx_slot[1];
    tunnel_t        *prev;
    tunnel_t        *tls;
    tunnel_t        *next;
} tlsserver_fixture_t;

static void fixtureSetup(tlsserver_fixture_t *fixture)
{
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->ssl_ctx = SSL_CTX_new(TLS_server_method());
    twfRequire(fixture->ssl_ctx != NULL, "failed to create the TlsServer test SSL_CTX");
    fixture->ssl_ctx_slot[0] = fixture->ssl_ctx;

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->tls  = tunnelCreate(NULL, sizeof(tlsserver_tstate_t), sizeof(tlsserver_lstate_t));
    twfRequire(fixture->tls != NULL, "failed to create the TlsServer tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->prev, fixture->tls);
    tunnelBind(fixture->tls, fixture->next);

    fixture->tls->fnInitU = &tlsserverTunnelUpStreamInit;
    fixture->tls->fnFinU  = &tlsserverTunnelUpStreamFinish;
    fixture->tls->fnFinD  = &tlsserverTunnelDownStreamFinish;

    tlsserver_tstate_t *ts       = tunnelGetState(fixture->tls);
    ts->threadlocal_ssl_contexts = fixture->ssl_ctx_slot;
    ts->handshake_timeout_ms     = kTestHandshakeTimeoutMs;
    ts->fallback_tunnel          = NULL;
    ts->verbose                  = false;
}

static void fixtureTeardown(tlsserver_fixture_t *fixture)
{
    twfRequireNoLeakedBuffers();
    SSL_CTX_free(fixture->ssl_ctx);
    memoryFree(fixture->prev);
    memoryFree(fixture->tls);
    memoryFree(fixture->next);
}

static void caseHandshakeDeadlineTimerFails(void)
{
    twfSetCase("handshake deadline timer allocation fails");

    tlsserver_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t        *l             = twfLineCreate(fixture.tls->lstate_size);
    const uint32_t refc_at_start = twfLineRefCount(l);

    g_timer_fails = true;
    tlsserverTunnelUpStreamInit(fixture.tls, l);
    g_timer_fails = false;

    twfRequireEqualText(fixture.trace.seq, "f", "the failing line did not close exactly the previous side");
    twfRequireEqualU32(fixture.trace.next_init, 0, "the protected branch received Init after the timer failure");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "the protected branch received Finish it never opened");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "the previous side was not finished exactly once");
    twfRequireLineStateZeroed(l, fixture.tls, "the failing TlsServer line state was not zeroed");
    twfRequireEqualU32(twfLineRefCount(l), refc_at_start, "the line reference count did not return to its start");
    twfRequireNoLeakedBuffers();

    twfLineDestroy(l);

    // A second line must still initialize normally once the allocator recovers.
    memoryZero(&fixture.trace, sizeof(fixture.trace));
    line_t *sibling = twfLineCreate(fixture.tls->lstate_size);
    tlsserverTunnelUpStreamInit(fixture.tls, sibling);

    twfRequireEqualU32(fixture.trace.prev_finish, 0, "the sibling line was closed even though its timer was armed");
    twfRequireEqualU32(fixture.trace.next_init, 1, "the sibling line did not open the protected branch");

    tlsserver_lstate_t *sibling_ls = lineGetState(sibling, fixture.tls);
    twfRequire(sibling_ls->handshake_deadline_armed, "the sibling line did not arm its handshake deadline");
    twfRequire(sibling_ls->handshake_deadline_timer != NULL,
               "the sibling line published an armed deadline with no timer");

    tlsserverLinestateDestroy(sibling_ls);
    twfRequireLineStateZeroed(sibling, fixture.tls, "the sibling line state was not zeroed");
    twfLineDestroy(sibling);

    fixtureTeardown(&fixture);
}

static void caseTlsAllocationFails(unsigned bio_failure, bool ssl_failure)
{
    twfSetCase("detached BIOs are released after partial TLS initialization");
    tlsserver_fixture_t fixture;
    fixtureSetup(&fixture);
    line_t *line    = twfLineCreate(fixture.tls->lstate_size);
    g_bio_calls     = 0;
    g_bio_failure   = bio_failure;
    g_ssl_fails     = ssl_failure;
    g_tls_injection = true;
    tlsserverTunnelUpStreamInit(fixture.tls, line);
    g_tls_injection = false;
    twfRequire(g_detached_bios[0] == NULL && g_detached_bios[1] == NULL,
               "a detached BIO leaked when SSL_new or another BIO allocation failed");
    twfRequire(fixture.trace.prev_finish == 1 && fixture.trace.next_init == 0,
               "allocation failure must close only the initialized side");
    twfRequireLineStateZeroed(line, fixture.tls, "partial TLS initialization retained state");
    twfLineDestroy(line);
    fixtureTeardown(&fixture);
}

static void caseZeroTimeoutNeedsNoTimer(void)
{
    twfSetCase("a zero handshake timeout arms nothing and succeeds");

    tlsserver_fixture_t fixture;
    fixtureSetup(&fixture);

    tlsserver_tstate_t *ts   = tunnelGetState(fixture.tls);
    ts->handshake_timeout_ms = 0;

    line_t *l = twfLineCreate(fixture.tls->lstate_size);

    // Even with every timer allocation failing, a line that needs no deadline must open normally.
    g_timer_fails = true;
    tlsserverTunnelUpStreamInit(fixture.tls, l);
    g_timer_fails = false;

    twfRequireEqualU32(fixture.trace.prev_finish, 0, "a line that needs no deadline was closed anyway");
    twfRequireEqualU32(fixture.trace.next_init, 1, "a line that needs no deadline did not open the protected branch");

    tlsserver_lstate_t *ls = lineGetState(l, fixture.tls);
    twfRequire(! ls->handshake_deadline_armed, "a zero timeout still published an armed deadline");
    twfRequire(ls->handshake_deadline_timer == NULL, "a zero timeout still created a timer");

    tlsserverLinestateDestroy(ls);
    twfLineDestroy(l);
    fixtureTeardown(&fixture);
}

int main(void)
{
    caseTlsAllocationFails(1, false);
    caseTlsAllocationFails(2, false);
    caseTlsAllocationFails(0, true);
    caseHandshakeDeadlineTimerFails();
    caseZeroTimeoutNeedsNoTimer();

    printf("tlsserver_line_failure_test: all cases passed\n");
    return 0;
}
