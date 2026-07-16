#include "TlsClient/structure.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct tlsclient_lifecycle_context_s
{
    char events[16];
    size_t events_len;
    bool kill_on_next_finish;
    bool saw_payload;
} tlsclient_lifecycle_context_t;

typedef struct tlsclient_lifecycle_fixture_s
{
    SSL_CTX *ssl_ctx;
    tunnel_t *prev;
    tunnel_t *tls;
    tunnel_t *next;
    line_t *line;
    tlsclient_lifecycle_context_t context;
} tlsclient_lifecycle_fixture_t;

static void requireTlsClient(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void recordEvent(tlsclient_lifecycle_context_t *context, char event)
{
    requireTlsClient(context->events_len + 1 < sizeof(context->events), "TlsClient lifecycle event overflow");
    context->events[context->events_len++] = event;
    context->events[context->events_len] = '\0';
}

static tlsclient_lifecycle_context_t *testContext(tunnel_t *t)
{
    return *(tlsclient_lifecycle_context_t **) tunnelGetState(t);
}

static void fakePrevFinish(tunnel_t *t, line_t *l)
{
    discard l;
    recordEvent(testContext(t), 'D');
}

static void fakeNextFinish(tunnel_t *t, line_t *l)
{
    tlsclient_lifecycle_context_t *context = testContext(t);
    recordEvent(context, 'U');
    if (context->kill_on_next_finish)
    {
        l->alive = false;
    }
}

static void fakePayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tlsclient_lifecycle_context_t *context = testContext(t);
    context->saw_payload = true;
    discard t;
    discard l;
    discard buf;
}

static void fixtureInitialize(tlsclient_lifecycle_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));

    fixture->ssl_ctx = SSL_CTX_new(TLS_client_method());
    requireTlsClient(fixture->ssl_ctx != NULL, "failed to create TlsClient test SSL_CTX");

    fixture->prev = tunnelCreate(NULL, sizeof(tlsclient_lifecycle_context_t *), 0);
    fixture->tls = tunnelCreate(NULL, 0, sizeof(tlsclient_lstate_t));
    fixture->next = tunnelCreate(NULL, sizeof(tlsclient_lifecycle_context_t *), 0);
    requireTlsClient(fixture->prev != NULL && fixture->tls != NULL && fixture->next != NULL,
                     "failed to create TlsClient lifecycle tunnels");

    tunnelBind(fixture->prev, fixture->tls);
    tunnelBind(fixture->tls, fixture->next);

    *(tlsclient_lifecycle_context_t **) tunnelGetState(fixture->prev) = &fixture->context;
    *(tlsclient_lifecycle_context_t **) tunnelGetState(fixture->next) = &fixture->context;

    fixture->prev->fnFinD = fakePrevFinish;
    fixture->prev->fnPayloadD = fakePayload;
    fixture->next->fnFinU = fakeNextFinish;
    fixture->next->fnPayloadU = fakePayload;

    uint32_t line_size = sizeof(line_t) + fixture->tls->lstate_size;
    fixture->line = memoryAllocateCacheAlignedZero(line_size);
    requireTlsClient(fixture->line != NULL, "failed to allocate TlsClient lifecycle line");
    atomic_init(&fixture->line->refc, 1);
    fixture->line->alive = true;
    fixture->line->wid = 0;

    tlsclient_lstate_t *ls = lineGetState(fixture->line, fixture->tls);
    tlsclientLinestateInitialize(ls, fixture->ssl_ctx);
    requireTlsClient(tlsclientConfigureSslForConnect(ls->ssl, ls->rbio, ls->wbio, "example.com", NULL, 0),
                     "failed to configure TlsClient lifecycle SSL object");
}

static void fixtureDestroy(tlsclient_lifecycle_fixture_t *fixture)
{
    tlsclient_lstate_t *ls = lineGetState(fixture->line, fixture->tls);
    const uint8_t *state = (const uint8_t *) ls;
    for (uint32_t i = 0; i < fixture->tls->lstate_size; ++i)
    {
        requireTlsClient(state[i] == 0, "TlsClient terminal path did not zero line state");
    }

    requireTlsClient(atomic_load(&fixture->line->refc) == 1, "TlsClient lifecycle line reference leaked");

    memoryFreeAligned(fixture->line);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->tls);
    tunnelDestroy(fixture->next);
    SSL_CTX_free(fixture->ssl_ctx);
}

static void requireScenario(tlsclient_lifecycle_fixture_t *fixture, const char *expected_events)
{
    requireTlsClient(strcmp(fixture->context.events, expected_events) == 0,
                     "TlsClient terminal callback ordering mismatch");
    requireTlsClient(! fixture->context.saw_payload, "TlsClient terminal path emitted payload");
}

static void testUpstreamFinishIsDirectional(void)
{
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    tlsclientTunnelUpStreamFinish(fixture.tls, fixture.line);
    requireScenario(&fixture, "U");
    fixtureDestroy(&fixture);
}

static void testDownstreamFinishIsDirectional(void)
{
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    tlsclientTunnelDownStreamFinish(fixture.tls, fixture.line);
    requireScenario(&fixture, "D");
    fixtureDestroy(&fixture);
}

static void testFatalCloseFinishesUpstreamThenDownstream(void)
{
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    tlsclientCloseLineBidirectional(fixture.tls, fixture.line);
    requireScenario(&fixture, "UD");
    fixtureDestroy(&fixture);
}

static void testFatalCloseStopsWhenFirstFinishKillsLine(void)
{
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    fixture.context.kill_on_next_finish = true;
    tlsclientCloseLineBidirectional(fixture.tls, fixture.line);
    requireScenario(&fixture, "U");
    requireTlsClient(! lineIsAlive(fixture.line), "TlsClient fatal close ignored line death");
    fixtureDestroy(&fixture);
}

static void testHandshakeTakeoverFinishStaysPayloadFree(void)
{
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);

    tlsclient_lstate_t *ls = lineGetState(fixture.line, fixture.tls);
    ls->handshake_completed = true;
    sbuf_t *pending_raw = NULL;
    requireTlsClient(tlsclientTunnelDeinitAfterHandshake(fixture.tls, fixture.line, &pending_raw),
                     "TlsClient handshake takeover deinit failed");
    requireTlsClient(pending_raw == NULL, "TlsClient handshake takeover unexpectedly drained raw bytes");
    requireTlsClient(ls->resources_released && ls->passthrough,
                     "TlsClient handshake takeover did not enter passthrough mode");

    tlsclientTunnelUpStreamFinish(fixture.tls, fixture.line);
    requireScenario(&fixture, "U");
    fixtureDestroy(&fixture);
}

int main(void)
{
    testUpstreamFinishIsDirectional();
    testDownstreamFinishIsDirectional();
    testFatalCloseFinishesUpstreamThenDownstream();
    testFatalCloseStopsWhenFirstFinishKillsLine();
    testHandshakeTakeoverFinishStaysPayloadFree();
    return 0;
}
