#include "RealityServer/structure.h"

#include "reality_tls_binding_fixture.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void requireParserMatchesAccessor(uint16_t version)
{
    reality_tls_handshake_fixture_t *fixture = memoryAllocate(sizeof(*fixture));
    require(fixture != NULL, "failed to allocate real TLS handshake fixture");
    require(realityTestBuildTlsHandshakeFixture(version, fixture), "real TLS handshake fixture failed");

    realityserver_tls_capture_t capture = {0};
    realityserver_tls_parser_t  client_parser;
    realityserver_tls_parser_t  server_parser;
    realityserverTlsParserInitialize(&client_parser, kRealityServerTlsParserClientHello);
    realityserverTlsParserInitialize(&server_parser, kRealityServerTlsParserServerHello);

    require(realityserverTlsParserFeed(
                &client_parser, fixture->client_flight, fixture->client_flight_len, &capture),
            "passive ClientHello parsing failed for real handshake");
    require(realityserverTlsParserFeed(
                &server_parser, fixture->server_flight, fixture->server_flight_len, &capture),
            "passive ServerHello parsing failed for real handshake");
    require(client_parser.complete && server_parser.complete && capture.client_ready && capture.server_ready,
            "passive parser did not complete the real handshake binding");
    require(capture.binding.tls_version == fixture->accessor_binding.tls_version,
            "passive parser and TlsClient accessor disagree on TLS version");
    require(capture.binding.cipher_suite == fixture->accessor_binding.cipher_suite,
            "passive parser and TlsClient accessor disagree on cipher suite");
    require(memoryEqual(capture.binding.client_random,
                        fixture->accessor_binding.client_random,
                        sizeof(capture.binding.client_random)),
            "passive parser and TlsClient accessor disagree on client random");
    require(memoryEqual(capture.binding.server_random,
                        fixture->accessor_binding.server_random,
                        sizeof(capture.binding.server_random)),
            "passive parser and TlsClient accessor disagree on server random");

    realityserverTlsParserDestroy(&client_parser);
    realityserverTlsParserDestroy(&server_parser);
    memoryZero(fixture, sizeof(*fixture));
    memoryFree(fixture);
}

int main(void)
{
    requireParserMatchesAccessor(0x0303);
    requireParserMatchesAccessor(0x0304);
    return 0;
}
