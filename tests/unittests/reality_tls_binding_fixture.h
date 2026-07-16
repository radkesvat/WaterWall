#pragma once

#include "TlsClient/interface.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum
{
    kRealityTlsFixtureFlightCapacity = 65536,
};

typedef struct reality_tls_handshake_fixture_s
{
    tlsclient_handshake_binding_t accessor_binding;
    uint8_t client_flight[kRealityTlsFixtureFlightCapacity];
    uint8_t server_flight[kRealityTlsFixtureFlightCapacity];
    uint8_t client_close_flight[kRealityTlsFixtureFlightCapacity];
    uint8_t server_close_flight[kRealityTlsFixtureFlightCapacity];
    size_t  client_flight_len;
    size_t  server_flight_len;
    size_t  client_close_flight_len;
    size_t  server_close_flight_len;
    bool    session_reused;
} reality_tls_handshake_fixture_t;

bool realityTestBuildTlsHandshakeFixture(uint16_t version, reality_tls_handshake_fixture_t *fixture);
bool realityTestBuildTlsHandshakeFixtureForCipher(uint16_t version, const char *cipher,
                                                  reality_tls_handshake_fixture_t *fixture);
bool realityTestBuildResumedTls12HandshakeFixtureForCipher(const char *cipher,
                                                           reality_tls_handshake_fixture_t *fixture);
