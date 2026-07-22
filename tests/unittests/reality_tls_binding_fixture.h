#pragma once

#include "TlsClient/interface.h"


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
    uint8_t server_post_handshake_flight[kRealityTlsFixtureFlightCapacity];
    uint8_t server_early_application_flight[kRealityTlsFixtureFlightCapacity];
    uint8_t server_key_update_not_requested_flight[kRealityTlsFixtureFlightCapacity];
    uint8_t server_key_update_requested_flight[kRealityTlsFixtureFlightCapacity];
    uint8_t client_key_update_response_flight[kRealityTlsFixtureFlightCapacity];
    size_t  client_flight_len;
    size_t  server_flight_len;
    size_t  client_close_flight_len;
    size_t  server_close_flight_len;
    size_t  server_post_handshake_flight_len;
    size_t  server_early_application_flight_len;
    size_t  server_key_update_not_requested_flight_len;
    size_t  server_key_update_requested_flight_len;
    size_t  client_key_update_response_flight_len;
    bool    session_reused;
} reality_tls_handshake_fixture_t;

bool realityTestBuildTlsHandshakeFixture(uint16_t version, reality_tls_handshake_fixture_t *fixture);
bool realityTestBuildTlsHandshakeFixtureForCipher(uint16_t version, const char *cipher,
                                                  reality_tls_handshake_fixture_t *fixture);
bool realityTestBuildResumedTls12HandshakeFixtureForCipher(const char *cipher,
                                                           reality_tls_handshake_fixture_t *fixture);
