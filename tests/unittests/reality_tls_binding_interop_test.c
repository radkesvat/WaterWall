#include "RealityServer/structure.h"

#include "reality_tls_binding_fixture.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/* SSL_shutdown() is only a public record-shape oracle. Reality's role-specific
 * shutdown policy does not reproduce BoringSSL's shutdown state machine. */

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static const uint8_t *requireLastRecord(const uint8_t *flight, size_t flight_len,
                                        uint16_t *last_body_len, const char *message)
{
    size_t offset = 0;
    const uint8_t *last_record = NULL;
    while (offset < flight_len)
    {
        require(flight_len - offset >= kRealityV2TlsRecordHeaderSize, message);
        uint16_t body_len = ((uint16_t) flight[offset + 3] << 8) | flight[offset + 4];
        require((size_t) body_len + kRealityV2TlsRecordHeaderSize <= flight_len - offset, message);
        last_record = flight + offset;
        *last_body_len = body_len;
        offset += kRealityV2TlsRecordHeaderSize + body_len;
    }
    require(last_record != NULL, message);
    return last_record;
}

static void requireSingleProtectedRecordBody(const uint8_t *flight, size_t flight_len,
                                             uint16_t expected_body_len, const char *message)
{
    require(flight_len == (size_t) expected_body_len + kRealityV2TlsRecordHeaderSize &&
                flight[0] == 0x17 && flight[1] == 0x03 && flight[2] == 0x03 &&
                (((uint16_t) flight[3] << 8) | flight[4]) == expected_body_len,
            message);
}

static const uint8_t *requireCloseFlightShape(const uint8_t *flight, size_t flight_len,
                                              uint16_t version, uint8_t profile, const char *message)
{
    uint8_t expected_type;
    uint16_t expected_body_len;
    if (version == kRealityV2Tls13)
    {
        expected_type     = 0x17;
        expected_body_len = 19;
    }
    else if (profile == kRealityV2RecordProfileTls12Gcm)
    {
        expected_type     = 0x15;
        expected_body_len = 26;
    }
    else if (profile == kRealityV2RecordProfileTls12Cbc)
    {
        expected_type     = 0x15;
        expected_body_len = 48;
    }
    else
    {
        expected_type     = 0x15;
        expected_body_len = 18;
    }

    uint16_t actual_body_len = 0;
    const uint8_t *last_record = requireLastRecord(flight, flight_len, &actual_body_len, message);
    require(last_record[0] == expected_type &&
                last_record[1] == 0x03 && last_record[2] == 0x03 &&
                actual_body_len == expected_body_len,
            message);
    return last_record;
}

static void requireParserMatchesAccessor(uint16_t version, const char *cipher, uint8_t expected_profile,
                                         bool resumed)
{
    reality_tls_handshake_fixture_t *fixture = memoryAllocate(sizeof(*fixture));
    require(fixture != NULL, "failed to allocate real TLS handshake fixture");
    bool fixture_ok = resumed
                          ? realityTestBuildResumedTls12HandshakeFixtureForCipher(cipher, fixture)
                          : realityTestBuildTlsHandshakeFixtureForCipher(version, cipher, fixture);
    require(fixture_ok,
            "real TLS handshake fixture failed");
    require(fixture->session_reused == resumed,
            "real TLS handshake fixture reported the wrong resumption state");
    const uint8_t *client_close_record =
        requireCloseFlightShape(fixture->client_close_flight,
                                fixture->client_close_flight_len,
                                version,
                                expected_profile,
                                "real client close_notify record has the wrong TLS shape");
    const uint8_t *server_close_record =
        requireCloseFlightShape(fixture->server_close_flight,
                                fixture->server_close_flight_len,
                                version,
                                expected_profile,
                                "real server close_notify record has the wrong TLS shape");

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

    if (version == kRealityV2Tls12)
    {
        reality_v2_record_profile_t profile;
        require(fixture->accessor_binding.tls12_sequences_valid,
                "TlsClient accessor did not expose TLS 1.2 sequences");
        require(realityV2SelectRecordProfile(capture.binding.tls_version,
                                             capture.binding.cipher_suite,
                                             &profile),
                "real TLS 1.2 handshake selected an unsupported Reality profile");
        require(profile.profile_id == expected_profile, "real TLS handshake selected the wrong record profile");

        realityserver_tls12_record_tracker_t client_tracker;
        realityserver_tls12_record_tracker_t server_tracker;
        realityserverTls12RecordTrackerInitialize(&client_tracker);
        realityserverTls12RecordTrackerInitialize(&server_tracker);
        require(realityserverTls12RecordTrackerSetProfile(&client_tracker, &profile) &&
                    realityserverTls12RecordTrackerSetProfile(&server_tracker, &profile),
                "failed to configure real-handshake TLS 1.2 trackers");
        require(realityserverTls12RecordTrackerFeed(
                    &client_tracker, fixture->client_flight, fixture->client_flight_len) &&
                    realityserverTls12RecordTrackerFeed(
                        &server_tracker, fixture->server_flight, fixture->server_flight_len),
                "passive TLS 1.2 tracking failed for real handshake");
        require(client_tracker.next_sequence == fixture->accessor_binding.next_write_sequence,
                "passive client sequence and TlsClient write sequence disagree");
        require(server_tracker.next_sequence == fixture->accessor_binding.next_read_sequence,
                "passive server sequence and TlsClient read sequence disagree");
        if (profile.profile_id == kRealityV2RecordProfileTls12Gcm)
        {
            require(client_tracker.sequence_pattern && server_tracker.sequence_pattern,
                    "BoringSSL TLS 1.2 GCM explicit nonces do not match record sequences");
            require(realityV2ReadBe64(client_close_record + kRealityV2TlsRecordHeaderSize) ==
                        fixture->accessor_binding.next_write_sequence,
                    "real client GCM close_notify explicit nonce did not continue its TLS sequence");
            require(realityV2ReadBe64(server_close_record + kRealityV2TlsRecordHeaderSize) ==
                        fixture->accessor_binding.next_read_sequence,
                    "real server GCM close_notify explicit nonce did not continue its TLS sequence");
        }
        else if (profile.profile_id == kRealityV2RecordProfileTls12Cbc)
        {
            uint16_t client_last_body_len = 0;
            uint16_t server_last_body_len = 0;
            const uint8_t *client_last_record =
                requireLastRecord(fixture->client_flight,
                                  fixture->client_flight_len,
                                  &client_last_body_len,
                                  "failed to locate the last client handshake record");
            const uint8_t *server_last_record =
                requireLastRecord(fixture->server_flight,
                                  fixture->server_flight_len,
                                  &server_last_body_len,
                                  "failed to locate the last server handshake record");
            require(client_last_body_len >= kRealityV2Tls12CbcPrefixSize &&
                        server_last_body_len >= kRealityV2Tls12CbcPrefixSize,
                    "real CBC handshake record was too short for an explicit IV");
            require(! memoryEqual(client_close_record + kRealityV2TlsRecordHeaderSize,
                                  client_last_record + kRealityV2TlsRecordHeaderSize,
                                  kRealityV2Tls12CbcPrefixSize) &&
                        ! memoryEqual(server_close_record + kRealityV2TlsRecordHeaderSize,
                                     server_last_record + kRealityV2TlsRecordHeaderSize,
                                     kRealityV2Tls12CbcPrefixSize) &&
                        ! memoryEqual(client_close_record + kRealityV2TlsRecordHeaderSize,
                                     server_close_record + kRealityV2TlsRecordHeaderSize,
                                     kRealityV2Tls12CbcPrefixSize),
                    "real CBC close_notify records did not use fresh explicit IVs");
        }
        realityserverTls12RecordTrackerDestroy(&client_tracker);
        realityserverTls12RecordTrackerDestroy(&server_tracker);
    }
    else
    {
        uint16_t protected_handshake_body_len = 0;
        const uint8_t *protected_handshake =
            requireLastRecord(fixture->server_flight,
                              fixture->server_flight_len,
                              &protected_handshake_body_len,
                              "failed to locate real TLS 1.3 protected handshake record");
        require(protected_handshake[0] == 0x17 &&
                    protected_handshake_body_len == kRealityV2ControlMaxTlsRecordBody,
                "control padding maximum no longer matches the real protected-handshake evidence");
        requireSingleProtectedRecordBody(fixture->server_post_handshake_flight,
                                         fixture->server_post_handshake_flight_len,
                                         381,
                                         "real two-ticket flight changed public record length");
        requireSingleProtectedRecordBody(fixture->server_early_application_flight,
                                         fixture->server_early_application_flight_len,
                                         55,
                                         "real early application flight changed public record length");
        requireSingleProtectedRecordBody(fixture->server_key_update_not_requested_flight,
                                         fixture->server_key_update_not_requested_flight_len,
                                         kRealityV2ControlMinTlsRecordBody,
                                         "real unrequested KeyUpdate changed public record length");
        requireSingleProtectedRecordBody(fixture->server_key_update_requested_flight,
                                         fixture->server_key_update_requested_flight_len,
                                         kRealityV2ControlMinTlsRecordBody,
                                         "real requested KeyUpdate changed public record length");
        requireSingleProtectedRecordBody(fixture->client_key_update_response_flight,
                                         fixture->client_key_update_response_flight_len,
                                         kRealityV2ControlMinTlsRecordBody,
                                         "real KeyUpdate response changed public record length");
        require(! fixture->accessor_binding.tls12_sequences_valid,
                "TlsClient accessor must not call TLS-only sequence accessors for TLS 1.3");
    }

    realityserverTlsParserDestroy(&client_parser);
    realityserverTlsParserDestroy(&server_parser);
    memoryZero(fixture, sizeof(*fixture));
    memoryFree(fixture);
}

int main(void)
{
    requireParserMatchesAccessor(
        0x0303, "ECDHE-RSA-AES128-GCM-SHA256", kRealityV2RecordProfileTls12Gcm, false);
    requireParserMatchesAccessor(
        0x0303, "ECDHE-RSA-AES256-GCM-SHA384", kRealityV2RecordProfileTls12Gcm, false);
    requireParserMatchesAccessor(0x0303, "ECDHE-RSA-AES128-SHA", kRealityV2RecordProfileTls12Cbc, false);
    requireParserMatchesAccessor(0x0303, "ECDHE-RSA-AES256-SHA", kRealityV2RecordProfileTls12Cbc, false);
    requireParserMatchesAccessor(
        0x0303, "ECDHE-RSA-CHACHA20-POLY1305", kRealityV2RecordProfileTls12ChaCha, false);
    requireParserMatchesAccessor(0x0304, NULL, kRealityV2RecordProfileTls13Aead, false);
    requireParserMatchesAccessor(
        0x0303, "ECDHE-RSA-AES128-GCM-SHA256", kRealityV2RecordProfileTls12Gcm, true);
    requireParserMatchesAccessor(0x0303, "ECDHE-RSA-AES128-SHA", kRealityV2RecordProfileTls12Cbc, true);
    requireParserMatchesAccessor(
        0x0303, "ECDHE-RSA-CHACHA20-POLY1305", kRealityV2RecordProfileTls12ChaCha, true);
    return 0;
}
