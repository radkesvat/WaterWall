#include "reality_tls_binding_fixture.h"

#include "TlsClient/structure.h"

#ifndef REALITY_TEST_CERT_FILE
#error "REALITY_TEST_CERT_FILE must name the test certificate"
#endif

#ifndef REALITY_TEST_KEY_FILE
#error "REALITY_TEST_KEY_FILE must name the test private key"
#endif

static bool appendAndForward(BIO *source, BIO *destination, uint8_t *flight, size_t *flight_len)
{
    uint8_t chunk[4096];

    while (BIO_ctrl_pending(source) > 0)
    {
        int read_len = BIO_read(source, chunk, sizeof(chunk));
        if (read_len <= 0 || (size_t) read_len > kRealityTlsFixtureFlightCapacity - *flight_len)
        {
            return false;
        }

        memoryCopy(flight + *flight_len, chunk, (size_t) read_len);
        *flight_len += (size_t) read_len;

        size_t written = 0;
        while (written < (size_t) read_len)
        {
            int write_len = BIO_write(destination, chunk + written, (int) ((size_t) read_len - written));
            if (write_len <= 0)
            {
                return false;
            }
            written += (size_t) write_len;
        }
    }

    return true;
}

static bool advanceHandshake(SSL *ssl, bool *complete)
{
    if (*complete)
    {
        return true;
    }

    int result = SSL_do_handshake(ssl);
    if (result == 1)
    {
        *complete = true;
        return true;
    }

    int error = SSL_get_error(ssl, result);
    return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE;
}

static bool driveHandshake(SSL *client, SSL *server, reality_tls_handshake_fixture_t *fixture)
{
    bool client_complete = false;
    bool server_complete = false;

    for (uint32_t step = 0; step < 10000; ++step)
    {
        if (! advanceHandshake(client, &client_complete) ||
            ! appendAndForward(SSL_get_wbio(client),
                               SSL_get_rbio(server),
                               fixture->client_flight,
                               &fixture->client_flight_len) ||
            ! advanceHandshake(server, &server_complete) ||
            ! appendAndForward(SSL_get_wbio(server),
                               SSL_get_rbio(client),
                               fixture->server_flight,
                               &fixture->server_flight_len))
        {
            return false;
        }

        if (client_complete && server_complete)
        {
            return true;
        }
    }

    return false;
}

static bool advanceShutdown(SSL *ssl, bool *complete)
{
    if (*complete)
    {
        return true;
    }

    int result = SSL_shutdown(ssl);
    if (result == 1)
    {
        *complete = true;
        return true;
    }
    if (result == 0)
    {
        return true;
    }

    int error = SSL_get_error(ssl, result);
    return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE;
}

static bool driveShutdown(SSL *client, SSL *server, reality_tls_handshake_fixture_t *fixture)
{
    bool client_complete = false;
    bool server_complete = false;

    for (uint32_t step = 0; step < 100; ++step)
    {
        if (! advanceShutdown(client, &client_complete) ||
            ! appendAndForward(SSL_get_wbio(client),
                               SSL_get_rbio(server),
                               fixture->client_close_flight,
                               &fixture->client_close_flight_len) ||
            ! advanceShutdown(server, &server_complete) ||
            ! appendAndForward(SSL_get_wbio(server),
                               SSL_get_rbio(client),
                               fixture->server_close_flight,
                               &fixture->server_close_flight_len))
        {
            return false;
        }

        if (client_complete && server_complete)
        {
            return fixture->client_close_flight_len != 0 && fixture->server_close_flight_len != 0;
        }
    }

    return false;
}

static bool collectTls13PostHandshakeFlights(SSL *client, SSL *server,
                                             reality_tls_handshake_fixture_t *fixture)
{
    static const uint8_t early_application[] = "Chrome-like early application payload";
    uint8_t application_plaintext[sizeof(early_application)] = {0};

    if (SSL_write(server, NULL, 0) < 0 ||
        ! appendAndForward(SSL_get_wbio(server),
                           SSL_get_rbio(client),
                           fixture->server_post_handshake_flight,
                           &fixture->server_post_handshake_flight_len) ||
        SSL_write(server, early_application, sizeof(early_application)) != (int) sizeof(early_application) ||
        ! appendAndForward(SSL_get_wbio(server),
                           SSL_get_rbio(client),
                           fixture->server_early_application_flight,
                           &fixture->server_early_application_flight_len) ||
        SSL_read(client, application_plaintext, sizeof(application_plaintext)) !=
            (int) sizeof(application_plaintext) ||
        ! memoryEqual(application_plaintext, early_application, sizeof(early_application)) ||
        ! SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED) || SSL_write(server, NULL, 0) < 0 ||
        ! appendAndForward(SSL_get_wbio(server),
                           SSL_get_rbio(client),
                           fixture->server_key_update_not_requested_flight,
                           &fixture->server_key_update_not_requested_flight_len))
    {
        memoryZero(application_plaintext, sizeof(application_plaintext));
        return false;
    }

    int read_result = SSL_read(client, application_plaintext, sizeof(application_plaintext));
    if (read_result >= 0 || SSL_get_error(client, read_result) != SSL_ERROR_WANT_READ ||
        ! SSL_key_update(server, SSL_KEY_UPDATE_REQUESTED) || SSL_write(server, NULL, 0) < 0 ||
        ! appendAndForward(SSL_get_wbio(server),
                           SSL_get_rbio(client),
                           fixture->server_key_update_requested_flight,
                           &fixture->server_key_update_requested_flight_len))
    {
        memoryZero(application_plaintext, sizeof(application_plaintext));
        return false;
    }

    read_result = SSL_read(client, application_plaintext, sizeof(application_plaintext));
    if (read_result >= 0 || SSL_get_error(client, read_result) != SSL_ERROR_WANT_READ ||
        SSL_write(client, NULL, 0) < 0 ||
        ! appendAndForward(SSL_get_wbio(client),
                           SSL_get_rbio(server),
                           fixture->client_key_update_response_flight,
                           &fixture->client_key_update_response_flight_len))
    {
        memoryZero(application_plaintext, sizeof(application_plaintext));
        return false;
    }

    read_result = SSL_read(server, application_plaintext, sizeof(application_plaintext));
    bool ok = read_result < 0 && SSL_get_error(server, read_result) == SSL_ERROR_WANT_READ;
    memoryZero(application_plaintext, sizeof(application_plaintext));
    return ok;
}

static bool readTlsClientAccessor(SSL *ssl, tlsclient_handshake_binding_t *binding)
{
    tunnel_t *tunnel = tunnelCreate(NULL, 0, sizeof(tlsclient_lstate_t));
    if (tunnel == NULL)
    {
        return false;
    }

    line_t *line = memoryAllocateCacheAlignedZero(sizeof(line_t) + tunnel->lstate_size);
    if (line == NULL)
    {
        tunnelDestroy(tunnel);
        return false;
    }

    tlsclient_lstate_t *line_state = lineGetState(line, tunnel);
    line_state->ssl                 = ssl;
    line_state->handshake_completed = true;

    bool ok = tlsclientTunnelGetHandshakeBinding(tunnel, line, binding);

    memoryZero(line_state, tunnel->lstate_size);
    memoryFreeAligned(line);
    tunnelDestroy(tunnel);
    return ok;
}

static bool buildTlsHandshakeFixture(uint16_t version, const char *cipher, bool resume,
                                     reality_tls_handshake_fixture_t *fixture)
{
    SSL_CTX *client_context = NULL;
    SSL_CTX *server_context = NULL;
    SSL     *client         = NULL;
    SSL     *server         = NULL;
    BIO     *client_rbio    = NULL;
    BIO     *client_wbio    = NULL;
    BIO     *server_rbio    = NULL;
    BIO     *server_wbio    = NULL;
    bool     ok             = false;

    if (fixture == NULL || (version != TLS1_2_VERSION && version != TLS1_3_VERSION) ||
        (resume && version != TLS1_2_VERSION))
    {
        return false;
    }
    *fixture = (reality_tls_handshake_fixture_t) {0};

    client_context = SSL_CTX_new(TLS_client_method());
    server_context = SSL_CTX_new(TLS_server_method());
    if (client_context == NULL || server_context == NULL ||
        ! SSL_CTX_set_min_proto_version(client_context, version) ||
        ! SSL_CTX_set_max_proto_version(client_context, version) ||
        ! SSL_CTX_set_min_proto_version(server_context, version) ||
        ! SSL_CTX_set_max_proto_version(server_context, version) ||
        SSL_CTX_use_certificate_chain_file(server_context, REALITY_TEST_CERT_FILE) != 1 ||
        SSL_CTX_use_PrivateKey_file(server_context, REALITY_TEST_KEY_FILE, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(server_context) != 1)
    {
        goto cleanup;
    }

    if (version == TLS1_2_VERSION && cipher != NULL &&
        (SSL_CTX_set_cipher_list(client_context, cipher) != 1 ||
         SSL_CTX_set_cipher_list(server_context, cipher) != 1))
    {
        goto cleanup;
    }
    if (version == TLS1_3_VERSION && SSL_CTX_set_num_tickets(server_context, 2) != 1)
    {
        goto cleanup;
    }

    client = SSL_new(client_context);
    server = SSL_new(server_context);
    client_rbio = BIO_new(BIO_s_mem());
    client_wbio = BIO_new(BIO_s_mem());
    server_rbio = BIO_new(BIO_s_mem());
    server_wbio = BIO_new(BIO_s_mem());
    if (client == NULL || server == NULL || client_rbio == NULL || client_wbio == NULL ||
        server_rbio == NULL || server_wbio == NULL)
    {
        goto cleanup;
    }

    BIO_set_mem_eof_return(client_rbio, -1);
    BIO_set_mem_eof_return(client_wbio, -1);
    BIO_set_mem_eof_return(server_rbio, -1);
    BIO_set_mem_eof_return(server_wbio, -1);

    SSL_set_bio(client, client_rbio, client_wbio);
    client_rbio = NULL;
    client_wbio = NULL;
    SSL_set_bio(server, server_rbio, server_wbio);
    server_rbio = NULL;
    server_wbio = NULL;
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    if (! driveHandshake(client, server, fixture))
    {
        goto cleanup;
    }

    if (resume)
    {
        SSL_SESSION *session = SSL_get_session(client);
        if (session == NULL || ! SSL_SESSION_is_resumable(session) ||
            SSL_clear(client) != 1 || SSL_clear(server) != 1)
        {
            goto cleanup;
        }

        *fixture = (reality_tls_handshake_fixture_t) {0};
        if (! driveHandshake(client, server, fixture) ||
            ! SSL_session_reused(client) || ! SSL_session_reused(server))
        {
            goto cleanup;
        }
        fixture->session_reused = true;
    }

    ok = readTlsClientAccessor(client, &fixture->accessor_binding) &&
         (version != TLS1_3_VERSION || collectTls13PostHandshakeFlights(client, server, fixture)) &&
         driveShutdown(client, server, fixture);

cleanup:
    BIO_free(client_rbio);
    BIO_free(client_wbio);
    BIO_free(server_rbio);
    BIO_free(server_wbio);
    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(client_context);
    SSL_CTX_free(server_context);
    return ok;
}

bool realityTestBuildTlsHandshakeFixtureForCipher(uint16_t version, const char *cipher,
                                                  reality_tls_handshake_fixture_t *fixture)
{
    return buildTlsHandshakeFixture(version, cipher, false, fixture);
}

bool realityTestBuildResumedTls12HandshakeFixtureForCipher(const char *cipher,
                                                           reality_tls_handshake_fixture_t *fixture)
{
    return buildTlsHandshakeFixture(TLS1_2_VERSION, cipher, true, fixture);
}

bool realityTestBuildTlsHandshakeFixture(uint16_t version, reality_tls_handshake_fixture_t *fixture)
{
    return realityTestBuildTlsHandshakeFixtureForCipher(version, NULL, fixture);
}
