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

bool realityTestBuildTlsHandshakeFixture(uint16_t version, reality_tls_handshake_fixture_t *fixture)
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

    if (fixture == NULL || (version != TLS1_2_VERSION && version != TLS1_3_VERSION))
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

    ok = driveHandshake(client, server, fixture) &&
         readTlsClientAccessor(client, &fixture->accessor_binding);

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
