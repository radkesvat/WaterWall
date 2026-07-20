#include "TlsClient/structure.h"

#include "global_state.h"

#include <stdio.h>
#include <stdlib.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static cJSON *parseSettings(const char *text)
{
    cJSON *settings = cJSON_Parse(text);
    require(settings != NULL && cJSON_IsObject(settings), "failed to parse ALPN test settings");
    return settings;
}

static void requireWire(const tlsclient_tstate_t *ts, const uint8_t *expected, size_t expected_len,
                        const char *message)
{
    require(ts->alpn_wire_len == expected_len, message);
    require(expected_len == 0 || memoryCompare(ts->alpn_wire, expected, expected_len) == 0, message);
}

static void releaseParsedAlpns(tlsclient_tstate_t *ts)
{
    memoryFree(ts->alpn_wire);
    ts->alpn_wire     = NULL;
    ts->alpn_wire_len = 0;
}

static void testDefaultOrder(void)
{
    static const uint8_t expected[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
    };

    cJSON              *settings = parseSettings("{}");
    tlsclient_tstate_t  ts       = {0};

    require(tlsclientParseAlpnSetting(&ts, settings), "default ALPN parsing failed");
    requireWire(&ts, expected, sizeof(expected), "default ALPN order changed");

    releaseParsedAlpns(&ts);
    cJSON_Delete(settings);
}

static void testConfiguredOrder(void)
{
    static const uint8_t expected[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
        2, 'h', '2',
        3, 'f', 'o', 'o',
    };

    cJSON             *settings = parseSettings("{\"alpns\":[\"http/1.1\",\"h2\",\"foo\"]}");
    tlsclient_tstate_t ts       = {0};

    require(tlsclientParseAlpnSetting(&ts, settings), "configured ALPN parsing failed");
    requireWire(&ts, expected, sizeof(expected), "configured ALPN order was not preserved");

    releaseParsedAlpns(&ts);
    cJSON_Delete(settings);
}

static void testEmptyListDisablesAlpn(void)
{
    cJSON             *settings = parseSettings("{\"alpns\":[]}");
    tlsclient_tstate_t ts       = {0};

    require(tlsclientParseAlpnSetting(&ts, settings), "empty ALPN list was rejected");
    requireWire(&ts, NULL, 0, "empty ALPN list did not disable ALPN");
    require(ts.alpn_wire == NULL, "empty ALPN list unexpectedly allocated wire data");

    cJSON_Delete(settings);
}

static void testInvalidListsAreRejected(void)
{
    static const char *invalid_settings[] = {
        "{\"alpns\":\"h2\"}",
        "{\"alpns\":[\"\"]}",
        "{\"alpns\":[2]}",
        "{\"alpns\":[\"h2\",\"h2\"]}",
    };

    for (size_t i = 0; i < ARRAY_SIZE(invalid_settings); ++i)
    {
        cJSON             *settings = parseSettings(invalid_settings[i]);
        tlsclient_tstate_t ts       = {0};

        require(! tlsclientParseAlpnSetting(&ts, settings), "invalid ALPN setting was accepted");
        require(ts.alpn_wire == NULL && ts.alpn_wire_len == 0,
                "invalid ALPN setting left allocated state behind");

        cJSON_Delete(settings);
    }
}

static int selectHttp11(SSL *ssl, const uint8_t **out, uint8_t *out_len, const uint8_t *in,
                        unsigned int in_len, void *arg)
{
    static const uint8_t supported[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
    };

    uint8_t *selected     = NULL;
    uint8_t  selected_len = 0;

    discard ssl;
    discard arg;

    if (SSL_select_next_proto(&selected,
                              &selected_len,
                              in,
                              in_len,
                              supported,
                              (unsigned int) sizeof(supported)) != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    *out     = selected;
    *out_len = selected_len;
    return SSL_TLSEXT_ERR_OK;
}

static bool transferBio(BIO *source, BIO *destination)
{
    uint8_t bytes[4096];

    while (BIO_ctrl_pending(source) > 0)
    {
        int read_len = BIO_read(source, bytes, (int) sizeof(bytes));
        if (read_len <= 0)
        {
            return false;
        }

        int written = 0;
        while (written < read_len)
        {
            int write_len = BIO_write(destination, bytes + written, read_len - written);
            if (write_len <= 0)
            {
                return false;
            }
            written += write_len;
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

static bool driveHandshake(SSL *client, SSL *server)
{
    bool client_complete = false;
    bool server_complete = false;

    for (uint32_t step = 0; step < 100; ++step)
    {
        if (! advanceHandshake(client, &client_complete) ||
            ! transferBio(SSL_get_wbio(client), SSL_get_rbio(server)) ||
            ! advanceHandshake(server, &server_complete) ||
            ! transferBio(SSL_get_wbio(server), SSL_get_rbio(client)))
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

static void testHttp11Negotiation(void)
{
    static const uint8_t expected[] = "http/1.1";

    const uint32_t saved_workers_count = GSTATE.workers_count;
    cJSON        *settings =
        parseSettings("{\"sni\":\"tls.integration.test\",\"alpns\":[\"http/1.1\"],\"verify\":false}");
    node_t node = {.node_settings_json = settings};

    GSTATE.workers_count = 2; // one regular worker plus WaterWall's additional lwIP worker

    tunnel_t *tunnel = tlsclientTunnelCreate(&node);
    require(tunnel != NULL, "failed to create HTTP/1.1-only TlsClient");

    tlsclient_tstate_t *ts             = tunnelGetState(tunnel);
    SSL_CTX             *client_context = ts->threadlocal_ssl_contexts[0];
    SSL_CTX             *server_context = SSL_CTX_new(TLS_server_method());

    require(client_context != NULL && server_context != NULL &&
                SSL_CTX_set_min_proto_version(client_context, TLS1_2_VERSION) == 1 &&
                SSL_CTX_set_max_proto_version(client_context, TLS1_2_VERSION) == 1 &&
                SSL_CTX_set_min_proto_version(server_context, TLS1_2_VERSION) == 1 &&
                SSL_CTX_set_max_proto_version(server_context, TLS1_2_VERSION) == 1 &&
                SSL_CTX_use_certificate_chain_file(server_context, REALITY_TEST_CERT_FILE) == 1 &&
                SSL_CTX_use_PrivateKey_file(server_context, REALITY_TEST_KEY_FILE, SSL_FILETYPE_PEM) == 1 &&
                SSL_CTX_check_private_key(server_context) == 1,
            "failed to configure ALPN negotiation contexts");

    SSL_CTX_set_alpn_select_cb(server_context, selectHttp11, NULL);

    SSL *client = SSL_new(client_context);
    SSL *server = SSL_new(server_context);
    BIO *client_rbio = BIO_new(BIO_s_mem());
    BIO *client_wbio = BIO_new(BIO_s_mem());
    BIO *server_rbio = BIO_new(BIO_s_mem());
    BIO *server_wbio = BIO_new(BIO_s_mem());

    require(client != NULL && server != NULL && client_rbio != NULL && client_wbio != NULL &&
                server_rbio != NULL && server_wbio != NULL,
            "failed to allocate ALPN negotiation state");

    BIO_set_mem_eof_return(client_rbio, -1);
    BIO_set_mem_eof_return(client_wbio, -1);
    BIO_set_mem_eof_return(server_rbio, -1);
    BIO_set_mem_eof_return(server_wbio, -1);
    SSL_set_bio(client, client_rbio, client_wbio);
    SSL_set_bio(server, server_rbio, server_wbio);
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    require(driveHandshake(client, server), "HTTP/1.1-only ALPN handshake failed");

    const uint8_t *client_alpn = NULL;
    const uint8_t *server_alpn = NULL;
    unsigned int   client_alpn_len = 0;
    unsigned int   server_alpn_len = 0;

    SSL_get0_alpn_selected(client, &client_alpn, &client_alpn_len);
    SSL_get0_alpn_selected(server, &server_alpn, &server_alpn_len);
    require(client_alpn_len == sizeof(expected) - 1 && server_alpn_len == sizeof(expected) - 1 &&
                memoryCompare(client_alpn, expected, sizeof(expected) - 1) == 0 &&
                memoryCompare(server_alpn, expected, sizeof(expected) - 1) == 0,
            "HTTP/1.1-only TlsClient did not negotiate http/1.1");

    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(server_context);
    tlsclientTunnelDestroy(tunnel);
    GSTATE.workers_count = saved_workers_count;
    cJSON_Delete(settings);
}

int main(void)
{
    testDefaultOrder();
    testConfiguredOrder();
    testEmptyListDisablesAlpn();
    testInvalidListsAreRejected();
    testHttp11Negotiation();
    return 0;
}
