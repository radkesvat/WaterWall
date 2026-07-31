#include <openssl/err.h>
#include <openssl/ssl.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct padding_test_state_s
{
    size_t  requested;
    size_t  calls;
    size_t  last_max;
    uint8_t last_type;
} padding_test_state_t;

typedef struct tls_pair_s
{
    SSL_CTX *client_context;
    SSL_CTX *server_context;
    SSL     *client;
    SSL     *server;
} tls_pair_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        ERR_print_errors_fp(stderr);
        exit(1);
    }
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
        int offset = 0;
        while (offset < read_len)
        {
            int written = BIO_write(destination, bytes + offset, read_len - offset);
            if (written <= 0)
            {
                return false;
            }
            offset += written;
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

static void driveHandshake(tls_pair_t *pair)
{
    bool client_complete = false;
    bool server_complete = false;
    for (unsigned int step = 0; step < 100; ++step)
    {
        require(advanceHandshake(pair->client, &client_complete), "client handshake failed");
        require(transferBio(SSL_get_wbio(pair->client), SSL_get_rbio(pair->server)),
                "client handshake transfer failed");
        require(advanceHandshake(pair->server, &server_complete), "server handshake failed");
        require(transferBio(SSL_get_wbio(pair->server), SSL_get_rbio(pair->client)),
                "server handshake transfer failed");
        if (client_complete && server_complete)
        {
            return;
        }
    }
    require(false, "TLS handshake did not complete");
}

static tls_pair_t createPair(uint16_t version)
{
    tls_pair_t pair     = {0};
    pair.client_context = SSL_CTX_new(TLS_client_method());
    pair.server_context = SSL_CTX_new(TLS_server_method());
    require(pair.client_context != NULL && pair.server_context != NULL, "failed to create TLS contexts");

    SSL_CTX_set_verify(pair.client_context, SSL_VERIFY_NONE, NULL);
    require(SSL_CTX_set_min_proto_version(pair.client_context, version) == 1 &&
                SSL_CTX_set_max_proto_version(pair.client_context, version) == 1 &&
                SSL_CTX_set_min_proto_version(pair.server_context, version) == 1 &&
                SSL_CTX_set_max_proto_version(pair.server_context, version) == 1 &&
                SSL_CTX_use_certificate_chain_file(pair.server_context, TLSCLIENT_TEST_CERT_FILE) == 1 &&
                SSL_CTX_use_PrivateKey_file(pair.server_context, TLSCLIENT_TEST_KEY_FILE, SSL_FILETYPE_PEM) == 1,
            "failed to configure TLS contexts");

    pair.client      = SSL_new(pair.client_context);
    pair.server      = SSL_new(pair.server_context);
    BIO *client_rbio = BIO_new(BIO_s_mem());
    BIO *client_wbio = BIO_new(BIO_s_mem());
    BIO *server_rbio = BIO_new(BIO_s_mem());
    BIO *server_wbio = BIO_new(BIO_s_mem());
    require(pair.client != NULL && pair.server != NULL && client_rbio != NULL && client_wbio != NULL &&
                server_rbio != NULL && server_wbio != NULL,
            "failed to allocate TLS pair state");

    BIO_set_mem_eof_return(client_rbio, -1);
    BIO_set_mem_eof_return(client_wbio, -1);
    BIO_set_mem_eof_return(server_rbio, -1);
    BIO_set_mem_eof_return(server_wbio, -1);
    SSL_set_bio(pair.client, client_rbio, client_wbio);
    SSL_set_bio(pair.server, server_rbio, server_wbio);
    SSL_set_connect_state(pair.client);
    SSL_set_accept_state(pair.server);
    driveHandshake(&pair);

    require(BIO_ctrl_pending(SSL_get_wbio(pair.client)) == 0,
            "client write BIO was not empty at the application-data boundary");
    return pair;
}

static void destroyPair(tls_pair_t *pair)
{
    SSL_free(pair->client);
    SSL_free(pair->server);
    SSL_CTX_free(pair->client_context);
    SSL_CTX_free(pair->server_context);
}

static size_t paddingCallback(SSL *ssl, uint8_t type, size_t plaintext_len, size_t max_padding, void *arg)
{
    (void) ssl;
    (void) plaintext_len;
    padding_test_state_t *state = arg;
    state->calls += 1;
    state->last_max  = max_padding;
    state->last_type = type;
    return state->requested;
}

static size_t writeAndDecrypt(tls_pair_t *pair, const uint8_t *plaintext, size_t plaintext_len)
{
    require(SSL_write(pair->client, plaintext, (int) plaintext_len) == (int) plaintext_len,
            "TLS application write failed");

    size_t ciphertext_len = BIO_ctrl_pending(SSL_get_wbio(pair->client));
    require(ciphertext_len >= SSL3_RT_HEADER_LENGTH, "TLS application write emitted no record");
    require(transferBio(SSL_get_wbio(pair->client), SSL_get_rbio(pair->server)),
            "TLS application record transfer failed");

    uint8_t recovered[SSL3_RT_MAX_PLAIN_LENGTH];
    int     recovered_len = SSL_read(pair->server, recovered, (int) sizeof(recovered));
    require(recovered_len == (int) plaintext_len && memcmp(recovered, plaintext, plaintext_len) == 0,
            "peer did not recover the original application bytes");
    return ciphertext_len;
}

static size_t runCase(uint16_t version, bool install_callback, size_t requested, size_t maximum,
                      padding_test_state_t *state)
{
    tls_pair_t pair = createPair(version);
    *state          = (padding_test_state_t) {.requested = requested};
    if (install_callback)
    {
        require(SSL_set_tls13_record_padding_callback(pair.client, paddingCallback, state, maximum) == 1,
                "failed to install TLS 1.3 padding callback");
    }

    static const uint8_t plaintext[]    = "record-padding-test";
    size_t               ciphertext_len = writeAndDecrypt(&pair, plaintext, sizeof(plaintext) - 1U);
    destroyPair(&pair);
    return ciphertext_len;
}

int main(void)
{
    padding_test_state_t state;
    size_t               baseline = runCase(TLS1_3_VERSION, false, 0, 0, &state);
    require(state.calls == 0, "callback ran when it was not installed");

    size_t zero = runCase(TLS1_3_VERSION, true, 0, 4096, &state);
    require(zero == baseline && state.calls == 1, "zero padding changed the record or callback count");

    size_t fixed = runCase(TLS1_3_VERSION, true, 128, 4096, &state);
    require(fixed == baseline + 128 && state.calls == 1 && state.last_type == SSL3_RT_APPLICATION_DATA,
            "fixed TLS 1.3 padding did not add the requested ciphertext length exactly once");

    size_t capped = runCase(TLS1_3_VERSION, true, SIZE_MAX, 256, &state);
    require(capped == baseline + 256 && state.last_max == 256,
            "oversized TLS 1.3 padding was not capped to the explicit maximum");

    size_t tls12_baseline = runCase(TLS1_2_VERSION, false, 0, 0, &state);
    size_t tls12_padded   = runCase(TLS1_2_VERSION, true, 128, 4096, &state);
    require(tls12_padded == tls12_baseline && state.calls == 0,
            "TLS 1.2 output was changed by the TLS 1.3 padding callback");
    return 0;
}
