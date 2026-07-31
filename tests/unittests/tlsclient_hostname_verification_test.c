#include "TlsClient/structure.h"

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
        if (! advanceHandshake(client, &client_complete) || ! transferBio(SSL_get_wbio(client), SSL_get_rbio(server)) ||
            ! advanceHandshake(server, &server_complete) || ! transferBio(SSL_get_wbio(server), SSL_get_rbio(client)))
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

static long runHandshake(const char *hostname, bool verify, bool *completed)
{
    SSL_CTX *client_context = SSL_CTX_new(TLS_client_method());
    SSL_CTX *server_context = SSL_CTX_new(TLS_server_method());

    require(client_context != NULL && server_context != NULL, "failed to create hostname-verification TLS contexts");

    SSL_CTX_set_verify(client_context, verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);
    require(SSL_CTX_set_min_proto_version(client_context, TLS1_2_VERSION) == 1 &&
                SSL_CTX_set_max_proto_version(client_context, TLS1_2_VERSION) == 1 &&
                SSL_CTX_set_min_proto_version(server_context, TLS1_2_VERSION) == 1 &&
                SSL_CTX_set_max_proto_version(server_context, TLS1_2_VERSION) == 1 &&
                SSL_CTX_load_verify_locations(client_context, TLSCLIENT_TEST_CERT_FILE, NULL) == 1 &&
                SSL_CTX_use_certificate_chain_file(server_context, TLSCLIENT_TEST_CERT_FILE) == 1 &&
                SSL_CTX_use_PrivateKey_file(server_context, TLSCLIENT_TEST_KEY_FILE, SSL_FILETYPE_PEM) == 1 &&
                SSL_CTX_check_private_key(server_context) == 1,
            "failed to configure hostname-verification TLS contexts");

    SSL *client      = SSL_new(client_context);
    SSL *server      = SSL_new(server_context);
    BIO *client_rbio = BIO_new(BIO_s_mem());
    BIO *client_wbio = BIO_new(BIO_s_mem());
    BIO *server_rbio = BIO_new(BIO_s_mem());
    BIO *server_wbio = BIO_new(BIO_s_mem());

    require(client != NULL && server != NULL && client_rbio != NULL && client_wbio != NULL && server_rbio != NULL &&
                server_wbio != NULL,
            "failed to allocate hostname-verification TLS state");

    BIO_set_mem_eof_return(client_rbio, -1);
    BIO_set_mem_eof_return(client_wbio, -1);
    BIO_set_mem_eof_return(server_rbio, -1);
    BIO_set_mem_eof_return(server_wbio, -1);

    require(tlsclientConfigureSslForConnect(client, client_rbio, client_wbio, hostname, NULL, 0),
            "TlsClient failed to configure the client SSL object");
    SSL_set_bio(server, server_rbio, server_wbio);
    SSL_set_accept_state(server);

    *completed         = driveHandshake(client, server);
    long verify_result = SSL_get_verify_result(client);

    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(client_context);
    SSL_CTX_free(server_context);

    return verify_result;
}

static void testMatchingHostnameSucceeds(void)
{
    bool completed = false;
    long result    = runHandshake("tls.integration.test", true, &completed);

    require(completed, "TlsClient rejected a trusted certificate with a matching DNS SAN");
    require(result == X509_V_OK, "matching TlsClient certificate verification did not return X509_V_OK");
}

static void testMismatchedHostnameFails(void)
{
    bool completed = false;
    long result    = runHandshake("unrelated.integration.test", true, &completed);

    require(! completed, "TlsClient accepted a trusted certificate for an unrelated hostname");
    require(result == X509_V_ERR_HOSTNAME_MISMATCH,
            "TlsClient hostname mismatch did not return X509_V_ERR_HOSTNAME_MISMATCH");
}

static void testVerificationDisabledAllowsMismatch(void)
{
    bool completed = false;
    long result    = runHandshake("unrelated.integration.test", false, &completed);

    require(completed, "TlsClient applied fatal hostname verification when verify was disabled");
    require(result == X509_V_OK, "verify=false unexpectedly configured hostname verification");
}

int main(void)
{
    testMatchingHostnameSucceeds();
    testMismatchedHostnameFails();
    testVerificationDisabledAllowsMismatch();
    return 0;
}
