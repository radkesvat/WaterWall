/*
 * Covers: TlsClient hostname and certificate-chain verification in TLS 1.2 and TLS 1.3, including the
 * explicit verify=false opt-out.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testMatchingHostnameSucceeds, testMismatchedHostnameFails,
 * testVerificationDisabledAllowsMismatch, testUntrustedCertificateFails
 * Checks: Assertion labels include: TlsClient rejected a trusted certificate with a matching DNS SAN;
 * matching TlsClient certificate verification did not return X509_V_OK; TlsClient accepted a trusted
 * certificate for an unrelated hostname; TlsClient hostname mismatch did not return
 * X509_V_ERR_HOSTNAME_MISMATCH
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tlsclient_hostname_verification_unit
 */
#include "TlsClient/structure.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

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

static long runHandshake(uint16_t version, const char *hostname, bool verify, bool trust_certificate, bool *completed)
{
    SSL_CTX *client_context = SSL_CTX_new(TLS_client_method());
    SSL_CTX *server_context = SSL_CTX_new(TLS_server_method());

    require(client_context != NULL && server_context != NULL, "failed to create hostname-verification TLS contexts");

    SSL_CTX_set_verify(client_context, verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);
    require(SSL_CTX_set_min_proto_version(client_context, version) == 1 &&
                SSL_CTX_set_max_proto_version(client_context, version) == 1 &&
                SSL_CTX_set_min_proto_version(server_context, version) == 1 &&
                SSL_CTX_set_max_proto_version(server_context, version) == 1 &&
                (! trust_certificate ||
                 SSL_CTX_load_verify_locations(client_context, TLSCLIENT_TEST_CERT_FILE, NULL) == 1) &&
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
    if (*completed)
    {
        require(SSL_version(client) == version && SSL_version(server) == version,
                "hostname-verification fixture negotiated the wrong TLS version");
    }

    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(client_context);
    SSL_CTX_free(server_context);

    return verify_result;
}

static void testMatchingHostnameSucceeds(uint16_t version)
{
    bool completed = false;
    long result    = runHandshake(version, "tls.integration.test", true, true, &completed);

    require(completed, "TlsClient rejected a trusted certificate with a matching DNS SAN");
    require(result == X509_V_OK, "matching TlsClient certificate verification did not return X509_V_OK");
}

static void testMismatchedHostnameFails(uint16_t version)
{
    bool completed = false;
    long result    = runHandshake(version, "unrelated.integration.test", true, true, &completed);

    require(! completed, "TlsClient accepted a trusted certificate for an unrelated hostname");
    require(result == X509_V_ERR_HOSTNAME_MISMATCH,
            "TlsClient hostname mismatch did not return X509_V_ERR_HOSTNAME_MISMATCH");
}

static void testVerificationDisabledAllowsMismatch(uint16_t version)
{
    bool completed = false;
    long result    = runHandshake(version, "unrelated.integration.test", false, true, &completed);

    require(completed, "TlsClient applied fatal hostname verification when verify was disabled");
    require(result == X509_V_OK, "verify=false unexpectedly configured hostname verification");
}

static void testUntrustedCertificateFails(uint16_t version)
{
    bool completed = false;
    long result    = runHandshake(version, "tls.integration.test", true, false, &completed);

    require(! completed, "TlsClient accepted an untrusted certificate with a matching hostname");
    require(result == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
            "TlsClient did not reject the fixture's untrusted self-signed certificate chain");
}

int main(void)
{
    static const struct
    {
        uint16_t    version;
        const char *name;
    } cases[] = {
        {TLS1_2_VERSION, "tlsclient_hostname_verification_tls12"},
        {TLS1_3_VERSION, "tlsclient_hostname_verification_tls13"},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        testCaseSet(cases[i].name);
        testMatchingHostnameSucceeds(cases[i].version);
        testMismatchedHostnameFails(cases[i].version);
        testVerificationDisabledAllowsMismatch(cases[i].version);
        testUntrustedCertificateFails(cases[i].version);
    }
    return 0;
}
