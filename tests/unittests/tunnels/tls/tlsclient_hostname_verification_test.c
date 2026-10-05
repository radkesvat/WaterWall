/*
 * Covers: TlsClient hostname and certificate-chain verification in TLS 1.2 and TLS 1.3, including the
 * explicit verify=false opt-out and TAI intermediate elision without extending root trust.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testMatchingHostnameSucceeds, testMismatchedHostnameFails,
 * testVerificationDisabledAllowsMismatch, testUntrustedCertificateFails, testTrustAnchorIntermediateElision
 * Checks: Assertion labels include: TlsClient rejected a trusted certificate with a matching DNS SAN;
 * matching TlsClient certificate verification did not return X509_V_OK; TlsClient accepted a trusted
 * certificate for an unrelated hostname; TlsClient hostname mismatch did not return
 * X509_V_ERR_HOSTNAME_MISMATCH
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tlsclient_hostname_verification_unit
 */
#include "TlsClient/structure.h"

#include <openssl/pool.h>

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
    require(tlsclientConfigureTrustAnchors(client_context), "failed to configure the real TAI certificate cache");
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

static void addCertificateExtension(X509 *certificate, int identifier, const char *value)
{
    X509_EXTENSION *extension = X509V3_EXT_nconf_nid(NULL, NULL, identifier, value);
    require(extension != NULL && X509_add_ext(certificate, extension, -1) == 1,
            "failed to add a synthetic certificate extension");
    X509_EXTENSION_free(extension);
}

static X509 *createCertificate(const char *name, EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key,
                               bool certificate_authority, bool server_name, bool expired)
{
    X509 *certificate = X509_new();
    require(certificate != NULL && X509_set_version(certificate, X509_VERSION_3) == 1 &&
                ASN1_INTEGER_set(X509_get_serialNumber(certificate), server_name ? 3 : (issuer != NULL ? 2 : 1)) == 1 &&
                X509_gmtime_adj(X509_getm_notBefore(certificate), -3600) != NULL &&
                X509_gmtime_adj(X509_getm_notAfter(certificate), expired ? -60 : 86400) != NULL &&
                X509_NAME_add_entry_by_txt(
                    X509_get_subject_name(certificate), "CN", MBSTRING_ASC, (const uint8_t *) name, -1, -1, 0) == 1 &&
                X509_set_issuer_name(certificate, X509_get_subject_name(issuer != NULL ? issuer : certificate)) == 1 &&
                X509_set_pubkey(certificate, key) == 1,
            "failed to configure a synthetic certificate");

    addCertificateExtension(
        certificate, NID_basic_constraints, certificate_authority ? "critical,CA:TRUE" : "critical,CA:FALSE");
    // Keep issuer key usage valid so the CA:false case reaches the basic-constraints check.
    addCertificateExtension(
        certificate, NID_key_usage, server_name ? "critical,digitalSignature" : "critical,keyCertSign,cRLSign");
    if (server_name)
    {
        addCertificateExtension(certificate, NID_subject_alt_name, "DNS:tls.integration.test");
        addCertificateExtension(certificate, NID_ext_key_usage, "serverAuth");
    }
    require(X509_sign(certificate, issuer_key, EVP_sha256()) > 0, "failed to sign a synthetic certificate");
    return certificate;
}

typedef struct trust_anchor_verification_probe_s
{
    STACK_OF(X509) * intermediates;
    uint32_t calls;
    bool     matched;
} trust_anchor_verification_probe_t;

static int verifyWithIntermediateProbe(X509_STORE_CTX *context, void *arg)
{
    trust_anchor_verification_probe_t *probe = arg;
    SSL                               *ssl = X509_STORE_CTX_get_ex_data(context, SSL_get_ex_data_X509_STORE_CTX_idx());
    require(ssl != NULL, "certificate callback did not retain the SSL verification context");
    probe->calls++;
    probe->matched = SSL_peer_matched_trust_anchor(ssl) != 0;

    STACK_OF(X509) *original = X509_STORE_CTX_get0_untrusted(context);
    require(sk_X509_num(original) == 1, "TAI fixture server must send only the leaf certificate");
    int result = tlsclientVerifyCertificateWithIntermediates(context, probe->intermediates);
    require(X509_STORE_CTX_get0_untrusted(context) == original && sk_X509_num(original) == 1,
            "TAI verification did not restore the borrowed peer certificate stack");
    return result;
}

static void testTrustAnchorIntermediateElision(void)
{
    static const uint8_t kRequestedAnchors[] = {1, 42};
    static const struct
    {
        const char *name;
        bool        request_anchor;
        bool        include_intermediate;
        bool        trust_root;
        bool        matching_hostname;
        bool        intermediate_is_ca;
        bool        intermediate_expired;
        long        expected_result;
    } cases[] = {
        {"tai_elided_intermediate", true, true, true, true, true, false, X509_V_OK},
        {"tai_missing_intermediate",
         true,
         false,
         true,
         true,
         true,
         false,
         X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY},
        {"tai_missing_root", true, true, false, true, true, false, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY},
        {"tai_hostname_mismatch", true, true, true, false, true, false, X509_V_ERR_HOSTNAME_MISMATCH},
        {"tai_invalid_intermediate_ca", true, true, true, true, false, false, X509_V_ERR_INVALID_CA},
        {"tai_expired_intermediate", true, true, true, true, true, true, X509_V_ERR_CERT_HAS_EXPIRED},
        {"tai_no_peer_match", false, true, true, true, true, false, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY},
    };

    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        testCaseSet(cases[i].name);
        EVP_PKEY *root_key         = EVP_PKEY_generate_from_alg(EVP_pkey_ec_p256());
        EVP_PKEY *intermediate_key = EVP_PKEY_generate_from_alg(EVP_pkey_ec_p256());
        EVP_PKEY *leaf_key         = EVP_PKEY_generate_from_alg(EVP_pkey_ec_p256());
        require(root_key != NULL && intermediate_key != NULL && leaf_key != NULL,
                "failed to generate the synthetic certificate keys");
        X509 *root         = createCertificate("TAI test root", root_key, NULL, root_key, true, false, false);
        X509 *intermediate = createCertificate("TAI test intermediate",
                                               intermediate_key,
                                               root,
                                               root_key,
                                               cases[i].intermediate_is_ca,
                                               false,
                                               cases[i].intermediate_expired);
        X509 *leaf =
            createCertificate("tls.integration.test", leaf_key, intermediate, intermediate_key, false, true, false);

        trust_anchor_verification_probe_t probe = {.intermediates = sk_X509_new_null()};
        require(probe.intermediates != NULL &&
                    (! cases[i].include_intermediate || sk_X509_push(probe.intermediates, intermediate)),
                "failed to configure the untrusted intermediate fixture");
        SSL_CTX *client_context = SSL_CTX_new(TLS_client_method());
        SSL_CTX *server_context = SSL_CTX_new(TLS_server_method());
        require(client_context != NULL && server_context != NULL, "failed to create the TAI verification contexts");
        SSL_CTX_set_verify(client_context, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_cert_verify_callback(client_context, verifyWithIntermediateProbe, &probe);
        require(
            SSL_CTX_set_min_proto_version(client_context, TLS1_3_VERSION) == 1 &&
                SSL_CTX_set_max_proto_version(client_context, TLS1_3_VERSION) == 1 &&
                SSL_CTX_set_min_proto_version(server_context, TLS1_3_VERSION) == 1 &&
                SSL_CTX_set_max_proto_version(server_context, TLS1_3_VERSION) == 1 &&
                (! cases[i].request_anchor || SSL_CTX_set1_requested_trust_anchors(
                                                  client_context, kRequestedAnchors, sizeof(kRequestedAnchors)) == 1) &&
                (! cases[i].trust_root || X509_STORE_add_cert(SSL_CTX_get_cert_store(client_context), root) == 1),
            "failed to configure TAI verification and root trust");

        uint8_t *leaf_der        = NULL;
        int      leaf_der_length = i2d_X509(leaf, &leaf_der);
        require(leaf_der_length > 0, "failed to encode the synthetic leaf certificate");
        CRYPTO_BUFFER  *leaf_buffer = CRYPTO_BUFFER_new(leaf_der, (size_t) leaf_der_length, NULL);
        SSL_CREDENTIAL *credential  = SSL_CREDENTIAL_new_x509();
        require(leaf_buffer != NULL && credential != NULL &&
                    SSL_CREDENTIAL_set1_cert_chain(credential, &leaf_buffer, 1) == 1 &&
                    SSL_CREDENTIAL_set1_private_key(credential, leaf_key) == 1 &&
                    SSL_CREDENTIAL_set1_trust_anchor_id(
                        credential, kRequestedAnchors + 1, sizeof(kRequestedAnchors) - 1) == 1,
                "failed to configure the leaf-only TAI server credential");
        SSL_CREDENTIAL_set_must_match_issuer(credential, cases[i].request_anchor);
        require(SSL_CTX_add1_credential(server_context, credential) == 1,
                "failed to install the leaf-only TAI server credential");
        SSL_CREDENTIAL_free(credential);
        CRYPTO_BUFFER_free(leaf_buffer);
        OPENSSL_free(leaf_der);

        SSL *client      = SSL_new(client_context);
        SSL *server      = SSL_new(server_context);
        BIO *client_rbio = BIO_new(BIO_s_mem());
        BIO *client_wbio = BIO_new(BIO_s_mem());
        BIO *server_rbio = BIO_new(BIO_s_mem());
        BIO *server_wbio = BIO_new(BIO_s_mem());
        require(client != NULL && server != NULL && client_rbio != NULL && client_wbio != NULL && server_rbio != NULL &&
                    server_wbio != NULL,
                "failed to allocate the TAI verification handshake");
        BIO_set_mem_eof_return(client_rbio, -1);
        BIO_set_mem_eof_return(client_wbio, -1);
        BIO_set_mem_eof_return(server_rbio, -1);
        BIO_set_mem_eof_return(server_wbio, -1);
        require(tlsclientConfigureSslForConnect(client,
                                                client_rbio,
                                                client_wbio,
                                                cases[i].matching_hostname ? "tls.integration.test"
                                                                           : "unrelated.integration.test",
                                                NULL,
                                                0),
                "failed to configure the TAI client connection");
        SSL_set_bio(server, server_rbio, server_wbio);
        SSL_set_accept_state(server);

        bool completed = driveHandshake(client, server);
        require(probe.calls == 1 && probe.matched == cases[i].request_anchor,
                "TAI verification did not observe the intended server match indication");
        const long verify_result = SSL_get_verify_result(client);
        if (completed != (cases[i].expected_result == X509_V_OK) || verify_result != cases[i].expected_result)
        {
            fprintf(stderr,
                    "TAI certificate verification: completed=%d result=%ld (%s), expected=%ld\n",
                    completed,
                    verify_result,
                    X509_verify_cert_error_string(verify_result),
                    cases[i].expected_result);
        }
        require(completed == (cases[i].expected_result == X509_V_OK) && verify_result == cases[i].expected_result,
                "TAI intermediate elision changed certificate trust, hostname, constraints, or expiry checks");

        SSL_free(client);
        SSL_free(server);
        SSL_CTX_free(client_context);
        SSL_CTX_free(server_context);
        sk_X509_free(probe.intermediates);
        X509_free(leaf);
        X509_free(intermediate);
        X509_free(root);
        EVP_PKEY_free(leaf_key);
        EVP_PKEY_free(intermediate_key);
        EVP_PKEY_free(root_key);
    }
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
    testTrustAnchorIntermediateElision();
    return 0;
}
