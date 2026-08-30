#include "TlsServer/structure.h"

typedef struct tlsserver_padding_fixture_s
{
    master_pool_t      *large_master;
    master_pool_t      *small_master;
    buffer_pool_t      *pool;
    tunnel_t           *tunnel;
    SSL_CTX            *client_context;
    SSL_CTX            *server_context;
    SSL                *client;
    tlsserver_lstate_t *server_state;
} tlsserver_padding_fixture_t;

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

static void driveHandshake(tlsserver_padding_fixture_t *fixture)
{
    bool client_complete = false;
    bool server_complete = false;
    for (unsigned int step = 0; step < 100; ++step)
    {
        require(advanceHandshake(fixture->client, &client_complete), "OpenSSL client handshake failed");
        require(transferBio(SSL_get_wbio(fixture->client), SSL_get_rbio(fixture->server_state->ssl)),
                "client handshake transfer failed");
        require(advanceHandshake(fixture->server_state->ssl, &server_complete), "TlsServer OpenSSL handshake failed");
        require(transferBio(SSL_get_wbio(fixture->server_state->ssl), SSL_get_rbio(fixture->client)),
                "server handshake transfer failed");
        if (client_complete && server_complete)
        {
            fixture->server_state->handshake_completed = true;
            require(BIO_ctrl_pending(SSL_get_wbio(fixture->server_state->ssl)) == 0,
                    "server write BIO was not empty at the application-data boundary");
            return;
        }
    }
    require(false, "OpenSSL TLS handshake did not complete");
}

static tlsrecordshaping_config_t fixedConfig(void)
{
    tlsrecordshaping_config_t config = {
        .first_application_records = 1,
        .outcome_count             = 1,
        .sender_role               = kTlsRecordShapingSenderServer,
        .enabled                   = true,
    };
    config.outcomes[0] = (tlsrecordshaping_outcome_t) {
        .padding_bytes = {.minimum = 128, .maximum = 128},
        .probability   = 100,
        .has_padding   = true,
    };
    return config;
}

static tlsserver_padding_fixture_t createFixture(uint16_t version)
{
    tlsserver_padding_fixture_t fixture = {0};
    fixture.large_master                = masterpoolCreateWithCapacity(8);
    fixture.small_master                = masterpoolCreateWithCapacity(8);
    fixture.pool                        = bufferpoolCreate(fixture.large_master, fixture.small_master, 4, 32768, 1024);
    require(fixture.large_master != NULL && fixture.small_master != NULL && fixture.pool != NULL,
            "failed to create the TlsServer padding buffer pool");
    bufferpoolUpdateAllocationPaddings(fixture.pool, 64, 64);

    fixture.tunnel = tunnelCreate(NULL, sizeof(tlsserver_tstate_t), sizeof(tlsserver_lstate_t));
    require(fixture.tunnel != NULL, "failed to create the TlsServer padding tunnel");
    tlsserver_tstate_t *ts = tunnelGetState(fixture.tunnel);
    ts->record_shaping     = fixedConfig();

    fixture.client_context = SSL_CTX_new(TLS_client_method());
    fixture.server_context = SSL_CTX_new(TLS_server_method());
    require(fixture.client_context != NULL && fixture.server_context != NULL,
            "failed to create OpenSSL padding contexts");
    SSL_CTX_set_verify(fixture.client_context, SSL_VERIFY_NONE, NULL);
    require(SSL_CTX_set_min_proto_version(fixture.client_context, version) == 1 &&
                SSL_CTX_set_max_proto_version(fixture.client_context, version) == 1 &&
                SSL_CTX_set_min_proto_version(fixture.server_context, version) == 1 &&
                SSL_CTX_set_max_proto_version(fixture.server_context, version) == 1 &&
                SSL_CTX_use_certificate_chain_file(fixture.server_context, TLSSERVER_TEST_CERT_FILE) == 1 &&
                SSL_CTX_use_PrivateKey_file(fixture.server_context, TLSSERVER_TEST_KEY_FILE, SSL_FILETYPE_PEM) == 1,
            "failed to configure OpenSSL padding contexts");
    SSL_CTX_set_record_padding_callback(fixture.server_context, tlsserverRecordPaddingCallback);
    SSL_CTX_set_msg_callback(fixture.server_context, tlsserverRecordMessageCallback);

    fixture.server_state =
        memoryAllocateCacheAlignedZero(tunnelGetCorrectAlignedLineStateSize(sizeof(tlsserver_lstate_t)));
    require(fixture.server_state != NULL &&
                tlsserverLinestateInitialize(
                    fixture.server_state, fixture.server_context, fixture.pool, &ts->record_shaping, false),
            "failed to initialize TlsServer line state");
    fixture.server_state->tunnel = fixture.tunnel;

    fixture.client   = SSL_new(fixture.client_context);
    BIO *client_rbio = BIO_new(BIO_s_mem());
    BIO *client_wbio = BIO_new(BIO_s_mem());
    require(fixture.client != NULL && client_rbio != NULL && client_wbio != NULL,
            "failed to allocate OpenSSL client state");
    BIO_set_mem_eof_return(client_rbio, -1);
    BIO_set_mem_eof_return(client_wbio, -1);
    BIO_set_mem_eof_return(SSL_get_rbio(fixture.server_state->ssl), -1);
    BIO_set_mem_eof_return(SSL_get_wbio(fixture.server_state->ssl), -1);
    SSL_set_bio(fixture.client, client_rbio, client_wbio);
    SSL_set_connect_state(fixture.client);
    driveHandshake(&fixture);
    return fixture;
}

static void destroyFixture(tlsserver_padding_fixture_t *fixture)
{
    tlsserverLinestateDestroy(fixture->server_state);
    memoryFreeAligned(fixture->server_state);
    SSL_free(fixture->client);
    SSL_CTX_free(fixture->client_context);
    SSL_CTX_free(fixture->server_context);
    tunnelDestroy(fixture->tunnel);
    bufferpoolDestroy(fixture->pool);
    masterpoolMakeEmpty(fixture->large_master);
    masterpoolMakeEmpty(fixture->small_master);
    masterpoolDestroy(fixture->large_master);
    masterpoolDestroy(fixture->small_master);
}

static size_t writeAndDecrypt(tlsserver_padding_fixture_t *fixture, const uint8_t *plaintext, size_t plaintext_len)
{
    fixture->server_state->shaping_writing_application = true;
    int written = SSL_write(fixture->server_state->ssl, plaintext, (int) plaintext_len);
    fixture->server_state->shaping_writing_application = false;
    require(written == (int) plaintext_len, "TlsServer application write failed");
    size_t ciphertext_len = BIO_ctrl_pending(SSL_get_wbio(fixture->server_state->ssl));
    require(ciphertext_len >= SSL3_RT_HEADER_LENGTH, "TlsServer application write emitted no record");
    require(transferBio(SSL_get_wbio(fixture->server_state->ssl), SSL_get_rbio(fixture->client)),
            "server application record transfer failed");

    uint8_t recovered[SSL3_RT_MAX_PLAIN_LENGTH];
    int     recovered_len = SSL_read(fixture->client, recovered, (int) sizeof(recovered));
    require(recovered_len == (int) plaintext_len && memoryEqual(recovered, plaintext, plaintext_len),
            "OpenSSL peer did not recover the original padded application bytes");
    return ciphertext_len;
}

static void testTls13FullRecordStillGetsDelayMetadata(void)
{
    tlsserver_padding_fixture_t fixture   = createFixture(TLS1_3_VERSION);
    uint8_t                    *plaintext = memoryAllocate(SSL3_RT_MAX_PLAIN_LENGTH);
    memorySet(plaintext, 0x5a, SSL3_RT_MAX_PLAIN_LENGTH);

    discard writeAndDecrypt(&fixture, plaintext, SSL3_RT_MAX_PLAIN_LENGTH);
    require(fixture.server_state->shaping_state.application_records_seen == 1 &&
                fixture.server_state->shaping_state.requested_padding_bytes == 128 &&
                fixture.server_state->shaping_state.effective_padding_bytes == 0 &&
                fixture.server_state->shaping_state.records_padded == 0,
            "full TLS 1.3 record did not consume scope with safely capped padding");

    memoryFree(plaintext);
    destroyFixture(&fixture);
}

static void testTls13PaddingScopeAndAlerts(void)
{
    tlsserver_padding_fixture_t fixture     = createFixture(TLS1_3_VERSION);
    static const uint8_t        plaintext[] = "tlsserver-padding-test";

    size_t padded = writeAndDecrypt(&fixture, plaintext, sizeof(plaintext) - 1U);
    size_t normal = writeAndDecrypt(&fixture, plaintext, sizeof(plaintext) - 1U);
    require(padded == normal + 128, "fixed OpenSSL TLS 1.3 padding did not add exactly 128 bytes");
    require(fixture.server_state->shaping_state.application_records_seen == 1 &&
                fixture.server_state->shaping_state.records_padded == 1 &&
                fixture.server_state->shaping_state.effective_padding_bytes == 128,
            "TlsServer application-record scope or padding accounting changed");

    require(SSL_shutdown(fixture.server_state->ssl) >= 0, "TlsServer could not generate close_notify");
    require(BIO_ctrl_pending(SSL_get_wbio(fixture.server_state->ssl)) > 0,
            "TlsServer close_notify emitted no alert record");
    require(fixture.server_state->shaping_state.application_records_seen == 1 &&
                fixture.server_state->shaping_state.effective_padding_bytes == 128,
            "TlsServer randomly padded or counted close_notify as application data");
    destroyFixture(&fixture);
}

static void testTls12RemainsUnshaped(void)
{
    tlsserver_padding_fixture_t fixture     = createFixture(TLS1_2_VERSION);
    static const uint8_t        plaintext[] = "tls12-unshaped";
    discard                     writeAndDecrypt(&fixture, plaintext, sizeof(plaintext) - 1U);
    require(fixture.server_state->shaping_state.application_records_seen == 0 &&
                fixture.server_state->shaping_state.records_padded == 0 &&
                fixture.server_state->shaping_state.effective_padding_bytes == 0,
            "TlsServer shaping changed TLS 1.2 record generation");
    require(tlsrecordshapingOutputQueueIsEmpty(&fixture.server_state->shaping_output),
            "TlsServer created TLS 1.3 metadata during a TLS 1.2 connection");
    destroyFixture(&fixture);
}

int main(void)
{
    require(globalstateInitializeSecureRandom(), "secure random provider initialization failed");
    require(frandGlobalInit(), "fast random global initialization failed");
    frandInit();
    require(wCryptoGlobalInit() == kWCryptoOk, "OpenSSL global initialization failed");
    testTls13PaddingScopeAndAlerts();
    testTls13FullRecordStillGetsDelayMetadata();
    testTls12RemainsUnshaped();
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}
