#include "TlsServer/structure.h"

#include "mux_tls_close_backpressure_fixture.h"

typedef struct mxb_tlsserver_private_s
{
    SSL_CTX *client_ctx;
    SSL_CTX *server_ctx;
    SSL     *client;
} mxb_tlsserver_private_t;

static mxb_fixture_t *g_mxb_tlsserver_fixture = NULL;

static tlsrecordshaping_config_t mxbTlsServerShapingConfig(void)
{
    tlsrecordshaping_config_t config = {
        .first_application_records = kTlsRecordShapingMaxApplicationRecords,
        .outcome_count             = 1,
        .sender_role               = kTlsRecordShapingSenderServer,
        .enabled                   = true,
    };
    config.outcomes[0] = (tlsrecordshaping_outcome_t) {
        .delay_ms          = {.minimum = kTlsRecordShapingMaxDelayMs, .maximum = kTlsRecordShapingMaxDelayMs},
        .probability       = 100,
        .delay_probability = 100,
        .has_delay         = true,
    };
    return config;
}

static bool mxbTlsServerTransferBio(BIO *source, BIO *destination)
{
    uint8_t bytes[16384];
    while (BIO_ctrl_pending(source) > 0)
    {
        int length = BIO_read(source, bytes, (int) sizeof(bytes));
        if (length <= 0)
        {
            return false;
        }
        int offset = 0;
        while (offset < length)
        {
            int written = BIO_write(destination, bytes + offset, length - offset);
            if (written <= 0)
            {
                return false;
            }
            offset += written;
        }
    }
    return true;
}

static bool mxbTlsServerAdvanceHandshake(SSL *ssl, bool *complete)
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

static void mxbTlsServerDriveHandshake(mxb_fixture_t *fixture, tlsserver_lstate_t *ls)
{
    mxb_tlsserver_private_t *private = fixture->tls_private;
    bool client_complete             = false;
    bool server_complete             = false;
    for (uint32_t step = 0; step < 100; ++step)
    {
        mxbRequire(mxbTlsServerAdvanceHandshake(private->client, &client_complete),
                   "in-memory TLS client handshake failed");
        mxbRequire(mxbTlsServerTransferBio(SSL_get_wbio(private->client), SSL_get_rbio(ls->ssl)),
                   "client-to-TlsServer handshake transfer failed");
        mxbRequire(mxbTlsServerAdvanceHandshake(ls->ssl, &server_complete), "in-memory TlsServer handshake failed");
        mxbRequire(mxbTlsServerTransferBio(SSL_get_wbio(ls->ssl), SSL_get_rbio(private->client)),
                   "TlsServer-to-client handshake transfer failed");
        if (client_complete && server_complete)
        {
            mxbRequire(BIO_ctrl_pending(SSL_get_wbio(ls->ssl)) == 0,
                       "TlsServer write BIO retained handshake ciphertext");
            ls->handshake_completed = true;
            return;
        }
    }
    mxbRequire(false, "in-memory TlsServer TLS 1.3 handshake did not complete");
}

static void mxbTlsServerDrainPeerPlaintext(mxb_fixture_t *fixture)
{
    mxb_tlsserver_private_t *private = fixture->tls_private;
    while (fixture->decrypted_length < fixture->decrypted_capacity)
    {
        int length = SSL_read(private->client,
                              fixture->decrypted + fixture->decrypted_length,
                              (int) min((size_t) INT_MAX, fixture->decrypted_capacity - fixture->decrypted_length));
        if (length > 0)
        {
            fixture->decrypted_length += (size_t) length;
            continue;
        }
        int error = SSL_get_error(private->client, length);
        mxbRequire(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_ZERO_RETURN,
                   "in-memory TLS client could not decrypt TlsServer output");
        return;
    }
}

static mxb_fixture_t *mxbTlsServerFixtureFromWire(tunnel_t *wire)
{
    return *(mxb_fixture_t **) tunnelGetState(wire);
}

static void mxbTlsServerWirePayload(tunnel_t *wire, line_t *line, sbuf_t *buf)
{
    mxb_fixture_t *fixture           = mxbTlsServerFixtureFromWire(wire);
    mxb_tlsserver_private_t *private = fixture->tls_private;
    ++fixture->wire_payload_calls;
    fixture->wire_payload_bytes += sbufGetLength(buf);

    const uint8_t *bytes  = sbufGetRawPtr(buf);
    uint32_t       length = sbufGetLength(buf);
    uint32_t       offset = 0;
    while (offset < length)
    {
        int written = BIO_write(SSL_get_rbio(private->client), bytes + offset, (int) (length - offset));
        mxbRequire(written > 0, "in-memory TLS client rejected TlsServer ciphertext");
        offset += (uint32_t) written;
    }
    lineReuseBuffer(line, buf);
    mxbTlsServerDrainPeerPlaintext(fixture);
}

static void mxbTlsServerWireFinish(tunnel_t *wire, line_t *line)
{
    mxb_fixture_t *fixture = mxbTlsServerFixtureFromWire(wire);
    mxbTlsServerDrainPeerPlaintext(fixture);
    ++fixture->wire_finish_calls;
    ++fixture->child_owner_finish_calls;
    fixture->decrypted_at_finish = fixture->decrypted_length;
    mxbRequire(mxbLineStateIsZero(line, fixture->mux), "MuxClient state survived the child owner's Finish");
    mxbRequire(mxbLineStateIsZero(line, fixture->tls), "TlsServer state survived the child owner's Finish");
    mxbRequire(lineIsAlive(line), "MuxClient borrowed child died before its true owner Finish");
    fixture->child_owner_destroyed = true;
    lineDestroy(line);
}

static void mxbTlsServerWireFlow(tunnel_t *wire, line_t *line)
{
    discard wire;
    discard line;
}

static void mxbTlsServerPlaintext(tunnel_t *tls, line_t *line, sbuf_t *buf)
{
    mxb_fixture_t *fixture = g_mxb_tlsserver_fixture;
    mxbRequire(fixture != NULL && fixture->tls == tls, "TlsServer plaintext wrapper lost its fixture");
    ++fixture->tls_plaintext_calls;
    fixture->tls_plaintext_bytes += sbufGetLength(buf);
    tlsserverTunnelDownStreamPayload(tls, line, buf);
}

void mxbTlsServerCreate(mxb_fixture_t *fixture)
{
    mxbRequire(g_mxb_tlsserver_fixture == NULL, "a TlsServer composition fixture is already active");
    fixture->tls  = tunnelCreate(NULL, sizeof(tlsserver_tstate_t), sizeof(tlsserver_lstate_t));
    fixture->wire = tunnelCreate(NULL, sizeof(mxb_fixture_t *), 0);
    mxbRequire(fixture->tls != NULL && fixture->wire != NULL, "failed to create TlsServer composition tunnels");
    g_mxb_tlsserver_fixture = fixture;

    fixture->tls->fnPayloadD = mxbTlsServerPlaintext;
    fixture->tls->fnFinD     = tlsserverTunnelDownStreamFinish;
    fixture->tls->fnPauseU   = tlsserverTunnelUpStreamPause;
    fixture->tls->fnResumeU  = tlsserverTunnelUpStreamResume;

    *(mxb_fixture_t **) tunnelGetState(fixture->wire) = fixture;
    fixture->wire->fnPayloadD                         = mxbTlsServerWirePayload;
    fixture->wire->fnFinD                             = mxbTlsServerWireFinish;
    fixture->wire->fnPauseD                           = mxbTlsServerWireFlow;
    fixture->wire->fnResumeD                          = mxbTlsServerWireFlow;
    tunnelBind(fixture->wire, fixture->tls);

    ((tlsserver_tstate_t *) tunnelGetState(fixture->tls))->record_shaping = mxbTlsServerShapingConfig();
}

void mxbTlsServerInitializeLine(mxb_fixture_t *fixture)
{
    mxb_tlsserver_private_t *private = memoryAllocateZero(sizeof(*private));
    mxbRequire(private != NULL, "failed to allocate TlsServer composition private state");
    fixture->tls_private = private;

    private->client_ctx = SSL_CTX_new(TLS_client_method());
    private->server_ctx = SSL_CTX_new(TLS_server_method());
    mxbRequire(private->client_ctx != NULL && private->server_ctx != NULL,
               "failed to create TlsServer composition SSL contexts");
    SSL_CTX_set_verify(private->client_ctx, SSL_VERIFY_NONE, NULL);
    mxbRequire(SSL_CTX_set_min_proto_version(private->client_ctx, TLS1_3_VERSION) == 1 &&
                   SSL_CTX_set_max_proto_version(private->client_ctx, TLS1_3_VERSION) == 1 &&
                   SSL_CTX_set_min_proto_version(private->server_ctx, TLS1_3_VERSION) == 1 &&
                   SSL_CTX_set_max_proto_version(private->server_ctx, TLS1_3_VERSION) == 1 &&
                   SSL_CTX_use_certificate_chain_file(private->server_ctx, MXB_TLS_CERT_FILE) == 1 &&
                   SSL_CTX_use_PrivateKey_file(private->server_ctx, MXB_TLS_KEY_FILE, SSL_FILETYPE_PEM) == 1,
               "failed to configure TlsServer composition SSL contexts");
    SSL_CTX_set_record_padding_callback(private->server_ctx, tlsserverRecordPaddingCallback);
    SSL_CTX_set_msg_callback(private->server_ctx, tlsserverRecordMessageCallback);

    tlsrecordshaping_config_t config = mxbTlsServerShapingConfig();
    tlsserver_lstate_t       *ls     = lineGetState(fixture->child, fixture->tls);
    mxbRequire(tlsserverLinestateInitialize(ls, private->server_ctx, fixture->env.pool, &config, false),
               "failed to initialize TlsServer composition line state");
    ls->tunnel              = fixture->tls;
    ls->line                = fixture->child;
    ls->protected_init_sent = true;

    private->client  = SSL_new(private->client_ctx);
    BIO *client_rbio = BIO_new(BIO_s_mem());
    BIO *client_wbio = BIO_new(BIO_s_mem());
    mxbRequire(private->client != NULL && client_rbio != NULL && client_wbio != NULL,
               "failed to create in-memory TLS client peer");
    BIO_set_mem_eof_return(client_rbio, -1);
    BIO_set_mem_eof_return(client_wbio, -1);
    BIO_set_mem_eof_return(SSL_get_rbio(ls->ssl), -1);
    BIO_set_mem_eof_return(SSL_get_wbio(ls->ssl), -1);
    SSL_set_bio(private->client, client_rbio, client_wbio);
    SSL_set_connect_state(private->client);
    mxbTlsServerDriveHandshake(fixture, ls);
}

void mxbTlsServerPauseWire(mxb_fixture_t *fixture)
{
    tlsserverTunnelUpStreamPause(fixture->tls, fixture->child);
}

void mxbTlsServerResumeWire(mxb_fixture_t *fixture)
{
    tlsserverTunnelUpStreamResume(fixture->tls, fixture->child);
}

bool mxbTlsServerForceReadyOutput(mxb_fixture_t *fixture)
{
    if (! lineIsAlive(fixture->child))
    {
        return false;
    }
    tlsserver_lstate_t *ls = lineGetState(fixture->child, fixture->tls);
    if (ls->tunnel != fixture->tls)
    {
        return false;
    }

    tlsserverCancelShapedOutputTimer(ls);
    bool output_ok = tlsserverDrainShapedOutput(fixture->tls, fixture->child, ls, true);
    if (! lineIsAlive(fixture->child))
    {
        return false;
    }
    ls = lineGetState(fixture->child, fixture->tls);
    if (ls->tunnel != fixture->tls)
    {
        return false;
    }
    mxbRequire(output_ok, "TlsServer could not force-drain ready shaped output");
    if (! tlsserverTryCompleteDeferredFinish(fixture->tls, fixture->child, ls))
    {
        return lineIsAlive(fixture->child);
    }
    return true;
}

size_t mxbTlsServerShapedBytes(const mxb_fixture_t *fixture)
{
    tlsserver_lstate_t *ls = lineGetState(fixture->child, fixture->tls);
    return tlsrecordshapingOutputQueueBytes(&ls->shaping_output);
}

bool mxbTlsServerProducerPaused(const mxb_fixture_t *fixture)
{
    return ((tlsserver_lstate_t *) lineGetState(fixture->child, fixture->tls))->shaping_producer_paused;
}

void mxbTlsServerDestroy(mxb_fixture_t *fixture)
{
    mxb_tlsserver_private_t *private = fixture->tls_private;
    if (fixture->child != NULL && lineIsAlive(fixture->child))
    {
        tlsserver_lstate_t *ls = lineGetState(fixture->child, fixture->tls);
        if (ls->tunnel == fixture->tls)
        {
            tlsserverLinestateDestroy(ls);
        }
    }
    SSL_free(private->client);
    SSL_CTX_free(private->client_ctx);
    SSL_CTX_free(private->server_ctx);
    memoryFree(private);
    fixture->tls_private = NULL;

    tunnelDestroy(fixture->wire);
    tunnelDestroy(fixture->tls);
    fixture->wire           = NULL;
    fixture->tls            = NULL;
    g_mxb_tlsserver_fixture = NULL;
}
