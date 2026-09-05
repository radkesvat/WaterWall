#include "TlsClient/structure.h"

#include "mux_tls_close_backpressure_fixture.h"

typedef struct mxb_tlsclient_private_s
{
    SSL_CTX *client_ctx;
    SSL_CTX *server_ctx;
    SSL     *server;
} mxb_tlsclient_private_t;

static mxb_fixture_t *g_mxb_tlsclient_fixture = NULL;

static tlsrecordshaping_config_t mxbTlsClientShapingConfig(void)
{
    tlsrecordshaping_config_t config = {
        .first_application_records = kTlsRecordShapingMaxApplicationRecords,
        .outcome_count             = 1,
        .sender_role               = kTlsRecordShapingSenderClient,
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

static bool mxbTlsClientTransferBio(BIO *source, BIO *destination)
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

static bool mxbTlsClientAdvanceHandshake(SSL *ssl, bool *complete)
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

static void mxbTlsClientDriveHandshake(mxb_fixture_t *fixture, tlsclient_lstate_t *ls)
{
    mxb_tlsclient_private_t *private = fixture->tls_private;
    bool client_complete             = false;
    bool server_complete             = false;
    for (uint32_t step = 0; step < 100; ++step)
    {
        mxbRequire(mxbTlsClientAdvanceHandshake(ls->ssl, &client_complete), "in-memory TlsClient handshake failed");
        mxbRequire(mxbTlsClientTransferBio(ls->wbio, SSL_get_rbio(private->server)),
                   "TlsClient-to-server handshake transfer failed");
        mxbRequire(mxbTlsClientAdvanceHandshake(private->server, &server_complete),
                   "in-memory TLS server handshake failed");
        mxbRequire(mxbTlsClientTransferBio(SSL_get_wbio(private->server), ls->rbio),
                   "server-to-TlsClient handshake transfer failed");
        if (client_complete && server_complete)
        {
            mxbRequire(BIO_ctrl_pending(ls->wbio) == 0, "TlsClient write BIO retained handshake ciphertext");
            ls->handshake_completed = true;
            return;
        }
    }
    mxbRequire(false, "in-memory TlsClient TLS 1.3 handshake did not complete");
}

static void mxbTlsClientDrainPeerPlaintext(mxb_fixture_t *fixture)
{
    mxb_tlsclient_private_t *private = fixture->tls_private;
    while (fixture->decrypted_length < fixture->decrypted_capacity)
    {
        int length = SSL_read(private->server,
                              fixture->decrypted + fixture->decrypted_length,
                              (int) min((size_t) INT_MAX, fixture->decrypted_capacity - fixture->decrypted_length));
        if (length > 0)
        {
            fixture->decrypted_length += (size_t) length;
            continue;
        }
        int error = SSL_get_error(private->server, length);
        mxbRequire(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_ZERO_RETURN,
                   "in-memory TLS server could not decrypt TlsClient output");
        return;
    }
}

static mxb_fixture_t *mxbTlsClientFixtureFromWire(tunnel_t *wire)
{
    return *(mxb_fixture_t **) tunnelGetState(wire);
}

static void mxbTlsClientWirePayload(tunnel_t *wire, line_t *line, sbuf_t *buf)
{
    mxb_fixture_t *fixture           = mxbTlsClientFixtureFromWire(wire);
    mxb_tlsclient_private_t *private = fixture->tls_private;
    ++fixture->wire_payload_calls;
    fixture->wire_payload_bytes += sbufGetLength(buf);

    const uint8_t *bytes  = sbufGetRawPtr(buf);
    uint32_t       length = sbufGetLength(buf);
    uint32_t       offset = 0;
    while (offset < length)
    {
        int written = BIO_write(SSL_get_rbio(private->server), bytes + offset, (int) (length - offset));
        mxbRequire(written > 0, "in-memory TLS server rejected TlsClient ciphertext");
        offset += (uint32_t) written;
    }
    lineReuseBuffer(line, buf);
    mxbTlsClientDrainPeerPlaintext(fixture);
}

static void mxbTlsClientWireFinish(tunnel_t *wire, line_t *line)
{
    mxb_fixture_t *fixture = mxbTlsClientFixtureFromWire(wire);
    mxbTlsClientDrainPeerPlaintext(fixture);
    ++fixture->wire_finish_calls;
    fixture->decrypted_at_finish = fixture->decrypted_length;
    mxbRequire(mxbLineStateIsZero(line, fixture->mux), "MuxServer state survived before wire Finish");
    mxbRequire(mxbLineStateIsZero(line, fixture->tls), "TlsClient state survived before wire Finish");
    mxbRequire(mxbMuxServerDetachedChildren(fixture) == 0 && mxbMuxServerDetachedCharge(fixture) == 0,
               "MuxServer did not unregister its owned child before nested Finish");
    mxbRequire(lineIsAlive(line), "MuxServer destroyed its owned child before the nested TlsClient Finish returned");
}

static void mxbTlsClientWireFlow(tunnel_t *wire, line_t *line)
{
    discard wire;
    discard line;
}

static void mxbTlsClientPlaintext(tunnel_t *tls, line_t *line, sbuf_t *buf)
{
    mxb_fixture_t *fixture = g_mxb_tlsclient_fixture;
    mxbRequire(fixture != NULL && fixture->tls == tls, "TlsClient plaintext wrapper lost its fixture");
    ++fixture->tls_plaintext_calls;
    fixture->tls_plaintext_bytes += sbufGetLength(buf);
    tlsclientTunnelUpStreamPayload(tls, line, buf);
}

void mxbTlsClientCreate(mxb_fixture_t *fixture)
{
    mxbRequire(g_mxb_tlsclient_fixture == NULL, "a TlsClient composition fixture is already active");
    fixture->tls  = tunnelCreate(NULL, sizeof(tlsclient_tstate_t), sizeof(tlsclient_lstate_t));
    fixture->wire = tunnelCreate(NULL, sizeof(mxb_fixture_t *), 0);
    mxbRequire(fixture->tls != NULL && fixture->wire != NULL, "failed to create TlsClient composition tunnels");
    g_mxb_tlsclient_fixture = fixture;

    fixture->tls->fnPayloadU = mxbTlsClientPlaintext;
    fixture->tls->fnFinU     = tlsclientTunnelUpStreamFinish;
    fixture->tls->fnPauseD   = tlsclientTunnelDownStreamPause;
    fixture->tls->fnResumeD  = tlsclientTunnelDownStreamResume;

    *(mxb_fixture_t **) tunnelGetState(fixture->wire) = fixture;
    fixture->wire->fnPayloadU                         = mxbTlsClientWirePayload;
    fixture->wire->fnFinU                             = mxbTlsClientWireFinish;
    fixture->wire->fnPauseU                           = mxbTlsClientWireFlow;
    fixture->wire->fnResumeU                          = mxbTlsClientWireFlow;
    tunnelBind(fixture->tls, fixture->wire);

    ((tlsclient_tstate_t *) tunnelGetState(fixture->tls))->record_shaping = mxbTlsClientShapingConfig();
}

void mxbTlsClientInitializeLine(mxb_fixture_t *fixture)
{
    mxb_tlsclient_private_t *private = memoryAllocateZero(sizeof(*private));
    mxbRequire(private != NULL, "failed to allocate TlsClient composition private state");
    fixture->tls_private = private;

    private->client_ctx = SSL_CTX_new(TLS_client_method());
    private->server_ctx = SSL_CTX_new(TLS_server_method());
    mxbRequire(private->client_ctx != NULL && private->server_ctx != NULL,
               "failed to create TlsClient composition SSL contexts");
    SSL_CTX_set_verify(private->client_ctx, SSL_VERIFY_NONE, NULL);
    mxbRequire(SSL_CTX_set_min_proto_version(private->client_ctx, TLS1_3_VERSION) == 1 &&
                   SSL_CTX_set_max_proto_version(private->client_ctx, TLS1_3_VERSION) == 1 &&
                   SSL_CTX_set_min_proto_version(private->server_ctx, TLS1_3_VERSION) == 1 &&
                   SSL_CTX_set_max_proto_version(private->server_ctx, TLS1_3_VERSION) == 1 &&
                   SSL_CTX_use_certificate_chain_file(private->server_ctx, MXB_TLS_CERT_FILE) == 1 &&
                   SSL_CTX_use_PrivateKey_file(private->server_ctx, MXB_TLS_KEY_FILE, SSL_FILETYPE_PEM) == 1,
               "failed to configure TlsClient composition SSL contexts");

    tlsrecordshaping_config_t config = mxbTlsClientShapingConfig();
    tlsclient_lstate_t       *ls     = lineGetState(fixture->child, fixture->tls);
    mxbRequire(
        tlsclientLinestateInitializeWithShaping(ls, private->client_ctx, fixture->env.pool, NULL, 0, &config, false),
        "failed to initialize TlsClient composition line state");
    ls->tunnel = fixture->tls;
    ls->line   = fixture->child;
    mxbRequire(tlsclientConfigureSslForConnect(ls->ssl, ls->rbio, ls->wbio, "localhost", NULL, 0),
               "failed to configure the in-memory TlsClient connection");

    private->server  = SSL_new(private->server_ctx);
    BIO *server_rbio = BIO_new(BIO_s_mem());
    BIO *server_wbio = BIO_new(BIO_s_mem());
    mxbRequire(private->server != NULL && server_rbio != NULL && server_wbio != NULL,
               "failed to create in-memory TLS server peer");
    BIO_set_mem_eof_return(server_rbio, -1);
    BIO_set_mem_eof_return(server_wbio, -1);
    BIO_set_mem_eof_return(ls->rbio, -1);
    BIO_set_mem_eof_return(ls->wbio, -1);
    SSL_set_bio(private->server, server_rbio, server_wbio);
    SSL_set_accept_state(private->server);
    mxbTlsClientDriveHandshake(fixture, ls);
}

void mxbTlsClientPauseWire(mxb_fixture_t *fixture)
{
    tlsclientTunnelDownStreamPause(fixture->tls, fixture->child);
}

void mxbTlsClientResumeWire(mxb_fixture_t *fixture)
{
    tlsclientTunnelDownStreamResume(fixture->tls, fixture->child);
}

bool mxbTlsClientForceReadyOutput(mxb_fixture_t *fixture)
{
    if (! lineIsAlive(fixture->child))
    {
        return false;
    }
    tlsclient_lstate_t *ls = lineGetState(fixture->child, fixture->tls);
    if (ls->tunnel != fixture->tls)
    {
        return false;
    }

    tlsclientCancelShapedOutputTimer(ls);
    bool output_ok = tlsclientDrainShapedOutput(fixture->tls, fixture->child, ls, true);
    if (! lineIsAlive(fixture->child))
    {
        return false;
    }
    ls = lineGetState(fixture->child, fixture->tls);
    if (ls->tunnel != fixture->tls)
    {
        return false;
    }
    mxbRequire(output_ok, "TlsClient could not force-drain ready shaped output");
    return true;
}

size_t mxbTlsClientShapedBytes(const mxb_fixture_t *fixture)
{
    tlsclient_lstate_t *ls = lineGetState(fixture->child, fixture->tls);
    return tlsrecordshapingOutputQueueBytes(&ls->shaping_output);
}

bool mxbTlsClientProducerPaused(const mxb_fixture_t *fixture)
{
    return ((tlsclient_lstate_t *) lineGetState(fixture->child, fixture->tls))->shaping_producer_paused;
}

void mxbTlsClientDestroy(mxb_fixture_t *fixture)
{
    mxb_tlsclient_private_t *private = fixture->tls_private;
    if (fixture->child != NULL && lineIsAlive(fixture->child))
    {
        tlsclient_lstate_t *ls = lineGetState(fixture->child, fixture->tls);
        if (ls->tunnel == fixture->tls)
        {
            tlsclientLinestateDestroy(ls);
        }
    }
    SSL_free(private->server);
    SSL_CTX_free(private->client_ctx);
    SSL_CTX_free(private->server_ctx);
    memoryFree(private);
    fixture->tls_private = NULL;

    tunnelDestroy(fixture->wire);
    tunnelDestroy(fixture->tls);
    fixture->wire           = NULL;
    fixture->tls            = NULL;
    g_mxb_tlsclient_fixture = NULL;
}
