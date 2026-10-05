#include "structure.h"

#include "loggers/network_logger.h"

static bool tlsclientAddConfiguredApplicationSettings(SSL *ssl, const uint8_t *alpn_wire, size_t alpn_wire_len)
{
    size_t offset = 0;
    while (offset < alpn_wire_len)
    {
        const size_t name_len = alpn_wire[offset++];
        assert(name_len > 0 && name_len <= alpn_wire_len - offset);

        const uint8_t *name = alpn_wire + offset;
        if (name_len == 2 && memoryCompare(name, "h2", 2) == 0)
        {
            // Chrome offers ALPS only for h2, with empty client settings. BoringSSL
            // encodes the protocol name separately in the ClientHello ALPS list.
            if (SSL_add_application_settings(ssl, name, name_len, NULL, 0) != 1)
            {
                return false;
            }
        }

        offset += name_len;
    }

    return true;
}

bool tlsclientConfigureClientHelloExtensions(SSL *ssl, const uint8_t *alpn_wire, size_t alpn_wire_len)
{
    assert(ssl != NULL);
    if (! tlsclientAddConfiguredApplicationSettings(ssl, alpn_wire, alpn_wire_len))
    {
        return false;
    }

    // Enable ECH GREASE to match Chrome's behavior.
    SSL_set_enable_ech_grease(ssl, 1);

    // Configure the remaining Chrome-like ClientHello extensions.
    SSL_enable_ocsp_stapling(ssl);
    SSL_enable_signed_cert_timestamps(ssl);
    return true;
}

/**
 * Release a line state that failed somewhere inside tlsclientLinestateInitialize().
 *
 * SSL_set_bio() has not run yet at that point, so the SSL object does not own the detached BIOs and the normal
 * tlsclientLinestateRelease() path would leak them. Each object is therefore freed by its current owner.
 */
static void tlsclientLinestateReleasePartial(tlsclient_lstate_t *ls)
{
    tlsrecordshapingOutputQueueDestroy(&ls->shaping_output);
    SSL_free(ls->ssl);
    BIO_free(ls->rbio);
    BIO_free(ls->wbio);
    bufferqueueDestroy(&(ls->bq));
    bufferbudgetReservationRelease(&ls->pending_reservation);
    bufferbudgetAssertEmpty(&ls->pending_budget);
    bufferstreamDestroy(&(ls->takeover_stream));
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tlsclient_lstate_t)));
}

bool tlsclientLinestateInitializeWithShaping(tlsclient_lstate_t *ls, SSL_CTX *sctx, buffer_pool_t *pool,
                                             const uint8_t *alpn_wire, size_t alpn_wire_len,
                                             const tlsrecordshaping_config_t *record_shaping, bool verbose)
{
    assert(alpn_wire != NULL || alpn_wire_len == 0);

    assert(ls != NULL && sctx != NULL && pool != NULL);

    *ls = (tlsclient_lstate_t) {
        .bq              = bufferqueueCreate(2),
        .takeover_stream = bufferstreamCreate(pool, 0),
        .takeover_phase  = kTlsClientTakeoverHandshake,
        .shaping_retired = false,
        .verbose         = verbose,
    };
    bufferbudgetInit(
        &ls->pending_budget,
        (buffer_budget_cost_t) {kTlsClientPendingPlaintextBytes, SIZE_MAX, kTlsClientPendingPlaintextBuffers});
    const bool attached = bufferqueueTryAttachBudget(&ls->bq, &ls->pending_budget);
    assert(attached);
    discard attached;

    if (record_shaping->enabled)
    {
        tlsrecordshapingOutputQueueInitialize(&ls->shaping_output, pool);
    }

    ls->rbio = tlsbufferbioNew(sctx, pool);
    ls->wbio = tlsbufferbioNew(sctx, pool);
    ls->ssl  = SSL_new(sctx);

    if (UNLIKELY(ls->rbio == NULL || ls->wbio == NULL || ls->ssl == NULL))
    {
        LOGE("Failed to allocate TlsClient BoringSSL line state");
        tlsclientLinestateReleasePartial(ls);
        return false;
    }

    tlsbufferbioEnableDirectWrite(ls->ssl);

    if (record_shaping->enabled && ! SSL_set_tls13_record_padding_callback(
                                       ls->ssl, tlsclientRecordPaddingCallback, ls, kTlsRecordShapingMaxPaddingBytes))
    {
        LOGE("Failed to install the TlsClient TLS 1.3 record padding callback");
        tlsclientLinestateReleasePartial(ls);
        return false;
    }

    if (! tlsclientConfigureClientHelloExtensions(ls->ssl, alpn_wire, alpn_wire_len))
    {
        LOGE("Failed to configure TlsClient ClientHello extensions");
        tlsclientLinestateReleasePartial(ls);
        return false;
    }

    return true;
}

bool tlsclientLinestateInitialize(tlsclient_lstate_t *ls, SSL_CTX *sctx, buffer_pool_t *pool, const uint8_t *alpn_wire,
                                  size_t alpn_wire_len)
{
    const tlsrecordshaping_config_t no_record_shaping = {0};
    return tlsclientLinestateInitializeWithShaping(ls, sctx, pool, alpn_wire, alpn_wire_len, &no_record_shaping, false);
}

void tlsclientLinestateRelease(tlsclient_lstate_t *ls)
{
    if (ls->resources_released)
    {
        return;
    }

    ls->resources_released = true;

    tlsclientCancelShapedOutputTimer(ls);
    if (ls->verbose &&
        (ls->shaping_state.application_records_seen > 0 || ls->shaping_state.maximum_queued_ciphertext_bytes > 0))
    {
        LOGD("TlsClient: record shaping summary eligible=%u padded=%u requested-padding=%" PRIu64
             " effective-padding=%" PRIu64 " delayed=%u max-queued=%zu",
             (unsigned int) ls->shaping_state.application_records_seen,
             (unsigned int) ls->shaping_state.records_padded,
             ls->shaping_state.requested_padding_bytes,
             ls->shaping_state.effective_padding_bytes,
             (unsigned int) ls->shaping_state.records_delayed,
             ls->shaping_state.maximum_queued_ciphertext_bytes);
    }

    tlsrecordshapingOutputQueueDestroy(&ls->shaping_output);

    discard SSL_set_tls13_record_padding_callback(ls->ssl, NULL, NULL, 0);
    SSL_free(ls->ssl); /* free the SSL object and its BIO's */
    ls->ssl  = NULL;
    ls->rbio = NULL;
    ls->wbio = NULL;
    if (ls->pending_plaintext != NULL)
    {
        lineReuseBuffer(ls->line, ls->pending_plaintext);
        ls->pending_plaintext = NULL;
    }
    bufferqueueDestroy(&(ls->bq));
    bufferbudgetReservationRelease(&ls->pending_reservation);
    bufferbudgetAssertEmpty(&ls->pending_budget);
    bufferstreamDestroy(&(ls->takeover_stream));
}

void tlsclientLinestateDestroy(tlsclient_lstate_t *ls)
{
    tlsclientLinestateRelease(ls);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tlsclient_lstate_t)));
}
