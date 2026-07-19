#include "RealityClient/structure.h"

#include "reality_close_lifecycle_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * TlsClient deliberately keeps its vendored BoringSSL headers private.  This
 * lifecycle test only needs opaque handles to construct an in-memory TLS 1.3
 * peer.  Declare the prefixed entry points used by the fixture rather than
 * adding the private BoringSSL include tree to every RealityClient consumer.
 */
struct bio_method_st;
struct bio_st;
struct ssl_ctx_st;
struct ssl_method_st;
struct ssl_st;
struct tlsclient_lstate_s;

extern const struct ssl_method_st *WW_BSSL_TLS_method(void);
extern const struct ssl_method_st *WW_BSSL_TLS_server_method(void);
extern struct ssl_ctx_st          *WW_BSSL_SSL_CTX_new(const struct ssl_method_st *method);
extern void WW_BSSL_SSL_CTX_free(struct ssl_ctx_st *ctx);
extern int  WW_BSSL_SSL_CTX_set_min_proto_version(struct ssl_ctx_st *ctx, uint16_t version);
extern int  WW_BSSL_SSL_CTX_set_max_proto_version(struct ssl_ctx_st *ctx, uint16_t version);
extern int  WW_BSSL_SSL_CTX_set_num_tickets(struct ssl_ctx_st *ctx, size_t num_tickets);
extern int  WW_BSSL_SSL_CTX_use_certificate_chain_file(struct ssl_ctx_st *ctx, const char *file);
extern int  WW_BSSL_SSL_CTX_use_PrivateKey_file(struct ssl_ctx_st *ctx, const char *file, int type);
extern int  WW_BSSL_SSL_CTX_check_private_key(const struct ssl_ctx_st *ctx);
extern struct ssl_st *WW_BSSL_SSL_new(struct ssl_ctx_st *ctx);
extern void WW_BSSL_SSL_free(struct ssl_st *ssl);
extern void WW_BSSL_SSL_set_bio(struct ssl_st *ssl, struct bio_st *rbio, struct bio_st *wbio);
extern void WW_BSSL_SSL_set_accept_state(struct ssl_st *ssl);
extern int  WW_BSSL_SSL_do_handshake(struct ssl_st *ssl);
extern int  WW_BSSL_SSL_is_init_finished(const struct ssl_st *ssl);
extern int  WW_BSSL_SSL_write(struct ssl_st *ssl, const void *buf, int len);
extern int  WW_BSSL_SSL_key_update(struct ssl_st *ssl, int request_type);
extern int  WW_BSSL_SSL_set_max_send_fragment(struct ssl_st *ssl, size_t max_send_fragment);
extern const struct bio_method_st *WW_BSSL_BIO_s_mem(void);
extern struct bio_st              *WW_BSSL_BIO_new(const struct bio_method_st *method);
extern int WW_BSSL_BIO_read(struct bio_st *bio, void *buf, int len);
extern int WW_BSSL_BIO_write(struct bio_st *bio, const void *buf, int len);

/* These helpers are internal to TlsClient and intentionally absent from its
 * owner-facing interface. Opaque, type-compatible declarations keep this test
 * source independent of TlsClient's private header while remaining unity-safe. */
extern void tlsclientLinestateInitialize(struct tlsclient_lstate_s *ls,
                                         struct ssl_ctx_st *ssl_ctx,
                                         buffer_pool_t *pool);
extern void tlsclientLinestateDestroy(struct tlsclient_lstate_s *ls);
extern bool tlsclientConfigureSslForConnect(struct ssl_st *ssl,
                                            struct bio_st *rbio,
                                            struct bio_st *wbio,
                                            const char *sni,
                                            const uint8_t *ech_grease_override_payload,
                                            size_t ech_grease_override_payload_len);

enum client_tls_fixture_e
{
    kClientTls13Version       = 0x0304,
    kClientSslFiletypePem     = 1,
    kClientTlsTunnelStateSize = 128,
    kClientTlsLineStateSize   = 512,
    kClientKeyUpdateRequested = 1,
    kClientTlsRecordHeaderSize = 5,
};

/* Prefix view of tlsclient_lstate_t. Keep synchronized with TlsClient's
 * structure.h; oversized tunnel storage below avoids coupling allocation to
 * this private view. */
typedef struct client_tls_lstate_view_s
{
    void           *ssl;
    void           *rbio;
    void           *wbio;
    buffer_queue_t  bq;
    buffer_stream_t takeover_stream;
    uint32_t        takeover_phase;
    bool            handshake_completed;
    bool            handshake_est_sent;
    bool            resources_released;
    bool            post_handshake_consume_in_progress;
} client_tls_lstate_view_t;

typedef struct client_lifecycle_context_s
{
    tunnel_t *reality;
    buffer_pool_t *pool;
    char events[16];
    size_t events_len;
    bool kill_on_payload;
    bool kill_on_next_finish;
    bool reenter_peer_close;
    bool send_data_after_close;
    bool advance_kind_after_confirm;
    bool kill_on_est;
    bool kill_on_application_payload;
    bool record_tls_output_event;
    uint32_t tls_output_count;
    uint32_t tls_finish_count;
    uint8_t expected_control_kind;
    uint8_t expected_alert_type;
    uint16_t expected_alert_body_len;
    uint8_t observed_alert;
    void *tls_peer_rbio;
} client_lifecycle_context_t;

typedef struct client_lifecycle_fixture_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *pool;
    buffer_pool_t *shortcut[1];
    buffer_pool_t **saved_shortcuts;
    tunnel_t *prev;
    tunnel_t *reality;
    tunnel_t *next;
    tunnel_t *tls_owner;
    tunnel_t *tls;
    tunnel_t *tls_wire;
    line_t *line;
    void *tls_client_ctx;
    void *tls_server_ctx;
    void *tls_server_ssl;
    void *tls_server_rbio;
    void *tls_server_wbio;
    bool tls_state_initialized;
    client_lifecycle_context_t context;
} client_lifecycle_fixture_t;

static void requireClient(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void clientEvent(client_lifecycle_context_t *context, char event)
{
    requireClient(context->events_len + 1 < sizeof(context->events), "client lifecycle event overflow");
    context->events[context->events_len++] = event;
    context->events[context->events_len] = '\0';
}

static client_lifecycle_context_t *clientContext(tunnel_t *t)
{
    return *(client_lifecycle_context_t **) tunnelGetState(t);
}

static void clientPrevFinish(tunnel_t *t, line_t *l)
{
    discard l;
    clientEvent(clientContext(t), 'D');
}

static void clientPrevPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    client_lifecycle_context_t *context = clientContext(t);
    const uint8_t *payload = sbufGetRawPtr(buf);
    requireClient(sbufGetLength(buf) == 1 && payload[0] == 0x5a,
                  "client delivered the wrong application payload");
    clientEvent(context, 'A');
    bufferpoolReuseBuffer(context->pool, buf);
    discard l;
}

static void clientPrevPause(tunnel_t *t, line_t *l)
{
    discard l;
    clientEvent(clientContext(t), 'p');
}

static void clientPrevResume(tunnel_t *t, line_t *l)
{
    discard l;
    clientEvent(clientContext(t), 'r');
}

static void clientPrevEst(tunnel_t *t, line_t *l)
{
    client_lifecycle_context_t *context = clientContext(t);
    clientEvent(context, 'E');
    if (context->kill_on_est)
    {
        realityclientTunnelUpStreamFinish(context->reality, l);
        l->alive = false;
    }
}

static void clientTlsPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    client_lifecycle_context_t *context = clientContext(t);
    ++context->tls_output_count;
    if (context->tls_peer_rbio != NULL)
    {
        int len = (int) sbufGetLength(buf);
        requireClient(WW_BSSL_BIO_write(context->tls_peer_rbio,
                                        sbufGetRawPtr(buf),
                                        len) == len,
                      "client TLS handoff fixture could not forward generated protocol output");
    }
    if (context->record_tls_output_event)
    {
        clientEvent(context, 'K');
    }
    lineReuseBuffer(l, buf);
}

static void clientTlsFinish(tunnel_t *t, line_t *l)
{
    discard l;
    ++clientContext(t)->tls_finish_count;
}

static int clientLifecycleDecrypt(void *context, unsigned char *dst, const unsigned char *src,
                                  size_t src_len, const unsigned char *ad, size_t ad_len,
                                  const unsigned char *nonce, const unsigned char *key)
{
    discard context;
    return chacha20poly1305Decrypt(dst, src, src_len, ad, ad_len, nonce, key);
}

static void clientNextHandoffPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    client_lifecycle_context_t *context = clientContext(t);
    realityclient_lstate_t *ls = lineGetState(l, context->reality);
    uint8_t expected_kind = context->expected_control_kind != 0
                                ? context->expected_control_kind
                                : kRealityV2RecordKindApplicationData;
    reality_v2_record_descriptor_t descriptor;
    uint8_t plaintext[kRealityV2ControlMaxInnerPlaintext] = {0};
    uint32_t payload_offset = 0;
    uint32_t payload_len = 0;
    requireClient(realityV2BuildRecordDescriptor(ls->tls_version,
                                                  &ls->record_profile,
                                                  expected_kind,
                                                  &descriptor) &&
                      realityV2TryDecryptExpectedRecord(&descriptor,
                                                        kRealityV2DirectionClientToServer,
                                                        ls->c2s_send_seq - 1U,
                                                        ls->session_id,
                                                        ls->c2s_key,
                                                        ls->c2s_iv,
                                                        sbufGetRawPtr(buf),
                                                        sbufGetLength(buf),
                                                        clientLifecycleDecrypt,
                                                        NULL,
                                                        plaintext,
                                                        sizeof(plaintext),
                                                        &payload_offset,
                                                        &payload_len),
                  "failed to authenticate client handoff lifecycle output");

    if (context->expected_control_kind != 0)
    {
        requireClient(realityV2ParseControl(expected_kind,
                                            plaintext + payload_offset,
                                            payload_len),
                      "client handoff lifecycle emitted invalid control semantics");
        clientEvent(context,
                    expected_kind == kRealityV2RecordKindHandoffRequest ? 'R' : 'C');
        if (expected_kind == kRealityV2RecordKindHandoffConfirm &&
            context->advance_kind_after_confirm)
        {
            context->expected_control_kind = 0;
        }
    }
    else
    {
        requireClient(payload_len == 1 && plaintext[payload_offset] == 0x5a,
                      "client handoff pending flush changed application payload");
        clientEvent(context, 'Q');
    }
    memoryZero(plaintext, sizeof(plaintext));
    bufferpoolReuseBuffer(context->pool, buf);

    if (context->kill_on_payload ||
        (expected_kind == kRealityV2RecordKindApplicationData &&
         context->kill_on_application_payload))
    {
        realityclientTunnelDownStreamFinish(context->reality, l);
        l->alive = false;
    }
}

static void clientNextPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    client_lifecycle_context_t *context = clientContext(t);
    realityclient_lstate_t *ls = lineGetState(l, context->reality);
    const uint8_t *record = sbufGetRawPtr(buf);
    requireClient(sbufGetLength(buf) == (uint32_t) context->expected_alert_body_len + 5U &&
                      record[0] == context->expected_alert_type && record[1] == 0x03 &&
                      record[2] == 0x03 &&
                      (((uint16_t) record[3] << 8) | record[4]) == context->expected_alert_body_len,
                  "client final alert has the wrong TLS shape");
    reality_v2_record_descriptor_t descriptor;
    requireClient(realityV2BuildRecordDescriptor(ls->tls_version,
                                                  &ls->record_profile,
                                                  kRealityV2RecordKindAlert,
                                                  &descriptor),
                  "failed to classify client final alert");
    uint32_t body_len = ((uint32_t) record[3] << 8) | record[4];
    uint32_t ciphertext_len = body_len - descriptor.visible_prefix_len;
    const uint8_t *visible_prefix = record + kRealityV2TlsRecordHeaderSize;
    const uint8_t *ciphertext = visible_prefix + descriptor.visible_prefix_len;
    uint64_t sequence = ls->c2s_send_seq - 1;
    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadMaxSize];
    uint8_t inner[64];
    size_t aad_len = 0;
    realityV2BuildNonce(ls->c2s_iv, sequence, nonce);
    requireClient(realityV2BuildRecordAad(&descriptor,
                                          kRealityV2DirectionClientToServer,
                                          sequence,
                                          ls->session_id,
                                          record,
                                          visible_prefix,
                                          descriptor.visible_prefix_len,
                                          aad,
                                          &aad_len) &&
                      chacha20poly1305Decrypt(inner,
                                              ciphertext,
                                              ciphertext_len,
                                              aad,
                                              aad_len,
                                              nonce,
                                              ls->c2s_key) == 0,
                  "failed to decrypt client final alert");
    uint32_t payload_offset = 0;
    uint32_t payload_len = 0;
    requireClient(realityV2ValidateInnerPlaintext(&descriptor,
                                                  inner,
                                                  ciphertext_len - kRealityV2TagSize,
                                                  &payload_offset,
                                                  &payload_len) &&
                      realityV2ParseAlert(inner + payload_offset,
                                          payload_len,
                                          &context->observed_alert),
                  "failed to parse client final alert semantics");
    memoryZero(nonce, sizeof(nonce));
    memoryZero(aad, sizeof(aad));
    memoryZero(inner, sizeof(inner));
    clientEvent(context, 'P');
    bufferpoolReuseBuffer(context->pool, buf);

    realityclientTunnelDownStreamPause(context->reality, l);
    realityclientTunnelDownStreamResume(context->reality, l);

    if (context->reenter_peer_close)
    {
        realityclientHandlePeerAlert(context->reality, l, kRealityV2AlertCloseNotify);
    }

    if (context->send_data_after_close)
    {
        sbuf_t *late = bufferpoolGetSmallBuffer(context->pool);
        late = sbufReserveSpace(late, 1);
        sbufSetLength(late, 1);
        sbufGetMutablePtr(late)[0] = 0xff;
        realityclientTunnelDownStreamPayload(context->reality, l, late);
    }

    if (context->kill_on_payload)
    {
        realityclientTunnelDownStreamFinish(context->reality, l);
        l->alive = false;
    }
}

static void clientNextFinish(tunnel_t *t, line_t *l)
{
    client_lifecycle_context_t *context = clientContext(t);
    clientEvent(context, 'U');
    if (context->kill_on_next_finish)
    {
        l->alive = false;
    }
}

static void clientFixtureInitialize(client_lifecycle_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    fixture->large_master = masterpoolCreateWithCapacity(8);
    fixture->small_master = masterpoolCreateWithCapacity(8);
    fixture->pool = bufferpoolCreate(fixture->large_master, fixture->small_master, 8, 8192, 1024);
    bufferpoolUpdateAllocationPaddings(fixture->pool,
                                       kRealityClientMaxFramePrefixSize,
                                       kRealityClientMaxFramePrefixSize);
    fixture->saved_shortcuts = GSTATE.shortcut_buffer_pools;
    fixture->shortcut[0] = fixture->pool;
    GSTATE.shortcut_buffer_pools = fixture->shortcut;

    fixture->prev = tunnelCreate(NULL, sizeof(client_lifecycle_context_t *), 0);
    fixture->reality = tunnelCreate(NULL, sizeof(realityclient_tstate_t), sizeof(realityclient_lstate_t));
    fixture->next = tunnelCreate(NULL, sizeof(client_lifecycle_context_t *), 0);
    fixture->tls_owner = tunnelCreate(NULL, sizeof(client_lifecycle_context_t *), 0);
    fixture->tls = tunnelCreate(NULL, kClientTlsTunnelStateSize, kClientTlsLineStateSize);
    fixture->tls_wire = tunnelCreate(NULL, sizeof(client_lifecycle_context_t *), 0);
    requireClient(fixture->prev != NULL && fixture->reality != NULL && fixture->next != NULL &&
                      fixture->tls_owner != NULL && fixture->tls != NULL && fixture->tls_wire != NULL,
                  "failed to create client lifecycle tunnels");
    tunnelBind(fixture->prev, fixture->reality);
    tunnelBind(fixture->reality, fixture->next);
    tunnelBind(fixture->tls_owner, fixture->tls);
    tunnelBind(fixture->tls, fixture->tls_wire);
    fixture->tls->lstate_offset = fixture->reality->lstate_size;

    fixture->context = (client_lifecycle_context_t) {
        .reality = fixture->reality,
        .pool = fixture->pool,
        .expected_alert_type = 0x17,
        .expected_alert_body_len = 19,
    };
    *(client_lifecycle_context_t **) tunnelGetState(fixture->prev) = &fixture->context;
    *(client_lifecycle_context_t **) tunnelGetState(fixture->next) = &fixture->context;
    *(client_lifecycle_context_t **) tunnelGetState(fixture->tls_owner) = &fixture->context;
    *(client_lifecycle_context_t **) tunnelGetState(fixture->tls_wire) = &fixture->context;
    fixture->prev->fnFinD = clientPrevFinish;
    fixture->prev->fnEstD = clientPrevEst;
    fixture->prev->fnPayloadD = clientPrevPayload;
    fixture->prev->fnPauseD = clientPrevPause;
    fixture->prev->fnResumeD = clientPrevResume;
    fixture->next->fnPayloadU = clientNextPayload;
    fixture->next->fnFinU = clientNextFinish;
    fixture->tls_owner->fnFinD = clientTlsFinish;
    fixture->tls_wire->fnPayloadU = clientTlsPayload;
    fixture->tls_wire->fnFinU = clientTlsFinish;

    uint32_t line_size = sizeof(line_t) + fixture->reality->lstate_size + fixture->tls->lstate_size;
    fixture->line = memoryAllocateCacheAlignedZero(line_size);
    requireClient(fixture->line != NULL, "failed to allocate client lifecycle line");
    atomic_init(&fixture->line->refc, 1);
    fixture->line->alive = true;
    fixture->line->wid = 0;

    realityclient_tstate_t *ts = tunnelGetState(fixture->reality);
    ts->algorithm = kRealityClientAlgorithmChaCha20Poly1305;
    ts->tls_tunnel = fixture->tls;
    realityclient_lstate_t *ls = lineGetState(fixture->line, fixture->reality);
    realityclientLinestateInitialize(ls, fixture->pool);
    ls->record_profile = (reality_v2_record_profile_t) {
        .profile_id = kRealityV2RecordProfileTls13Aead,
        .visible_prefix_len = 0,
    };
    ls->tls_version = kRealityV2Tls13;
    ls->phase = kRealityClientPhaseRealityActive;
    ls->session_keys_ready = true;
    ls->handoff_ack_authenticated = true;
    ls->handoff_confirm_sent = true;
    ls->downstream_est_sent = true;
    memorySet(ls->session_id, 0x11, sizeof(ls->session_id));
    memorySet(ls->c2s_key, 0x22, sizeof(ls->c2s_key));
    memorySet(ls->c2s_iv, 0x33, sizeof(ls->c2s_iv));
    memorySet(ls->s2c_key, 0x44, sizeof(ls->s2c_key));
    memorySet(ls->s2c_iv, 0x55, sizeof(ls->s2c_iv));
}

static void clientFixtureSetFailureMode(client_lifecycle_fixture_t *fixture,
                                        bool kill_on_payload, bool kill_on_next_finish)
{
    fixture->context.kill_on_payload = kill_on_payload;
    fixture->context.kill_on_next_finish = kill_on_next_finish;
}

static void clientFixtureDestroy(client_lifecycle_fixture_t *fixture)
{
    realityclient_lstate_t *ls = lineGetState(fixture->line, fixture->reality);
    const uint8_t *state = (const uint8_t *) ls;
    for (uint32_t i = 0; i < fixture->reality->lstate_size; ++i)
    {
        requireClient(state[i] == 0, "client terminal path did not zero line state");
    }

    if (fixture->tls_state_initialized)
    {
        tlsclientLinestateDestroy(lineGetState(fixture->line, fixture->tls));
        fixture->tls_state_initialized = false;
    }
    const uint8_t *tls_state = lineGetState(fixture->line, fixture->tls);
    for (uint32_t i = 0; i < fixture->tls->lstate_size; ++i)
    {
        requireClient(tls_state[i] == 0, "client TLS handoff fixture did not zero retained state");
    }

    requireClient(atomic_load(&fixture->line->refc) == 1, "client lifecycle line reference leaked");
    WW_BSSL_SSL_free(fixture->tls_server_ssl);
    WW_BSSL_SSL_CTX_free(fixture->tls_server_ctx);
    WW_BSSL_SSL_CTX_free(fixture->tls_client_ctx);
    memoryFreeAligned(fixture->line);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->reality);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->tls_owner);
    tunnelDestroy(fixture->tls);
    tunnelDestroy(fixture->tls_wire);
    GSTATE.shortcut_buffer_pools = fixture->saved_shortcuts;
    bufferpoolDestroy(fixture->pool);
    masterpoolMakeEmpty(fixture->large_master);
    masterpoolMakeEmpty(fixture->small_master);
    masterpoolDestroy(fixture->large_master);
    masterpoolDestroy(fixture->small_master);
}

static void runClientScenario(void (*action)(tunnel_t *, line_t *), const char *expected,
                              bool kill_on_payload, bool kill_on_next_finish)
{
    client_lifecycle_fixture_t fixture;
    clientFixtureInitialize(&fixture);
    clientFixtureSetFailureMode(&fixture, kill_on_payload, kill_on_next_finish);
    action(fixture.reality, fixture.line);
    requireClient(strcmp(fixture.context.events, expected) == 0, "client terminal callback ordering mismatch");
    requireClient(strchr(fixture.context.events, 'p') == NULL && strchr(fixture.context.events, 'r') == NULL,
                  "client final alert reflected Pause/Resume toward a terminal side");
    clientFixtureDestroy(&fixture);
}

static void clientPeerClose(tunnel_t *t, line_t *l)
{
    realityclientHandlePeerAlert(t, l, kRealityV2AlertCloseNotify);
}

static void clientPeerFatal(tunnel_t *t, line_t *l)
{
    realityclientHandlePeerAlert(t, l, kRealityV2AlertBadRecordMac);
}

static sbuf_t *clientBufferFromBytes(client_lifecycle_fixture_t *fixture,
                                     const uint8_t *data, uint32_t len)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(fixture->pool);
    requireClient(len <= sbufGetMaximumWriteableSize(buf), "client parser fixture buffer is too small");
    buf = sbufReserveSpace(buf, len);
    sbufSetLength(buf, len);
    memoryCopy(sbufGetMutablePtr(buf), data, len);
    return buf;
}

static sbuf_t *buildClientInboundRecord(client_lifecycle_fixture_t *fixture,
                                        uint16_t tls_version,
                                        const reality_v2_record_profile_t *profile,
                                        uint8_t record_kind,
                                        const uint8_t *payload,
                                        uint32_t payload_len,
                                        uint64_t sequence)
{
    realityclient_lstate_t *ls = lineGetState(fixture->line, fixture->reality);
    reality_v2_record_descriptor_t descriptor;
    reality_v2_record_layout_t layout;
    requireClient(realityV2BuildRecordDescriptor(tls_version, profile, record_kind, &descriptor) &&
                      realityV2CalculateDescriptorLayout(&descriptor, payload_len, &layout),
                  "failed to construct client inbound descriptor");

    if (record_kind == kRealityV2RecordKindAlert)
    {
        fixture->context.expected_alert_type = descriptor.outer_content_type;
        fixture->context.expected_alert_body_len = (uint16_t) layout.wire_body_len;
    }

    uint32_t frame_len = kRealityV2TlsRecordHeaderSize + layout.wire_body_len;
    sbuf_t *buf = bufferpoolGetSmallBuffer(fixture->pool);
    requireClient(frame_len <= sbufGetMaximumWriteableSize(buf), "client inbound record is too large");
    buf = sbufReserveSpace(buf, frame_len);
    sbufSetLength(buf, frame_len);
    uint8_t *frame = sbufGetMutablePtr(buf);
    frame[0] = descriptor.outer_content_type;
    frame[1] = 0x03;
    frame[2] = 0x03;
    frame[3] = (uint8_t) (layout.wire_body_len >> 8);
    frame[4] = (uint8_t) layout.wire_body_len;
    uint8_t *visible_prefix = frame + kRealityV2TlsRecordHeaderSize;
    memorySet(visible_prefix, 0xa5, descriptor.visible_prefix_len);
    if (profile->profile_id == kRealityV2RecordProfileTls12Gcm)
    {
        realityV2WriteBe64(visible_prefix, 1 + sequence);
    }
    uint8_t *ciphertext = visible_prefix + descriptor.visible_prefix_len;
    requireClient(realityV2BuildInnerPlaintext(&descriptor,
                                                payload,
                                                payload_len,
                                                ciphertext,
                                                layout.inner_plaintext_len),
                  "failed to construct client inbound plaintext");

    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadMaxSize];
    size_t aad_len = 0;
    realityV2BuildNonce(ls->s2c_iv, sequence, nonce);
    requireClient(realityV2BuildRecordAad(&descriptor,
                                          kRealityV2DirectionServerToClient,
                                          sequence,
                                          ls->session_id,
                                          frame,
                                          visible_prefix,
                                          descriptor.visible_prefix_len,
                                          aad,
                                          &aad_len) &&
                      chacha20poly1305Encrypt(ciphertext,
                                              ciphertext,
                                              layout.inner_plaintext_len,
                                              aad,
                                              aad_len,
                                              nonce,
                                              ls->s2c_key) == 0,
                  "failed to encrypt client inbound record");
    memoryZero(nonce, sizeof(nonce));
    memoryZero(aad, sizeof(aad));
    return buf;
}

static void clientTlsCredentialPath(char *out, size_t out_size, const char *name)
{
    static const char source_marker[] = "/tests/unittests/";
    const char *marker = strstr(__FILE__, source_marker);
    requireClient(marker != NULL, "client TLS fixture cannot locate the source root");
    size_t root_len = (size_t) (marker - __FILE__);
    int n = snprintf(out,
                     out_size,
                     "%.*s/tests/cases/tls_roundtrip/%s",
                     (int) root_len,
                     __FILE__,
                     name);
    requireClient(n > 0 && (size_t) n < out_size,
                  "client TLS fixture credential path overflow");
}

static uint32_t clientTransferTlsBytes(void *from, void *to)
{
    uint8_t bytes[65536];
    uint32_t total = 0;
    while (true)
    {
        int n = WW_BSSL_BIO_read(from, bytes, (int) sizeof(bytes));
        if (n <= 0)
        {
            return total;
        }
        requireClient(WW_BSSL_BIO_write(to, bytes, n) == n,
                      "client TLS fixture failed to transfer handshake bytes");
        total += (uint32_t) n;
    }
}

static void clientFixtureEnableTls13TakeoverWithTickets(client_lifecycle_fixture_t *fixture,
                                                        size_t ticket_count)
{
    char certificate[1024];
    char private_key[1024];
    clientTlsCredentialPath(certificate, sizeof(certificate), "server.crt");
    clientTlsCredentialPath(private_key, sizeof(private_key), "server.key");

    fixture->tls_client_ctx = WW_BSSL_SSL_CTX_new(WW_BSSL_TLS_method());
    fixture->tls_server_ctx = WW_BSSL_SSL_CTX_new(WW_BSSL_TLS_server_method());
    requireClient(fixture->tls_client_ctx != NULL && fixture->tls_server_ctx != NULL,
                  "client TLS fixture failed to create contexts");
    requireClient(WW_BSSL_SSL_CTX_set_min_proto_version(fixture->tls_client_ctx,
                                                        kClientTls13Version) == 1 &&
                      WW_BSSL_SSL_CTX_set_max_proto_version(fixture->tls_client_ctx,
                                                            kClientTls13Version) == 1 &&
                      WW_BSSL_SSL_CTX_set_min_proto_version(fixture->tls_server_ctx,
                                                            kClientTls13Version) == 1 &&
                      WW_BSSL_SSL_CTX_set_max_proto_version(fixture->tls_server_ctx,
                                                            kClientTls13Version) == 1 &&
                      WW_BSSL_SSL_CTX_set_num_tickets(fixture->tls_server_ctx,
                                                     ticket_count) == 1 &&
                      WW_BSSL_SSL_CTX_use_certificate_chain_file(fixture->tls_server_ctx,
                                                                  certificate) == 1 &&
                      WW_BSSL_SSL_CTX_use_PrivateKey_file(fixture->tls_server_ctx,
                                                          private_key,
                                                          kClientSslFiletypePem) == 1 &&
                      WW_BSSL_SSL_CTX_check_private_key(fixture->tls_server_ctx) == 1,
                  "client TLS fixture failed to configure TLS 1.3 credentials");

    client_tls_lstate_view_t *tls_ls = lineGetState(fixture->line, fixture->tls);
    tlsclientLinestateInitialize((struct tlsclient_lstate_s *) tls_ls,
                                 fixture->tls_client_ctx,
                                 fixture->pool);
    fixture->tls_state_initialized = true;
    requireClient(tlsclientConfigureSslForConnect(tls_ls->ssl,
                                                   tls_ls->rbio,
                                                   tls_ls->wbio,
                                                   "example.com",
                                                   NULL,
                                                   0),
                  "client TLS fixture failed to configure the retained client");
    tlsclientTunnelEnableHandshakeTakeover(fixture->tls);

    fixture->tls_server_ssl = WW_BSSL_SSL_new(fixture->tls_server_ctx);
    fixture->tls_server_rbio = WW_BSSL_BIO_new(WW_BSSL_BIO_s_mem());
    fixture->tls_server_wbio = WW_BSSL_BIO_new(WW_BSSL_BIO_s_mem());
    requireClient(fixture->tls_server_ssl != NULL && fixture->tls_server_rbio != NULL &&
                      fixture->tls_server_wbio != NULL,
                  "client TLS fixture failed to create the in-memory server");
    if (ticket_count > 1)
    {
        requireClient(WW_BSSL_SSL_set_max_send_fragment(fixture->tls_server_ssl,
                                                        512) == 1,
                      "client TLS fixture failed to separate multiple ticket records");
    }
    WW_BSSL_SSL_set_bio(fixture->tls_server_ssl,
                        fixture->tls_server_rbio,
                        fixture->tls_server_wbio);
    WW_BSSL_SSL_set_accept_state(fixture->tls_server_ssl);
    fixture->context.tls_peer_rbio = fixture->tls_server_rbio;

    bool completed = false;
    for (uint32_t iteration = 0; iteration < 100; ++iteration)
    {
        discard WW_BSSL_SSL_do_handshake(tls_ls->ssl);
        uint32_t moved = clientTransferTlsBytes(tls_ls->wbio, fixture->tls_server_rbio);
        discard WW_BSSL_SSL_do_handshake(fixture->tls_server_ssl);
        if (WW_BSSL_SSL_is_init_finished(tls_ls->ssl) == 1 &&
            WW_BSSL_SSL_is_init_finished(fixture->tls_server_ssl) == 1)
        {
            /* Keep configured post-handshake tickets in the server write BIO.
             * They belong to the record-at-a-time handoff path, not SSL_connect. */
            completed = true;
            break;
        }
        moved += clientTransferTlsBytes(fixture->tls_server_wbio, tls_ls->rbio);
        requireClient(moved > 0,
                      "client TLS fixture handshake stalled before completion");
    }
    requireClient(completed, "client TLS fixture did not complete its TLS 1.3 handshake");

    tls_ls->handshake_completed = true;
    sbuf_t *pending_raw = NULL;
    requireClient(tlsclientTunnelBeginTakeoverDrain(fixture->tls,
                                                     fixture->line,
                                                     &pending_raw) &&
                      pending_raw == NULL,
                  "client TLS fixture failed to enter retained drain mode at a clean boundary");
}

static void clientFixtureEnableTls13Takeover(client_lifecycle_fixture_t *fixture)
{
    clientFixtureEnableTls13TakeoverWithTickets(fixture, 0);
}

static sbuf_t *clientDrainTlsServerWire(client_lifecycle_fixture_t *fixture,
                                        const char *failure_message)
{
    uint8_t wire[8192];
    int wire_len = WW_BSSL_BIO_read(fixture->tls_server_wbio,
                                    wire,
                                    (int) sizeof(wire));
    requireClient(wire_len > 0 &&
                      WW_BSSL_BIO_read(fixture->tls_server_wbio,
                                       wire,
                                       (int) sizeof(wire)) <= 0,
                  failure_message);
    sbuf_t *flight = (uint32_t) wire_len <= bufferpoolGetSmallBufferSize(fixture->pool)
                         ? bufferpoolGetSmallBuffer(fixture->pool)
                         : bufferpoolGetLargeBuffer(fixture->pool);
    requireClient((uint32_t) wire_len <= sbufGetMaximumWriteableSize(flight),
                  "client TLS server flight exceeds its pooled buffer");
    flight = sbufReserveSpace(flight, (uint32_t) wire_len);
    sbufSetLength(flight, (uint32_t) wire_len);
    memoryCopy(sbufGetMutablePtr(flight), wire, (uint32_t) wire_len);
    memoryZero(wire, sizeof(wire));
    return flight;
}

static uint32_t clientCountTlsRecords(const sbuf_t *flight)
{
    const uint8_t *bytes = sbufGetRawPtr(flight);
    uint32_t len = sbufGetLength(flight);
    uint32_t offset = 0;
    uint32_t count = 0;
    while (offset < len)
    {
        requireClient(len - offset >= kClientTlsRecordHeaderSize,
                      "client TLS flight ended in a partial header");
        uint32_t body_len = ((uint32_t) bytes[offset + 3] << 8U) |
                            (uint32_t) bytes[offset + 4];
        uint32_t record_len = kClientTlsRecordHeaderSize + body_len;
        requireClient(bytes[offset] == 0x17 && record_len <= len - offset,
                      "client TLS flight did not contain complete protected TLS 1.3 records");
        offset += record_len;
        ++count;
    }
    return count;
}

static sbuf_t *clientCopyTlsRecord(client_lifecycle_fixture_t *fixture,
                                   const sbuf_t *flight,
                                   uint32_t record_index)
{
    const uint8_t *bytes = sbufGetRawPtr(flight);
    uint32_t len = sbufGetLength(flight);
    uint32_t offset = 0;
    for (uint32_t index = 0; offset < len; ++index)
    {
        requireClient(len - offset >= kClientTlsRecordHeaderSize,
                      "client TLS record copy found a partial header");
        uint32_t body_len = ((uint32_t) bytes[offset + 3] << 8U) |
                            (uint32_t) bytes[offset + 4];
        uint32_t record_len = kClientTlsRecordHeaderSize + body_len;
        requireClient(record_len <= len - offset,
                      "client TLS record copy found a partial body");
        if (index == record_index)
        {
            return clientBufferFromBytes(fixture, bytes + offset, record_len);
        }
        offset += record_len;
    }
    requireClient(false, "client TLS record index is out of range");
    return NULL;
}

static sbuf_t *clientBuildCoverApplicationRecord(client_lifecycle_fixture_t *fixture)
{
    uint8_t plaintext[32];
    for (uint32_t i = 0; i < sizeof(plaintext); ++i)
    {
        plaintext[i] = (uint8_t) (0x80U + i);
    }
    requireClient(WW_BSSL_SSL_write(fixture->tls_server_ssl,
                                    plaintext,
                                    (int) sizeof(plaintext)) == (int) sizeof(plaintext),
                  "client TLS fixture failed to emit cover application data");

    uint8_t wire[1024];
    int wire_len = WW_BSSL_BIO_read(fixture->tls_server_wbio, wire, (int) sizeof(wire));
    requireClient(wire_len > 0 &&
                      WW_BSSL_BIO_read(fixture->tls_server_wbio, wire, (int) sizeof(wire)) <= 0,
                  "client TLS fixture emitted an unexpected cover-record flight");
    memoryZero(plaintext, sizeof(plaintext));
    return clientBufferFromBytes(fixture, wire, (uint32_t) wire_len);
}

static sbuf_t *clientBuildRequestedKeyUpdateRecord(client_lifecycle_fixture_t *fixture)
{
    requireClient(WW_BSSL_SSL_key_update(fixture->tls_server_ssl,
                                        kClientKeyUpdateRequested) == 1 &&
                      WW_BSSL_SSL_write(fixture->tls_server_ssl, NULL, 0) == 0,
                  "client TLS fixture failed to emit requested KeyUpdate");
    sbuf_t *record = clientDrainTlsServerWire(fixture,
                                              "client TLS fixture emitted no KeyUpdate record");
    requireClient(clientCountTlsRecords(record) == 1,
                  "client TLS fixture emitted an unexpected KeyUpdate flight");
    return record;
}

static sbuf_t *clientBuildHandoffAck(client_lifecycle_fixture_t *fixture)
{
    uint8_t padding[kRealityV2ControlMinPadding];
    uint8_t control[kRealityV2ControlMinPayload];
    memorySet(padding, 0xa6, sizeof(padding));
    requireClient(realityV2SerializeControl(kRealityV2RecordKindHandoffAck,
                                            padding,
                                            sizeof(padding),
                                            control,
                                            sizeof(control)),
                  "failed to serialize client ACK fixture");
    realityclient_lstate_t *ls = lineGetState(fixture->line, fixture->reality);
    sbuf_t *ack = buildClientInboundRecord(fixture,
                                           kRealityV2Tls13,
                                           &ls->record_profile,
                                           kRealityV2RecordKindHandoffAck,
                                           control,
                                           sizeof(control),
                                           0);
    memoryZero(padding, sizeof(padding));
    memoryZero(control, sizeof(control));
    return ack;
}

static sbuf_t *clientJoinRecords(client_lifecycle_fixture_t *fixture,
                                 sbuf_t *first, sbuf_t *second)
{
    uint32_t first_len = sbufGetLength(first);
    uint32_t second_len = sbufGetLength(second);
    uint32_t combined_len = first_len + second_len;
    sbuf_t *combined = bufferpoolGetSmallBuffer(fixture->pool);
    requireClient(combined_len <= sbufGetMaximumWriteableSize(combined),
                  "client coalesced handoff fixture exceeds its buffer");
    combined = sbufReserveSpace(combined, combined_len);
    sbufSetLength(combined, combined_len);
    memoryCopy(sbufGetMutablePtr(combined), sbufGetRawPtr(first), first_len);
    memoryCopy(sbufGetMutablePtr(combined) + first_len,
               sbufGetRawPtr(second),
               second_len);
    lineReuseBuffer(fixture->line, first);
    lineReuseBuffer(fixture->line, second);
    return combined;
}

static void configureClientProfile(client_lifecycle_fixture_t *fixture,
                                   uint16_t tls_version,
                                   const reality_v2_record_profile_t *profile)
{
    realityclient_lstate_t *ls = lineGetState(fixture->line, fixture->reality);
    ls->tls_version = tls_version;
    ls->record_profile = *profile;
    ls->tls12_sequences_valid = tls_version == kRealityV2Tls12;
    ls->tls12_next_write_sequence = 1;
    ls->tls12_next_read_sequence = 1;
}

static void runClientFragmentedAlert(uint16_t tls_version,
                                     const reality_v2_record_profile_t *profile)
{
    client_lifecycle_fixture_t template_fixture;
    clientFixtureInitialize(&template_fixture);
    configureClientProfile(&template_fixture, tls_version, profile);
    uint8_t alert[kRealityV2AlertMessageSize];
    requireClient(realityV2SerializeAlert(kRealityV2AlertCloseNotify, alert),
                  "failed to serialize fragmented client alert");
    sbuf_t *whole = buildClientInboundRecord(&template_fixture,
                                             tls_version,
                                             profile,
                                             kRealityV2RecordKindAlert,
                                             alert,
                                             sizeof(alert),
                                             0);
    uint32_t whole_len = sbufGetLength(whole);
    uint8_t record[64];
    requireClient(whole_len <= sizeof(record), "fragmented client alert fixture overflow");
    memoryCopy(record, sbufGetRawPtr(whole), whole_len);
    lineReuseBuffer(template_fixture.line, whole);
    realityclientLinestateDestroy(lineGetState(template_fixture.line, template_fixture.reality));
    clientFixtureDestroy(&template_fixture);

    for (uint32_t split = 1; split < whole_len; ++split)
    {
        client_lifecycle_fixture_t fixture;
        clientFixtureInitialize(&fixture);
        configureClientProfile(&fixture, tls_version, profile);
        reality_v2_record_descriptor_t descriptor;
        reality_v2_record_layout_t layout;
        requireClient(realityV2BuildRecordDescriptor(tls_version,
                                                      profile,
                                                      kRealityV2RecordKindAlert,
                                                      &descriptor) &&
                          realityV2CalculateDescriptorLayout(&descriptor, sizeof(alert), &layout),
                      "failed to restore fragmented client alert shape");
        fixture.context.expected_alert_type = descriptor.outer_content_type;
        fixture.context.expected_alert_body_len = (uint16_t) layout.wire_body_len;
        requireClient(realityclientProcessDownstream(fixture.reality,
                                                     fixture.line,
                                                     clientBufferFromBytes(&fixture, record, split)),
                      "client rejected an incomplete alert fragment");
        requireClient(fixture.context.events_len == 0,
                      "client emitted callbacks before the alert was complete");
        requireClient(! realityclientProcessDownstream(
                          fixture.reality,
                          fixture.line,
                          clientBufferFromBytes(&fixture, record + split, whole_len - split)),
                      "client did not terminate after a complete fragmented alert");
        requireClient(strcmp(fixture.context.events, "UD") == 0,
                      "client fragmented close_notify did not close both sides immediately");
        clientFixtureDestroy(&fixture);
    }
}

static void testClientCoalescedRecords(uint16_t tls_version,
                                       const reality_v2_record_profile_t *profile,
                                       bool alert_first)
{
    client_lifecycle_fixture_t fixture;
    clientFixtureInitialize(&fixture);
    configureClientProfile(&fixture, tls_version, profile);
    uint8_t alert[kRealityV2AlertMessageSize];
    uint8_t application = 0x5a;
    requireClient(realityV2SerializeAlert(kRealityV2AlertCloseNotify, alert),
                  "failed to serialize coalesced client alert");
    sbuf_t *first = buildClientInboundRecord(&fixture,
                                             tls_version,
                                             profile,
                                             alert_first ? kRealityV2RecordKindAlert
                                                         : kRealityV2RecordKindApplicationData,
                                             alert_first ? alert : &application,
                                             alert_first ? sizeof(alert) : sizeof(application),
                                             0);
    sbuf_t *second = buildClientInboundRecord(&fixture,
                                              tls_version,
                                              profile,
                                              alert_first ? kRealityV2RecordKindApplicationData
                                                          : kRealityV2RecordKindAlert,
                                              alert_first ? &application : alert,
                                              alert_first ? sizeof(application) : sizeof(alert),
                                              1);
    uint32_t combined_len = sbufGetLength(first) + sbufGetLength(second);
    uint8_t combined[128];
    requireClient(combined_len <= sizeof(combined), "coalesced client fixture overflow");
    memoryCopy(combined, sbufGetRawPtr(first), sbufGetLength(first));
    memoryCopy(combined + sbufGetLength(first), sbufGetRawPtr(second), sbufGetLength(second));
    lineReuseBuffer(fixture.line, first);
    lineReuseBuffer(fixture.line, second);
    requireClient(! realityclientProcessDownstream(fixture.reality,
                                                   fixture.line,
                                                   clientBufferFromBytes(&fixture,
                                                                         combined,
                                                                         combined_len)),
                  "client did not terminate after a coalesced alert");
    requireClient(strcmp(fixture.context.events, alert_first ? "UD" : "AUD") == 0,
                  "client coalesced close_notify did not close immediately or discarded trailing data incorrectly");
    clientFixtureDestroy(&fixture);
}

static void testClientTerminalReentry(void)
{
    client_lifecycle_fixture_t fixture;
    clientFixtureInitialize(&fixture);
    fixture.context.reenter_peer_close = true;
    fixture.context.send_data_after_close = true;
    realityclientFailAuthenticated(fixture.reality, fixture.line);
    requireClient(strcmp(fixture.context.events, "PUD") == 0,
                  "client fatal terminal re-entry emitted duplicate callbacks");
    requireClient(fixture.context.observed_alert == kRealityV2AlertBadRecordMac,
                  "client orderly close displaced an in-progress fatal alert");
    clientFixtureDestroy(&fixture);
}

static void testClientSecureRandomFailure(void)
{
    const reality_v2_record_profile_t profile = {
        kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20};
    client_lifecycle_fixture_t fixture;
    clientFixtureInitialize(&fixture);
    configureClientProfile(&fixture, kRealityV2Tls12, &profile);

    const bool random_was_initialized = GSTATE.secure_random.initialized;
    GSTATE.secure_random.initialized = false;
    realityclientFailAuthenticated(fixture.reality, fixture.line);
    GSTATE.secure_random.initialized = random_was_initialized;

    requireClient(strcmp(fixture.context.events, "UD") == 0,
                  "client random failure did not close without emitting a partial alert");
    requireClient(fixture.context.observed_alert == kRealityV2AlertInvalid,
                  "client random failure exposed an alert frame");
    clientFixtureDestroy(&fixture);
}

static void configureClientAwaitAck(client_lifecycle_fixture_t *fixture, bool request_already_sent)
{
    realityclient_lstate_t *ls = lineGetState(fixture->line, fixture->reality);
    ls->phase = kRealityClientPhaseTls13AwaitAck;
    ls->handoff_request_sent = request_already_sent;
    ls->handoff_ack_authenticated = false;
    ls->handoff_confirm_sent = false;
    ls->handoff_cover_consume_in_progress = false;
    ls->handoff_completion_in_progress = false;
    ls->downstream_est_sent = false;
    ls->c2s_send_seq = request_already_sent ? 1 : 0;
    ls->s2c_recv_seq = 0;
}

static sbuf_t *clientOneBytePayload(client_lifecycle_fixture_t *fixture)
{
    const uint8_t payload = 0x5a;
    return clientBufferFromBytes(fixture, &payload, sizeof(payload));
}

static void testClientHandoffRequestAndQueue(void)
{
    client_lifecycle_fixture_t fixture;
    clientFixtureInitialize(&fixture);
    configureClientAwaitAck(&fixture, false);
    fixture.next->fnPayloadU = clientNextHandoffPayload;
    fixture.context.expected_control_kind = kRealityV2RecordKindHandoffRequest;

    requireClient(realityclientSendHandoffControl(fixture.reality,
                                                   fixture.line,
                                                   kRealityV2RecordKindHandoffRequest),
                  "client failed to send handoff request");
    realityclient_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    requireClient(strcmp(fixture.context.events, "R") == 0 &&
                      ls->handoff_request_sent && ls->c2s_send_seq == 1,
                  "client did not send exactly one sequence-zero request");
    requireClient(! realityclientSendHandoffControl(fixture.reality,
                                                    fixture.line,
                                                    kRealityV2RecordKindHandoffRequest) &&
                      ls->c2s_send_seq == 1 && strcmp(fixture.context.events, "R") == 0,
                  "client sent a duplicate handoff request");

    realityclientTunnelUpStreamPayload(fixture.reality,
                                       fixture.line,
                                       clientOneBytePayload(&fixture));
    requireClient(bufferqueueGetBufCount(&ls->pending_up) == 1 &&
                      strcmp(fixture.context.events, "R") == 0,
                  "client released application data before ACK");

    realityclientHandleUpstreamFinish(fixture.reality, fixture.line);
    requireClient(strcmp(fixture.context.events, "RU") == 0,
                  "client pre-ACK local finish emitted a Reality alert or reflected close");
    clientFixtureDestroy(&fixture);
}

static void testClientConfirmEstAndFlushOrdering(void)
{
    client_lifecycle_fixture_t fixture;
    clientFixtureInitialize(&fixture);
    realityclient_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    ls->phase = kRealityClientPhaseRealityActive;
    ls->handoff_request_sent = true;
    ls->handoff_ack_authenticated = true;
    ls->handoff_confirm_sent = false;
    ls->handoff_completion_in_progress = true;
    ls->downstream_est_sent = false;
    ls->c2s_send_seq = 1;
    ls->s2c_recv_seq = 1;
    fixture.next->fnPayloadU = clientNextHandoffPayload;

    realityclientTunnelUpStreamPayload(fixture.reality,
                                       fixture.line,
                                       clientOneBytePayload(&fixture));
    requireClient(bufferqueueGetBufCount(&ls->pending_up) == 1,
                  "client did not queue application during ACK completion");

    fixture.context.expected_control_kind = kRealityV2RecordKindHandoffConfirm;
    requireClient(realityclientSendHandoffControl(fixture.reality,
                                                   fixture.line,
                                                   kRealityV2RecordKindHandoffConfirm),
                  "client failed to send handoff confirmation");
    ls = lineGetState(fixture.line, fixture.reality);
    requireClient(ls->handoff_confirm_sent && ls->c2s_send_seq == 2 &&
                      strcmp(fixture.context.events, "C") == 0,
                  "client confirmation did not consume c2s sequence one");

    ls->downstream_est_sent = true;
    tunnelPrevDownStreamEst(fixture.reality, fixture.line);
    fixture.context.expected_control_kind = 0;
    requireClient(realityclientFlushPendingUpstream(fixture.reality, fixture.line),
                  "client failed to flush queued application after confirmation");
    ls = lineGetState(fixture.line, fixture.reality);
    ls->handoff_completion_in_progress = false;
    requireClient(strcmp(fixture.context.events, "CEQ") == 0 &&
                      ls->c2s_send_seq == 3 &&
                      bufferqueueGetBufCount(&ls->pending_up) == 0,
                  "client did not preserve CONFIRM -> Est -> queued-application order");

    realityclientHandleUpstreamFinish(fixture.reality, fixture.line);
    requireClient(strcmp(fixture.context.events, "CEQU") == 0,
                  "client handoff ordering fixture did not close cleanly");
    clientFixtureDestroy(&fixture);
}

static void testClientNestedAckIsDeferredDuringCoverConsume(void)
{
    client_lifecycle_fixture_t fixture;
    clientFixtureInitialize(&fixture);
    configureClientAwaitAck(&fixture, true);

    uint8_t padding[kRealityV2ControlMinPadding];
    uint8_t control[kRealityV2ControlMinPayload];
    memorySet(padding, 0xa6, sizeof(padding));
    requireClient(realityV2SerializeControl(kRealityV2RecordKindHandoffAck,
                                            padding,
                                            sizeof(padding),
                                            control,
                                            sizeof(control)),
                  "failed to serialize nested client ACK fixture");

    realityclient_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    sbuf_t *ack = buildClientInboundRecord(&fixture,
                                           kRealityV2Tls13,
                                           &ls->record_profile,
                                           kRealityV2RecordKindHandoffAck,
                                           control,
                                           sizeof(control),
                                           0);
    uint32_t ack_len = sbufGetLength(ack);
    ls->handoff_cover_consume_in_progress = true;

    requireClient(realityclientProcessHandoffDownstream(fixture.reality,
                                                        fixture.line,
                                                        ack),
                  "client rejected a nested ACK while cover consume owned TLS state");
    ls = lineGetState(fixture.line, fixture.reality);
    requireClient(ls->phase == kRealityClientPhaseTls13AwaitAck &&
                      ls->handoff_cover_consume_in_progress &&
                      ! ls->handoff_ack_authenticated && ! ls->handoff_confirm_sent &&
                      ls->s2c_recv_seq == 0 && ls->c2s_send_seq == 1 &&
                      bufferstreamGetBufLen(&ls->handoff_stream) == ack_len &&
                      fixture.context.events_len == 0,
                  "nested ACK completed takeover or advanced state before cover consume returned");

    ls->handoff_cover_consume_in_progress = false;
    requireClient(bufferstreamGetBufLen(&ls->handoff_stream) == ack_len,
                  "clearing the cover-consume guard lost the deferred ACK");
    realityclientHandleUpstreamFinish(fixture.reality, fixture.line);
    requireClient(strcmp(fixture.context.events, "U") == 0,
                  "deferred nested ACK fixture did not close without emitting a control");
    memoryZero(padding, sizeof(padding));
    memoryZero(control, sizeof(control));
    clientFixtureDestroy(&fixture);
}

static void testClientFailedAckDelegatesOriginalCoverRecord(void)
{
    client_lifecycle_fixture_t fixture;
    clientFixtureInitialize(&fixture);
    configureClientAwaitAck(&fixture, true);
    clientFixtureEnableTls13Takeover(&fixture);

    sbuf_t *cover_record = clientBuildCoverApplicationRecord(&fixture);
    uint32_t cover_len = sbufGetLength(cover_record);
    uint8_t cover_snapshot[1024];
    requireClient(cover_len <= sizeof(cover_snapshot),
                  "client cover-record snapshot overflow");
    memoryCopy(cover_snapshot, sbufGetRawPtr(cover_record), cover_len);

    realityclientTunnelDownStreamPayload(fixture.reality, fixture.line, cover_record);
    realityclient_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    client_tls_lstate_view_t *tls_ls = lineGetState(fixture.line, fixture.tls);
    requireClient(ls->phase == kRealityClientPhaseTls13AwaitAck &&
                      ! ls->handoff_ack_authenticated && ! ls->handoff_confirm_sent &&
                      ls->s2c_recv_seq == 0 && ls->c2s_send_seq == 1 &&
                      bufferstreamIsEmpty(&ls->handoff_stream),
                  "failed ACK trial advanced Reality state or retained the cover record");
    requireClient(tls_ls->takeover_phase == 1U && ! tls_ls->resources_released &&
                      fixture.context.tls_output_count == 0 &&
                      fixture.context.tls_finish_count == 0 &&
                      fixture.context.events_len == 0,
                  "failed ACK trial did not delegate the original record cleanly to TLS");

    /* The record carried valid TLS 1.3 ciphertext of a control-plausible public
     * length. BoringSSL accepting it proves the duplicate ACK trial did not
     * mutate the owner record before delegation. */
    requireClient(cover_snapshot[0] == 0x17 && cover_snapshot[1] == 0x03 &&
                      cover_snapshot[2] == 0x03 && cover_len >= 5U + 22U,
                  "client cover record did not exercise the ACK candidate range");
    memoryZero(cover_snapshot, sizeof(cover_snapshot));

    realityclientHandleUpstreamFinish(fixture.reality, fixture.line);
    requireClient(strcmp(fixture.context.events, "U") == 0,
                  "client cover-delegation fixture did not close cleanly");
    clientFixtureDestroy(&fixture);
}

static void testClientRequestedKeyUpdateResponsePrecedesConfirm(void)
{
    client_lifecycle_fixture_t fixture;
    clientFixtureInitialize(&fixture);
    configureClientAwaitAck(&fixture, true);
    clientFixtureEnableTls13Takeover(&fixture);
    fixture.next->fnPayloadU = clientNextHandoffPayload;
    fixture.context.expected_control_kind = kRealityV2RecordKindHandoffConfirm;
    fixture.context.record_tls_output_event = true;

    sbuf_t *requested_key_update = clientBuildRequestedKeyUpdateRecord(&fixture);
    sbuf_t *ack = clientBuildHandoffAck(&fixture);
    realityclientTunnelDownStreamPayload(fixture.reality,
                                         fixture.line,
                                         clientJoinRecords(&fixture,
                                                           requested_key_update,
                                                           ack));

    realityclient_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    client_tls_lstate_view_t *tls_ls = lineGetState(fixture.line, fixture.tls);
    requireClient(strcmp(fixture.context.events, "KCE") == 0 &&
                      fixture.context.tls_output_count == 1 &&
                      ls->phase == kRealityClientPhaseRealityActive &&
                      ls->handoff_ack_authenticated && ls->handoff_confirm_sent &&
                      ls->downstream_est_sent && ls->c2s_send_seq == 2 &&
                      ls->s2c_recv_seq == 1 &&
                      tls_ls->resources_released && tls_ls->ssl == NULL,
                  "requested KeyUpdate response was not forwarded before HANDOFF_CONFIRM");

    realityclientHandleUpstreamFinish(fixture.reality, fixture.line);
    requireClient(strcmp(fixture.context.events, "KCEU") == 0,
                  "requested-KeyUpdate ordering fixture did not close cleanly");
    clientFixtureDestroy(&fixture);
}

static void testClientFragmentedTicketsThenCoalescedAck(void)
{
    client_lifecycle_fixture_t fixture;
    clientFixtureInitialize(&fixture);
    configureClientAwaitAck(&fixture, true);
    clientFixtureEnableTls13TakeoverWithTickets(&fixture, 3);
    fixture.next->fnPayloadU = clientNextHandoffPayload;
    fixture.context.expected_control_kind = kRealityV2RecordKindHandoffConfirm;

    requireClient(WW_BSSL_SSL_write(fixture.tls_server_ssl, NULL, 0) == 0,
                  "client TLS fixture could not flush configured tickets");
    sbuf_t *ticket_flight = clientDrainTlsServerWire(&fixture,
                                                     "client TLS fixture emitted no ticket flight");
    requireClient(clientCountTlsRecords(ticket_flight) == 2,
                  "client TLS fixture did not emit multiple distinct ticket-bearing records");
    sbuf_t *first_ticket_record = clientCopyTlsRecord(&fixture, ticket_flight, 0);
    const uint8_t *first_bytes = sbufGetRawPtr(first_ticket_record);
    uint32_t first_len = sbufGetLength(first_ticket_record);
    for (uint32_t i = 0; i < first_len; ++i)
    {
        realityclientTunnelDownStreamPayload(fixture.reality,
                                             fixture.line,
                                             clientBufferFromBytes(&fixture,
                                                                   first_bytes + i,
                                                                   1));
        requireClient(lineIsAlive(fixture.line),
                      "client closed on a fragmented genuine ticket record");
    }
    lineReuseBuffer(fixture.line, first_ticket_record);

    realityclient_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    requireClient(ls->phase == kRealityClientPhaseTls13AwaitAck &&
                      ! ls->handoff_ack_authenticated && ls->s2c_recv_seq == 0 &&
                      ls->c2s_send_seq == 1 && fixture.context.events_len == 0 &&
                      bufferstreamIsEmpty(&ls->handoff_stream),
                  "fragmented ticket record advanced Reality authentication state");

    sbuf_t *second_ticket_record = clientCopyTlsRecord(&fixture, ticket_flight, 1);
    lineReuseBuffer(fixture.line, ticket_flight);
    realityclientTunnelDownStreamPayload(fixture.reality,
                                         fixture.line,
                                         clientJoinRecords(&fixture,
                                                           second_ticket_record,
                                                           clientBuildHandoffAck(&fixture)));

    ls = lineGetState(fixture.line, fixture.reality);
    client_tls_lstate_view_t *tls_ls = lineGetState(fixture.line, fixture.tls);
    requireClient(strcmp(fixture.context.events, "CE") == 0 &&
                      fixture.context.tls_output_count == 0 &&
                      ls->phase == kRealityClientPhaseRealityActive &&
                      ls->handoff_ack_authenticated && ls->handoff_confirm_sent &&
                      ls->c2s_send_seq == 2 && ls->s2c_recv_seq == 1 &&
                      bufferstreamIsEmpty(&ls->handoff_stream) &&
                      tls_ls->resources_released && tls_ls->ssl == NULL,
                  "multiple fragmented tickets plus coalesced ACK did not complete handoff once");

    realityclientHandleUpstreamFinish(fixture.reality, fixture.line);
    requireClient(strcmp(fixture.context.events, "CEU") == 0,
                  "fragmented-ticket handoff fixture did not close cleanly");
    clientFixtureDestroy(&fixture);
}

static void testClientAckCoalescedApplicationCompletesHandoff(void)
{
    client_lifecycle_fixture_t fixture;
    clientFixtureInitialize(&fixture);
    configureClientAwaitAck(&fixture, true);
    clientFixtureEnableTls13Takeover(&fixture);
    fixture.next->fnPayloadU = clientNextHandoffPayload;
    fixture.context.expected_control_kind = kRealityV2RecordKindHandoffConfirm;
    fixture.context.advance_kind_after_confirm = true;

    realityclientTunnelUpStreamPayload(fixture.reality,
                                       fixture.line,
                                       clientOneBytePayload(&fixture));
    realityclient_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    requireClient(bufferqueueGetBufCount(&ls->pending_up) == 1,
                  "client ACK transition fixture did not queue local application data");

    const uint8_t server_application = 0x5a;
    sbuf_t *ack = clientBuildHandoffAck(&fixture);
    sbuf_t *application = buildClientInboundRecord(&fixture,
                                                   kRealityV2Tls13,
                                                   &ls->record_profile,
                                                   kRealityV2RecordKindApplicationData,
                                                   &server_application,
                                                   sizeof(server_application),
                                                   1);
    realityclientTunnelDownStreamPayload(fixture.reality,
                                         fixture.line,
                                         clientJoinRecords(&fixture, ack, application));

    ls = lineGetState(fixture.line, fixture.reality);
    client_tls_lstate_view_t *tls_ls = lineGetState(fixture.line, fixture.tls);
    requireClient(strcmp(fixture.context.events, "CEQA") == 0 &&
                      ls->phase == kRealityClientPhaseRealityActive &&
                      ls->handoff_ack_authenticated && ls->handoff_confirm_sent &&
                      ls->downstream_est_sent && ! ls->handoff_completion_in_progress &&
                      ls->c2s_send_seq == 3 && ls->s2c_recv_seq == 2 &&
                      bufferqueueGetBufCount(&ls->pending_up) == 0 &&
                      bufferstreamIsEmpty(&ls->handoff_stream) &&
                      bufferstreamIsEmpty(&ls->read_stream),
                  "encrypted ACK did not preserve CONFIRM -> Est -> queued-up -> coalesced-down ordering");
    requireClient(tls_ls->resources_released && tls_ls->takeover_phase == 2U &&
                      tls_ls->ssl == NULL && fixture.context.tls_finish_count == 0,
                  "authenticated ACK did not release retained TLS exactly once");

    realityclientHandleUpstreamFinish(fixture.reality, fixture.line);
    requireClient(strcmp(fixture.context.events, "CEQAU") == 0,
                  "client authenticated handoff fixture did not close cleanly");
    clientFixtureDestroy(&fixture);
}

typedef enum client_ack_death_point_e
{
    kClientAckDeathDuringConfirm = 0,
    kClientAckDeathDuringEst,
    kClientAckDeathDuringPendingFlush,
} client_ack_death_point_t;

static void runClientAckTransitionLineDeath(client_ack_death_point_t death_point,
                                            const char *expected_events)
{
    client_lifecycle_fixture_t fixture;
    clientFixtureInitialize(&fixture);
    configureClientAwaitAck(&fixture, true);
    clientFixtureEnableTls13Takeover(&fixture);
    fixture.next->fnPayloadU = clientNextHandoffPayload;
    fixture.context.expected_control_kind = kRealityV2RecordKindHandoffConfirm;

    if (death_point == kClientAckDeathDuringConfirm)
    {
        fixture.context.kill_on_payload = true;
    }
    else if (death_point == kClientAckDeathDuringEst)
    {
        fixture.context.kill_on_est = true;
    }
    else
    {
        fixture.context.advance_kind_after_confirm = true;
        fixture.context.kill_on_application_payload = true;
        realityclientTunnelUpStreamPayload(fixture.reality,
                                           fixture.line,
                                           clientOneBytePayload(&fixture));
    }

    realityclientTunnelDownStreamPayload(fixture.reality,
                                         fixture.line,
                                         clientBuildHandoffAck(&fixture));
    requireClient(! lineIsAlive(fixture.line) &&
                      strcmp(fixture.context.events, expected_events) == 0,
                  "client ACK-transition line death emitted callbacks after teardown");
    clientFixtureDestroy(&fixture);
}

static void testClientAckTransitionLineDeath(void)
{
    runClientAckTransitionLineDeath(kClientAckDeathDuringConfirm, "CD");
    runClientAckTransitionLineDeath(kClientAckDeathDuringEst, "CEU");
    runClientAckTransitionLineDeath(kClientAckDeathDuringPendingFlush, "CEQD");
}

static void testClientPreAckSilentFailures(void)
{
    client_lifecycle_fixture_t fixture;
    clientFixtureInitialize(&fixture);
    configureClientAwaitAck(&fixture, true);
    realityclientFailAuthenticated(fixture.reality, fixture.line);
    requireClient(strcmp(fixture.context.events, "UD") == 0 &&
                      fixture.context.observed_alert == kRealityV2AlertInvalid,
                  "client pre-ACK failure emitted a simulated Reality alert");
    clientFixtureDestroy(&fixture);

    clientFixtureInitialize(&fixture);
    configureClientAwaitAck(&fixture, true);
    realityclientHandleDownstreamFinish(fixture.reality, fixture.line);
    requireClient(strcmp(fixture.context.events, "D") == 0,
                  "client pre-ACK wire finish reflected a callback to the wire");
    clientFixtureDestroy(&fixture);
}

static void testClientRequestLineDeath(void)
{
    client_lifecycle_fixture_t fixture;
    clientFixtureInitialize(&fixture);
    configureClientAwaitAck(&fixture, false);
    fixture.next->fnPayloadU = clientNextHandoffPayload;
    fixture.context.expected_control_kind = kRealityV2RecordKindHandoffRequest;
    fixture.context.kill_on_payload = true;
    requireClient(! realityclientSendHandoffControl(fixture.reality,
                                                    fixture.line,
                                                    kRealityV2RecordKindHandoffRequest),
                  "client request send ignored synchronous line death");
    requireClient(strcmp(fixture.context.events, "RD") == 0,
                  "client request line-death callback ordering changed");
    clientFixtureDestroy(&fixture);
}

void realityTestClientCloseLifecycle(void)
{
    runClientScenario(realityclientHandleUpstreamFinish, "U", false, false);
    runClientScenario(clientPeerClose, "UD", false, false);
    runClientScenario(clientPeerClose, "U", false, true);
    runClientScenario(clientPeerFatal, "UD", false, false);
    runClientScenario(realityclientHandleDownstreamFinish, "D", false, false);
    runClientScenario(realityclientFailAuthenticated, "PUD", false, false);
    runClientScenario(realityclientFailAuthenticated, "P", true, false);
    runClientScenario(realityclientFailAuthenticated, "PU", false, true);

    const reality_v2_record_profile_t profiles[] = {
        {kRealityV2RecordProfileTls13Aead, 0, 0, 0},
        {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0},
        {kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20},
        {kRealityV2RecordProfileTls12ChaCha, 0, 0, 0},
    };
    const uint16_t versions[] = {
        kRealityV2Tls13,
        kRealityV2Tls12,
        kRealityV2Tls12,
        kRealityV2Tls12,
    };
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        runClientFragmentedAlert(versions[i], &profiles[i]);
        testClientCoalescedRecords(versions[i], &profiles[i], false);
        testClientCoalescedRecords(versions[i], &profiles[i], true);
    }
    testClientTerminalReentry();
    testClientSecureRandomFailure();
    testClientHandoffRequestAndQueue();
    testClientNestedAckIsDeferredDuringCoverConsume();
    testClientFailedAckDelegatesOriginalCoverRecord();
    testClientRequestedKeyUpdateResponsePrecedesConfirm();
    testClientFragmentedTicketsThenCoalescedAck();
    testClientAckCoalescedApplicationCompletesHandoff();
    testClientAckTransitionLineDeath();
    testClientConfirmEstAndFlushOrdering();
    testClientPreAckSilentFailures();
    testClientRequestLineDeath();
}

typedef struct client_sizing_context_s
{
    tunnel_t *reality;
    buffer_pool_t *pool;
    const uint8_t *expected_payload;
    uint32_t expected_payload_len;
    uint32_t recovered_payload_len;
    uint32_t body_lengths[3];
    uint32_t record_count;
    bool kill_after_first_record;
} client_sizing_context_t;

static void clientSizingCapture(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    client_sizing_context_t *context = *(client_sizing_context_t **) tunnelGetState(t);
    realityclient_lstate_t *ls = lineGetState(l, context->reality);
    const uint8_t *record = sbufGetRawPtr(buf);
    uint32_t record_len = sbufGetLength(buf);
    requireClient(record_len >= kRealityV2TlsRecordHeaderSize,
                  "client sizing capture received a truncated TLS record");

    reality_v2_record_descriptor_t descriptor;
    requireClient(realityV2BuildRecordDescriptor(ls->tls_version,
                                                  &ls->record_profile,
                                                  kRealityV2RecordKindApplicationData,
                                                  &descriptor),
                  "client sizing descriptor construction failed");
    uint32_t chunk_len = min(context->expected_payload_len - context->recovered_payload_len,
                             (uint32_t) kRealityV2MaxPlaintextFragment);
    reality_v2_record_layout_t layout;
    requireClient(realityV2CalculateDescriptorLayout(&descriptor, chunk_len, &layout) &&
                      record_len == kRealityV2TlsRecordHeaderSize + layout.wire_body_len &&
                      record[0] == descriptor.outer_content_type && record[1] == 0x03 &&
                      record[2] == 0x03 &&
                      ((((uint32_t) record[3] << 8) | record[4]) == layout.wire_body_len),
                  "client sizing capture observed the wrong native record body length");
    requireClient(context->record_count < sizeof(context->body_lengths) / sizeof(context->body_lengths[0]),
                  "client sizing capture emitted too many records");
    context->body_lengths[context->record_count] = layout.wire_body_len;

    const uint8_t *visible_prefix = record + kRealityV2TlsRecordHeaderSize;
    if (descriptor.profile.profile_id == kRealityV2RecordProfileTls12Gcm)
    {
        requireClient(realityV2ReadBe64(visible_prefix) == 10U + context->record_count,
                      "client sizing GCM explicit nonce did not continue the TLS sequence");
    }
    const uint8_t *ciphertext = visible_prefix + descriptor.visible_prefix_len;
    uint32_t ciphertext_len = layout.wire_body_len - descriptor.visible_prefix_len;
    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadMaxSize];
    uint8_t inner[kRealityV2MaxPlaintextFragment + kRealityV2TagSize + 1];
    size_t aad_len = 0;
    realityV2BuildNonce(ls->c2s_iv, context->record_count, nonce);
    requireClient(realityV2BuildRecordAad(&descriptor,
                                          kRealityV2DirectionClientToServer,
                                          context->record_count,
                                          ls->session_id,
                                          record,
                                          visible_prefix,
                                          descriptor.visible_prefix_len,
                                          aad,
                                          &aad_len) &&
                      chacha20poly1305Decrypt(inner,
                                              ciphertext,
                                              ciphertext_len,
                                              aad,
                                              aad_len,
                                              nonce,
                                              ls->c2s_key) == 0,
                  "client sizing record failed to decrypt");
    uint32_t payload_offset;
    uint32_t payload_len;
    requireClient(realityV2ValidateInnerPlaintext(&descriptor,
                                                  inner,
                                                  ciphertext_len - kRealityV2TagSize,
                                                  &payload_offset,
                                                  &payload_len) &&
                      payload_len == chunk_len &&
                      memcmp(inner + payload_offset,
                             context->expected_payload + context->recovered_payload_len,
                             payload_len) == 0,
                  "client sizing record did not recover the original plaintext chunk");

    context->recovered_payload_len += payload_len;
    ++context->record_count;
    bufferpoolReuseBuffer(context->pool, buf);
    if (context->kill_after_first_record)
    {
        l->alive = false;
    }
}

static void runClientSizingCase(uint16_t tls_version,
                                const reality_v2_record_profile_t *profile,
                                uint32_t input_len,
                                bool kill_after_first_record)
{
    master_pool_t *large_master = masterpoolCreateWithCapacity(8);
    master_pool_t *small_master = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool = bufferpoolCreate(large_master, small_master, 8, 65536, 1024);
    bufferpoolUpdateAllocationPaddings(pool,
                                       kRealityClientMaxFramePrefixSize,
                                       kRealityClientMaxFramePrefixSize);
    buffer_pool_t *shortcut[1] = {pool};
    buffer_pool_t **saved_shortcuts = GSTATE.shortcut_buffer_pools;
    GSTATE.shortcut_buffer_pools = shortcut;

    tunnel_t *reality = tunnelCreate(NULL, sizeof(realityclient_tstate_t), sizeof(realityclient_lstate_t));
    tunnel_t *capture = tunnelCreate(NULL, sizeof(client_sizing_context_t *), 0);
    requireClient(reality != NULL && capture != NULL, "failed to create client sizing tunnels");
    tunnelBind(reality, capture);
    capture->fnPayloadU = clientSizingCapture;

    line_t *line = memoryAllocateCacheAlignedZero(sizeof(line_t) + reality->lstate_size);
    requireClient(line != NULL, "failed to allocate client sizing line");
    atomic_init(&line->refc, 1);
    line->alive = true;
    line->wid = 0;

    realityclient_tstate_t *ts = tunnelGetState(reality);
    ts->algorithm = kRealityClientAlgorithmChaCha20Poly1305;
    realityclient_lstate_t *ls = lineGetState(line, reality);
    realityclientLinestateInitialize(ls, pool);
    ls->record_profile = *profile;
    ls->tls_version = tls_version;
    ls->phase = kRealityClientPhaseRealityActive;
    ls->session_keys_ready = true;
    ls->handoff_ack_authenticated = tls_version == kRealityV2Tls13;
    ls->handoff_confirm_sent = tls_version == kRealityV2Tls13;
    ls->downstream_est_sent = true;
    ls->tls12_sequences_valid = tls_version == kRealityV2Tls12;
    ls->tls12_next_write_sequence = 10;
    memorySet(ls->session_id, 0x31, sizeof(ls->session_id));
    memorySet(ls->c2s_key, 0x42, sizeof(ls->c2s_key));
    memorySet(ls->c2s_iv, 0x53, sizeof(ls->c2s_iv));

    sbuf_t *input = bufferpoolGetLargeBuffer(pool);
    requireClient(input_len <= sbufGetMaximumWriteableSize(input),
                  "client sizing input does not fit the test buffer");
    input = sbufReserveSpace(input, input_len);
    sbufSetLength(input, input_len);
    uint8_t *input_bytes = sbufGetMutablePtr(input);
    uint8_t *expected_bytes = memoryAllocate(input_len);
    requireClient(expected_bytes != NULL, "failed to allocate client sizing expected payload");
    for (uint32_t i = 0; i < input_len; ++i)
    {
        input_bytes[i] = (uint8_t) (i * 29U + 7U);
        expected_bytes[i] = input_bytes[i];
    }

    client_sizing_context_t context = {
        .reality = reality,
        .pool = pool,
        .expected_payload = expected_bytes,
        .expected_payload_len = input_len,
        .kill_after_first_record = kill_after_first_record,
    };
    *(client_sizing_context_t **) tunnelGetState(capture) = &context;

    bool sent = realityclientEncryptAndSend(reality, line, input);
    uint32_t expected_records = (input_len + kRealityV2MaxPlaintextFragment - 1U) /
                                kRealityV2MaxPlaintextFragment;
    if (kill_after_first_record)
    {
        requireClient(! sent && context.record_count == 1 &&
                          context.recovered_payload_len == kRealityV2MaxPlaintextFragment,
                      "client sizing sender did not stop immediately when the line died");
        line->alive = true;
    }
    else
    {
        requireClient(sent && context.record_count == expected_records &&
                          context.recovered_payload_len == input_len,
                      "client sizing sender emitted the wrong chunk sequence");
        if (input_len == 32768)
        {
            requireClient(context.record_count == 2,
                          "client 32768-byte callback emitted a tiny third record");
        }
    }

    realityclientLinestateDestroy(ls);
    memoryFree(expected_bytes);
    requireClient(atomic_load(&line->refc) == 1, "client sizing line reference leaked");
    memoryFreeAligned(line);
    tunnelDestroy(reality);
    tunnelDestroy(capture);
    GSTATE.shortcut_buffer_pools = saved_shortcuts;
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);
}

void realityTestClientRecordSizing(void)
{
    static const struct
    {
        uint16_t tls_version;
        reality_v2_record_profile_t profile;
    } profiles[] = {
        {kRealityV2Tls13, {kRealityV2RecordProfileTls13Aead, 0, 0, 0}},
        {kRealityV2Tls12, {kRealityV2RecordProfileTls12ChaCha, 0, 0, 0}},
        {kRealityV2Tls12,
         {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0}},
        {kRealityV2Tls12,
         {kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20}},
    };
    static const uint32_t input_lengths[] = {1, 16383, 16384, 16385, 32768, 32769};
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        for (size_t j = 0; j < sizeof(input_lengths) / sizeof(input_lengths[0]); ++j)
        {
            runClientSizingCase(profiles[i].tls_version,
                                &profiles[i].profile,
                                input_lengths[j],
                                false);
        }
        runClientSizingCase(profiles[i].tls_version, &profiles[i].profile, 32768, true);
    }
}
