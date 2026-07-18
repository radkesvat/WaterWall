#include "RealityServer/structure.h"

#include "reality_close_lifecycle_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct server_lifecycle_context_s
{
    tunnel_t *reality;
    buffer_pool_t *pool;
    char events[64];
    size_t events_len;
    bool kill_on_payload;
    bool kill_on_next_finish;
    bool kill_on_prev_finish;
    bool finish_on_destination_payload;
    bool kill_on_cover_payload;
    bool kill_on_ack_payload;
    bool kill_on_destination_finish;
    bool kill_on_protected_init;
    bool kill_on_protected_payload;
    bool inject_destination_callbacks_on_ack;
    bool inject_destination_callbacks_on_finish;
    bool reenter_peer_close;
    bool send_data_after_close;
    uint8_t expected_alert_type;
    uint16_t expected_alert_body_len;
    uint8_t observed_alert;
    uint8_t cover_downstream[128];
    uint32_t cover_downstream_bytes;
    uint32_t destination_upstream_records;
    uint32_t handoff_ack_records;
    uint32_t destination_callbacks_injected;
    const uint8_t *expected_destination_payload;
    uint32_t expected_destination_payload_len;
    uint32_t matched_destination_payloads;
    sbuf_t *request_on_cover_payload;
    sbuf_t *destination_payload_on_cover_payload;
    sbuf_t *request_on_destination_payload;
} server_lifecycle_context_t;

typedef struct server_lifecycle_fixture_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *pool;
    buffer_pool_t *shortcut[1];
    buffer_pool_t **saved_shortcuts;
    tunnel_t *prev;
    tunnel_t *reality;
    tunnel_t *next;
    tunnel_t *destination;
    line_t *line;
    server_lifecycle_context_t context;
} server_lifecycle_fixture_t;

static void requireServer(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void serverEvent(server_lifecycle_context_t *context, char event)
{
    requireServer(context->events_len + 1 < sizeof(context->events), "server lifecycle event overflow");
    context->events[context->events_len++] = event;
    context->events[context->events_len] = '\0';
}

static server_lifecycle_context_t *serverContext(tunnel_t *t)
{
    return *(server_lifecycle_context_t **) tunnelGetState(t);
}

static void serverKillLineFromPrevious(server_lifecycle_context_t *context, line_t *l)
{
    realityserverTunnelUpStreamFinish(context->reality, l);
    l->alive = false;
}

static void serverInjectDestinationDownstreamCallbacks(server_lifecycle_context_t *context,
                                                       line_t *l)
{
    sbuf_t *payload = bufferpoolGetSmallBuffer(context->pool);
    payload = sbufReserveSpace(payload, 1);
    sbufSetLength(payload, 1);
    sbufGetMutablePtr(payload)[0] = 0xd7;

    realityserverTunnelDownStreamPayload(context->reality, l, payload);
    realityserverTunnelDownStreamPause(context->reality, l);
    realityserverTunnelDownStreamResume(context->reality, l);
    realityserverTunnelDownStreamEst(context->reality, l);
    realityserverTunnelDownStreamFinish(context->reality, l);
    context->destination_callbacks_injected += 5;
}

static void serverPrevEst(tunnel_t *t, line_t *l)
{
    discard l;
    serverEvent(serverContext(t), 'e');
}

static void serverPrevPause(tunnel_t *t, line_t *l)
{
    discard l;
    serverEvent(serverContext(t), 'q');
}

static void serverPrevResume(tunnel_t *t, line_t *l)
{
    discard l;
    serverEvent(serverContext(t), 's');
}

static void serverPrevPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    server_lifecycle_context_t *context = serverContext(t);
    realityserver_lstate_t *ls = lineGetState(l, context->reality);
    const uint8_t *record = sbufGetRawPtr(buf);
    requireServer(sbufGetLength(buf) == (uint32_t) context->expected_alert_body_len + 5U &&
                      record[0] == context->expected_alert_type && record[1] == 0x03 &&
                      record[2] == 0x03 &&
                      (((uint16_t) record[3] << 8) | record[4]) == context->expected_alert_body_len,
                  "server final alert has the wrong TLS shape");
    reality_v2_record_descriptor_t descriptor;
    requireServer(realityV2BuildRecordDescriptor(ls->tls_capture.binding.tls_version,
                                                  &ls->record_profile,
                                                  kRealityV2RecordKindAlert,
                                                  &descriptor),
                  "failed to classify server final alert");
    uint32_t body_len = ((uint32_t) record[3] << 8) | record[4];
    uint32_t ciphertext_len = body_len - descriptor.visible_prefix_len;
    const uint8_t *visible_prefix = record + kRealityV2TlsRecordHeaderSize;
    const uint8_t *ciphertext = visible_prefix + descriptor.visible_prefix_len;
    uint64_t sequence = ls->s2c_send_seq - 1;
    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadMaxSize];
    uint8_t inner[64];
    size_t aad_len = 0;
    realityV2BuildNonce(ls->s2c_iv, sequence, nonce);
    requireServer(realityV2BuildRecordAad(&descriptor,
                                          kRealityV2DirectionServerToClient,
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
                                              ls->s2c_key) == 0,
                  "failed to decrypt server final alert");
    uint32_t payload_offset = 0;
    uint32_t payload_len = 0;
    requireServer(realityV2ValidateInnerPlaintext(&descriptor,
                                                  inner,
                                                  ciphertext_len - kRealityV2TagSize,
                                                  &payload_offset,
                                                  &payload_len) &&
                      realityV2ParseAlert(inner + payload_offset,
                                          payload_len,
                                          &context->observed_alert),
                  "failed to parse server final alert semantics");
    memoryZero(nonce, sizeof(nonce));
    memoryZero(aad, sizeof(aad));
    memoryZero(inner, sizeof(inner));
    serverEvent(context, 'P');
    bufferpoolReuseBuffer(context->pool, buf);

    realityserverTunnelUpStreamPause(context->reality, l);
    realityserverTunnelUpStreamResume(context->reality, l);

    if (context->reenter_peer_close)
    {
        realityserverHandlePeerAlert(context->reality, l, kRealityV2AlertCloseNotify);
    }

    if (context->send_data_after_close)
    {
        sbuf_t *late = bufferpoolGetSmallBuffer(context->pool);
        late = sbufReserveSpace(late, 1);
        sbufSetLength(late, 1);
        sbufGetMutablePtr(late)[0] = 0xff;
        realityserverTunnelUpStreamPayload(context->reality, l, late);
    }

    if (context->kill_on_payload)
    {
        realityserverTunnelUpStreamFinish(context->reality, l);
        l->alive = false;
    }
}

static void serverPrevFinish(tunnel_t *t, line_t *l)
{
    server_lifecycle_context_t *context = serverContext(t);
    serverEvent(context, 'D');
    if (context->kill_on_prev_finish)
    {
        l->alive = false;
    }
}

static void serverNextFinish(tunnel_t *t, line_t *l)
{
    server_lifecycle_context_t *context = serverContext(t);
    serverEvent(context, 'U');
    if (context->kill_on_next_finish)
    {
        l->alive = false;
    }
}

static void serverNextPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    server_lifecycle_context_t *context = serverContext(t);
    const uint8_t *payload = sbufGetRawPtr(buf);
    requireServer(sbufGetLength(buf) == 1 && payload[0] == 0x5a,
                  "server delivered the wrong application payload");
    serverEvent(context, 'A');
    bufferpoolReuseBuffer(context->pool, buf);
    if (context->kill_on_protected_payload)
    {
        context->kill_on_protected_payload = false;
        serverKillLineFromPrevious(context, l);
    }
}

static void serverNextInit(tunnel_t *t, line_t *l)
{
    server_lifecycle_context_t *context = serverContext(t);
    serverEvent(context, 'I');
    if (context->kill_on_protected_init)
    {
        context->kill_on_protected_init = false;
        serverKillLineFromPrevious(context, l);
    }
}

static void serverNextPause(tunnel_t *t, line_t *l)
{
    discard l;
    serverEvent(serverContext(t), 'p');
}

static void serverNextResume(tunnel_t *t, line_t *l)
{
    discard l;
    serverEvent(serverContext(t), 'r');
}

static int serverControlDecrypt(void *context, unsigned char *dst,
                                const unsigned char *src, size_t src_len,
                                const unsigned char *ad, size_t ad_len,
                                const unsigned char *nonce, const unsigned char *key)
{
    discard context;
    return chacha20poly1305Decrypt(dst, src, src_len, ad, ad_len, nonce, key);
}

static void serverHandoffPrevPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    server_lifecycle_context_t *context = serverContext(t);
    realityserver_lstate_t *ls = lineGetState(l, context->reality);

    if (ls->mode != kRealityServerModeHandoffAwaitConfirm)
    {
        uint32_t len = sbufGetLength(buf);
        requireServer(context->cover_downstream_bytes + len <= sizeof(context->cover_downstream),
                      "server cover capture overflow");
        memoryCopy(context->cover_downstream + context->cover_downstream_bytes,
                   sbufGetRawPtr(buf),
                   len);
        context->cover_downstream_bytes += len;
        serverEvent(context, 'c');
        bufferpoolReuseBuffer(context->pool, buf);
        if (context->kill_on_cover_payload)
        {
            context->kill_on_cover_payload = false;
            serverKillLineFromPrevious(context, l);
            return;
        }
        if (context->request_on_cover_payload != NULL)
        {
            sbuf_t *request = context->request_on_cover_payload;
            context->request_on_cover_payload = NULL;
            requireServer(realityserverProcessUpstream(context->reality, l, request),
                          "server rejected re-entrant handoff request");
        }
        if (context->destination_payload_on_cover_payload != NULL)
        {
            sbuf_t *destination_payload = context->destination_payload_on_cover_payload;
            context->destination_payload_on_cover_payload = NULL;
            realityserverTunnelDownStreamPayload(context->reality, l, destination_payload);
        }
        return;
    }

    reality_v2_record_descriptor_t descriptor;
    uint8_t plaintext[kRealityV2ControlMaxInnerPlaintext];
    uint32_t payload_offset = 0;
    uint32_t payload_len = 0;
    requireServer(ls->handoff_ack_sent && ls->destination_downstream_cutoff &&
                      ls->s2c_send_seq == 1 &&
                      realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                                     &ls->record_profile,
                                                     kRealityV2RecordKindHandoffAck,
                                                     &descriptor) &&
                      realityV2TryDecryptExpectedRecord(&descriptor,
                                                        kRealityV2DirectionServerToClient,
                                                        0,
                                                        ls->session_id,
                                                        ls->s2c_key,
                                                        ls->s2c_iv,
                                                        sbufGetRawPtr(buf),
                                                        sbufGetLength(buf),
                                                        serverControlDecrypt,
                                                        NULL,
                                                        plaintext,
                                                        sizeof(plaintext),
                                                        &payload_offset,
                                                        &payload_len) &&
                      realityV2ParseControl(kRealityV2RecordKindHandoffAck,
                                            plaintext + payload_offset,
                                            payload_len),
                  "server handoff emitted an invalid ACK or marked cutoff too late");
    memoryZero(plaintext, sizeof(plaintext));
    ++context->handoff_ack_records;
    serverEvent(context, 'K');
    bufferpoolReuseBuffer(context->pool, buf);
    if (context->inject_destination_callbacks_on_ack)
    {
        context->inject_destination_callbacks_on_ack = false;
        serverInjectDestinationDownstreamCallbacks(context, l);
    }
    if (context->kill_on_ack_payload)
    {
        context->kill_on_ack_payload = false;
        serverKillLineFromPrevious(context, l);
    }
}

static void serverDestinationPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    server_lifecycle_context_t *context = serverContext(t);
    if (context->expected_destination_payload != NULL)
    {
        requireServer(sbufGetLength(buf) == context->expected_destination_payload_len &&
                          memoryEqual(sbufGetRawPtr(buf),
                                      context->expected_destination_payload,
                                      context->expected_destination_payload_len),
                      "server changed a failed handoff candidate before fallback forwarding");
        ++context->matched_destination_payloads;
    }
    ++context->destination_upstream_records;
    serverEvent(context, 'T');
    bufferpoolReuseBuffer(context->pool, buf);
    if (context->finish_on_destination_payload)
    {
        realityserverTunnelDownStreamFinish(context->reality, l);
        return;
    }
    if (context->request_on_destination_payload != NULL)
    {
        sbuf_t *request = context->request_on_destination_payload;
        context->request_on_destination_payload = NULL;
        requireServer(realityserverProcessUpstream(context->reality, l, request),
                      "server rejected request re-entered by destination payload");
    }
}

static void serverDestinationFinish(tunnel_t *t, line_t *l)
{
    server_lifecycle_context_t *context = serverContext(t);
    serverEvent(context, 'F');
    if (context->inject_destination_callbacks_on_finish)
    {
        context->inject_destination_callbacks_on_finish = false;
        serverInjectDestinationDownstreamCallbacks(context, l);
    }
    if (context->kill_on_destination_finish)
    {
        context->kill_on_destination_finish = false;
        serverKillLineFromPrevious(context, l);
    }
}

static void serverFixtureAddDestination(server_lifecycle_fixture_t *fixture)
{
    fixture->destination = tunnelCreate(NULL, sizeof(server_lifecycle_context_t *), 0);
    requireServer(fixture->destination != NULL, "failed to create server destination fixture");
    *(server_lifecycle_context_t **) tunnelGetState(fixture->destination) = &fixture->context;
    fixture->destination->fnPayloadU = serverDestinationPayload;
    fixture->destination->fnFinU = serverDestinationFinish;

    realityserver_tstate_t *ts = tunnelGetState(fixture->reality);
    realityserver_lstate_t *ls = lineGetState(fixture->line, fixture->reality);
    ts->destination_tunnel = fixture->destination;
    ls->destination_init_sent = true;
}

static void serverFixtureInitialize(server_lifecycle_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    fixture->large_master = masterpoolCreateWithCapacity(8);
    fixture->small_master = masterpoolCreateWithCapacity(8);
    fixture->pool = bufferpoolCreate(fixture->large_master, fixture->small_master, 8, 8192, 1024);
    bufferpoolUpdateAllocationPaddings(fixture->pool,
                                       kRealityServerMaxFramePrefixSize,
                                       kRealityServerMaxFramePrefixSize);
    fixture->saved_shortcuts = GSTATE.shortcut_buffer_pools;
    fixture->shortcut[0] = fixture->pool;
    GSTATE.shortcut_buffer_pools = fixture->shortcut;

    fixture->prev = tunnelCreate(NULL, sizeof(server_lifecycle_context_t *), 0);
    fixture->reality = tunnelCreate(NULL, sizeof(realityserver_tstate_t), sizeof(realityserver_lstate_t));
    fixture->next = tunnelCreate(NULL, sizeof(server_lifecycle_context_t *), 0);
    requireServer(fixture->prev != NULL && fixture->reality != NULL && fixture->next != NULL,
                  "failed to create server lifecycle tunnels");
    tunnelBind(fixture->prev, fixture->reality);
    tunnelBind(fixture->reality, fixture->next);

    fixture->context = (server_lifecycle_context_t) {
        .reality = fixture->reality,
        .pool = fixture->pool,
        .expected_alert_type = 0x17,
        .expected_alert_body_len = 19,
    };
    *(server_lifecycle_context_t **) tunnelGetState(fixture->prev) = &fixture->context;
    *(server_lifecycle_context_t **) tunnelGetState(fixture->next) = &fixture->context;
    fixture->prev->fnPayloadD = serverPrevPayload;
    fixture->prev->fnFinD = serverPrevFinish;
    fixture->prev->fnEstD = serverPrevEst;
    fixture->prev->fnPauseD = serverPrevPause;
    fixture->prev->fnResumeD = serverPrevResume;
    fixture->next->fnFinU = serverNextFinish;
    fixture->next->fnPayloadU = serverNextPayload;
    fixture->next->fnInitU = serverNextInit;
    fixture->next->fnPauseU = serverNextPause;
    fixture->next->fnResumeU = serverNextResume;

    uint32_t line_size = sizeof(line_t) + fixture->reality->lstate_size;
    fixture->line = memoryAllocateCacheAlignedZero(line_size);
    requireServer(fixture->line != NULL, "failed to allocate server lifecycle line");
    atomic_init(&fixture->line->refc, 1);
    fixture->line->alive = true;
    fixture->line->wid = 0;

    realityserver_tstate_t *ts = tunnelGetState(fixture->reality);
    ts->algorithm = kRealityServerAlgorithmChaCha20Poly1305;
    realityserver_lstate_t *ls = lineGetState(fixture->line, fixture->reality);
    realityserverLinestateInitialize(ls, fixture->pool);
    ls->mode = kRealityServerModeAuthorized;
    ls->protected_init_sent = true;
    ls->record_profile = (reality_v2_record_profile_t) {
        .profile_id = kRealityV2RecordProfileTls13Aead,
        .visible_prefix_len = 0,
    };
    ls->tls_capture.binding.tls_version = kRealityV2Tls13;
    ls->session_keys_ready = true;
    memorySet(ls->session_id, 0x44, sizeof(ls->session_id));
    memorySet(ls->s2c_key, 0x55, sizeof(ls->s2c_key));
    memorySet(ls->s2c_iv, 0x66, sizeof(ls->s2c_iv));
}

static void serverFixtureSetFailureMode(server_lifecycle_fixture_t *fixture,
                                        bool kill_on_payload, bool kill_on_next_finish)
{
    fixture->context.kill_on_payload = kill_on_payload;
    fixture->context.kill_on_next_finish = kill_on_next_finish;
}

static void serverFixtureDestroy(server_lifecycle_fixture_t *fixture)
{
    realityserver_lstate_t *ls = lineGetState(fixture->line, fixture->reality);
    const uint8_t *state = (const uint8_t *) ls;
    for (uint32_t i = 0; i < fixture->reality->lstate_size; ++i)
    {
        requireServer(state[i] == 0, "server terminal path did not zero line state");
    }
    requireServer(atomic_load(&fixture->line->refc) == 1, "server lifecycle line reference leaked");
    memoryFreeAligned(fixture->line);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->reality);
    tunnelDestroy(fixture->next);
    if (fixture->destination != NULL)
    {
        tunnelDestroy(fixture->destination);
    }
    GSTATE.shortcut_buffer_pools = fixture->saved_shortcuts;
    bufferpoolDestroy(fixture->pool);
    masterpoolMakeEmpty(fixture->large_master);
    masterpoolMakeEmpty(fixture->small_master);
    masterpoolDestroy(fixture->large_master);
    masterpoolDestroy(fixture->small_master);
}

static void runServerScenario(void (*action)(tunnel_t *, line_t *), const char *expected,
                              bool kill_on_payload, bool kill_on_next_finish)
{
    server_lifecycle_fixture_t fixture;
    serverFixtureInitialize(&fixture);
    serverFixtureSetFailureMode(&fixture, kill_on_payload, kill_on_next_finish);
    action(fixture.reality, fixture.line);
    requireServer(strcmp(fixture.context.events, expected) == 0, "server terminal callback ordering mismatch");
    requireServer(strchr(fixture.context.events, 'p') == NULL && strchr(fixture.context.events, 'r') == NULL,
                  "server final alert reflected Pause/Resume toward a terminal side");
    serverFixtureDestroy(&fixture);
}

static void serverPeerClose(tunnel_t *t, line_t *l)
{
    realityserverHandlePeerAlert(t, l, kRealityV2AlertCloseNotify);
}

static void serverPeerFatal(tunnel_t *t, line_t *l)
{
    realityserverHandlePeerAlert(t, l, kRealityV2AlertBadRecordMac);
}

static sbuf_t *serverBufferFromBytes(server_lifecycle_fixture_t *fixture,
                                     const uint8_t *data, uint32_t len)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(fixture->pool);
    requireServer(len <= sbufGetMaximumWriteableSize(buf), "server parser fixture buffer is too small");
    buf = sbufReserveSpace(buf, len);
    sbufSetLength(buf, len);
    memoryCopy(sbufGetMutablePtr(buf), data, len);
    return buf;
}

static sbuf_t *buildServerInboundRecord(server_lifecycle_fixture_t *fixture,
                                        uint16_t tls_version,
                                        const reality_v2_record_profile_t *profile,
                                        uint8_t record_kind,
                                        const uint8_t *payload,
                                        uint32_t payload_len,
                                        uint64_t sequence)
{
    realityserver_lstate_t *ls = lineGetState(fixture->line, fixture->reality);
    reality_v2_record_descriptor_t descriptor;
    reality_v2_record_layout_t layout;
    requireServer(realityV2BuildRecordDescriptor(tls_version,
                                                  profile,
                                                  record_kind,
                                                  &descriptor) &&
                      realityV2CalculateDescriptorLayout(&descriptor, payload_len, &layout),
                  "failed to construct server inbound descriptor");
    if (record_kind == kRealityV2RecordKindAlert)
    {
        fixture->context.expected_alert_type = descriptor.outer_content_type;
        fixture->context.expected_alert_body_len = (uint16_t) layout.wire_body_len;
    }

    sbuf_t *buf = bufferpoolGetSmallBuffer(fixture->pool);
    uint32_t frame_len = kRealityV2TlsRecordHeaderSize + layout.wire_body_len;
    requireServer(frame_len <= sbufGetMaximumWriteableSize(buf), "first-alert fixture buffer is too small");
    sbufSetLength(buf, frame_len);
    uint8_t *frame = sbufGetMutablePtr(buf);
    frame[0] = descriptor.outer_content_type;
    frame[1] = 0x03;
    frame[2] = 0x03;
    frame[3] = (uint8_t) (layout.wire_body_len >> 8);
    frame[4] = (uint8_t) layout.wire_body_len;
    uint8_t *visible_prefix = frame + kRealityV2TlsRecordHeaderSize;
    memorySet(visible_prefix, 0xb6, descriptor.visible_prefix_len);
    if (profile->profile_id == kRealityV2RecordProfileTls12Gcm)
    {
        realityV2WriteBe64(visible_prefix, 1 + sequence);
    }
    uint8_t *ciphertext = visible_prefix + descriptor.visible_prefix_len;
    requireServer(realityV2BuildInnerPlaintext(&descriptor,
                                                payload,
                                                payload_len,
                                                ciphertext,
                                                layout.inner_plaintext_len),
                  "failed to construct server inbound plaintext");

    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadMaxSize];
    size_t aad_len = 0;
    realityV2BuildNonce(ls->c2s_iv, sequence, nonce);
    requireServer(realityV2BuildRecordAad(&descriptor,
                                          kRealityV2DirectionClientToServer,
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
                                              ls->c2s_key) == 0,
                  "failed to encrypt server inbound fixture");
    memoryZero(nonce, sizeof(nonce));
    memoryZero(aad, sizeof(aad));
    return buf;
}

static sbuf_t *buildServerInboundControl(server_lifecycle_fixture_t *fixture,
                                         uint8_t record_kind, uint64_t sequence)
{
    const uint8_t padding[kRealityV2ControlMinPadding] = {0xa1, 0xb2, 0xc3};
    uint8_t payload[kRealityV2ControlMinPayload];
    requireServer(realityV2SerializeControl(record_kind,
                                             padding,
                                             sizeof(padding),
                                             payload,
                                             sizeof(payload)),
                  "failed to serialize server handoff control fixture");
    realityserver_lstate_t *ls = lineGetState(fixture->line, fixture->reality);
    return buildServerInboundRecord(fixture,
                                    kRealityV2Tls13,
                                    &ls->record_profile,
                                    record_kind,
                                    payload,
                                    sizeof(payload),
                                    sequence);
}

static void prepareServerPendingProfile(server_lifecycle_fixture_t *fixture,
                                        uint16_t tls_version,
                                        const reality_v2_record_profile_t *profile)
{
    realityserver_lstate_t *ls = lineGetState(fixture->line, fixture->reality);
    realityserver_tstate_t *ts = tunnelGetState(fixture->reality);
    ls->mode = kRealityServerModePending;
    ls->protected_init_sent = false;
    ls->client_hello_parser.complete = true;
    ls->tls_capture.binding.tls_version = tls_version;
    ls->record_profile = *profile;
    ts->tls12_gcm_server_nonce_policy = kRealityServerGcmNoncePolicyAuto;
    ts->sniffing_attempts = kRealityServerDefaultSniffingAttempts;

    if (tls_version == kRealityV2Tls12)
    {
        requireServer(realityserverTls12RecordTrackerSetProfile(&ls->client_record_tracker, profile) &&
                          realityserverTls12RecordTrackerSetProfile(&ls->server_record_tracker, profile),
                      "failed to configure pending TLS 1.2 trackers");
        ls->client_record_tracker.protected_epoch = true;
        ls->client_record_tracker.next_sequence = 1;
        ls->server_record_tracker.protected_epoch = true;
        ls->server_record_tracker.saw_protected_record = true;
        ls->server_record_tracker.last_record_was_protected = true;
        ls->server_record_tracker.next_sequence = 1;
        if (profile->profile_id == kRealityV2RecordProfileTls12Gcm)
        {
            ls->server_record_tracker.explicit_nonce_sample_count = 1;
            ls->server_record_tracker.sequence_pattern = true;
        }
    }
}

static void runFirstFatalAuthorization(uint16_t tls_version,
                                       const reality_v2_record_profile_t *profile)
{
    server_lifecycle_fixture_t fixture;
    serverFixtureInitialize(&fixture);
    prepareServerPendingProfile(&fixture, tls_version, profile);
    uint8_t alert[kRealityV2AlertMessageSize];
    requireServer(realityV2SerializeAlert(kRealityV2AlertBadRecordMac, alert),
                  "failed to serialize first fatal authorization alert");
    sbuf_t *record = buildServerInboundRecord(&fixture,
                                              tls_version,
                                              profile,
                                              kRealityV2RecordKindAlert,
                                              alert,
                                              sizeof(alert),
                                              0);
    requireServer(! realityserverProcessUpstream(fixture.reality, fixture.line, record),
                  "first alert did not terminate the authorized line");
    requireServer(strcmp(fixture.context.events, "IUD") == 0,
                  "first fatal alert did not authorize and close without a response");
    serverFixtureDestroy(&fixture);
}

static void runServerFragmentedAlert(uint16_t tls_version,
                                     const reality_v2_record_profile_t *profile)
{
    server_lifecycle_fixture_t template_fixture;
    serverFixtureInitialize(&template_fixture);
    prepareServerPendingProfile(&template_fixture, tls_version, profile);
    uint8_t alert[kRealityV2AlertMessageSize];
    requireServer(realityV2SerializeAlert(kRealityV2AlertBadRecordMac, alert),
                  "failed to serialize fragmented server alert");
    sbuf_t *whole = buildServerInboundRecord(&template_fixture,
                                             tls_version,
                                             profile,
                                             kRealityV2RecordKindAlert,
                                             alert,
                                             sizeof(alert),
                                             0);
    uint32_t whole_len = sbufGetLength(whole);
    uint8_t record[64];
    requireServer(whole_len <= sizeof(record), "fragmented server alert fixture overflow");
    memoryCopy(record, sbufGetRawPtr(whole), whole_len);
    lineReuseBuffer(template_fixture.line, whole);
    realityserverLinestateDestroy(lineGetState(template_fixture.line, template_fixture.reality));
    serverFixtureDestroy(&template_fixture);

    for (uint32_t split = 1; split < whole_len; ++split)
    {
        server_lifecycle_fixture_t fixture;
        serverFixtureInitialize(&fixture);
        prepareServerPendingProfile(&fixture, tls_version, profile);
        reality_v2_record_descriptor_t descriptor;
        reality_v2_record_layout_t layout;
        requireServer(realityV2BuildRecordDescriptor(tls_version,
                                                      profile,
                                                      kRealityV2RecordKindAlert,
                                                      &descriptor) &&
                          realityV2CalculateDescriptorLayout(&descriptor, sizeof(alert), &layout),
                      "failed to restore fragmented server alert shape");
        fixture.context.expected_alert_type = descriptor.outer_content_type;
        fixture.context.expected_alert_body_len = (uint16_t) layout.wire_body_len;
        requireServer(realityserverProcessUpstream(
                          fixture.reality,
                          fixture.line,
                          serverBufferFromBytes(&fixture, record, split)),
                      "server rejected an incomplete alert fragment");
        requireServer(fixture.context.events_len == 0,
                      "server emitted callbacks before the alert was complete");
        requireServer(! realityserverProcessUpstream(
                          fixture.reality,
                          fixture.line,
                          serverBufferFromBytes(&fixture, record + split, whole_len - split)),
                      "server did not terminate after a complete fragmented alert");
        requireServer(strcmp(fixture.context.events, "IUD") == 0,
                      "server fragmented alert callback ordering mismatch");
        serverFixtureDestroy(&fixture);
    }
}

static void testServerCoalescedRecords(uint16_t tls_version,
                                       const reality_v2_record_profile_t *profile,
                                       bool alert_first)
{
    server_lifecycle_fixture_t fixture;
    serverFixtureInitialize(&fixture);
    prepareServerPendingProfile(&fixture, tls_version, profile);
    uint8_t alert[kRealityV2AlertMessageSize];
    uint8_t application = 0x5a;
    requireServer(realityV2SerializeAlert(kRealityV2AlertBadRecordMac, alert),
                  "failed to serialize coalesced server alert");
    sbuf_t *first = buildServerInboundRecord(&fixture,
                                             tls_version,
                                             profile,
                                             alert_first ? kRealityV2RecordKindAlert
                                                         : kRealityV2RecordKindApplicationData,
                                             alert_first ? alert : &application,
                                             alert_first ? sizeof(alert) : sizeof(application),
                                             0);
    sbuf_t *second = buildServerInboundRecord(&fixture,
                                              tls_version,
                                              profile,
                                              alert_first ? kRealityV2RecordKindApplicationData
                                                          : kRealityV2RecordKindAlert,
                                              alert_first ? &application : alert,
                                              alert_first ? sizeof(application) : sizeof(alert),
                                              1);
    uint32_t combined_len = sbufGetLength(first) + sbufGetLength(second);
    uint8_t combined[128];
    requireServer(combined_len <= sizeof(combined), "coalesced server fixture overflow");
    memoryCopy(combined, sbufGetRawPtr(first), sbufGetLength(first));
    memoryCopy(combined + sbufGetLength(first), sbufGetRawPtr(second), sbufGetLength(second));
    lineReuseBuffer(fixture.line, first);
    lineReuseBuffer(fixture.line, second);
    requireServer(! realityserverProcessUpstream(fixture.reality,
                                                 fixture.line,
                                                 serverBufferFromBytes(&fixture,
                                                                       combined,
                                                                       combined_len)),
                  "server did not terminate after a coalesced alert");
    requireServer(strcmp(fixture.context.events, alert_first ? "IUD" : "IAUD") == 0,
                  "server coalesced record behavior mismatch");
    serverFixtureDestroy(&fixture);
}

static void testServerTerminalReentry(void)
{
    server_lifecycle_fixture_t fixture;
    serverFixtureInitialize(&fixture);
    fixture.context.reenter_peer_close = true;
    fixture.context.send_data_after_close = true;
    realityserverHandleDownstreamFinish(fixture.reality, fixture.line);
    requireServer(strcmp(fixture.context.events, "PD") == 0,
                  "server terminal re-entry emitted duplicate callbacks");
    requireServer(fixture.context.observed_alert == kRealityV2AlertCloseNotify,
                  "server simultaneous close changed the orderly alert");
    serverFixtureDestroy(&fixture);

    serverFixtureInitialize(&fixture);
    fixture.context.reenter_peer_close = true;
    realityserverFailAuthenticated(fixture.reality, fixture.line);
    requireServer(strcmp(fixture.context.events, "PUD") == 0,
                  "server fatal terminal re-entry emitted duplicate callbacks");
    requireServer(fixture.context.observed_alert == kRealityV2AlertBadRecordMac,
                  "server orderly close displaced an in-progress fatal alert");
    serverFixtureDestroy(&fixture);
}

static void testServerUnauthenticatedCloseModes(void)
{
    const uint8_t modes[] = {
        kRealityServerModePending,
        kRealityServerModeHandoffAwaitBoundary,
        kRealityServerModeHandoffAwaitConfirm,
        kRealityServerModeVisitor,
    };
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i)
    {
        server_lifecycle_fixture_t fixture;
        serverFixtureInitialize(&fixture);
        realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
        ls->mode = modes[i];
        ls->protected_init_sent = false;
        realityserverHandleDownstreamFinish(fixture.reality, fixture.line);
        requireServer(strcmp(fixture.context.events, "D") == 0,
                      "pre-authorization close synthesized a Reality alert");
        serverFixtureDestroy(&fixture);
    }

    server_lifecycle_fixture_t fixture;
    serverFixtureInitialize(&fixture);
    realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    ls->closing_destination_for_authorized = true;
    realityserverTunnelDownStreamFinish(fixture.reality, fixture.line);
    requireServer(fixture.context.events_len == 0,
                  "destination teardown synthesized a Reality alert or Finish");
    realityserverLinestateDestroy(ls);
    serverFixtureDestroy(&fixture);
}

static void testServerSecureRandomFailure(void)
{
    const reality_v2_record_profile_t profiles[] = {
        {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0},
        {kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20},
    };
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        server_lifecycle_fixture_t fixture;
        serverFixtureInitialize(&fixture);
        realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
        ls->tls_capture.binding.tls_version = kRealityV2Tls12;
        ls->record_profile = profiles[i];
        ls->server_gcm_nonce_policy = kRealityServerGcmNoncePolicyRandom;

        const bool random_was_initialized = GSTATE.secure_random.initialized;
        GSTATE.secure_random.initialized = false;
        realityserverHandleDownstreamFinish(fixture.reality, fixture.line);
        GSTATE.secure_random.initialized = random_was_initialized;

        requireServer(strcmp(fixture.context.events, "D") == 0,
                      "server random failure did not close without emitting a partial alert");
        requireServer(fixture.context.observed_alert == kRealityV2AlertInvalid,
                      "server random failure exposed an alert frame");
        serverFixtureDestroy(&fixture);
    }
}

static void testServerTlsRecordBoundaryTracker(void)
{
    const uint8_t first_record[] = {
        0x17, 0x03, 0x03, 0x00, 0x06, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    };
    const uint8_t second_record[] = {
        0x16, 0x03, 0x03, 0x00, 0x03, 0x20, 0x21, 0x22,
    };

    for (size_t split = 1; split < sizeof(first_record); ++split)
    {
        realityserver_tls_record_boundary_tracker_t tracker;
        realityserverTlsRecordBoundaryTrackerInitialize(&tracker);
        requireServer(realityserverTlsRecordBoundaryTrackerIsAtBoundary(&tracker),
                      "server boundary tracker did not start between records");

        size_t consumed = 0;
        requireServer(realityserverTlsRecordBoundaryTrackerFeed(&tracker,
                                                                 first_record,
                                                                 split,
                                                                 false,
                                                                 &consumed) &&
                          consumed == split &&
                          ! realityserverTlsRecordBoundaryTrackerIsAtBoundary(&tracker),
                      "server boundary tracker lost a fragmented record prefix");
        requireServer(realityserverTlsRecordBoundaryTrackerFeed(&tracker,
                                                                 first_record + split,
                                                                 sizeof(first_record) - split,
                                                                 true,
                                                                 &consumed) &&
                          consumed == sizeof(first_record) - split &&
                          realityserverTlsRecordBoundaryTrackerIsAtBoundary(&tracker),
                      "server boundary tracker did not report the fragmented record end");
        realityserverTlsRecordBoundaryTrackerDestroy(&tracker);
    }

    uint8_t coalesced[sizeof(first_record) + sizeof(second_record)];
    memoryCopy(coalesced, first_record, sizeof(first_record));
    memoryCopy(coalesced + sizeof(first_record), second_record, sizeof(second_record));
    realityserver_tls_record_boundary_tracker_t tracker;
    realityserverTlsRecordBoundaryTrackerInitialize(&tracker);
    size_t consumed = 0;
    requireServer(realityserverTlsRecordBoundaryTrackerFeed(&tracker,
                                                             coalesced,
                                                             sizeof(coalesced),
                                                             true,
                                                             &consumed) &&
                      consumed == sizeof(first_record) &&
                      realityserverTlsRecordBoundaryTrackerIsAtBoundary(&tracker),
                  "server boundary tracker did not split at the first complete record");
    requireServer(realityserverTlsRecordBoundaryTrackerFeed(&tracker,
                                                             coalesced + consumed,
                                                             sizeof(coalesced) - consumed,
                                                             false,
                                                             &consumed) &&
                      consumed == sizeof(second_record) &&
                      realityserverTlsRecordBoundaryTrackerIsAtBoundary(&tracker),
                  "server boundary tracker did not resume after a cutoff split");

    const uint8_t invalid_header[] = {0x18, 0x03, 0x03, 0x00, 0x00};
    realityserverTlsRecordBoundaryTrackerInitialize(&tracker);
    requireServer(! realityserverTlsRecordBoundaryTrackerFeed(&tracker,
                                                               invalid_header,
                                                               sizeof(invalid_header),
                                                               false,
                                                               &consumed) &&
                      tracker.failed,
                  "server boundary tracker accepted an invalid TLS content type");
    realityserverTlsRecordBoundaryTrackerDestroy(&tracker);
}

static void testServerTls13AuthenticatedHandoff(void)
{
    server_lifecycle_fixture_t fixture;
    serverFixtureInitialize(&fixture);
    serverFixtureAddDestination(&fixture);
    fixture.prev->fnPayloadD = serverHandoffPrevPayload;

    const reality_v2_record_profile_t profile = {
        .profile_id = kRealityV2RecordProfileTls13Aead,
        .visible_prefix_len = 0,
    };
    prepareServerPendingProfile(&fixture, kRealityV2Tls13, &profile);
    realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    memorySet(ls->c2s_key, 0x31, sizeof(ls->c2s_key));
    memorySet(ls->c2s_iv, 0x42, sizeof(ls->c2s_iv));

    const uint8_t cover_record[] = {
        0x17, 0x03, 0x03, 0x00, 0x06, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
    };
    const uint32_t first_cover_part = 8;
    realityserverTunnelDownStreamPayload(
        fixture.reality,
        fixture.line,
        serverBufferFromBytes(&fixture, cover_record, first_cover_part));
    requireServer(strcmp(fixture.context.events, "c") == 0 &&
                      fixture.context.cover_downstream_bytes == first_cover_part &&
                      ! realityserverTlsRecordBoundaryTrackerIsAtBoundary(
                          &ls->destination_record_boundary),
                  "server did not track the already-forwarded partial cover record");

    const uint8_t early_application[] = {0x51, 0x52, 0x53, 0x54, 0x55};
    sbuf_t *application_before_request = buildServerInboundRecord(
        &fixture,
        kRealityV2Tls13,
        &profile,
        kRealityV2RecordKindApplicationData,
        early_application,
        sizeof(early_application),
        0);
    requireServer(realityserverProcessUpstream(fixture.reality,
                                               fixture.line,
                                               application_before_request) &&
                      ls->mode == kRealityServerModePending && ls->c2s_recv_seq == 0 &&
                      fixture.context.destination_upstream_records == 1,
                  "TLS 1.3 application data authorized before HANDOFF_REQUEST");

    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffRequest,
                                                0)) &&
                      ls->mode == kRealityServerModeHandoffAwaitBoundary &&
                      ls->handoff_request_authenticated && ! ls->handoff_ack_sent &&
                      ls->c2s_recv_seq == 1 && ! ls->protected_init_sent,
                  "server did not consume REQUEST while waiting for a cover-record boundary");

    const uint8_t suppressed_record[] = {
        0x17, 0x03, 0x03, 0x00, 0x02, 0x91, 0x92,
    };
    uint8_t final_cover_callback[(sizeof(cover_record) - first_cover_part) +
                                 sizeof(suppressed_record)];
    uint32_t final_prefix_len = sizeof(cover_record) - first_cover_part;
    memoryCopy(final_cover_callback, cover_record + first_cover_part, final_prefix_len);
    memoryCopy(final_cover_callback + final_prefix_len,
               suppressed_record,
               sizeof(suppressed_record));
    realityserverTunnelDownStreamPayload(
        fixture.reality,
        fixture.line,
        serverBufferFromBytes(&fixture,
                              final_cover_callback,
                              sizeof(final_cover_callback)));
    requireServer(ls->mode == kRealityServerModeHandoffAwaitConfirm &&
                      ls->handoff_ack_sent && ls->destination_downstream_cutoff &&
                      ls->s2c_send_seq == 1 && fixture.context.handoff_ack_records == 1 &&
                      fixture.context.cover_downstream_bytes == sizeof(cover_record) &&
                      strcmp(fixture.context.events, "cTcK") == 0,
                  "server did not split the final cover record before sending ACK");

    realityserverTunnelDownStreamPayload(
        fixture.reality,
        fixture.line,
        serverBufferFromBytes(&fixture, suppressed_record, sizeof(suppressed_record)));
    requireServer(strcmp(fixture.context.events, "cTcK") == 0,
                  "destination payload escaped after the downstream cutoff");

    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundRecord(&fixture,
                                               kRealityV2Tls13,
                                               &profile,
                                               kRealityV2RecordKindApplicationData,
                                               early_application,
                                               sizeof(early_application),
                                               1)) &&
                      ls->mode == kRealityServerModeHandoffAwaitConfirm &&
                      ls->c2s_recv_seq == 1 &&
                      fixture.context.destination_upstream_records == 2 &&
                      strcmp(fixture.context.events, "cTcKT") == 0,
                  "server did not route late cover TLS output to the destination");

    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffConfirm,
                                                1)) &&
                      ls->mode == kRealityServerModeAuthorized && ls->c2s_recv_seq == 2 &&
                      ls->s2c_send_seq == 1 && ls->destination_up_finished &&
                      ls->protected_init_sent && strcmp(fixture.context.events, "cTcKTFI") == 0,
                  "server did not close the destination and initialize protected routing after CONFIRM");

    const uint8_t protected_application = 0x5a;
    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundRecord(&fixture,
                                               kRealityV2Tls13,
                                               &profile,
                                               kRealityV2RecordKindApplicationData,
                                               &protected_application,
                                               sizeof(protected_application),
                                               2)) &&
                      ls->c2s_recv_seq == 3 && strcmp(fixture.context.events, "cTcKTFIA") == 0,
                  "server did not enter strict application routing at c2s sequence two");

    realityserverLinestateDestroy(ls);
    serverFixtureDestroy(&fixture);
}

static void testServerTls13ReentrantRequestCutsOffCoalescedSuffix(void)
{
    server_lifecycle_fixture_t fixture;
    serverFixtureInitialize(&fixture);
    serverFixtureAddDestination(&fixture);
    fixture.prev->fnPayloadD = serverHandoffPrevPayload;

    const reality_v2_record_profile_t profile = {
        .profile_id = kRealityV2RecordProfileTls13Aead,
        .visible_prefix_len = 0,
    };
    prepareServerPendingProfile(&fixture, kRealityV2Tls13, &profile);
    realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    memorySet(ls->c2s_key, 0x37, sizeof(ls->c2s_key));
    memorySet(ls->c2s_iv, 0x48, sizeof(ls->c2s_iv));

    const uint8_t first_record[] = {
        0x17, 0x03, 0x03, 0x00, 0x03, 0x81, 0x82, 0x83,
    };
    const uint8_t suppressed_record[] = {
        0x17, 0x03, 0x03, 0x00, 0x02, 0x91, 0x92,
    };
    uint8_t coalesced[sizeof(first_record) + sizeof(suppressed_record)];
    memoryCopy(coalesced, first_record, sizeof(first_record));
    memoryCopy(coalesced + sizeof(first_record), suppressed_record, sizeof(suppressed_record));
    fixture.context.request_on_cover_payload = buildServerInboundControl(
        &fixture, kRealityV2RecordKindHandoffRequest, 0);

    realityserverTunnelDownStreamPayload(
        fixture.reality,
        fixture.line,
        serverBufferFromBytes(&fixture, coalesced, sizeof(coalesced)));

    requireServer(ls->mode == kRealityServerModeHandoffAwaitConfirm &&
                      ls->handoff_request_authenticated && ls->handoff_ack_sent &&
                      ls->destination_downstream_cutoff && ls->c2s_recv_seq == 1 &&
                      ls->s2c_send_seq == 1 && fixture.context.handoff_ack_records == 1 &&
                      fixture.context.cover_downstream_bytes == sizeof(first_record) &&
                      memoryEqual(fixture.context.cover_downstream,
                                  first_record,
                                  sizeof(first_record)) &&
                      strcmp(fixture.context.events, "cK") == 0,
                  "server forwarded a coalesced record after the first re-entrant safe boundary");

    realityserverLinestateDestroy(ls);
    serverFixtureDestroy(&fixture);
}

static void testServerTls13NestedDestinationPayloadCompletesBoundary(void)
{
    server_lifecycle_fixture_t fixture;
    serverFixtureInitialize(&fixture);
    serverFixtureAddDestination(&fixture);
    fixture.prev->fnPayloadD = serverHandoffPrevPayload;

    const reality_v2_record_profile_t profile = {
        .profile_id = kRealityV2RecordProfileTls13Aead,
        .visible_prefix_len = 0,
    };
    prepareServerPendingProfile(&fixture, kRealityV2Tls13, &profile);
    realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    memorySet(ls->c2s_key, 0x39, sizeof(ls->c2s_key));
    memorySet(ls->c2s_iv, 0x4a, sizeof(ls->c2s_iv));

    const uint8_t first_record[] = {
        0x17, 0x03, 0x03, 0x00, 0x06, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
    };
    const uint32_t first_part_len = 8;
    const uint8_t suppressed_record[] = {
        0x17, 0x03, 0x03, 0x00, 0x02, 0x91, 0x92,
    };
    uint8_t nested_payload[(sizeof(first_record) - first_part_len) +
                           sizeof(suppressed_record)];
    memoryCopy(nested_payload,
               first_record + first_part_len,
               sizeof(first_record) - first_part_len);
    memoryCopy(nested_payload + sizeof(first_record) - first_part_len,
               suppressed_record,
               sizeof(suppressed_record));

    fixture.context.request_on_cover_payload = buildServerInboundControl(
        &fixture, kRealityV2RecordKindHandoffRequest, 0);
    fixture.context.destination_payload_on_cover_payload = serverBufferFromBytes(
        &fixture, nested_payload, sizeof(nested_payload));

    realityserverTunnelDownStreamPayload(
        fixture.reality,
        fixture.line,
        serverBufferFromBytes(&fixture, first_record, first_part_len));

    requireServer(fixture.context.request_on_cover_payload == NULL &&
                      fixture.context.destination_payload_on_cover_payload == NULL &&
                      ls->destination_downstream_forward_depth == 0 &&
                      ls->mode == kRealityServerModeHandoffAwaitConfirm &&
                      ls->handoff_request_authenticated && ls->handoff_ack_sent &&
                      ls->destination_downstream_cutoff && ls->c2s_recv_seq == 1 &&
                      ls->s2c_send_seq == 1 && fixture.context.handoff_ack_records == 1 &&
                      fixture.context.cover_downstream_bytes == sizeof(first_record) &&
                      memoryEqual(fixture.context.cover_downstream,
                                  first_record,
                                  sizeof(first_record)) &&
                      strcmp(fixture.context.events, "ccK") == 0,
                  "server did not defer ACK across nested destination Payload callbacks");

    realityserverLinestateDestroy(ls);
    serverFixtureDestroy(&fixture);
}

static void testServerTls13PendingCandidateBudgetIncludesNonControlLengths(void)
{
    server_lifecycle_fixture_t fixture;
    serverFixtureInitialize(&fixture);
    serverFixtureAddDestination(&fixture);

    const reality_v2_record_profile_t profile = {
        .profile_id = kRealityV2RecordProfileTls13Aead,
        .visible_prefix_len = 0,
    };
    prepareServerPendingProfile(&fixture, kRealityV2Tls13, &profile);
    realityserver_tstate_t *ts = tunnelGetState(fixture.reality);
    realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    ts->sniffing_attempts = 1;

    const uint32_t body_len = kRealityV2ControlMaxTlsRecordBody + 1U;
    const uint32_t frame_len = kRealityV2TlsRecordHeaderSize + body_len;
    sbuf_t *record = bufferpoolGetLargeBuffer(fixture.pool);
    requireServer(frame_len <= sbufGetMaximumWriteableSize(record),
                  "server non-control candidate fixture exceeds the large buffer");
    record = sbufReserveSpace(record, frame_len);
    sbufSetLength(record, frame_len);
    uint8_t *frame = sbufGetMutablePtr(record);
    memoryZero(frame, frame_len);
    frame[0] = 0x17;
    frame[1] = 0x03;
    frame[2] = 0x03;
    frame[3] = (uint8_t) (body_len >> 8);
    frame[4] = (uint8_t) body_len;

    requireServer(realityserverProcessUpstream(fixture.reality, fixture.line, record) &&
                      ls->mode == kRealityServerModeVisitor && ls->sniffing_attempts == 1 &&
                      ls->c2s_recv_seq == 0 &&
                      fixture.context.destination_upstream_records == 1 &&
                      strcmp(fixture.context.events, "T") == 0,
                  "server did not apply the Pending candidate budget outside control lengths");

    realityserverLinestateDestroy(ls);
    serverFixtureDestroy(&fixture);
}

static void testServerTls13NonRequestControlsStayPending(void)
{
    const uint8_t control_kinds[] = {
        kRealityV2RecordKindHandoffAck,
        kRealityV2RecordKindHandoffConfirm,
    };
    const reality_v2_record_profile_t profile = {
        .profile_id = kRealityV2RecordProfileTls13Aead,
        .visible_prefix_len = 0,
    };

    for (size_t i = 0; i < sizeof(control_kinds) / sizeof(control_kinds[0]); ++i)
    {
        server_lifecycle_fixture_t fixture;
        serverFixtureInitialize(&fixture);
        serverFixtureAddDestination(&fixture);
        prepareServerPendingProfile(&fixture, kRealityV2Tls13, &profile);
        realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);

        sbuf_t *control = buildServerInboundControl(&fixture, control_kinds[i], 0);
        uint8_t expected[128];
        uint32_t expected_len = sbufGetLength(control);
        requireServer(expected_len <= sizeof(expected),
                      "server non-REQUEST control fixture overflow");
        memoryCopy(expected, sbufGetRawPtr(control), expected_len);
        fixture.context.expected_destination_payload = expected;
        fixture.context.expected_destination_payload_len = expected_len;

        requireServer(realityserverProcessUpstream(fixture.reality, fixture.line, control) &&
                          ls->mode == kRealityServerModePending &&
                          ! ls->handoff_request_authenticated && ! ls->handoff_ack_sent &&
                          ! ls->protected_init_sent && ls->c2s_recv_seq == 0 &&
                          ls->s2c_send_seq == 0 && ls->sniffing_attempts == 1 &&
                          fixture.context.destination_upstream_records == 1 &&
                          fixture.context.matched_destination_payloads == 1 &&
                          strcmp(fixture.context.events, "T") == 0,
                      "server accepted ACK/CONFIRM as the initial handoff control");

        realityserverLinestateDestroy(ls);
        serverFixtureDestroy(&fixture);
    }
}

static void testServerTls13FailedRequestIsByteExactFallback(void)
{
    server_lifecycle_fixture_t fixture;
    serverFixtureInitialize(&fixture);
    serverFixtureAddDestination(&fixture);
    const reality_v2_record_profile_t profile = {
        .profile_id = kRealityV2RecordProfileTls13Aead,
        .visible_prefix_len = 0,
    };
    prepareServerPendingProfile(&fixture, kRealityV2Tls13, &profile);
    realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);

    sbuf_t *request = buildServerInboundControl(
        &fixture, kRealityV2RecordKindHandoffRequest, 0);
    uint32_t expected_len = sbufGetLength(request);
    uint8_t expected[128];
    requireServer(expected_len <= sizeof(expected), "server failed-REQUEST fixture overflow");
    sbufGetMutablePtr(request)[expected_len - 1U] ^= 0x80;
    memoryCopy(expected, sbufGetRawPtr(request), expected_len);
    fixture.context.expected_destination_payload = expected;
    fixture.context.expected_destination_payload_len = expected_len;

    requireServer(realityserverProcessUpstream(fixture.reality, fixture.line, request) &&
                      ls->mode == kRealityServerModePending &&
                      ! ls->handoff_request_authenticated && ! ls->handoff_ack_sent &&
                      ! ls->protected_init_sent && ls->c2s_recv_seq == 0 &&
                      ls->s2c_send_seq == 0 && ls->sniffing_attempts == 1 &&
                      fixture.context.destination_upstream_records == 1 &&
                      fixture.context.matched_destination_payloads == 1 &&
                      strcmp(fixture.context.events, "T") == 0,
                  "server mutated or consumed a failed HANDOFF_REQUEST trial");

    realityserverLinestateDestroy(ls);
    serverFixtureDestroy(&fixture);
}

static void testServerTls13DuplicateConfirmDoesNotReinitializeNext(void)
{
    server_lifecycle_fixture_t fixture;
    serverFixtureInitialize(&fixture);
    serverFixtureAddDestination(&fixture);
    fixture.prev->fnPayloadD = serverHandoffPrevPayload;
    const reality_v2_record_profile_t profile = {
        .profile_id = kRealityV2RecordProfileTls13Aead,
        .visible_prefix_len = 0,
    };
    prepareServerPendingProfile(&fixture, kRealityV2Tls13, &profile);
    realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);

    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffRequest,
                                                0)) &&
                      ls->mode == kRealityServerModeHandoffAwaitConfirm &&
                      strcmp(fixture.context.events, "K") == 0,
                  "server did not prepare duplicate-CONFIRM fixture");

    sbuf_t *confirm = buildServerInboundControl(
        &fixture, kRealityV2RecordKindHandoffConfirm, 1);
    sbuf_t *duplicate = buildServerInboundControl(
        &fixture, kRealityV2RecordKindHandoffConfirm, 1);
    requireServer(realityserverProcessUpstream(fixture.reality, fixture.line, confirm) &&
                      ls->mode == kRealityServerModeAuthorized &&
                      ls->protected_init_sent && strcmp(fixture.context.events, "KFI") == 0,
                  "server did not authorize the first valid CONFIRM");
    requireServer(! realityserverProcessUpstream(fixture.reality, fixture.line, duplicate) &&
                      strcmp(fixture.context.events, "KFIcUD") == 0,
                  "server accepted a duplicate CONFIRM or initialized protected routing twice");
    requireServer(strchr(fixture.context.events, 'I') ==
                      strrchr(fixture.context.events, 'I'),
                  "server emitted more than one protected Init for duplicate CONFIRM");

    serverFixtureDestroy(&fixture);
}

static void testServerTls13PendingForwardReentrantFinishKillsLine(void)
{
    server_lifecycle_fixture_t fixture;
    serverFixtureInitialize(&fixture);
    serverFixtureAddDestination(&fixture);
    const reality_v2_record_profile_t profile = {
        .profile_id = kRealityV2RecordProfileTls13Aead,
        .visible_prefix_len = 0,
    };
    prepareServerPendingProfile(&fixture, kRealityV2Tls13, &profile);
    fixture.context.finish_on_destination_payload = true;
    fixture.context.kill_on_prev_finish = true;

    requireServer(! realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffAck,
                                                0)) &&
                      ! lineIsAlive(fixture.line) &&
                      strcmp(fixture.context.events, "TD") == 0,
                  "server touched Pending state after a re-entrant destination Finish killed the line");

    serverFixtureDestroy(&fixture);
}

static void testServerTls13PendingBudgetCannotOverwriteReentrantHandoff(void)
{
    server_lifecycle_fixture_t fixture;
    serverFixtureInitialize(&fixture);
    serverFixtureAddDestination(&fixture);
    fixture.prev->fnPayloadD = serverHandoffPrevPayload;

    const reality_v2_record_profile_t profile = {
        .profile_id = kRealityV2RecordProfileTls13Aead,
        .visible_prefix_len = 0,
    };
    prepareServerPendingProfile(&fixture, kRealityV2Tls13, &profile);
    realityserver_tstate_t *ts = tunnelGetState(fixture.reality);
    realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    ts->sniffing_attempts = 1;
    fixture.context.request_on_destination_payload = buildServerInboundControl(
        &fixture, kRealityV2RecordKindHandoffRequest, 0);

    const uint32_t body_len = kRealityV2ControlMaxTlsRecordBody + 1U;
    const uint32_t frame_len = kRealityV2TlsRecordHeaderSize + body_len;
    sbuf_t *record = bufferpoolGetLargeBuffer(fixture.pool);
    requireServer(frame_len <= sbufGetMaximumWriteableSize(record),
                  "server re-entrant budget fixture exceeds the large buffer");
    record = sbufReserveSpace(record, frame_len);
    sbufSetLength(record, frame_len);
    uint8_t *frame = sbufGetMutablePtr(record);
    memoryZero(frame, frame_len);
    frame[0] = 0x17;
    frame[1] = 0x03;
    frame[2] = 0x03;
    frame[3] = (uint8_t) (body_len >> 8);
    frame[4] = (uint8_t) body_len;

    requireServer(realityserverProcessUpstream(fixture.reality, fixture.line, record) &&
                      fixture.context.request_on_destination_payload == NULL &&
                      ls->mode == kRealityServerModeHandoffAwaitConfirm &&
                      ls->handoff_request_authenticated && ls->handoff_ack_sent &&
                      ls->destination_downstream_cutoff && ls->sniffing_attempts == 1 &&
                      ls->c2s_recv_seq == 1 && ls->s2c_send_seq == 1 &&
                      fixture.context.destination_upstream_records == 1 &&
                      fixture.context.handoff_ack_records == 1 &&
                      strcmp(fixture.context.events, "TK") == 0,
                  "server Pending budget overwrote a handoff authenticated by re-entry");

    realityserverLinestateDestroy(ls);
    serverFixtureDestroy(&fixture);
}

static void prepareServerTls13ReentryFixture(server_lifecycle_fixture_t *fixture)
{
    const reality_v2_record_profile_t profile = {
        .profile_id = kRealityV2RecordProfileTls13Aead,
        .visible_prefix_len = 0,
    };

    serverFixtureInitialize(fixture);
    serverFixtureAddDestination(fixture);
    fixture->prev->fnPayloadD = serverHandoffPrevPayload;
    prepareServerPendingProfile(fixture, kRealityV2Tls13, &profile);
}

static void testServerTls13LineDeathAtHandoffCallbacks(void)
{
    server_lifecycle_fixture_t fixture;
    prepareServerTls13ReentryFixture(&fixture);
    realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);

    const uint8_t cover_record[] = {
        0x17, 0x03, 0x03, 0x00, 0x06, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
    };
    const uint8_t suppressed_record[] = {
        0x17, 0x03, 0x03, 0x00, 0x02, 0x91, 0x92,
    };
    const uint32_t first_part_len = 8;
    realityserverTunnelDownStreamPayload(
        fixture.reality,
        fixture.line,
        serverBufferFromBytes(&fixture, cover_record, first_part_len));
    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffRequest,
                                                0)) &&
                      ls->mode == kRealityServerModeHandoffAwaitBoundary &&
                      strcmp(fixture.context.events, "c") == 0,
                  "server did not prepare the final-cover-prefix death fixture");

    uint8_t final_callback[(sizeof(cover_record) - first_part_len) +
                           sizeof(suppressed_record)];
    memoryCopy(final_callback,
               cover_record + first_part_len,
               sizeof(cover_record) - first_part_len);
    memoryCopy(final_callback + sizeof(cover_record) - first_part_len,
               suppressed_record,
               sizeof(suppressed_record));
    fixture.context.kill_on_cover_payload = true;
    realityserverTunnelDownStreamPayload(
        fixture.reality,
        fixture.line,
        serverBufferFromBytes(&fixture, final_callback, sizeof(final_callback)));
    requireServer(! lineIsAlive(fixture.line) &&
                      fixture.context.cover_downstream_bytes == sizeof(cover_record) &&
                      memoryEqual(fixture.context.cover_downstream,
                                  cover_record,
                                  sizeof(cover_record)) &&
                      fixture.context.handoff_ack_records == 0 &&
                      strcmp(fixture.context.events, "ccF") == 0,
                  "server continued after line death in final cover-prefix forwarding");
    serverFixtureDestroy(&fixture);

    prepareServerTls13ReentryFixture(&fixture);
    fixture.context.kill_on_ack_payload = true;
    requireServer(! realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffRequest,
                                                0)) &&
                      ! lineIsAlive(fixture.line) &&
                      fixture.context.handoff_ack_records == 1 &&
                      strcmp(fixture.context.events, "KF") == 0,
                  "server continued after line death during HANDOFF_ACK send");
    serverFixtureDestroy(&fixture);

    prepareServerTls13ReentryFixture(&fixture);
    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffRequest,
                                                0)) &&
                      strcmp(fixture.context.events, "K") == 0,
                  "server did not prepare the destination-Finish death fixture");
    fixture.context.kill_on_destination_finish = true;
    requireServer(! realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffConfirm,
                                                1)) &&
                      ! lineIsAlive(fixture.line) &&
                      strcmp(fixture.context.events, "KF") == 0,
                  "server continued after line death during destination Finish");
    serverFixtureDestroy(&fixture);

    prepareServerTls13ReentryFixture(&fixture);
    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffRequest,
                                                0)) &&
                      strcmp(fixture.context.events, "K") == 0,
                  "server did not prepare the protected-Init death fixture");
    fixture.context.kill_on_protected_init = true;
    requireServer(! realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffConfirm,
                                                1)) &&
                      ! lineIsAlive(fixture.line) &&
                      strcmp(fixture.context.events, "KFIU") == 0,
                  "server continued after line death during protected Init");
    serverFixtureDestroy(&fixture);

    prepareServerTls13ReentryFixture(&fixture);
    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffRequest,
                                                0)) &&
                      realityserverProcessUpstream(
                          fixture.reality,
                          fixture.line,
                          buildServerInboundControl(&fixture,
                                                    kRealityV2RecordKindHandoffConfirm,
                                                    1)) &&
                      strcmp(fixture.context.events, "KFI") == 0,
                  "server did not prepare the first-application death fixture");
    ls = lineGetState(fixture.line, fixture.reality);
    fixture.context.kill_on_protected_payload = true;
    const uint8_t protected_application = 0x5a;
    requireServer(! realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundRecord(&fixture,
                                               kRealityV2Tls13,
                                               &ls->record_profile,
                                               kRealityV2RecordKindApplicationData,
                                               &protected_application,
                                               sizeof(protected_application),
                                               2)) &&
                      ! lineIsAlive(fixture.line) &&
                      strcmp(fixture.context.events, "KFIAU") == 0,
                  "server continued after line death during first protected application");
    serverFixtureDestroy(&fixture);
}

static void testServerTls13DestinationCallbacksStaySuppressed(void)
{
    server_lifecycle_fixture_t fixture;
    prepareServerTls13ReentryFixture(&fixture);
    fixture.context.inject_destination_callbacks_on_ack = true;
    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffRequest,
                                                0)),
                  "server rejected REQUEST during cutoff callback injection");
    realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    requireServer(ls->mode == kRealityServerModeHandoffAwaitConfirm &&
                      ls->destination_downstream_cutoff && ls->destination_up_finished &&
                      ! ls->protected_init_sent && ! ls->prev_est_sent &&
                      fixture.context.destination_callbacks_injected == 5 &&
                      fixture.context.cover_downstream_bytes == 0 &&
                      strcmp(fixture.context.events, "K") == 0,
                  "destination callbacks escaped while the downstream cutoff was active");

    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffConfirm,
                                                1)) &&
                      ls->mode == kRealityServerModeAuthorized &&
                      ls->protected_init_sent && strcmp(fixture.context.events, "KI") == 0,
                  "cutoff callback suppression prevented clean authorization");
    const uint8_t protected_application = 0x5a;
    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundRecord(&fixture,
                                               kRealityV2Tls13,
                                               &ls->record_profile,
                                               kRealityV2RecordKindApplicationData,
                                               &protected_application,
                                               sizeof(protected_application),
                                               2)) &&
                      strcmp(fixture.context.events, "KIA") == 0,
                  "protected routing did not remain usable after cutoff callback suppression");
    realityserverLinestateDestroy(ls);
    serverFixtureDestroy(&fixture);

    prepareServerTls13ReentryFixture(&fixture);
    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffRequest,
                                                0)) &&
                      strcmp(fixture.context.events, "K") == 0,
                  "server did not prepare the destination-close callback fixture");
    fixture.context.inject_destination_callbacks_on_finish = true;
    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffConfirm,
                                                1)),
                  "server rejected CONFIRM during destination-close callback injection");
    ls = lineGetState(fixture.line, fixture.reality);
    requireServer(ls->mode == kRealityServerModeAuthorized && ls->destination_up_finished &&
                      ls->protected_init_sent && ! ls->closing_destination_for_authorized &&
                      ! ls->prev_est_sent &&
                      fixture.context.destination_callbacks_injected == 5 &&
                      fixture.context.cover_downstream_bytes == 0 &&
                      strcmp(fixture.context.events, "KFI") == 0,
                  "destination callbacks escaped during the authorization close window");

    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundRecord(&fixture,
                                               kRealityV2Tls13,
                                               &ls->record_profile,
                                               kRealityV2RecordKindApplicationData,
                                               &protected_application,
                                               sizeof(protected_application),
                                               2)) &&
                      strcmp(fixture.context.events, "KFIA") == 0,
                  "protected routing did not remain usable after close callback suppression");
    realityserverLinestateDestroy(ls);
    serverFixtureDestroy(&fixture);
}

static void testServerTls13HandoffTailBound(void)
{
    server_lifecycle_fixture_t fixture;
    serverFixtureInitialize(&fixture);
    serverFixtureAddDestination(&fixture);
    fixture.prev->fnPayloadD = serverHandoffPrevPayload;

    const reality_v2_record_profile_t profile = {
        .profile_id = kRealityV2RecordProfileTls13Aead,
        .visible_prefix_len = 0,
    };
    prepareServerPendingProfile(&fixture, kRealityV2Tls13, &profile);
    realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
    memorySet(ls->c2s_key, 0x61, sizeof(ls->c2s_key));
    memorySet(ls->c2s_iv, 0x72, sizeof(ls->c2s_iv));

    requireServer(realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      buildServerInboundControl(&fixture,
                                                kRealityV2RecordKindHandoffRequest,
                                                0)) &&
                      ls->mode == kRealityServerModeHandoffAwaitConfirm &&
                      strcmp(fixture.context.events, "K") == 0,
                  "server did not ACK an authenticated request at an existing boundary");

    const uint8_t late_cover_record[] = {0x17, 0x03, 0x03, 0x00, 0x01, 0xa5};
    for (uint32_t i = 0; i < kRealityServerMaxHandoffTailRecords; ++i)
    {
        requireServer(realityserverProcessUpstream(
                          fixture.reality,
                          fixture.line,
                          serverBufferFromBytes(&fixture,
                                                late_cover_record,
                                                sizeof(late_cover_record))),
                      "server closed before reaching the handoff-tail record bound");
    }
    requireServer(ls->c2s_recv_seq == 1 &&
                      fixture.context.destination_upstream_records ==
                          kRealityServerMaxHandoffTailRecords &&
                      strcmp(fixture.context.events, "KTTTTTTTT") == 0,
                  "failed handoff trials changed sequence state or skipped destination routing");

    requireServer(! realityserverProcessUpstream(
                      fixture.reality,
                      fixture.line,
                      serverBufferFromBytes(&fixture,
                                            late_cover_record,
                                            sizeof(late_cover_record))) &&
                      strcmp(fixture.context.events, "KTTTTTTTTFD") == 0,
                  "server did not close silently at the handoff-tail record bound");
    serverFixtureDestroy(&fixture);
}

void realityTestServerCloseLifecycle(void)
{
    runServerScenario(realityserverHandleDownstreamFinish, "PD", false, false);
    runServerScenario(serverPeerClose, "PUD", false, false);
    runServerScenario(serverPeerFatal, "UD", false, false);
    runServerScenario(realityserverHandleUpstreamFinish, "U", false, false);
    runServerScenario(realityserverFailAuthenticated, "PUD", false, false);
    runServerScenario(realityserverHandleDownstreamFinish, "P", true, false);
    runServerScenario(realityserverFailAuthenticated, "PU", false, true);

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
        if (versions[i] == kRealityV2Tls12)
        {
            runFirstFatalAuthorization(versions[i], &profiles[i]);
            runServerFragmentedAlert(versions[i], &profiles[i]);
            testServerCoalescedRecords(versions[i], &profiles[i], false);
            testServerCoalescedRecords(versions[i], &profiles[i], true);
        }
    }
    testServerTerminalReentry();
    testServerUnauthenticatedCloseModes();
    testServerSecureRandomFailure();
    testServerTlsRecordBoundaryTracker();
    testServerTls13PendingCandidateBudgetIncludesNonControlLengths();
    testServerTls13NonRequestControlsStayPending();
    testServerTls13FailedRequestIsByteExactFallback();
    testServerTls13DuplicateConfirmDoesNotReinitializeNext();
    testServerTls13PendingForwardReentrantFinishKillsLine();
    testServerTls13PendingBudgetCannotOverwriteReentrantHandoff();
    testServerTls13ReentrantRequestCutsOffCoalescedSuffix();
    testServerTls13NestedDestinationPayloadCompletesBoundary();
    testServerTls13LineDeathAtHandoffCallbacks();
    testServerTls13DestinationCallbacksStaySuppressed();
    testServerTls13AuthenticatedHandoff();
    testServerTls13HandoffTailBound();
}

typedef struct server_sizing_context_s
{
    tunnel_t *reality;
    buffer_pool_t *pool;
    const uint8_t *expected_payload;
    uint32_t expected_payload_len;
    uint32_t recovered_payload_len;
    uint32_t body_lengths[3];
    uint32_t record_count;
    bool kill_after_first_record;
} server_sizing_context_t;

static void serverSizingCapture(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    server_sizing_context_t *context = *(server_sizing_context_t **) tunnelGetState(t);
    realityserver_lstate_t *ls = lineGetState(l, context->reality);
    const uint8_t *record = sbufGetRawPtr(buf);
    uint32_t record_len = sbufGetLength(buf);
    requireServer(record_len >= kRealityV2TlsRecordHeaderSize,
                  "server sizing capture received a truncated TLS record");

    reality_v2_record_descriptor_t descriptor;
    requireServer(realityV2BuildRecordDescriptor(ls->tls_capture.binding.tls_version,
                                                  &ls->record_profile,
                                                  kRealityV2RecordKindApplicationData,
                                                  &descriptor),
                  "server sizing descriptor construction failed");
    uint32_t chunk_len = min(context->expected_payload_len - context->recovered_payload_len,
                             (uint32_t) kRealityV2MaxPlaintextFragment);
    reality_v2_record_layout_t layout;
    requireServer(realityV2CalculateDescriptorLayout(&descriptor, chunk_len, &layout) &&
                      record_len == kRealityV2TlsRecordHeaderSize + layout.wire_body_len &&
                      record[0] == descriptor.outer_content_type && record[1] == 0x03 &&
                      record[2] == 0x03 &&
                      ((((uint32_t) record[3] << 8) | record[4]) == layout.wire_body_len),
                  "server sizing capture observed the wrong native record body length");
    requireServer(context->record_count < sizeof(context->body_lengths) / sizeof(context->body_lengths[0]),
                  "server sizing capture emitted too many records");
    context->body_lengths[context->record_count] = layout.wire_body_len;

    const uint8_t *visible_prefix = record + kRealityV2TlsRecordHeaderSize;
    if (descriptor.profile.profile_id == kRealityV2RecordProfileTls12Gcm)
    {
        requireServer(realityV2ReadBe64(visible_prefix) == 10U + context->record_count,
                      "server sizing GCM explicit nonce did not continue the TLS sequence");
    }
    const uint8_t *ciphertext = visible_prefix + descriptor.visible_prefix_len;
    uint32_t ciphertext_len = layout.wire_body_len - descriptor.visible_prefix_len;
    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadMaxSize];
    uint8_t inner[kRealityV2MaxPlaintextFragment + kRealityV2TagSize + 1];
    size_t aad_len = 0;
    realityV2BuildNonce(ls->s2c_iv, context->record_count, nonce);
    requireServer(realityV2BuildRecordAad(&descriptor,
                                          kRealityV2DirectionServerToClient,
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
                                              ls->s2c_key) == 0,
                  "server sizing record failed to decrypt");
    uint32_t payload_offset;
    uint32_t payload_len;
    requireServer(realityV2ValidateInnerPlaintext(&descriptor,
                                                  inner,
                                                  ciphertext_len - kRealityV2TagSize,
                                                  &payload_offset,
                                                  &payload_len) &&
                      payload_len == chunk_len &&
                      memcmp(inner + payload_offset,
                             context->expected_payload + context->recovered_payload_len,
                             payload_len) == 0,
                  "server sizing record did not recover the original plaintext chunk");

    context->recovered_payload_len += payload_len;
    ++context->record_count;
    bufferpoolReuseBuffer(context->pool, buf);
    if (context->kill_after_first_record)
    {
        l->alive = false;
    }
}

static void runServerSizingCase(uint16_t tls_version,
                                const reality_v2_record_profile_t *profile,
                                uint32_t input_len,
                                bool kill_after_first_record)
{
    master_pool_t *large_master = masterpoolCreateWithCapacity(8);
    master_pool_t *small_master = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool = bufferpoolCreate(large_master, small_master, 8, 65536, 1024);
    bufferpoolUpdateAllocationPaddings(pool,
                                       kRealityServerMaxFramePrefixSize,
                                       kRealityServerMaxFramePrefixSize);
    buffer_pool_t *shortcut[1] = {pool};
    buffer_pool_t **saved_shortcuts = GSTATE.shortcut_buffer_pools;
    GSTATE.shortcut_buffer_pools = shortcut;

    tunnel_t *capture = tunnelCreate(NULL, sizeof(server_sizing_context_t *), 0);
    tunnel_t *reality = tunnelCreate(NULL, sizeof(realityserver_tstate_t), sizeof(realityserver_lstate_t));
    requireServer(capture != NULL && reality != NULL, "failed to create server sizing tunnels");
    tunnelBind(capture, reality);
    capture->fnPayloadD = serverSizingCapture;

    line_t *line = memoryAllocateCacheAlignedZero(sizeof(line_t) + reality->lstate_size);
    requireServer(line != NULL, "failed to allocate server sizing line");
    atomic_init(&line->refc, 1);
    line->alive = true;
    line->wid = 0;

    realityserver_tstate_t *ts = tunnelGetState(reality);
    ts->algorithm = kRealityServerAlgorithmChaCha20Poly1305;
    realityserver_lstate_t *ls = lineGetState(line, reality);
    realityserverLinestateInitialize(ls, pool);
    ls->record_profile = *profile;
    ls->tls_capture.binding.tls_version = tls_version;
    ls->session_keys_ready = true;
    ls->mode = kRealityServerModeAuthorized;
    ls->server_gcm_nonce_policy = kRealityServerGcmNoncePolicySequence;
    ls->server_tls_sequence_base = 10;
    memorySet(ls->session_id, 0x64, sizeof(ls->session_id));
    memorySet(ls->s2c_key, 0x75, sizeof(ls->s2c_key));
    memorySet(ls->s2c_iv, 0x86, sizeof(ls->s2c_iv));

    sbuf_t *input = bufferpoolGetLargeBuffer(pool);
    requireServer(input_len <= sbufGetMaximumWriteableSize(input),
                  "server sizing input does not fit the test buffer");
    input = sbufReserveSpace(input, input_len);
    sbufSetLength(input, input_len);
    uint8_t *input_bytes = sbufGetMutablePtr(input);
    uint8_t *expected_bytes = memoryAllocate(input_len);
    requireServer(expected_bytes != NULL, "failed to allocate server sizing expected payload");
    for (uint32_t i = 0; i < input_len; ++i)
    {
        input_bytes[i] = (uint8_t) (i * 31U + 11U);
        expected_bytes[i] = input_bytes[i];
    }

    server_sizing_context_t context = {
        .reality = reality,
        .pool = pool,
        .expected_payload = expected_bytes,
        .expected_payload_len = input_len,
        .kill_after_first_record = kill_after_first_record,
    };
    *(server_sizing_context_t **) tunnelGetState(capture) = &context;

    bool sent = realityserverEncryptAndSendDownstream(reality, line, input);
    uint32_t expected_records = (input_len + kRealityV2MaxPlaintextFragment - 1U) /
                                kRealityV2MaxPlaintextFragment;
    if (kill_after_first_record)
    {
        requireServer(! sent && context.record_count == 1 &&
                          context.recovered_payload_len == kRealityV2MaxPlaintextFragment,
                      "server sizing sender did not stop immediately when the line died");
        line->alive = true;
    }
    else
    {
        requireServer(sent && context.record_count == expected_records &&
                          context.recovered_payload_len == input_len,
                      "server sizing sender emitted the wrong chunk sequence");
        if (input_len == 32768)
        {
            requireServer(context.record_count == 2,
                          "server 32768-byte callback emitted a tiny third record");
        }
    }

    realityserverLinestateDestroy(ls);
    memoryFree(expected_bytes);
    requireServer(atomic_load(&line->refc) == 1, "server sizing line reference leaked");
    memoryFreeAligned(line);
    tunnelDestroy(capture);
    tunnelDestroy(reality);
    GSTATE.shortcut_buffer_pools = saved_shortcuts;
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);
}

void realityTestServerRecordSizing(void)
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
            runServerSizingCase(profiles[i].tls_version,
                                &profiles[i].profile,
                                input_lengths[j],
                                false);
        }
        runServerSizingCase(profiles[i].tls_version, &profiles[i].profile, 32768, true);
    }
}
