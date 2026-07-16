#include "RealityServer/structure.h"

#include "reality_close_lifecycle_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct server_lifecycle_context_s
{
    tunnel_t *reality;
    buffer_pool_t *pool;
    char events[16];
    size_t events_len;
    bool kill_on_payload;
    bool kill_on_next_finish;
    bool reenter_peer_close;
    bool send_data_after_close;
    uint8_t expected_alert_type;
    uint16_t expected_alert_body_len;
    uint8_t observed_alert;
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
    discard l;
    serverEvent(serverContext(t), 'D');
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
    discard l;
}

static void serverNextInit(tunnel_t *t, line_t *l)
{
    discard l;
    serverEvent(serverContext(t), 'I');
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
    const uint8_t modes[] = {kRealityServerModePending, kRealityServerModeVisitor};
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i)
    {
        server_lifecycle_fixture_t fixture;
        serverFixtureInitialize(&fixture);
        realityserver_lstate_t *ls = lineGetState(fixture.line, fixture.reality);
        ls->mode = modes[i];
        ls->protected_init_sent = false;
        realityserverHandleDownstreamFinish(fixture.reality, fixture.line);
        requireServer(strcmp(fixture.context.events, "D") == 0,
                      "Pending/Visitor close synthesized a Reality alert");
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
        runFirstFatalAuthorization(versions[i], &profiles[i]);
        runServerFragmentedAlert(versions[i], &profiles[i]);
        testServerCoalescedRecords(versions[i], &profiles[i], false);
        testServerCoalescedRecords(versions[i], &profiles[i], true);
    }
    testServerTerminalReentry();
    testServerUnauthenticatedCloseModes();
    testServerSecureRandomFailure();
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
