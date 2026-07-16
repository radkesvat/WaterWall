#include "RealityClient/structure.h"

#include "reality_close_lifecycle_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    uint8_t expected_alert_type;
    uint16_t expected_alert_body_len;
    uint8_t observed_alert;
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
    line_t *line;
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
                                                  1,
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
    requireClient(fixture->prev != NULL && fixture->reality != NULL && fixture->next != NULL,
                  "failed to create client lifecycle tunnels");
    tunnelBind(fixture->prev, fixture->reality);
    tunnelBind(fixture->reality, fixture->next);

    fixture->context = (client_lifecycle_context_t) {
        .reality = fixture->reality,
        .pool = fixture->pool,
        .expected_alert_type = 0x17,
        .expected_alert_body_len = 19,
    };
    *(client_lifecycle_context_t **) tunnelGetState(fixture->prev) = &fixture->context;
    *(client_lifecycle_context_t **) tunnelGetState(fixture->next) = &fixture->context;
    fixture->prev->fnFinD = clientPrevFinish;
    fixture->prev->fnPayloadD = clientPrevPayload;
    fixture->prev->fnPauseD = clientPrevPause;
    fixture->prev->fnResumeD = clientPrevResume;
    fixture->next->fnPayloadU = clientNextPayload;
    fixture->next->fnFinU = clientNextFinish;

    uint32_t line_size = sizeof(line_t) + fixture->reality->lstate_size;
    fixture->line = memoryAllocateCacheAlignedZero(line_size);
    requireClient(fixture->line != NULL, "failed to allocate client lifecycle line");
    atomic_init(&fixture->line->refc, 1);
    fixture->line->alive = true;
    fixture->line->wid = 0;

    realityclient_tstate_t *ts = tunnelGetState(fixture->reality);
    ts->algorithm = kRealityClientAlgorithmChaCha20Poly1305;
    ts->max_frame_payload = 1;
    realityclient_lstate_t *ls = lineGetState(fixture->line, fixture->reality);
    realityclientLinestateInitialize(ls, fixture->pool);
    ls->record_profile = (reality_v2_record_profile_t) {
        .profile_id = kRealityV2RecordProfileOpaque,
        .visible_prefix_len = kRealityV2OpaquePrefixSize,
    };
    ls->tls_version = kRealityV2Tls13;
    ls->session_keys_ready = true;
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
    requireClient(atomic_load(&fixture->line->refc) == 1, "client lifecycle line reference leaked");
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
        {kRealityV2RecordProfileOpaque, kRealityV2OpaquePrefixSize, 0, 0},
        {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0},
        {kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20},
        {kRealityV2RecordProfileOpaque, kRealityV2OpaquePrefixSize, 0, 0},
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
}
