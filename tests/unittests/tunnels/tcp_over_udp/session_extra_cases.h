#pragma once

/* These cases use the paired fixture's real engines and only advance its
 * monotonic clock explicitly, so protocol traffic cannot hide deadline resets. */
static void extraDiscardQueuedWire(void)
{
    for (size_t i = 0; i < active->count_packets; ++i)
        bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), active->queue[i].buffer);
    active->count_packets = 0;
}

static const uint8_t *extraKcpBody(sbuf_t *packet, size_t *size)
{
    tou_wire_t wire;
    if (! touWireDecode(sbufGetRawPtr(packet), sbufGetLength(packet), &wire))
        return NULL;
    if (wire.kind == kTouKcp)
    {
        *size = wire.body_len;
        return wire.body;
    }
    if (wire.kind == kTouFec && wire.body_len >= 8 && wire.body[4] == 0xf1 && wire.body[5] == 0)
    {
        *size = wire.body_len - 8;
        return wire.body + 8;
    }
    return NULL;
}

static sbuf_t *extraFindRecord(endpoint_t *ep, unsigned direction, uint8_t command, int flag)
{
    for (size_t i = 0; i < active->count_packets; ++i)
    {
        packet_t *packet = &active->queue[i];
        if (packet->endpoint != ep || packet->direction != direction)
            continue;
        size_t         size = 0;
        const uint8_t *body = extraKcpBody(packet->buffer, &size);
        for (size_t at = 0; body != NULL && at + 24 <= size;)
        {
            const uint32_t length = le32(body + at + 20);
            if (length > size - at - 24)
                break;
            if (body[at + 4] == command && (flag < 0 || (length == 1 && body[at + 24] == (uint8_t) flag)))
                return copyPacket(packet->buffer);
            at += 24U + length;
        }
    }
    return NULL;
}

static void casePendingChallengeBound(void)
{
    testCaseSet("pending challenge has one identity and a fixed original expiry");
    fixture_t fixture;
    setup(&fixture, false, 1000, 1000, 1500);
    endpoint_t *anchor = openApp();
    established(anchor); /* Keep the borrowed carrier alive after pending expiry. */
    fixture.drop_kind      = kTouConfirm;
    fixture.drop_direction = 0;
    fixture.drop_remaining = 100;
    endpoint_t    *first   = openApp();
    const uint64_t origin  = clock_us / 1000;
    flushWire(); /* HELLO publishes the pending challenge. */
    flushWire(); /* CHALLENGE reaches the client; its CONFIRM is deliberately lost. */
    require(! touNonceIsZero(touSessionServerNonce(first->client_session)) && first->service == NULL,
            "pending fixture did not stop between CHALLENGE and confirmation");
    const tou_settings_t settings = *touSessionSettings(first->client_session);
    uint8_t              first_server[kTouNonceSize];
    memcpy(first_server, touSessionServerNonce(first->client_session), sizeof(first_server));
    uint8_t zero[kTouNonceSize] = {0};
    sbuf_t *hello               = touControlCreate(
        getCurrentWorkerBufferPool(), kTouHello, touSessionClientNonce(first->client_session), zero, &settings);
    sbuf_t *old_confirm = touControlCreate(getCurrentWorkerBufferPool(),
                                           kTouConfirm,
                                           touSessionClientNonce(first->client_session),
                                           first_server,
                                           &settings);
    require(hello && old_confirm, "pending control fixture geometry failed");
    endpoint_t *other = openApp();
    flushWire();
    require(other->service == NULL && touNonceIsZero(touSessionServerNonce(other->client_session)),
            "a different HELLO replaced the unexpired pending challenge");
    clock_us = (origin + 1900) * 1000;
    wloopUpdateTime(getWorkerLoop(0));
    deliver((packet_t) {copyPacket(hello), first, 0});
    flushWire();
    require(! memcmp(first_server, touSessionServerNonce(first->client_session), kTouNonceSize) &&
                fixture.service_inits == 1,
            "repeated HELLO changed the pending identity or initialized a service");
    /* At equality, the old CONFIRM must already be invalid even if the repeating
     * timer has not run. The retry above must not move the original expiry. */
    clock_us = (origin + 2000) * 1000;
    wloopUpdateTime(getWorkerLoop(0));
    deliver((packet_t) {copyPacket(old_confirm), first, 0});
    require(fixture.service_inits == 1 && first->service == NULL && lineIsAlive(anchor->service),
            "a retry extended pending expiry or expired confirmation initialized service");
    deliver((packet_t) {copyPacket(hello), first, 0});
    require(fixture.count_packets > 0, "pending expiry did not permit a fresh challenge");
    bool fresh_challenge = false;
    for (size_t i = 0; i < fixture.count_packets; ++i)
    {
        tou_wire_t wire;
        packet_t  *packet = &fixture.queue[i];
        if (packet->direction == 1 && packet->endpoint == first &&
            touWireDecode(sbufGetRawPtr(packet->buffer), sbufGetLength(packet->buffer), &wire) &&
            wire.kind == kTouChallenge && memcmp(wire.server_nonce, first_server, kTouNonceSize) != 0)
            fresh_challenge = true;
    }
    require(fresh_challenge, "post-expiry HELLO reused the retired challenge nonce");
    deliver((packet_t) {copyPacket(old_confirm), first, 0});
    require(fixture.service_inits == 1 && first->service == NULL, "old CONFIRM answered a newly issued challenge");
    bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), hello);
    bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), old_confirm);
    teardown();
}

static void caseTrafficCannotExtendDeadline(bool fec)
{
    testCaseSet("ACK progress, ping, duplicate control and unrelated sessions cannot extend close");
    fixture_t fixture;
    setup(&fixture, fec, 800, 800, 1500);
    endpoint_t *ep = openApp();
    established(ep);
    sendBytes(ep, 0, 70001);
    closeApp(ep);
    const uint64_t deadline = touSessionSendDeadline(ep->client_session);
    clock_us += 10000;
    wloopUpdateTime(getWorkerLoop(0));
    touSessionTick(ep->client_session, clock_us / 1000);
    flushDirection(0); /* Receiver accepts data; its ACKs remain captured. */
    sbuf_t *ack = extraFindRecord(ep, 1, 82, -1);
    require(ack != NULL, "deadline fixture did not capture real KCP ACK progress");
    int before = ikcp_waitsnd(touSessionKcp(ep->client_session));
    deliver((packet_t) {copyPacket(ack), ep, 1});
    int after = ikcp_waitsnd(touSessionKcp(ep->client_session));
    require(after > 0 && after < before, "selected ACK did not make partial send progress");
    require(touSessionSendDeadline(ep->client_session) == deadline, "ACK progress extended the send deadline");
    extraDiscardQueuedWire();

    clock_us += 150000;
    wloopUpdateTime(getWorkerLoop(0));
    touSessionTick(ep->server_session, clock_us / 1000);
    sbuf_t *ping = extraFindRecord(ep, 1, 81, kTouFramePing);
    require(ping != NULL, "deadline fixture did not emit a real ping");
    deliver((packet_t) {copyPacket(ping), ep, 1});
    require(touSessionSendDeadline(ep->client_session) == deadline, "ping traffic extended the send deadline");
    extraDiscardQueuedWire();

    sbuf_t *ready = touControlCreate(getCurrentWorkerBufferPool(),
                                     kTouReady,
                                     touSessionClientNonce(ep->client_session),
                                     touSessionServerNonce(ep->client_session),
                                     touSessionSettings(ep->client_session));
    require(ready != NULL, "duplicate READY fixture geometry failed");
    clock_us += 100000;
    wloopUpdateTime(getWorkerLoop(0));
    deliver((packet_t) {copyPacket(ready), ep, 1});
    deliver((packet_t) {copyPacket(ack), ep, 1});
    require(touSessionSendDeadline(ep->client_session) == deadline,
            "duplicate control or ACK changed the original send deadline");
    extraDiscardQueuedWire();

    fixture.direct    = true;
    endpoint_t *fresh = openApp();
    require(fresh->service != NULL && touSessionIsReady(fresh->client_session),
            "unrelated session could not establish on the retained carrier");
    sendBytes(fresh, 0, 4097);
    clock_us += 100000;
    wloopUpdateTime(getWorkerLoop(0));
    touSessionTick(fresh->client_session, clock_us / 1000);
    require(fresh->received[0] == 4097 && touSessionSendDeadline(ep->client_session) == deadline,
            "unrelated session traffic changed another session's close budget");
    fixture.direct = false;
    require(ikcp_waitsnd(touSessionKcp(ep->client_session)) > 0, "deadline fixture lost its outstanding obligation");

    clock_us = (deadline - 1) * 1000;
    wloopUpdateTime(getWorkerLoop(0));
    deliver((packet_t) {copyPacket(ack), ep, 1});
    deliver((packet_t) {copyPacket(ping), ep, 1});
    deliver((packet_t) {copyPacket(ready), ep, 1});
    require(touSessionIsAlive(ep->client_session) && touSessionSendDeadline(ep->client_session) == deadline,
            "valid traffic before expiry moved the original deadline");
    clock_us = deadline * 1000;
    wloopUpdateTime(getWorkerLoop(0));
    touSessionTick(ep->client_session, deadline);
    require(! touSessionIsAlive(ep->client_session) && ! touSessionCloseConfirmed(ep->client_session),
            "traffic extended a fixed unconfirmed send budget past equality");
    deliver((packet_t) {copyPacket(ack), ep, 1});
    require(! touSessionCloseConfirmed(ep->client_session), "late duplicate ACK rewrote an expired outcome");
    bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), ack);
    bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), ping);
    bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), ready);
    teardown();
}

static void tcpOverUdpExtraCases(void)
{
    casePendingChallengeBound();
    caseTrafficCannotExtendDeadline(false);
    caseTrafficCannotExtendDeadline(true);
}
