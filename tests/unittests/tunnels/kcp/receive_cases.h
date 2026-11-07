/*
 * Identity-aware receive regressions shared by the real paired-node fixtures.
 * Real KCP covers fragmented/exact-capacity/oversized messages, missing/unknown
 * flags, empty DATA and ping control records. Closing receivers must never
 * deliver data or notify an already retired application again.
 */
#pragma once

enum
{
    kReceiveOversized,
    kReceiveUnknown,
    kReceiveMissingFlag,
    kReceiveExactCapacity,
    kReceiveControls,
    kReceiveClose,
    kReceiveCaseCount
};

static void receiveWrite32(uint8_t *bytes, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i)
        bytes[i] = (uint8_t) (value >> (8U * i));
}
static void receivePush(endpoint_t *ep, bool server, uint32_t sequence, uint8_t fragments, uint32_t length,
                        uint8_t first, size_t data_offset)
{
    tou_session_t *receiver = server ? ep->server_session : ep->client_session;
    uint8_t       *body     = memoryAllocate(24U + length);
    memoryZero(body, 24);
    receiveWrite32(body, touSessionKcp(receiver)->conv);
    body[4] = 81;
    body[5] = fragments;
    body[6] = 128;
    receiveWrite32(body + 12, sequence);
    receiveWrite32(body + 20, length);
    for (uint32_t i = 0; i < length; ++i)
        body[24U + i] = (uint8_t) ((data_offset + i - 1U) * 29U + 17U);
    if (length && data_offset == 0)
        body[24] = first;
    sbuf_t *packet = touWireCreate(getCurrentWorkerBufferPool(),
                                   kTouKcp,
                                   touSessionClientNonce(receiver),
                                   touSessionServerNonce(receiver),
                                   body,
                                   24U + length);
    require(packet != NULL, "raw receive fixture exceeded buffer geometry");
    memoryFree(body);
    deliver((packet_t) {packet, ep, server ? 0U : 1U});
}
static void caseReceiveMessages(bool server)
{
    for (unsigned closing = 0; closing < 2; ++closing)
        for (unsigned kind = 0; kind < (closing ? 3U : kReceiveCaseCount); ++kind)
        {
            testCaseSet("session-identified KCP receive framing and closing rejection");
            fixture_t fixture;
            setup(&fixture, false, 1000, 1000, 65535);
            endpoint_t *ep = openApp();
            established(ep);
            tou_session_t *receiver = server ? ep->server_session : ep->client_session;
            uint32_t       sequence = touSessionKcp(receiver)->rcv_nxt;
            if (closing)
            {
                if (server)
                    closeService(ep);
                else
                    closeApp(ep);
            }
            sbuf_t  *probe    = bufferpoolGetLargeBuffer(getCurrentWorkerBufferPool());
            uint32_t capacity = sbufGetMaximumWriteableSize(probe);
            bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), probe);
            uint32_t       remaining = kind == kReceiveOversized || kind == kReceiveExactCapacity
                                           ? capacity + (kind == kReceiveOversized)
                                       : kind == kReceiveMissingFlag ? 0
                                                                     : 1;
            const uint32_t total     = remaining;
            size_t         offset    = 0;
            do
            {
                uint32_t length = min(remaining, 60000U);
                uint8_t first = kind == kReceiveUnknown ? 0x7f : kind == kReceiveClose ? kTouFrameClose : kTouFrameData;
                receivePush(
                    ep, server, sequence++, (uint8_t) ((remaining - length + 59999U) / 60000U), length, first, offset);
                remaining -= length;
                offset += length;
                if (remaining)
                {
                    require(touSessionIsAlive(receiver), "incomplete KCP message closed the session");
                    require(ep->received[server ? 0 : 1] == 0, "incomplete KCP message was delivered");
                }
            } while (remaining);
            if (kind == kReceiveControls)
            {
                receivePush(ep, server, sequence++, 0, 1, kTouFramePing, 0);
                receivePush(ep, server, sequence++, 0, 2, kTouFrameData, 0);
            }
            if (! closing)
            {
                bool accepted = kind == kReceiveExactCapacity || kind == kReceiveControls;
                if (accepted)
                {
                    require(touSessionIsAlive(receiver), "valid receive closed the session");
                    require(ep->received[server ? 0 : 1] == (kind == kReceiveControls ? 1U : total - 1U),
                            "valid receive lost exact-capacity/control payload");
                }
                else
                {
                    line_t *app = server ? ep->service : ep->app;
                    require(! lineIsAlive(app), "malformed/close message left its application active");
                    require(ep->received[server ? 0 : 1] == 0, "data behind rejected control escaped");
                }
            }
            else
                require(ep->received[server ? 0 : 1] == 0, "closing session delivered bytes to a retired application");
            teardown();
        }
}
