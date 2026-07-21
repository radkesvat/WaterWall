#include "structure.h"

static sbuf_t *realityserverCopyCoverBytes(buffer_pool_t *pool, const uint8_t *data, uint32_t len)
{
    sbuf_t *prefix;
    if (len <= bufferpoolGetSmallBufferSize(pool))
    {
        prefix = bufferpoolGetSmallBuffer(pool);
    }
    else if (len <= bufferpoolGetLargeBufferSize(pool))
    {
        prefix = bufferpoolGetLargeBuffer(pool);
    }
    else
    {
        prefix = sbufCreateWithPadding(len, bufferpoolGetLargeBufferPadding(pool));
    }

    prefix = sbufReserveSpace(prefix, len);
    sbufSetLength(prefix, len);
    memoryCopyLarge(sbufGetMutablePtr(prefix), data, len);
    return prefix;
}

static bool realityserverForwardCoverDownstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityserver_lstate_t *ls = lineGetState(l, t);
    assert(! ls->destination_downstream_cutoff);
    if (ls->destination_downstream_forward_depth == UINT32_MAX)
    {
        lineReuseBuffer(l, buf);
        realityserverCloseLineBidirectional(t, l);
        return false;
    }

    ++ls->destination_downstream_forward_depth;
    if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf))
    {
        return false;
    }

    ls = lineGetState(l, t);
    assert(ls->destination_downstream_forward_depth != 0);
    --ls->destination_downstream_forward_depth;
    return true;
}

static void realityserverHandlePendingDestinationPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    const uint8_t *data = sbufGetRawPtr(buf);
    uint32_t       len  = sbufGetLength(buf);

    if (len == 0)
    {
        if (! realityserverForwardCoverDownstream(t, l, buf))
        {
            return;
        }
        realityserver_lstate_t *ls = lineGetState(l, t);
        if (ls->mode == kRealityServerModeHandoffAwaitBoundary &&
            realityserverTlsRecordBoundaryTrackerIsAtBoundary(&ls->destination_record_boundary))
        {
            realityserverSendHandoffAckAtBoundary(t, l);
        }
        return;
    }

    uint32_t offset = 0;
    while (offset < len)
    {
        realityserver_lstate_t *ls = lineGetState(l, t);
        if (ls->mode == kRealityServerModeVisitor)
        {
            sbuf_t *remaining = realityserverCopyCoverBytes(pool, data + offset, len - offset);
            bufferpoolReuseBuffer(pool, buf);
            realityserverForwardCoverDownstream(t, l, remaining);
            return;
        }
        if (ls->mode != kRealityServerModePending)
        {
            bufferpoolReuseBuffer(pool, buf);
            return;
        }

        size_t consumed    = 0;
        bool   boundary_ok = realityserverTlsRecordBoundaryTrackerFeed(
            &ls->destination_record_boundary, data + offset, len - offset, true, &consumed);
        uint32_t chunk_len = boundary_ok ? (uint32_t) consumed : len - offset;
        if (chunk_len == 0)
        {
            bufferpoolReuseBuffer(pool, buf);
            realityserverCloseLineBidirectional(t, l);
            return;
        }

        lineLock(l);
        bool alive = realityserverObserveDownstreamHandshake(t, l, data + offset, chunk_len);
        if (! alive || ! lineIsAlive(l))
        {
            bufferpoolReuseBuffer(pool, buf);
            lineUnlock(l);
            return;
        }
        lineUnlock(l);

        ls = lineGetState(l, t);
        if (ls->mode == kRealityServerModeVisitor)
        {
            sbuf_t *remaining = realityserverCopyCoverBytes(pool, data + offset, len - offset);
            bufferpoolReuseBuffer(pool, buf);
            realityserverForwardCoverDownstream(t, l, remaining);
            return;
        }

        sbuf_t *prefix = realityserverCopyCoverBytes(pool, data + offset, chunk_len);
        offset += chunk_len;
        if (! realityserverForwardCoverDownstream(t, l, prefix))
        {
            bufferpoolReuseBuffer(pool, buf);
            return;
        }

        ls = lineGetState(l, t);
        if (! boundary_ok || ls->destination_record_boundary.failed)
        {
            bufferpoolReuseBuffer(pool, buf);
            if (ls->mode == kRealityServerModeHandoffAwaitBoundary)
            {
                realityserverCloseLineBidirectional(t, l);
            }
            return;
        }
        if (ls->mode == kRealityServerModeHandoffAwaitBoundary)
        {
            bufferpoolReuseBuffer(pool, buf);
            if (realityserverTlsRecordBoundaryTrackerIsAtBoundary(&ls->destination_record_boundary))
            {
                realityserverSendHandoffAckAtBoundary(t, l);
            }
            return;
        }
    }

    bufferpoolReuseBuffer(pool, buf);
}

static void realityserverHandleBoundaryDestinationPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityserver_lstate_t *ls   = lineGetState(l, t);
    buffer_pool_t          *pool = lineGetBufferPool(l);
    uint32_t                len  = sbufGetLength(buf);

    if (ls->destination_record_boundary.failed)
    {
        bufferpoolReuseBuffer(pool, buf);
        realityserverCloseLineBidirectional(t, l);
        return;
    }

    if (realityserverTlsRecordBoundaryTrackerIsAtBoundary(&ls->destination_record_boundary))
    {
        bufferpoolReuseBuffer(pool, buf);
        realityserverSendHandoffAckAtBoundary(t, l);
        return;
    }

    size_t consumed = 0;
    if (! realityserverTlsRecordBoundaryTrackerFeed(
            &ls->destination_record_boundary, sbufGetRawPtr(buf), len, true, &consumed))
    {
        bufferpoolReuseBuffer(pool, buf);
        realityserverCloseLineBidirectional(t, l);
        return;
    }

    if (consumed == 0)
    {
        bufferpoolReuseBuffer(pool, buf);
        return;
    }

    sbuf_t *prefix = buf;
    if (consumed < len)
    {
        prefix = realityserverCopyCoverBytes(pool, sbufGetRawPtr(buf), (uint32_t) consumed);
        bufferpoolReuseBuffer(pool, buf);
    }

    if (! realityserverForwardCoverDownstream(t, l, prefix))
    {
        return;
    }

    ls = lineGetState(l, t);
    if (realityserverTlsRecordBoundaryTrackerIsAtBoundary(&ls->destination_record_boundary))
    {
        realityserverSendHandoffAckAtBoundary(t, l);
    }
}

void realityserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityserver_lstate_t *ls = lineGetState(l, t);

    if (ls->closing_destination_for_authorized || ls->terminal_closing || ls->prev_finished)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    switch (ls->mode)
    {
    case kRealityServerModeAuthorized:
        realityserverEncryptAndSendDownstream(t, l, buf);
        return;
    case kRealityServerModeVisitor:
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    case kRealityServerModePending:
        realityserverHandlePendingDestinationPayload(t, l, buf);
        return;
    case kRealityServerModeHandoffAwaitBoundary:
        realityserverHandleBoundaryDestinationPayload(t, l, buf);
        return;
    case kRealityServerModeHandoffAwaitConfirm:
        assert(ls->destination_downstream_cutoff);
        lineReuseBuffer(l, buf);
        return;
    default:
        assert(false);
        lineReuseBuffer(l, buf);
        return;
    }
}
