/*
 * Covers: halfduplex splice fixture; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Opt-in fixture/header composition. The including suite owns setup, case publication, and cleanup;
 * this header has no independent CTest entry.
 * Cases: the explicit main/fixture operations and boundary vectors below
 * Checks: private pipe creation failed; private pipe did not receive every claimed byte
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network or
 * application-throughput behavior.
 * CTest: owning suite registration in tests/cmake/native/; this is a helper/conditional source, not a
 * separate selectable test
 */
#pragma once

#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/protocols/splice_source.h"

/* Small real-pipe inputs; large cases use resident prefix storage rather than
 * assuming that the kernel grants pipe growth. Include after the TWF harness. */
#if WW_HAVE_SPLICE
#include <unistd.h>
#endif

static sbuf_t *halfduplexTestBytes(buffer_pool_t *pool, const void *data, uint32_t length, bool splice, uint16_t prefix)
{
#if WW_HAVE_SPLICE
    if (splice)
    {
        twfRequire(prefix <= length && length - prefix <= 4096, "invalid real-pipe fixture geometry");
        sbuf_t  *buf  = twfTrackAcquired(sbufCreateSplice(max(prefix, (uint16_t) 64)));
        uint32_t body = length - prefix;
        if (body != 0)
        {
            twfRequire(testSpliceSourceInitPipe(buf) == 0, "private pipe lease failed");
            twfRequire(write(sbufSpliceMetadata(buf).pipefd[1], (const uint8_t *) data + prefix, body) == body,
                       "private pipe did not receive every claimed byte");
        }
        buf->capacity += body;
        sbufSetLength(buf, body);
        sbufShiftLeft(buf, prefix);
        if (prefix != 0)
            memoryCopyLarge(sbufGetMutablePtr(buf), data, prefix);
        return buf;
    }
#else
    discard splice;
    discard prefix;
#endif
    sbuf_t *buf = bufferpoolGetBestFit(pool, length, bufferpoolGetLargeBufferPadding(pool));
    sbufSetLength(buf, length);
    if (length != 0)
        memoryCopyLarge(sbufGetMutablePtr(buf), data, length);
    return buf;
}

static sbuf_t *halfduplexTestMaterialize(buffer_pool_t *pool, sbuf_t *buf)
{
    if (! sbufIsSplice(buf))
        return buf;
    sbuf_t *out = bufferpoolGetBestFit(pool, sbufGetLength(buf), 64);
    sbufSpliceReadToBuffer(buf, out, sbufGetLength(buf));
    bufferpoolReuseBuffer(pool, buf);
    return out;
}
