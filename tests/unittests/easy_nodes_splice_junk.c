#include "JunkDatagramSender/structure.h"
#include "easy_nodes_splice_fixture.h"

void testJunkSplice(bool splice)
{
    for (unsigned close = 0; close < 2; ++close)
    {
        easy_fixture_t f;
        easySetup(&f, tunnelCreate(NULL, sizeof(junkdatagramsender_tstate_t), sizeof(junkdatagramsender_lstate_t)));
        junkdatagramsender_tstate_t *ts = tunnelGetState(f.node);
        ts->selected_protocol_mask      = UINT64_C(1) << kJunkDatagramSenderProtocolDns;
        ts->packet_count_min = ts->packet_count_max = 1;
        ts->resend_again_times                      = 1;
        junkdatagramsender_lstate_t *ls             = lineGetState(f.line, f.node);
        junkdatagramsenderLinestateInitialize(ls, ts);
        f.node->fnFinD     = junkdatagramsenderTunnelDownStreamFinish;
        f.close_on_payload = close;
        sbuf_t *buf        = easyPayload(splice);
        easyExpect(&f, buf, "prebody", 7, 3);
        if (close)
            easyWatch(buf);
        junkdatagramsenderTunnelUpStreamPayload(f.node, f.line, buf);
        if (close)
        {
            easyRequireDisposed();
            easyRequire(f.line == NULL && f.upstream == 1, "junk-triggered death must discard application buffer");
        }
        else
        {
            easyRequire(f.expected == NULL && f.upstream == 2, "junk then opaque application ordering");
            buf = easyPayload(splice);
            easyExpect(&f, buf, "prebody", 7, 3);
            junkdatagramsenderTunnelDownStreamPayload(f.node, f.line, buf);
            easyRequire(f.expected == NULL && f.downstream == 1, "opaque downstream application");
            ls->upstream_finished = ls->downstream_finished = true;
            buf                                             = easyPayload(splice);
            easyWatch(buf);
            junkdatagramsenderTunnelUpStreamPayload(f.node, f.line, buf);
            easyRequireDisposed();
            buf = easyPayload(splice);
            easyWatch(buf);
            junkdatagramsenderTunnelDownStreamPayload(f.node, f.line, buf);
            easyRequireDisposed();
            easyRequire(f.upstream == 2 && f.downstream == 1, "terminal direction published data");
        }
        easyTeardown(&f);
    }
}
