#include "structure.h"

#include "loggers/network_logger.h"

#include "tricks/protoswap/trick.h"
#include "tricks/firstsni/trick.h"
#include "tricks/overlapsni/trick.h"
#include "tricks/smugglefin/trick.h"
#include "tricks/smugglesni/trick.h"
#include "tricks/sniblender/trick.h"
#include "tricks/synfinsni/trick.h"
#include "tricks/tcpbitchange/trick.h"

void ipmanipulatorUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (state->trick_smuggle_fin && smugglefintrickUpStreamPayload(t, l, buf))
    {
        return;
    }

    if (state->trick_proto_swap)
    {
        protoswaptrickUpStreamPayload(t, l, buf);
    }

    if (state->trick_tcp_bit_changes)
    {
        tcpbitchangetrickUpStreamPayload(t, l, &buf);
        if (buf == NULL)
        {
            return;
        }
    }
    // LOGD("IpManipulator: Upstream payload received, length=%d", sbufGetLength(buf));

    if (state->trick_synfin_sni && synfinsnitrickUpStreamPayload(t, l, buf))
    {
        return;
    }

    if (state->trick_overlap_sni && overlapsnitrickUpStreamPayload(t, l, buf))
    {
        return;
    }

    if (state->trick_smuggle_sni && smugglesnitrickUpStreamPayload(t, l, buf))
    {
        return;
    }

    if (state->trick_first_sni && firstsnitrickUpStreamPayload(t, l, buf))
    {
        return;
    }

    if (state->trick_sni_blender && sniblendertrickUpStreamPayload(t, l, buf))
    {
        return;
    }

    ipmanipulatorSendUpstreamFinal(t, l, buf);
}
