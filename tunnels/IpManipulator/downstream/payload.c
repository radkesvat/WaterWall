#include "structure.h"

#include "loggers/network_logger.h"

#include "tricks/protoswap/trick.h"
#include "tricks/overlapsni/trick.h"
#include "tricks/portghost/trick.h"
#include "tricks/smugglefin/trick.h"
#include "tricks/smugglesni/trick.h"
#include "tricks/sniblender/trick.h"
#include "tricks/tcpbitchange/trick.h"

void ipmanipulatorDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (state->trick_source_port_ghost || state->trick_dest_port_ghost)
    {
        discard portghosttrickRestore(t, l, &buf);
        if (buf == NULL)
        {
            return;
        }
    }

    if (state->trick_smuggle_fin && smugglefintrickDownStreamPayload(t, l, buf))
    {
        return;
    }

    if (state->trick_overlap_sni && overlapsnitrickDownStreamPayload(t, l, buf))
    {
        return;
    }

    if (state->trick_proto_swap)
    {
        protoswaptrickDownStreamPayload(t, l, buf);
    }

    if (state->trick_tcp_bit_changes)
    {
        tcpbitchangetrickDownStreamPayload(t, l, &buf);
        if (buf == NULL)
        {
            return;
        }
    }

    if (state->trick_sni_blender)
    {
        sniblendertrickDownStreamPayload(t, l, buf);
    }

    if (state->trick_smuggle_sni)
    {
        smugglesnitrickLogDownStreamServerHello(t, l, buf);
    }

    ipmanipulatorSendDownstreamFinal(t, l, buf);
}
