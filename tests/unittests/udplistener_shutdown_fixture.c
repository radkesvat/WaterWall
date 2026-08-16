#include "UdpListener/structure.h"

#include "udplistener_shutdown_fixture.h"

tunnel_t *udplistenerShutdownFixtureCreateTunnel(void)
{
    tunnel_t *udp = tunnelCreate(NULL, sizeof(udplistener_tstate_t), sizeof(udplistener_lstate_t));
    if (udp != NULL)
    {
        udp->fnEstD = udplistenerTunnelDownStreamEst;
    }
    return udp;
}

local_idle_item_t *udplistenerShutdownFixtureAttach(tunnel_t *udp, line_t *line, local_idle_table_t *table,
                                                    udpsock_t *socket, hash_t hash)
{
    udplistener_lstate_t *ls = lineGetState(line, udp);
    *ls                      = (udplistener_lstate_t) {.tunnel = udp, .line = line, .uio = socket, .listener_fd = -1};

    local_idle_item_t *idle = localidletableCreateItem(table, hash, ls, udplistenerOnConnectionExpire, UINT64_C(30000));
    if (idle != NULL)
    {
        ls->idle_handle = idle;
    }
    return idle;
}
